use anyhow::Result;
use ark_crypto_primitives::sponge::Absorb;
use ark_ec::{CurveConfig, CurveGroup};
use ark_ff::{PrimeField, UniformRand};
use ark_std::rand::Rng;

use crate::curve_absorb::CurveAbsorb;
use crate::shuffling::{
    bayer_groth::decomposition::random_permutation as bg_random_permutation,
    shuffle_and_rerandomize_random, CommunityDecryptionShare, ElGamalCiphertext,
    PlayerAccessibleCiphertext, PlayerTargetedBlindingContribution, PartialUnblindingShare,
};

pub type Deck<C, const N: usize> = [ElGamalCiphertext<C>; N];

#[derive(Clone, Debug)]
pub struct Shuffler<C: CurveGroup> {
    pub index: usize,
    pub secret_key: C::ScalarField,
    pub public_key: C,
    pub aggregated_public_key: C,
}

impl<C> Shuffler<C>
where
    C: CurveGroup,
{
    pub fn new(index: usize, secret_key: C::ScalarField, public_key: C, aggregated_public_key: C) -> Self {
        Self {
            index,
            secret_key,
            public_key,
            aggregated_public_key,
        }
    }
}

pub trait ShufflerApi<C: CurveGroup> {
    /// Receives an encrypted deck and returns a shuffled, re-encrypted deck
    fn shuffle<const N: usize, R: Rng>(&self, input_deck: &Deck<C, N>, rng: &mut R) -> Result<Deck<C, N>>
    where
        C::Config: CurveConfig<ScalarField = C::ScalarField>,
        C::ScalarField: PrimeField + UniformRand;

    /// Provides a player-targeted blinding contribution + proof (for later combination)
    fn provide_blinding_player_decryption_share<R: Rng>(
        &self,
        player_public_key: C,
        rng: &mut R,
    ) -> Result<PlayerTargetedBlindingContribution<C>>
    where
        C::BaseField: PrimeField,
        C::ScalarField: PrimeField + Absorb,
        C::Affine: Absorb,
        C: CurveAbsorb<C::BaseField>;

    /// Provides a PartialUnblinding share for a player’s ciphertext (n-of-n)
    fn provide_unblinding_decryption_share(
        &self,
        player_ciphertext: &PlayerAccessibleCiphertext<C>,
    ) -> Result<PartialUnblindingShare<C>>
    where
        C::ScalarField: PrimeField;

    /// Provides a CommunityDecryptionShare + proof for a community card (n-of-n)
    fn provide_community_decryption_share<R: Rng>(
        &self,
        ciphertext: &ElGamalCiphertext<C>,
        rng: &mut R,
    ) -> Result<CommunityDecryptionShare<C>>
    where
        C::BaseField: PrimeField,
        C::ScalarField: PrimeField + Absorb,
        C: CurveAbsorb<C::BaseField>;
}

impl<C> ShufflerApi<C> for Shuffler<C>
where
    C: CurveGroup,
{
    fn shuffle<const N: usize, R: Rng>(
        &self,
        input_deck: &Deck<C, N>,
        rng: &mut R,
    ) -> Result<Deck<C, N>>
    where
        C::Config: CurveConfig<ScalarField = C::ScalarField>,
        C::ScalarField: PrimeField + UniformRand,
    {
        // Draw a random permutation using existing utility
        let perm_vec = bg_random_permutation(N, rng);
        let permutation: [usize; N] = core::array::from_fn(|i| perm_vec[i]);

        // Shuffle and re-randomize with the aggregated public key
        let (output_deck, _rerands) = shuffle_and_rerandomize_random(
            input_deck,
            &permutation,
            self.aggregated_public_key,
            rng,
        );
        Ok(output_deck)
    }

    fn provide_blinding_player_decryption_share<R: Rng>(
        &self,
        player_public_key: C,
        rng: &mut R,
    ) -> Result<PlayerTargetedBlindingContribution<C>>
    where
        C::BaseField: PrimeField,
        C::ScalarField: PrimeField + Absorb,
        C::Affine: Absorb,
        C: CurveAbsorb<C::BaseField>,
    {
        // Use the shuffler's long-term secret as the blinding share δ_j.
        // This avoids introducing extra bounds (UniformRand) here and matches the requested trait signature.
        let delta_j = self.secret_key;

        let contribution = crate::shuffling::player_decryption::native::PlayerTargetedBlindingContribution::generate(
            delta_j,
            self.aggregated_public_key,
            player_public_key,
            rng,
        );
        Ok(contribution)
    }

    fn provide_unblinding_decryption_share(
        &self,
        player_ciphertext: &PlayerAccessibleCiphertext<C>,
    ) -> Result<PartialUnblindingShare<C>>
    where
        C::ScalarField: PrimeField,
    {
        // μ_{u,j} = A_u^{x_j}; index is self.index
        let share = crate::shuffling::generate_committee_decryption_share(
            player_ciphertext,
            self.secret_key,
            self.index,
        );
        Ok(share)
    }

    fn provide_community_decryption_share<R: Rng>(
        &self,
        ciphertext: &ElGamalCiphertext<C>,
        rng: &mut R,
    ) -> Result<CommunityDecryptionShare<C>>
    where
        C::BaseField: PrimeField,
        C::ScalarField: PrimeField + Absorb,
        C: CurveAbsorb<C::BaseField>,
    {
        let share = crate::shuffling::CommunityDecryptionShare::generate(
            ciphertext,
            self.secret_key,
            self.index,
            rng,
        );
        Ok(share)
    }
}

pub mod cluster;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shuffling::{
        combine_blinding_contributions_for_player, decrypt_community_card, generate_random_ciphertexts,
        recover_card_value,
    };
    use ark_ec::PrimeGroup;
    use ark_grumpkin::Projective as GrumpkinProjective;
    use ark_std::test_rng;

    const N_SHUFFLERS: usize = 3;
    const DECK_N: usize = 52;

    #[test]
    fn test_shuffle_and_player_targeted_recovery() {
        let mut rng = test_rng();

        // Build a cluster of shufflers
        let cluster = crate::shuffler::cluster::ShufflerCluster::<GrumpkinProjective>::generate(
            N_SHUFFLERS,
            &mut rng,
        )
        .expect("cluster generation");
        let agg_pk = cluster.aggregated_public_key;

        // Generate an initial encrypted deck using the aggregated public key
        let (mut deck, _r) =
            generate_random_ciphertexts::<GrumpkinProjective, DECK_N>(&agg_pk, &mut rng);

        // Sequentially shuffle across all shufflers
        for s in &cluster.shufflers {
            deck = s.shuffle(&deck, &mut rng).expect("shuffle");
        }

        // Choose a safe card index (avoid last which could map to 52)
        let card_index = 10usize; // expected value = 11
        let card_ct = deck[card_index].clone();

        // Player keys
        let player_sk = <GrumpkinProjective as PrimeGroup>::ScalarField::rand(&mut rng);
        let player_pk = GrumpkinProjective::generator() * player_sk;

        // Each shuffler provides a blinding contribution for this player
        let mut contributions = Vec::with_capacity(N_SHUFFLERS);
        for s in &cluster.shufflers {
            let c = s
                .provide_blinding_player_decryption_share(player_pk, &mut rng)
                .expect("blinding share");
            contributions.push(c);
        }

        // Combine into a player-accessible ciphertext
        let player_ciphertext = combine_blinding_contributions_for_player(
            &card_ct,
            &contributions,
            agg_pk,
            player_pk,
        )
        .expect("combine blinding contributions");

        // Each shuffler provides partial unblinding
        let mut unblinding_shares = Vec::with_capacity(N_SHUFFLERS);
        for s in &cluster.shufflers {
            let u = s
                .provide_unblinding_decryption_share(&player_ciphertext)
                .expect("unblinding share");
            unblinding_shares.push(u);
        }

        // Recover card value via player-targeted path
        let recovered = recover_card_value::<GrumpkinProjective>(
            &player_ciphertext,
            player_sk,
            unblinding_shares,
            N_SHUFFLERS,
        )
        .expect("recover card value");

        // Also derive expected value via community decryption of the same post-shuffle ciphertext
        let mut comm_shares = Vec::with_capacity(N_SHUFFLERS);
        for s in &cluster.shufflers {
            comm_shares.push(
                s.provide_community_decryption_share(&card_ct, &mut rng)
                    .expect("community share"),
            );
        }
        let expected_value = decrypt_community_card::<GrumpkinProjective>(
            &card_ct,
            comm_shares,
            N_SHUFFLERS,
        )
        .expect("community decrypt");

        // Player-targeted recovery should match community decryption result
        assert_eq!(recovered, expected_value);
    }

    #[test]
    fn test_community_decryption_flow() {
        let mut rng = test_rng();

        // Build a cluster of shufflers
        let cluster = crate::shuffler::cluster::ShufflerCluster::<GrumpkinProjective>::generate(
            N_SHUFFLERS,
            &mut rng,
        )
        .expect("cluster generation");
        let agg_pk = cluster.aggregated_public_key;

        // Encrypt a community card with known value in [0..51]
        let card_value: u8 = 25;
        let message = <GrumpkinProjective as PrimeGroup>::ScalarField::from(card_value as u64);
        let msg_point = GrumpkinProjective::generator() * message;
        let randomness = <GrumpkinProjective as PrimeGroup>::ScalarField::rand(&mut rng);
        let ciphertext = ElGamalCiphertext::encrypt(msg_point, randomness, agg_pk);

        // Collect community decryption shares from all shufflers
        let mut shares = Vec::with_capacity(N_SHUFFLERS);
        for s in &cluster.shufflers {
            let share = s
                .provide_community_decryption_share(&ciphertext, &mut rng)
                .expect("community share");
            shares.push(share);
        }

        // Decrypt using all shares (n-of-n)
        let recovered = decrypt_community_card::<GrumpkinProjective>(&ciphertext, shares, N_SHUFFLERS)
            .expect("community decrypt");
        assert_eq!(recovered, card_value);
    }
}
