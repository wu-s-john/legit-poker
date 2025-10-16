use anyhow::{anyhow, Result};
use ark_crypto_primitives::signature::{schnorr::Schnorr, SignatureScheme};
use ark_crypto_primitives::sponge::Absorb;
use ark_ec::{CurveConfig, CurveGroup};
use ark_ff::{PrimeField, UniformRand, Zero};
use ark_serialize::CanonicalSerialize;
use ark_std::rand::Rng;
use dashmap::DashMap;
use parking_lot::Mutex;
use rand::{rngs::StdRng, RngCore, SeedableRng};
use sha2::Sha256;
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::curve_absorb::CurveAbsorb;
use crate::ledger::{
    actor::{AnyActor, ShufflerActor},
    messages::{
        sign_enveloped_action, AnyGameMessage, AnyMessageEnvelope, EnvelopedMessage,
        GameShuffleMessage, MetadataEnvelope, SignatureEncoder,
    },
    snapshot::TableAtShuffling,
    types::{GameId, HandId, ShufflerId},
};
use crate::shuffling::data_structures::ShuffleProof;
use crate::shuffling::{
    bayer_groth::decomposition::random_permutation as bg_random_permutation,
    shuffle_and_rerandomize_random, CommunityDecryptionShare, ElGamalCiphertext,
    PartialUnblindingShare, PlayerAccessibleCiphertext, PlayerTargetedBlindingContribution,
    DECK_SIZE,
};
use crate::signing::WithSignature;

pub type Deck<C, const N: usize> = [ElGamalCiphertext<C>; N];

pub type ShufflerScheme<C> = Schnorr<C, Sha256>;

const LOG_TARGET: &str = "game::shuffler";

#[derive(Clone, Debug)]
pub struct ShufflerKeypair<C: CurveGroup> {
    pub index: usize,
    pub secret_key: C::ScalarField,
    pub public_key: C,
    pub aggregated_public_key: C,
}

impl<C> ShufflerKeypair<C>
where
    C: CurveGroup,
{
    pub(crate) fn new(
        index: usize,
        secret_key: C::ScalarField,
        public_key: C,
        aggregated_public_key: C,
    ) -> Self {
        Self {
            index,
            secret_key,
            public_key,
            aggregated_public_key,
        }
    }
}

pub trait ShufflerApi<C: CurveGroup> {
    /// Receives an encrypted deck and returns a shuffled, re-encrypted deck with proof
    fn shuffle<const N: usize, R: Rng>(
        &self,
        input_deck: &Deck<C, N>,
        rng: &mut R,
    ) -> Result<(Deck<C, N>, ShuffleProof<C>)>
    where
        C::Config: CurveConfig<ScalarField = C::ScalarField>,
        C::ScalarField: PrimeField + UniformRand,
        C::BaseField: PrimeField;

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

impl<C> ShufflerApi<C> for ShufflerKeypair<C>
where
    C: CurveGroup,
{
    fn shuffle<const N: usize, R: Rng>(
        &self,
        input_deck: &Deck<C, N>,
        rng: &mut R,
    ) -> Result<(Deck<C, N>, ShuffleProof<C>)>
    where
        C::Config: CurveConfig<ScalarField = C::ScalarField>,
        C::ScalarField: PrimeField + UniformRand,
        C::BaseField: PrimeField,
    {
        // Draw a random permutation using existing utility
        let perm_vec = bg_random_permutation(N, rng);
        let permutation: [usize; N] = core::array::from_fn(|i| perm_vec[i]);

        // Shuffle and re-randomize with the aggregated public key
        let (output_deck, rerands) = shuffle_and_rerandomize_random(
            input_deck,
            &permutation,
            self.aggregated_public_key,
            rng,
        );
        let input_vec = input_deck.to_vec();
        let sorted_pairs = output_deck
            .iter()
            .cloned()
            .map(|cipher| (cipher, C::BaseField::zero()))
            .collect();
        let rerand_vec = rerands.to_vec();
        let proof = ShuffleProof::new(input_vec, sorted_pairs, rerand_vec)
            .map_err(|err| anyhow!("failed to construct shuffle proof: {err}"))?;
        Ok((output_deck, proof))
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

#[derive(Clone, Debug)]
pub struct ShufflerRunConfig {
    pub rng_seed: [u8; 32],
    pub message_history_cap: usize,
}

impl ShufflerRunConfig {
    pub fn new(rng_seed: [u8; 32]) -> Self {
        Self {
            rng_seed,
            message_history_cap: 64,
        }
    }

    pub fn with_message_history_cap(mut self, cap: usize) -> Self {
        self.message_history_cap = cap;
        self
    }
}

#[derive(Debug)]
pub struct ShufflingHandState<C: CurveGroup> {
    pub expected_order: Vec<ShufflerId>,
    pub buffered: Vec<EnvelopedMessage<C, GameShuffleMessage<C>>>,
    pub next_nonce: u64,
    pub turn_index: usize,
    pub initial_deck: [ElGamalCiphertext<C>; DECK_SIZE],
    pub latest_deck: [ElGamalCiphertext<C>; DECK_SIZE],
    pub completed: bool,
    pub acted: bool,
    pub rng: StdRng,
}

#[derive(Debug)]
struct HandRuntime<C: CurveGroup> {
    pub game_id: GameId,
    pub hand_id: HandId,
    pub cancel: CancellationToken,
    pub state: Mutex<ShufflingHandState<C>>,
}

pub struct Shuffler<C, S>
where
    C: CurveGroup,
    S: SignatureScheme,
{
    index: usize,
    shuffler_id: ShufflerId,
    public_key: C,
    params: Arc<S::Parameters>,
    secret_key: Arc<S::SecretKey>,
    api: Arc<ShufflerKeypair<C>>,
    submit: mpsc::Sender<AnyMessageEnvelope<C>>,
    states: Arc<DashMap<(GameId, HandId), Arc<HandRuntime<C>>>>,
    rng: Mutex<StdRng>,
    config: ShufflerRunConfig,
}

impl<C, S> Shuffler<C, S>
where
    C: CurveGroup,
    S: SignatureScheme<PublicKey = C::Affine>,
{
    pub fn new(
        index: usize,
        shuffler_id: ShufflerId,
        public_key: C,
        aggregated_public_key: C,
        shuffle_secret: C::ScalarField,
        params: S::Parameters,
        secret_key: S::SecretKey,
        submit: mpsc::Sender<AnyMessageEnvelope<C>>,
        config: ShufflerRunConfig,
    ) -> Self {
        let rng = StdRng::from_seed(config.rng_seed);
        let api = Arc::new(ShufflerKeypair::new(
            index,
            shuffle_secret,
            public_key.clone(),
            aggregated_public_key.clone(),
        ));
        Self {
            index,
            shuffler_id,
            public_key,
            params: Arc::new(params),
            secret_key: Arc::new(secret_key),
            api,
            submit,
            states: Arc::new(DashMap::new()),
            rng: Mutex::new(rng),
            config,
        }
    }

    pub fn shuffler_id(&self) -> ShufflerId {
        self.shuffler_id
    }

    pub fn index(&self) -> usize {
        self.index
    }

    pub fn cancel_all(&self) {
        let mut keys = Vec::new();
        for entry in self.states.iter() {
            entry.value().cancel.cancel();
            keys.push(*entry.key());
        }
        for key in keys {
            self.states.remove(&key);
        }
    }

    pub async fn subscribe_per_hand(
        &self,
        game_id: GameId,
        hand_id: HandId,
        turn_index: usize,
        snapshot: &TableAtShuffling<C>,
        updates: broadcast::Receiver<EnvelopedMessage<C, GameShuffleMessage<C>>>,
    ) -> Result<HandSubscription<C>>
    where
        C::Config: CurveConfig<ScalarField = C::ScalarField>,
        C::ScalarField: CanonicalSerialize + PrimeField + UniformRand + Send + Sync,
        C::BaseField: PrimeField + Send + Sync,
        S::Signature: SignatureEncoder + Send + Sync + 'static,
        S::Parameters: Send + Sync + 'static,
        S::SecretKey: Send + Sync + 'static,
    {
        let key = (game_id, hand_id);
        if self.states.contains_key(&key) {
            return Err(anyhow!(
                "hand {} for game {} already registered on shuffler {}",
                hand_id,
                game_id,
                self.shuffler_id
            ));
        }

        let mut global_rng = self.rng.lock();
        let mut hand_seed = [0u8; 32];
        global_rng.fill_bytes(&mut hand_seed);
        drop(global_rng);

        let expected_order = snapshot.shuffling.expected_order.clone();
        if expected_order.is_empty() {
            return Err(anyhow!(
                "hand {} for game {} has empty shuffler order",
                hand_id,
                game_id
            ));
        }
        if turn_index >= expected_order.len() {
            return Err(anyhow!(
                "turn index {} out of range ({} shufflers) for hand {}",
                turn_index,
                expected_order.len(),
                hand_id
            ));
        }

        let initial_deck = snapshot.shuffling.initial_deck.clone();
        let latest_deck = snapshot.shuffling.initial_deck.clone();
        let next_nonce = u64::from(snapshot.sequence);

        let state = ShufflingHandState {
            expected_order,
            buffered: Vec::new(),
            next_nonce,
            turn_index,
            initial_deck,
            latest_deck,
            completed: false,
            rng: StdRng::from_seed(hand_seed),
            acted: false,
        };

        let cancel = CancellationToken::new();
        let runtime = Arc::new(HandRuntime {
            game_id,
            hand_id,
            cancel: cancel.clone(),
            state: Mutex::new(state),
        });

        let states = Arc::clone(&self.states);
        if states.insert(key, Arc::clone(&runtime)).is_some() {
            return Err(anyhow!(
                "hand {} for game {} already registered on shuffler {}",
                hand_id,
                game_id,
                self.shuffler_id
            ));
        }

        info!(
            target = LOG_TARGET,
            game_id,
            hand_id,
            shuffler_id = self.shuffler_id,
            turn_index,
            "registered hand subscription"
        );

        let api = Arc::clone(&self.api);
        let params = Arc::clone(&self.params);
        let secret = Arc::clone(&self.secret_key);
        let submit = self.submit.clone();
        let public_key = self.public_key.clone();
        let actor = ShufflerActor {
            shuffler_id: self.shuffler_id,
        };
        let history_cap = self.config.message_history_cap;
        let handle = Self::spawn_hand_loop(
            self.index,
            api.clone(),
            params.clone(),
            secret.clone(),
            submit.clone(),
            Arc::clone(&runtime),
            updates,
            history_cap,
            public_key.clone(),
            actor,
        );

        if turn_index == 0 {
            if let Err(err) = Self::emit_shuffle(
                &api,
                &params,
                &secret,
                &submit,
                &runtime,
                &public_key,
                actor,
            )
            .await
            {
                warn!(
                    target = LOG_TARGET,
                    game_id,
                    hand_id,
                    shuffler_id = self.shuffler_id,
                    error = %err,
                    "initial shuffle emission failed; cancelling subscription"
                );
                cancel.cancel();
                handle.abort();
                self.states.remove(&key);
                return Err(err);
            }
        }

        Ok(HandSubscription::new(
            key,
            Arc::clone(&self.states),
            cancel,
            handle,
        ))
    }

    fn spawn_hand_loop(
        shuffler_index: usize,
        api: Arc<ShufflerKeypair<C>>,
        params: Arc<S::Parameters>,
        secret: Arc<S::SecretKey>,
        submit: mpsc::Sender<AnyMessageEnvelope<C>>,
        runtime: Arc<HandRuntime<C>>,
        updates: broadcast::Receiver<EnvelopedMessage<C, GameShuffleMessage<C>>>,
        history_cap: usize,
        public_key: C,
        actor: ShufflerActor,
    ) -> JoinHandle<()>
    where
        C: Send + Sync + 'static,
        C::Config: CurveConfig<ScalarField = C::ScalarField>,
        C::ScalarField: CanonicalSerialize + PrimeField + UniformRand + Send + Sync + 'static,
        C::BaseField: PrimeField + Send + Sync + 'static,
        S::Signature: SignatureEncoder + Send + Sync + 'static,
        S::Parameters: Send + Sync + 'static,
        S::SecretKey: Send + Sync + 'static,
    {
        tokio::spawn(async move {
            let game_id = runtime.game_id;
            let hand_id = runtime.hand_id;
            if let Err(err) = Self::hand_loop(
                api,
                params,
                secret,
                submit,
                Arc::clone(&runtime),
                updates,
                history_cap,
                public_key,
                actor,
                shuffler_index,
            )
            .await
            {
                warn!(
                    target = LOG_TARGET,
                    game_id,
                    hand_id,
                    shuffler_index,
                    error = %err,
                    "hand loop exited with error"
                );
            } else {
                debug!(
                    target = LOG_TARGET,
                    game_id, hand_id, shuffler_index, "hand loop finished"
                );
            }
        })
    }

    async fn hand_loop(
        api: Arc<ShufflerKeypair<C>>,
        params: Arc<S::Parameters>,
        secret: Arc<S::SecretKey>,
        submit: mpsc::Sender<AnyMessageEnvelope<C>>,
        runtime: Arc<HandRuntime<C>>,
        mut updates: broadcast::Receiver<EnvelopedMessage<C, GameShuffleMessage<C>>>,
        history_cap: usize,
        public_key: C,
        actor: ShufflerActor,
        shuffler_index: usize,
    ) -> Result<()>
    where
        C::Config: CurveConfig<ScalarField = C::ScalarField>,
        C::ScalarField: CanonicalSerialize + PrimeField + UniformRand,
        C::BaseField: PrimeField,
        S::Signature: SignatureEncoder,
    {
        loop {
            tokio::select! {
                _ = runtime.cancel.cancelled() => {
                    debug!(
                        target = LOG_TARGET,
                        game_id = runtime.game_id,
                        hand_id = runtime.hand_id,
                        shuffler_index,
                        "cancellation token triggered; stopping hand loop"
                    );
                    break;
                }
                msg = updates.recv() => {
                    match msg {
                        Ok(envelope) => {
                            let should_emit = Self::record_incoming(&runtime, &envelope, history_cap);
                            if should_emit {
                                if let Err(err) = Self::emit_shuffle(
                                    &api,
                                    &params,
                                    &secret,
                                    &submit,
                                    &runtime,
                                    &public_key,
                                    actor,
                                )
                                .await
                                {
                                    error!(
                                        target = LOG_TARGET,
                                        game_id = runtime.game_id,
                                        hand_id = runtime.hand_id,
                                        shuffler_index,
                                        error = %err,
                                        "failed to emit shuffle message"
                                    );
                                    break;
                                }
                            }

                            if runtime.state.lock().completed {
                                info!(
                                    target = LOG_TARGET,
                                    game_id = runtime.game_id,
                                    hand_id = runtime.hand_id,
                                    shuffler_index,
                                    "shuffling complete; exiting hand loop"
                                );
                                break;
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(skipped)) => {
                            warn!(
                                target = LOG_TARGET,
                                game_id = runtime.game_id,
                                hand_id = runtime.hand_id,
                                shuffler_index,
                                skipped,
                                "lagged on realtime updates"
                            );
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            debug!(
                                target = LOG_TARGET,
                                game_id = runtime.game_id,
                                hand_id = runtime.hand_id,
                                shuffler_index,
                                "realtime channel closed"
                            );
                            break;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    fn record_incoming(
        runtime: &HandRuntime<C>,
        envelope: &EnvelopedMessage<C, GameShuffleMessage<C>>,
        history_cap: usize,
    ) -> bool {
        let mut state = runtime.state.lock();
        if envelope.hand_id != runtime.hand_id || envelope.game_id != runtime.game_id {
            return false;
        }
        if state.completed {
            return false;
        }

        let position = state.buffered.len();
        if let Some(expected) = state.expected_order.get(position) {
            if *expected != envelope.actor.shuffler_id {
                warn!(
                    target = LOG_TARGET,
                    game_id = runtime.game_id,
                    hand_id = runtime.hand_id,
                    expected = *expected,
                    actual = envelope.actor.shuffler_id,
                    "incoming shuffle actor mismatch"
                );
            }
        }

        state.latest_deck = envelope.message.value.deck_out.clone();
        state.buffered.push(envelope.clone());
        if state.buffered.len() > history_cap {
            let drop_count = state.buffered.len() - history_cap;
            state.buffered.drain(0..drop_count);
        }
        state.next_nonce = state.next_nonce.max(envelope.nonce.saturating_add(1));
        state.completed = state.buffered.len() >= state.expected_order.len();

        !state.acted && state.buffered.len() == state.turn_index
    }

    async fn emit_shuffle(
        api: &Arc<ShufflerKeypair<C>>,
        params: &Arc<S::Parameters>,
        secret: &Arc<S::SecretKey>,
        submit: &mpsc::Sender<AnyMessageEnvelope<C>>,
        runtime: &Arc<HandRuntime<C>>,
        public_key: &C,
        actor: ShufflerActor,
    ) -> Result<()>
    where
        C::Config: CurveConfig<ScalarField = C::ScalarField>,
        C::ScalarField: CanonicalSerialize + PrimeField + UniformRand,
        C::BaseField: PrimeField,
        S::Signature: SignatureEncoder,
    {
        let (envelope_for_state, deck_out_state, nonce_for_update) = {
            let mut state = runtime.state.lock();
            if state.completed || state.acted {
                return Ok(());
            }

            let position = state.buffered.len();
            if let Some(expected) = state.expected_order.get(position) {
                if *expected != actor.shuffler_id {
                    warn!(
                        target = LOG_TARGET,
                        game_id = runtime.game_id,
                        hand_id = runtime.hand_id,
                        expected = *expected,
                        actual = actor.shuffler_id,
                        "attempted to emit shuffle out of turn"
                    );
                    return Ok(());
                }
            }

            let deck_in = state.latest_deck.clone();
            let (deck_out, proof) = api.shuffle(&deck_in, &mut state.rng)?;
            let turn_index = u16::try_from(state.turn_index)
                .map_err(|_| anyhow!("turn index overflow for shuffle message"))?;
            let message =
                GameShuffleMessage::new(deck_in.clone(), deck_out.clone(), proof, turn_index);

            let meta = MetadataEnvelope {
                hand_id: runtime.hand_id,
                game_id: runtime.game_id,
                actor,
                nonce: state.next_nonce,
                public_key: public_key.clone(),
            };

            let signed = sign_enveloped_action::<S, C, GameShuffleMessage<C>, _>(
                meta,
                message,
                params,
                secret,
                &mut state.rng,
            )?;

            let deck_out_state = signed.message.value.deck_out.clone();
            let nonce = state.next_nonce;

            (signed, deck_out_state, nonce)
        };

        let any_envelope = Self::wrap_any_envelope(actor.shuffler_id, &envelope_for_state);
        submit
            .send(any_envelope)
            .await
            .map_err(|err| anyhow!(err.to_string()))?;

        {
            let mut state = runtime.state.lock();
            state.next_nonce = nonce_for_update.saturating_add(1);
            state.latest_deck = deck_out_state;
            // History is updated via record_incoming when the broadcasted envelope arrives.
            state.acted = true;
        }

        info!(
            target = LOG_TARGET,
            game_id = runtime.game_id,
            hand_id = runtime.hand_id,
            shuffler_id = actor.shuffler_id,
            "emitted shuffle message"
        );

        Ok(())
    }

    fn wrap_any_envelope(
        shuffler_id: ShufflerId,
        envelope: &EnvelopedMessage<C, GameShuffleMessage<C>>,
    ) -> AnyMessageEnvelope<C> {
        let signed = envelope.message.clone();
        AnyMessageEnvelope {
            hand_id: envelope.hand_id,
            game_id: envelope.game_id,
            actor: AnyActor::Shuffler { shuffler_id },
            nonce: envelope.nonce,
            public_key: envelope.public_key,
            message: WithSignature {
                value: AnyGameMessage::Shuffle(signed.value),
                signature: signed.signature,
                transcript: signed.transcript,
            },
        }
    }
}

pub struct HandSubscription<C: CurveGroup> {
    key: (GameId, HandId),
    map: Arc<DashMap<(GameId, HandId), Arc<HandRuntime<C>>>>,
    cancel: CancellationToken,
    handle: Option<JoinHandle<()>>,
}

impl<C: CurveGroup> HandSubscription<C> {
    fn new(
        key: (GameId, HandId),
        map: Arc<DashMap<(GameId, HandId), Arc<HandRuntime<C>>>>,
        cancel: CancellationToken,
        handle: JoinHandle<()>,
    ) -> Self {
        Self {
            key,
            map,
            cancel,
            handle: Some(handle),
        }
    }

    pub fn cancel(&self) {
        self.cancel.cancel();
    }
}

impl<C: CurveGroup> Drop for HandSubscription<C> {
    fn drop(&mut self) {
        self.cancel.cancel();
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
        self.map.remove(&self.key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shuffling::{
        combine_blinding_contributions_for_player, decrypt_community_card,
        generate_random_ciphertexts, make_global_public_keys, recover_card_value,
    };
    use ark_ec::PrimeGroup;
    use ark_grumpkin::Projective as GrumpkinProjective;
    use ark_std::test_rng;

    const N_SHUFFLERS: usize = 3;
    const DECK_N: usize = 52;

    #[test]
    fn test_shuffle_and_player_targeted_recovery() {
        let mut rng = test_rng();

        // Build shufflers from random secrets
        let mut secrets = Vec::with_capacity(N_SHUFFLERS);
        let mut public_keys = Vec::with_capacity(N_SHUFFLERS);
        for _ in 0..N_SHUFFLERS {
            let secret = <GrumpkinProjective as PrimeGroup>::ScalarField::rand(&mut rng);
            let public_key = GrumpkinProjective::generator() * secret;
            secrets.push(secret);
            public_keys.push(public_key);
        }
        let aggregated_public_key = make_global_public_keys(public_keys.clone());
        let shufflers: Vec<_> = secrets
            .into_iter()
            .zip(public_keys.into_iter())
            .enumerate()
            .map(|(idx, (secret, public_key))| {
                ShufflerKeypair::new(idx, secret, public_key, aggregated_public_key.clone())
            })
            .collect();

        let agg_pk = aggregated_public_key.clone();

        // Generate an initial encrypted deck using the aggregated public key
        let (mut deck, _r) =
            generate_random_ciphertexts::<GrumpkinProjective, DECK_N>(&agg_pk, &mut rng);

        // Sequentially shuffle across all shufflers
        for s in &shufflers {
            let (next_deck, _proof) = s.shuffle(&deck, &mut rng).expect("shuffle");
            deck = next_deck;
        }

        // Choose a safe card index (avoid last which could map to 52)
        let card_index = 10usize; // expected value = 11
        let card_ct = deck[card_index].clone();

        // Player keys
        let player_sk = <GrumpkinProjective as PrimeGroup>::ScalarField::rand(&mut rng);
        let player_pk = GrumpkinProjective::generator() * player_sk;

        // Each shuffler provides a blinding contribution for this player
        let mut contributions = Vec::with_capacity(N_SHUFFLERS);
        for s in &shufflers {
            let c = s
                .provide_blinding_player_decryption_share(player_pk, &mut rng)
                .expect("blinding share");
            contributions.push(c);
        }

        // Combine into a player-accessible ciphertext
        let player_ciphertext =
            combine_blinding_contributions_for_player(&card_ct, &contributions, agg_pk, player_pk)
                .expect("combine blinding contributions");

        // Each shuffler provides partial unblinding
        let mut unblinding_shares = Vec::with_capacity(N_SHUFFLERS);
        for s in &shufflers {
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
        for s in &shufflers {
            comm_shares.push(
                s.provide_community_decryption_share(&card_ct, &mut rng)
                    .expect("community share"),
            );
        }
        let expected_value =
            decrypt_community_card::<GrumpkinProjective>(&card_ct, comm_shares, N_SHUFFLERS)
                .expect("community decrypt");

        // Player-targeted recovery should match community decryption result
        assert_eq!(recovered, expected_value);
    }

    #[test]
    fn test_community_decryption_flow() {
        let mut rng = test_rng();

        let mut secrets = Vec::with_capacity(N_SHUFFLERS);
        let mut public_keys = Vec::with_capacity(N_SHUFFLERS);
        for _ in 0..N_SHUFFLERS {
            let secret = <GrumpkinProjective as PrimeGroup>::ScalarField::rand(&mut rng);
            let public_key = GrumpkinProjective::generator() * secret;
            secrets.push(secret);
            public_keys.push(public_key);
        }
        let aggregated_public_key = make_global_public_keys(public_keys.clone());
        let shufflers: Vec<_> = secrets
            .into_iter()
            .zip(public_keys.into_iter())
            .enumerate()
            .map(|(idx, (secret, public_key))| {
                ShufflerKeypair::new(idx, secret, public_key, aggregated_public_key.clone())
            })
            .collect();
        let agg_pk = aggregated_public_key;

        // Encrypt a community card with known value in [0..51]
        let card_value: u8 = 25;
        let message = <GrumpkinProjective as PrimeGroup>::ScalarField::from(card_value as u64);
        let msg_point = GrumpkinProjective::generator() * message;
        let randomness = <GrumpkinProjective as PrimeGroup>::ScalarField::rand(&mut rng);
        let ciphertext = ElGamalCiphertext::encrypt(msg_point, randomness, agg_pk);

        // Collect community decryption shares from all shufflers
        let mut shares = Vec::with_capacity(N_SHUFFLERS);
        for s in &shufflers {
            let share = s
                .provide_community_decryption_share(&ciphertext, &mut rng)
                .expect("community share");
            shares.push(share);
        }

        // Decrypt using all shares (n-of-n)
        let recovered =
            decrypt_community_card::<GrumpkinProjective>(&ciphertext, shares, N_SHUFFLERS)
                .expect("community decrypt");
        assert_eq!(recovered, card_value);
    }
}
