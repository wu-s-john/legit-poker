use ark_ec::CurveGroup;
use ark_ff::{Field, UniformRand};
use ark_std::rand::Rng;

/// Draw a random shuffler secret/public key pair
/// Each shuffler independently generates their own secret key and derives the public key
/// Returns a tuple of (secret_key, public_key)
pub fn draw_shuffler_public_key<C, R>(rng: &mut R) -> (C::ScalarField, C)
where
    C: CurveGroup,
    C::ScalarField: Field,
    R: Rng,
{
    let secret_key = C::ScalarField::rand(rng);
    let generator = C::generator();
    let public_key = generator * secret_key;
    (secret_key, public_key)
}

/// Merge multiple shuffler public keys to create the global public key
/// pk_global = sum(pk_i) = sum(sk_i * G) = (sum(sk_i)) * G
pub fn make_global_public_keys<C>(shuffler_keys: Vec<C>) -> C
where
    C: CurveGroup,
{
    shuffler_keys
        .into_iter()
        .fold(C::zero(), |acc, pk| acc + pk)
}

#[cfg(test)]
mod tests {
    use crate::shuffling::ElGamalCiphertext;

    use super::*;
    use ark_ec::PrimeGroup;
    use ark_grumpkin::Projective as GrumpkinProjective;
    use ark_std::test_rng;

    #[test]
    fn test_public_key_setup_and_encryption() {
        let mut rng = test_rng();

        // Step 1: Two shufflers generate their secret/public key pairs
        let (shuffler1_secret, shuffler1_public) =
            draw_shuffler_public_key::<GrumpkinProjective, _>(&mut rng);
        let (shuffler2_secret, shuffler2_public) =
            draw_shuffler_public_key::<GrumpkinProjective, _>(&mut rng);

        // Step 2: Create the global public key by merging individual public keys
        let public_keys = vec![shuffler1_public, shuffler2_public];
        let global_public_key = make_global_public_keys(public_keys);

        // Verify that global_public_key = (s1 + s2) * G
        let generator = GrumpkinProjective::generator();
        let combined_secret = shuffler1_secret + shuffler2_secret;
        let expected_global_pk = generator * combined_secret;
        assert_eq!(global_public_key, expected_global_pk);

        // Step 3: Encrypt a message using ElGamal
        let message_value = 10u64;
        let message_scalar = <GrumpkinProjective as PrimeGroup>::ScalarField::from(message_value);
        let message_point = generator * message_scalar;

        // Start with initial ciphertext (0, M)
        let initial_ciphertext = ElGamalCiphertext::new(GrumpkinProjective::zero(), message_point);

        // Step 4: Apply re-randomization from both shufflers
        // Shuffler 1 adds their encryption layer with randomness r1
        let r1 = <GrumpkinProjective as PrimeGroup>::ScalarField::rand(&mut rng);
        let ciphertext_after_s1 = initial_ciphertext.add_encryption_layer(r1, global_public_key);

        // Shuffler 2 adds their encryption layer with randomness r2
        let r2 = <GrumpkinProjective as PrimeGroup>::ScalarField::rand(&mut rng);
        let final_ciphertext = ciphertext_after_s1.add_encryption_layer(r2, global_public_key);

        // Step 5: Verify the mathematical relationships
        // A = g^(r1 + r2)
        let expected_a = generator * (r1 + r2);
        assert_eq!(final_ciphertext.c1, expected_a);

        // B = M + (r1 + r2) * pk_global
        // Which equals: g^m + g^((s1 + s2) * (r1 + r2))
        let expected_b = message_point + global_public_key * (r1 + r2);
        assert_eq!(final_ciphertext.c2, expected_b);

        // Additional verification: decrypt the ciphertext
        // To decrypt, we need to remove the contribution of each shuffler's secret key
        // First, shuffler 1 partially decrypts
        let partial_decrypt_1 = final_ciphertext.c2 - final_ciphertext.c1 * shuffler1_secret;

        // Then, shuffler 2 partially decrypts
        let decrypted_message = partial_decrypt_1 - final_ciphertext.c1 * shuffler2_secret;

        // The decrypted message should equal the original message point
        assert_eq!(decrypted_message, message_point);
    }
}
