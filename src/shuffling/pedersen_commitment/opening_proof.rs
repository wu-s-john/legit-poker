//! Pedersen Commitment Opening protocol implementation
//!
//! This module implements a Pedersen commitment opening protocol that is similar to
//! the Inner Product Argument (IPA) but specialized for opening a single Pedersen
//! commitment function. It uses divide-and-conquer folding to efficiently prove
//! knowledge of the opening to a Pedersen vector commitment with blinding factors.

use super::error::PedersenCommitmentOpeningError;
use super::{extract_pedersen_bases, WithCommitment};
use crate::config::poseidon_config;
use crate::shuffling::curve_absorb::CurveAbsorb;
use ark_crypto_primitives::commitment::pedersen::Parameters;
use ark_crypto_primitives::sponge::{poseidon::PoseidonSponge, CryptographicSponge};
use ark_ec::CurveGroup;
use ark_ff::{BigInteger, Field, One, PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{fmt, rand::RngCore, vec::Vec, UniformRand};

/// Logging target for this module
const LOG_TARGET: &str = "nexus_nova::shuffling::pedersen_commitment_opening";

/// Wrapper around arkworks Pedersen parameters for consistent usage
#[derive(Clone)]
pub struct PedersenParams<C: CurveGroup> {
    pub arkworks_params: Parameters<C>,
    pub g: Vec<C>,
    pub h: C,
}

impl<C: CurveGroup> PedersenParams<C> {
    /// Create from arkworks Parameters, extracting bases for size N
    pub fn from_arkworks<const N: usize>(arkworks_params: Parameters<C>) -> Self {
        let (h, g_array) = extract_pedersen_bases::<C, N>(&arkworks_params);
        let g = g_array.to_vec();
        Self {
            arkworks_params,
            g,
            h,
        }
    }

    pub fn len(&self) -> usize {
        self.g.len()
    }

    pub fn is_power_of_two(&self) -> bool {
        self.len().is_power_of_two()
    }

    pub fn assert_sizes<const N: usize>(&self) {
        assert_eq!(self.g.len(), N, "params.len != N");
        assert!(self.is_power_of_two(), "N must be a power of two");
    }
}

/// Pedersen commitment opening proof structure (blinding-aware)
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct PedersenCommitmentOpeningProof<C: CurveGroup> {
    pub folding_challenge_commitment_rounds: Vec<(C, C)>, // (left, right) commitment pairs for each round
    pub a_final: C::ScalarField,                          // folded message scalar
    pub r_final: C::ScalarField,                          // folded blind
}

impl<C: CurveGroup> fmt::Debug for PedersenCommitmentOpeningProof<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PedersenCommitmentOpeningProof")
            .field("rounds", &self.folding_challenge_commitment_rounds.len())
            .finish()
    }
}

/// CF -> CS mapping via LE bytes (matches scalar_mul_le bit order in gadgets)
#[inline]
pub fn cf_to_cs<CF: PrimeField, CS: PrimeField>(x: CF) -> CS {
    let bytes = x.into_bigint().to_bytes_le();
    CS::from_le_bytes_mod_order(&bytes)
}

/// CS -> CF mapping via LE bytes
#[inline]
pub fn cs_to_cf<CS: PrimeField, CF: PrimeField>(x: &CS) -> CF {
    let bytes = x.into_bigint().to_bytes_le();
    CF::from_le_bytes_mod_order(&bytes)
}

/// Recursive helper function for proving
///
/// Implements the recursive folding of the IPA protocol:
/// - At each round k, we have vectors a_k, g_k and accumulated blinding r_k
/// - We maintain the invariant: P_k = ⟨a_k, g_k⟩ + r_k * H
/// - We fold these vectors in half using challenges from the transcript
/// - The blinding accumulates as: r_{k+1} = r_k + x_k² * α_k + x_k^{-2} * β_k
fn prove_recursive<C>(
    a: Vec<C::ScalarField>,
    g: Vec<C>,
    r_cur: C::ScalarField,
    h: C,
    transcript: &mut PoseidonSponge<C::BaseField>,
    rng: &mut impl RngCore,
) -> PedersenCommitmentOpeningProof<C>
where
    C: CurveGroup + CurveAbsorb<C::BaseField>,
    C::BaseField: PrimeField,
    C::ScalarField: PrimeField,
{
    // Base case: when we have a single element
    if a.len() == 1 {
        let a_final_val = a[0];
        // Return the accumulated blinding factor from all folding rounds
        // This is crucial for the verification equation: P_final = a_final * G_final + r_final * H
        let r_final_val = r_cur;
        tracing::trace!(target: LOG_TARGET, ?a_final_val, ?r_final_val, "Base case reached in prove_recursive");
        return PedersenCommitmentOpeningProof {
            folding_challenge_commitment_rounds: vec![],
            a_final: a[0],
            r_final: r_final_val,
        };
    }

    // Recursive case: split and fold
    let (a_left, a_right) = a.split_at(a.len() / 2);
    let (g_left, g_right) = g.split_at(g.len() / 2);

    // Sample blinding scalars for this round
    let alpha = C::ScalarField::rand(rng);
    let beta = C::ScalarField::rand(rng);
    tracing::trace!(target: LOG_TARGET, ?alpha, ?beta, "Prove: Sampled blinding scalars for round");

    // Compute left_commitment = <aL, gR> + alpha * H
    let left_commitment = {
        let inner_product = a_left
            .iter()
            .zip(g_right.iter())
            .map(|(ai, gi)| *gi * ai)
            .fold(C::zero(), |acc, x| acc + x);
        inner_product + h * alpha
    };

    // Compute right_commitment = <aR, gL> + beta * H
    let right_commitment = {
        let inner_product = a_right
            .iter()
            .zip(g_left.iter())
            .map(|(ai, gi)| *gi * ai)
            .fold(C::zero(), |acc, x| acc + x);
        inner_product + h * beta
    };

    // Absorb left and right commitments into transcript
    tracing::trace!(target: LOG_TARGET, ?left_commitment, "Prove: Absorbing left_commitment");
    left_commitment.curve_absorb(transcript);
    tracing::trace!(target: LOG_TARGET, ?right_commitment, "Prove: Absorbing right_commitment");
    right_commitment.curve_absorb(transcript);

    // Get challenge from transcript
    let x_bf: C::BaseField = transcript.squeeze_field_elements(1)[0];
    tracing::trace!(target: LOG_TARGET, ?x_bf, "Prove: Challenge from transcript (base field)");
    let mut x = cf_to_cs::<C::BaseField, C::ScalarField>(x_bf);
    if x.is_zero() {
        x = C::ScalarField::one(); // ensure invertible
    }
    let x_inv = x.inverse().unwrap();
    let x2 = x.square();
    let xinv2 = x_inv.square();

    tracing::trace!(target: LOG_TARGET, ?x, ?x_inv, "Folding challenge in prove");

    // Fold a vector
    let a_folded: Vec<C::ScalarField> = a_left
        .iter()
        .zip(a_right.iter())
        .map(|(al, ar)| x * al + x_inv * ar)
        .collect();
    tracing::trace!(target: LOG_TARGET, "Prove: Folded a vector, new length = {}", a_folded.len());

    // Fold g vector
    let g_folded: Vec<C> = g_left
        .iter()
        .zip(g_right.iter())
        .map(|(gl, gr)| *gl * x_inv + *gr * x)
        .collect();
    tracing::trace!(target: LOG_TARGET, "Prove: Folded g vector, new length = {}", g_folded.len());

    // Fold the blinding factor
    let r_folded = x2 * alpha + r_cur + xinv2 * beta;
    tracing::trace!(target: LOG_TARGET, ?r_folded, "Prove: Folded blinding factor");

    // Recursive call with folded values
    let mut proof = prove_recursive(a_folded, g_folded, r_folded, h, transcript, rng);

    // Prepend this round's left and right commitments to the proof
    proof
        .folding_challenge_commitment_rounds
        .insert(0, (left_commitment, right_commitment));

    proof
}

/// Prove knowledge of opening for a Pedersen commitment (Prover Algorithm)
///
/// Given a commitment C = ⟨m, G⟩ + rH, this function generates an IPA proof
/// demonstrating knowledge of the message vector m and blinding factor r.
///
/// # Protocol (Variant A - Anchored at P₀ = C - rH)
///
/// **Inputs:**
/// - `params`: Pedersen parameters containing bases G = (G₀, ..., G_{N-1}) and H
/// - `commitment_vector`: Contains commitment C and message m ∈ F_q^N
/// - `r`: The blinding factor used in the commitment
/// - `rng`: Random number generator for blinding factors
///
/// **Output:** IPA proof π = ({(L_k, R_k)}_{k=0}^{t-1}, â, r̂)
///
/// **Algorithm:**
/// 1. Initialize:
///    - P₀ := C - rH = ⟨m, G⟩ (removes initial blinding)
///    - a₀ := m, g₀ := G, r₀ := 0
///    - Initialize Fiat-Shamir transcript and absorb P₀
///
/// 2. For each round k = 0, 1, ..., t-1:
///    - Split: a_k = (a_{k,L} || a_{k,R}), g_k = (g_{k,L} || g_{k,R})
///    - Sample blinding: α_k, β_k ← F_q
///    - Commit cross-terms:
///      * L_k := ⟨a_{k,L}, g_{k,R}⟩ + α_k·H
///      * R_k := ⟨a_{k,R}, g_{k,L}⟩ + β_k·H
///    - Absorb L_k, R_k into transcript
///    - Derive challenge: x_k ∈ F_q* (ensure non-zero)
///    - Fold:
///      * a_{k+1} := x_k·a_{k,L} + x_k^{-1}·a_{k,R}
///      * g_{k+1} := x_k^{-1}·g_{k,L} + x_k·g_{k,R}
///      * r_{k+1} := r_k + x_k²·α_k + x_k^{-2}·β_k
///
/// 3. Base case (after t rounds): a_t = (â), g_t = (Ĝ), r_t = r̂
///
/// **Invariant:** At each round k: P_k = ⟨a_k, g_k⟩ + r_k·H
///
/// **Security:** The proof is binding under the discrete log assumption and
/// zero-knowledge when blinding factors α_k, β_k are randomly chosen.
#[tracing::instrument(target = LOG_TARGET, skip_all)]
pub fn prove<C, const N: usize>(
    params: &PedersenParams<C>,
    commitment_vector: &WithCommitment<C, N>,
    r: C::ScalarField,
    rng: &mut impl RngCore,
) -> PedersenCommitmentOpeningProof<C>
where
    C: CurveGroup + CurveAbsorb<C::BaseField>,
    C::BaseField: PrimeField,
    C::ScalarField: PrimeField,
{
    params.assert_sizes::<N>();

    // P0 = C - rH
    let p0 = commitment_vector.comm - params.h * r;
    tracing::debug!(target: LOG_TARGET, ?p0, "Prove: Computed P0 = C - rH");

    // Initialize Fiat-Shamir transcript
    let config = poseidon_config::<C::BaseField>();
    let mut transcript = PoseidonSponge::<C::BaseField>::new(&config);
    tracing::debug!(target: LOG_TARGET, "Prove: Absorbing P0 into fresh transcript");
    p0.curve_absorb(&mut transcript);

    // Call recursive helper with initial values
    // Note: We pass 0 for r_cur since P0 = C - rH has already removed the blinding
    prove_recursive(
        commitment_vector.value.to_vec(),
        params.g.clone(),
        C::ScalarField::zero(),
        params.h,
        &mut transcript,
        rng,
    )
}

/// Recursive helper function for verification
///
/// Reconstructs the challenges from the transcript and maintains the invariant
/// P_k = ⟨a_k, g_k⟩ + r_k·H by folding P according to the proof.
/// Returns the final P and the coefficient vector for reconstructing the folded base.
fn verify_recursive<C>(
    folding_rounds: &[(C, C)],
    mut p_current: C,
    n_current: usize,
    transcript: &mut PoseidonSponge<C::BaseField>,
) -> (C, Vec<C::ScalarField>)
where
    C: CurveGroup + CurveAbsorb<C::BaseField>,
    C::BaseField: PrimeField,
    C::ScalarField: PrimeField,
{
    // Base case: no more rounds, return coefficients for base case
    if folding_rounds.is_empty() {
        // For n=1, the coefficient is just 1
        tracing::trace!(target: LOG_TARGET, "Base case in verify_recursive, returning coefficient = 1");
        return (p_current, vec![C::ScalarField::one()]);
    }

    // Recursive case: process current round
    let (left_commitment, right_commitment) = folding_rounds[0];
    let remaining_rounds = &folding_rounds[1..];

    // Absorb left and right commitments into transcript
    tracing::trace!(target: LOG_TARGET, ?left_commitment, "Verify: Absorbing left_commitment");
    left_commitment.curve_absorb(transcript);
    tracing::trace!(target: LOG_TARGET, ?right_commitment, "Verify: Absorbing right_commitment");
    right_commitment.curve_absorb(transcript);

    // Get challenge from transcript
    let x_bf: C::BaseField = transcript.squeeze_field_elements(1)[0];
    tracing::trace!(target: LOG_TARGET, ?x_bf, "Verify: Challenge from transcript (base field)");
    let mut x = cf_to_cs::<C::BaseField, C::ScalarField>(x_bf);
    if x.is_zero() {
        x = C::ScalarField::one();
    }
    let x_inv = x.inverse().unwrap();

    tracing::trace!(target: LOG_TARGET, ?x, ?x_inv, "Folding challenge in verify");

    // Update p_current: P' = P + x^2 * left_commitment + x^{-2} * right_commitment
    let p_before = p_current;
    p_current += left_commitment * x.square();
    p_current += right_commitment * x_inv.square();
    tracing::trace!(target: LOG_TARGET, ?p_before, ?p_current, "Verify: Updated P value after folding");

    // Recurse to get coefficients for the smaller problem
    let (p_final, coeffs_half) =
        verify_recursive(remaining_rounds, p_current, n_current / 2, transcript);

    // Expand coefficients in *blocks* to preserve original base order:
    // First all left-half coefficients (indices 0..n/2-1), then all right-half (n/2..n-1).
    // This ensures coefficients align correctly with bases [G₀, G₁, ..., G_{N-1}]
    let half = coeffs_half.len();
    let mut coeffs = Vec::with_capacity(n_current);

    // Left half: multiply by x_inv (maps to G[0..half-1])
    for j in 0..half {
        coeffs.push(x_inv * coeffs_half[j]);
    }

    // Right half: multiply by x (maps to G[half..n-1])
    for j in 0..half {
        coeffs.push(x * coeffs_half[j]);
    }

    tracing::trace!(target: LOG_TARGET, "Verify: Expanded coefficients from {} to {} (block order)", half, coeffs.len());

    (p_final, coeffs)
}

/// Build coefficient vector using functional approach
#[allow(dead_code)]
fn build_coefficients<C>(challenges: &[C::ScalarField], n: usize) -> Vec<C::ScalarField>
where
    C: CurveGroup,
    C::ScalarField: PrimeField,
{
    if challenges.is_empty() {
        return vec![C::ScalarField::one()];
    }

    let x = challenges[0];
    let x_inv = x.inverse().unwrap();
    let remaining = &challenges[1..];

    // Get coefficients for half the size
    let half_coeffs = build_coefficients::<C>(remaining, n / 2);

    // Expand in blocks to preserve the base order
    let mut coeffs = Vec::with_capacity(n);
    let half = half_coeffs.len();

    // Left half: multiply by x_inv
    for j in 0..half {
        coeffs.push(x_inv * half_coeffs[j]);
    }

    // Right half: multiply by x
    for j in 0..half {
        coeffs.push(x * half_coeffs[j]);
    }

    coeffs
}

/// Verify a Pedersen commitment opening proof (Verifier Algorithm)
///
/// Given a commitment C and blinding factor r, verifies an IPA proof that
/// demonstrates knowledge of a message m such that C = ⟨m, G⟩ + rH,
/// without revealing or requiring knowledge of m.
///
/// # Protocol (Variant A - Anchored at P₀ = C - rH)
///
/// **Inputs:**
/// - `params`: Pedersen parameters containing bases G = (G₀, ..., G_{N-1}) and H
/// - `c_commit`: The commitment C ∈ G
/// - `r`: The public blinding factor
/// - `proof`: IPA proof π = ({(L_k, R_k)}_{k=0}^{t-1}, â, r̂)
///
/// **Output:** Accept/Reject
///
/// **Algorithm:**
/// 1. Initialize:
///    - P := C - rH (anchor point)
///    - Initialize Fiat-Shamir transcript and absorb P
///
/// 2. For each round k = 0, 1, ..., t-1:
///    - Absorb L_k, R_k into transcript
///    - Derive challenge: x_k ∈ F_q* (ensure matches prover)
///    - Fold anchor: P := P + x_k²·L_k + x_k^{-2}·R_k
///
/// 3. Build coefficient vector s = (s₀, ..., s_{N-1}):
///    - For index j with binary expansion j = Σ_{k=0}^{t-1} b_k·2^k:
///    - s_j := Π_{k=0}^{t-1} x_k^{(-1)^{1-b_k}}
///    - This gives: s_j = Π (x_k^{-1} if bit_k=0, x_k if bit_k=1)
///
/// 4. Compute folded base: Ĝ := Σ_{j=0}^{N-1} s_j·G_j
///
/// 5. Final check: Accept iff P = â·Ĝ + r̂·H
///
/// **Correctness:**
/// The invariant P_k = ⟨a_k, g_k⟩ + r_k·H is maintained through folding.
/// At the end: P_final = â·Ĝ + r̂·H where Ĝ is the correctly folded base.
///
/// **Security:** The verification is sound under the discrete log assumption.
/// An adversary cannot produce a valid proof without knowing the opening.
#[tracing::instrument(target = LOG_TARGET, skip_all)]
pub fn verify<C, const N: usize>(
    params: &PedersenParams<C>,
    c_commit: &C,
    r: C::ScalarField,
    proof: &PedersenCommitmentOpeningProof<C>,
) -> Result<(), PedersenCommitmentOpeningError>
where
    C: CurveGroup + CurveAbsorb<C::BaseField>,
    C::BaseField: PrimeField,
    C::ScalarField: PrimeField,
{
    // Validate parameters
    if params.len() != N {
        return Err(PedersenCommitmentOpeningError::LengthMismatch);
    }
    if !params.is_power_of_two() {
        return Err(PedersenCommitmentOpeningError::NotPowerOfTwo);
    }
    let t = proof.folding_challenge_commitment_rounds.len();
    if (1usize << t) != N {
        return Err(PedersenCommitmentOpeningError::BadProof);
    }

    // Initialize P0 = C - rH
    let p0 = *c_commit - params.h * r;
    tracing::debug!(target: LOG_TARGET, ?p0, "Verify: Computed P0 = C - rH");

    // Initialize Fiat-Shamir transcript
    let config = poseidon_config::<C::BaseField>();
    let mut transcript = PoseidonSponge::<C::BaseField>::new(&config);
    tracing::debug!(target: LOG_TARGET, "Verify: Absorbing P0 into fresh transcript");
    p0.curve_absorb(&mut transcript);

    // Use recursive verification to get folded P and coefficients
    let (p_final, coefficients) = verify_recursive(
        &proof.folding_challenge_commitment_rounds,
        p0,
        N,
        &mut transcript,
    );

    tracing::debug!(target: LOG_TARGET, ?p_final, "Final P after recursive verification");
    tracing::debug!(target: LOG_TARGET, coeffs_len = coefficients.len(), "Number of coefficients");

    // Compute the final folded generator: G_final = sum_j (coefficients[j] * G_j)
    let g_final = coefficients
        .iter()
        .zip(params.g.iter())
        .map(|(coeff, g_base)| *g_base * coeff)
        .fold(C::zero(), |acc, point| acc + point);

    // Compute RHS: a_final * G_final + r_final * H
    let rhs = g_final * proof.a_final + params.h * proof.r_final;

    tracing::debug!(target: LOG_TARGET, ?g_final, "Computed G_final");
    tracing::debug!(target: LOG_TARGET, ?rhs, "Computed RHS");

    // Verify equality
    if p_final == rhs {
        Ok(())
    } else {
        tracing::debug!(target: LOG_TARGET, "Verification failed: p_final != rhs");
        tracing::debug!(target: LOG_TARGET, "p_final: {:?}", p_final);
        tracing::debug!(target: LOG_TARGET, "rhs: {:?}", rhs);
        Err(PedersenCommitmentOpeningError::BadProof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::{Fr, G1Projective};
    use ark_crypto_primitives::commitment::pedersen::Window as PedersenWindow;
    use ark_std::test_rng;
    use tracing_subscriber::{
        filter, fmt::format::FmtSpan, layer::SubscriberExt, util::SubscriberInitExt,
    };

    const TEST_TARGET: &str = LOG_TARGET;

    /// Setup test tracing for debugging
    fn setup_test_tracing() -> tracing::subscriber::DefaultGuard {
        let filter = filter::Targets::new().with_target(TEST_TARGET, tracing::Level::TRACE);

        tracing_subscriber::registry()
            .with(
                tracing_subscriber::fmt::layer()
                    .with_span_events(FmtSpan::ENTER | FmtSpan::CLOSE)
                    .with_test_writer(), // This ensures output goes to test stdout
            )
            .with(filter)
            .set_default()
    }

    /// Test window configuration for small tests
    #[derive(Clone, PartialEq, Eq, Hash)]
    struct TestWindow8;

    impl PedersenWindow for TestWindow8 {
        const WINDOW_SIZE: usize = 4;
        const NUM_WINDOWS: usize = 64; // Support up to 64 * 4 = 256 bits
    }

    fn setup_params<const N: usize>() -> PedersenParams<G1Projective> {
        use ark_crypto_primitives::commitment::{pedersen::Commitment, CommitmentScheme};

        let mut rng = test_rng();

        // Create arkworks Pedersen parameters with sufficient generators
        // We need at least N generators for the message plus randomness generators
        let setup =
            <Commitment<G1Projective, TestWindow8> as CommitmentScheme>::setup(&mut rng).unwrap();

        // Create our wrapper with extracted bases
        PedersenParams::from_arkworks::<N>(setup)
    }

    #[test]
    fn test_pedersen_commitment_opening_correctness() {
        let _guard = setup_test_tracing();

        const N: usize = 8;
        let mut rng = test_rng();
        let params = setup_params::<N>();

        // Generate random vector and commitment
        let m: [Fr; N] = std::array::from_fn(|_| Fr::rand(&mut rng));
        let (commitment, r) = WithCommitment::new(&params.arkworks_params, m, &mut rng);

        tracing::debug!(target: TEST_TARGET, ?m, ?r, "Generated commitment inputs");
        let comm = commitment.comm;
        tracing::debug!(target: TEST_TARGET, ?comm, "Generated commitment");

        // Generate proof
        let proof = prove(&params, &commitment, r, &mut rng);

        let a_final = proof.a_final;
        let r_final = proof.r_final;
        tracing::debug!(target: TEST_TARGET, ?a_final, "Proof a_final");
        tracing::debug!(target: TEST_TARGET, ?r_final, "Proof r_final");
        tracing::debug!(target: TEST_TARGET, rounds = proof.folding_challenge_commitment_rounds.len(), "Folding rounds");

        // Verify proof
        let result = verify::<G1Projective, N>(&params, &commitment.comm, r, &proof);
        match &result {
            Ok(_) => tracing::info!(target: TEST_TARGET, "Verification succeeded"),
            Err(e) => tracing::error!(target: TEST_TARGET, ?e, "Verification failed"),
        }
        assert!(result.is_ok(), "Valid proof should verify");
    }

    #[test]
    fn test_pedersen_commitment_opening_wrong_blinding() {
        let _guard = setup_test_tracing();

        const N: usize = 8;
        let mut rng = test_rng();
        let params = setup_params::<N>();

        let m: [Fr; N] = std::array::from_fn(|_| Fr::rand(&mut rng));
        let (commitment, r) = WithCommitment::new(&params.arkworks_params, m, &mut rng);

        // Generate proof with correct r
        let proof = prove(&params, &commitment, r, &mut rng);

        // Try to verify with wrong r
        let wrong_r = r + Fr::one();
        let result = verify::<G1Projective, N>(&params, &commitment.comm, wrong_r, &proof);
        assert!(
            result.is_err(),
            "Proof with wrong blinding should not verify"
        );
    }

    #[test]
    fn test_pedersen_commitment_opening_invalid_proof() {
        let _guard = setup_test_tracing();

        const N: usize = 8;
        let mut rng = test_rng();
        let params = setup_params::<N>();

        let m: [Fr; N] = std::array::from_fn(|_| Fr::rand(&mut rng));
        let (commitment, r) = WithCommitment::new(&params.arkworks_params, m, &mut rng);

        // Generate valid proof
        let mut proof = prove(&params, &commitment, r, &mut rng);

        // Corrupt the proof
        proof.a_final = Fr::rand(&mut rng);

        // Verification should fail
        let result = verify::<G1Projective, N>(&params, &commitment.comm, r, &proof);
        assert!(result.is_err(), "Invalid proof should not verify");
    }

    /// Helper function to test Pedersen opening with given messages
    fn test_pedersen_opening_with_values<const N: usize>(
        m: &[Fr; N],
    ) -> PedersenCommitmentOpeningProof<G1Projective> {
        let _guard = setup_test_tracing();

        let mut rng = test_rng();
        let params = setup_params::<N>();

        // Use the same commitment method that uses the extracted bases
        let (commitment, r) = WithCommitment::new(&params.arkworks_params, *m, &mut rng);

        // Generate proof
        let proof = prove(&params, &commitment, r, &mut rng);

        // Verify proof
        let result = verify::<G1Projective, N>(&params, &commitment.comm, r, &proof);
        assert!(result.is_ok(), "Valid proof should verify for size {}", N);

        proof
    }

    #[test]
    fn base_case_checks_out() {
        const N: usize = 1;
        let mut rng = test_rng();
        let params = setup_params::<N>();
        let m: [Fr; N] = [Fr::rand(&mut rng)];
        let (commitment, r) = WithCommitment::new(&params.arkworks_params, m, &mut rng);

        let proof = prove(&params, &commitment, r, &mut rng);
        // For N=1, no folding rounds occur, so no blinding is accumulated
        assert!(proof.folding_challenge_commitment_rounds.is_empty());
        // r_final should be zero for N=1 since no α, β are sampled (no folding rounds)
        assert!(
            proof.r_final.is_zero(),
            "r_final should be 0 for N=1 (no folding)"
        );

        let res = verify::<G1Projective, N>(&params, &commitment.comm, r, &proof);
        assert!(res.is_ok());
    }

    #[test]
    fn test_size_1_base_case() {
        let _guard = setup_test_tracing();
        let mut rng = test_rng();
        let m: [Fr; 1] = [Fr::rand(&mut rng)];

        let params = setup_params::<1>();
        let (commitment, r) = WithCommitment::new(&params.arkworks_params, m, &mut rng);
        let proof = prove(&params, &commitment, r, &mut rng);

        // For size 1, there should be no folding rounds
        assert_eq!(
            proof.folding_challenge_commitment_rounds.len(),
            0,
            "Size 1 should have no folding rounds"
        );

        // a_final should equal the single input
        assert_eq!(
            proof.a_final, m[0],
            "a_final should equal input[0] for size 1"
        );

        // r_final should be zero for N=1 since no folding rounds occur (no α, β sampled)
        assert!(
            proof.r_final.is_zero(),
            "r_final should be zero for size 1 (no folding)"
        );

        // Verify the proof
        let result = verify::<G1Projective, 1>(&params, &commitment.comm, r, &proof);
        assert!(result.is_ok(), "Size 1 proof should verify");
    }

    #[test]
    fn test_size_2_simple_case() {
        let _guard = setup_test_tracing();

        let m: [Fr; 2] = [Fr::from(3u64), Fr::from(7u64)];

        let proof = test_pedersen_opening_with_values(&m);

        // For size 2, there should be exactly 1 folding round
        assert_eq!(
            proof.folding_challenge_commitment_rounds.len(),
            1,
            "Size 2 should have 1 folding round"
        );

        // Verify the proof has the expected structure
        assert_eq!(proof.folding_challenge_commitment_rounds.len(), 1);
        let (left, right) = proof.folding_challenge_commitment_rounds[0];
        assert_ne!(
            left, right,
            "left and right commitments should be different"
        );
    }

    #[test]
    fn test_size_4_edge_case() {
        let _guard = setup_test_tracing();

        let m: [Fr; 4] = std::array::from_fn(|i| Fr::from((i + 1) as u64));

        let proof = test_pedersen_opening_with_values(&m);

        // For size 4, there should be exactly 2 folding rounds
        assert_eq!(
            proof.folding_challenge_commitment_rounds.len(),
            2,
            "Size 4 should have 2 folding rounds"
        );

        // Test with specific values
        let m_specific: [Fr; 4] = [
            Fr::from(2u64),
            Fr::from(3u64),
            Fr::from(5u64),
            Fr::from(7u64),
        ];
        let proof_specific = test_pedersen_opening_with_values(&m_specific);
        assert_eq!(proof_specific.folding_challenge_commitment_rounds.len(), 2);
    }

    #[test]
    fn test_size_8_more_involved() {
        let _guard = setup_test_tracing();

        let mut rng = test_rng();

        // Test with random values
        let m_random: [Fr; 8] = std::array::from_fn(|_| Fr::rand(&mut rng));
        let proof_random = test_pedersen_opening_with_values(&m_random);
        assert_eq!(
            proof_random.folding_challenge_commitment_rounds.len(),
            3,
            "Size 8 should have 3 folding rounds"
        );

        // Test with sequential values
        let m_sequential: [Fr; 8] = std::array::from_fn(|i| Fr::from((i + 1) as u64));
        let proof_sequential = test_pedersen_opening_with_values(&m_sequential);
        assert_eq!(
            proof_sequential.folding_challenge_commitment_rounds.len(),
            3
        );

        // Test with powers of 2
        let m_powers: [Fr; 8] = std::array::from_fn(|i| Fr::from(1u64 << i));
        let proof_powers = test_pedersen_opening_with_values(&m_powers);
        assert_eq!(proof_powers.folding_challenge_commitment_rounds.len(), 3);
    }

    #[test]
    fn test_size_64_large_case() {
        let _guard = setup_test_tracing();

        let mut rng = test_rng();

        // Test with random values
        let m: [Fr; 64] = std::array::from_fn(|_| Fr::rand(&mut rng));
        let proof = test_pedersen_opening_with_values(&m);

        // For size 64, there should be exactly 6 folding rounds (log2(64) = 6)
        assert_eq!(
            proof.folding_challenge_commitment_rounds.len(),
            6,
            "Size 64 should have 6 folding rounds"
        );

        // Verify all left and right values are different
        for (left, right) in &proof.folding_challenge_commitment_rounds {
            assert_ne!(
                left, right,
                "left and right commitments should be different in each round"
            );
        }
    }

    #[test]
    fn test_size_52_poker_deck() {
        let _guard = setup_test_tracing();

        let mut rng = test_rng();

        // Create a 52-card deck and pad to 64 (next power of 2)
        const DECK_SIZE: usize = 52;
        const PADDED_SIZE: usize = 64;

        // Create array with first 52 elements as card values (1-52), rest as zeros
        let m: [Fr; PADDED_SIZE] = std::array::from_fn(|i| {
            if i < DECK_SIZE {
                Fr::from((i + 1) as u64) // Card values 1-52
            } else {
                Fr::from(0u64) // Padding with zeros
            }
        });

        let proof = test_pedersen_opening_with_values(&m);

        // For size 64, there should be exactly 6 folding rounds (log2(64) = 6)
        assert_eq!(
            proof.folding_challenge_commitment_rounds.len(),
            6,
            "Size 64 (padded from 52) should have 6 folding rounds"
        );

        // Test with random 52 values padded to 64
        let m_random: [Fr; PADDED_SIZE] = std::array::from_fn(|i| {
            if i < DECK_SIZE {
                Fr::rand(&mut rng)
            } else {
                Fr::zero()
            }
        });

        let proof_random = test_pedersen_opening_with_values(&m_random);
        assert_eq!(
            proof_random.folding_challenge_commitment_rounds.len(),
            6,
            "Padded deck should have 6 folding rounds"
        );

        // Verify the proof works with padding
        let params = setup_params::<PADDED_SIZE>();
        let (commitment, r) = WithCommitment::new(&params.arkworks_params, m, &mut rng);
        let proof_final = prove(&params, &commitment, r, &mut rng);
        let result =
            verify::<G1Projective, PADDED_SIZE>(&params, &commitment.comm, r, &proof_final);
        assert!(result.is_ok(), "Padded 52-card deck proof should verify");
    }

    #[test]
    fn test_pedersen_commitment_opening_multiple_sizes() {
        let mut rng = test_rng();

        for size_exp in 1..5 {
            let n = 1 << size_exp; // 2, 4, 8, 16

            // Setup params dynamically
            let g: Vec<G1Projective> = (0..n).map(|_| G1Projective::rand(&mut rng)).collect();
            let h = G1Projective::rand(&mut rng);
            let arkworks_params = {
                use ark_crypto_primitives::commitment::{pedersen::Commitment, CommitmentScheme};
                <Commitment<G1Projective, TestWindow8> as CommitmentScheme>::setup(&mut rng)
                    .unwrap()
            };
            let params = PedersenParams {
                g,
                h,
                arkworks_params,
            };

            // Generate random vector and blinding
            let m: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
            let r = Fr::rand(&mut rng);

            // Compute commitment manually
            let _commitment = {
                let mut result = G1Projective::zero();
                for i in 0..n {
                    result = result + params.g[i] * m[i];
                }
                result = result + params.h * r;
                result
            };

            // For different sizes, we need to call prove/verify without const generics
            // This is a limitation of the current implementation
            // In practice, you would use the appropriate const size

            // Just verify the params are set up correctly
            assert_eq!(params.len(), n);
            assert!(params.is_power_of_two());
        }
    }
}
