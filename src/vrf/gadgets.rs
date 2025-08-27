//! VRF gadgets for SNARK circuits

use super::{
    dst_beta_digest, dst_challenge_digest, dst_nonce_digest, VrfParams, VrfPedersenWindow,
};
use crate::shuffling::curve_absorb::CurveAbsorbGadget;
use crate::{poseidon_config, track_constraints};
use ark_crypto_primitives::crh::pedersen::constraints::{
    CRHGadget as PedersenCRHGadget, CRHParametersVar as PedersenCRHParamsVar,
};
use ark_crypto_primitives::crh::{pedersen, CRHSchemeGadget};
use ark_crypto_primitives::sponge::constraints::CryptographicSpongeVar;
use ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar;
use ark_crypto_primitives::sponge::Absorb;
use ark_ec::CurveGroup;
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::{
    alloc::AllocVar,
    boolean::Boolean,
    fields::{emulated_fp::EmulatedFpVar, fp::FpVar, FieldVar},
    groups::CurveVar,
    prelude::{ToBitsGadget, ToBytesGadget},
    uint8::UInt8,
    GR1CSVar,
};
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};

const LOG_TARGET: &str = "vrf::gadgets";

type ConstraintF<C> = <<C as CurveGroup>::BaseField as Field>::BasePrimeField;

/// Hash message to curve point in circuit using Pedersen CRH + cofactor clearing
pub fn hash_to_curve_var<C, GG>(
    params_var: &PedersenCRHParamsVar<C, GG>,
    msg_bytes: &[UInt8<ConstraintF<C>>],
) -> Result<GG, SynthesisError>
where
    C: CurveGroup,
    GG: CurveVar<C, ConstraintF<C>>,
    for<'a> &'a GG: ark_r1cs_std::groups::GroupOpsBounds<'a, C, GG>,
    ConstraintF<C>: PrimeField,
{
    // Apply Pedersen CRH to get curve point
    // Note: The correct order is CRHGadget<C, GG, W> not CRHGadget<C, W, GG>
    let h_raw = <PedersenCRHGadget<C, GG, VrfPedersenWindow> as CRHSchemeGadget<
        pedersen::CRH<C, VrfPedersenWindow>,
        ConstraintF<C>,
    >>::evaluate(params_var, msg_bytes)?;

    // Cofactor clear: multiply by cofactor using doublings
    // For Grumpkin/Jubjub: cofactor = 8 → 3 doublings
    // For Bandersnatch: cofactor = 4 → 2 doublings
    let mut h = h_raw.clone();
    h.double_in_place()?;
    h.double_in_place()?;
    h.double_in_place()?; // Safe to do extra doubling

    Ok(h)
}

/// Generate deterministic nonce k in circuit
pub fn generate_nonce_var<C, GG>(
    cs: ConstraintSystemRef<ConstraintF<C>>,
    sk: &EmulatedFpVar<C::ScalarField, ConstraintF<C>>,
    h: &GG,
    msg_bytes: &[UInt8<ConstraintF<C>>],
) -> Result<
    (
        EmulatedFpVar<C::ScalarField, ConstraintF<C>>,
        Vec<Boolean<ConstraintF<C>>>,
    ),
    SynthesisError,
>
where
    C: CurveGroup,
    GG: CurveVar<C, ConstraintF<C>> + CurveAbsorbGadget<ConstraintF<C>>,
    ConstraintF<C>: PrimeField + Absorb,
    C::ScalarField: PrimeField,
{
    let config = poseidon_config::<ConstraintF<C>>();
    let mut sponge = PoseidonSpongeVar::new(cs.clone(), &config);

    // Use precomputed DST digest as constant (no constraints)
    let dst_digest = dst_nonce_digest::<ConstraintF<C>>();
    let dst_var = FpVar::constant(dst_digest);
    sponge.absorb(&dst_var)?;

    // Convert sk to base field elements for absorption
    // We absorb the bit representation
    let sk_bits = sk.to_bits_le()?;
    let sk_fe_bits: Vec<FpVar<ConstraintF<C>>> =
        sk_bits.iter().map(|b| FpVar::from(b.clone())).collect();
    sponge.absorb(&sk_fe_bits)?;

    // Absorb H using CurveAbsorbGadget trait
    h.curve_absorb_gadget(&mut sponge)?;

    // Absorb message bytes
    let msg_fe: Vec<FpVar<ConstraintF<C>>> = msg_bytes
        .iter()
        .map(|byte| {
            let bits = byte.to_bits_le()?;
            let mut value = FpVar::zero();
            let mut power = FpVar::one();
            for bit in bits.iter().take(8) {
                let bit_fe = FpVar::from(bit.clone());
                value += &bit_fe * &power;
                power.double_in_place()?;
            }
            Ok(value)
        })
        .collect::<Result<Vec<_>, SynthesisError>>()?;
    sponge.absorb(&msg_fe)?;

    // Squeeze nonce in base field
    let k_base = sponge.squeeze_field_elements(1)?[0].clone();

    // Convert to scalar field (non-native) and get bits
    let k_bytes = k_base.to_bytes_le()?;
    let k_scalar = EmulatedFpVar::<C::ScalarField, ConstraintF<C>>::new_witness(cs, || {
        // Compute the actual value for witness generation
        let bytes = k_bytes
            .iter()
            .map(|b| b.value().unwrap_or_default())
            .collect::<Vec<u8>>();
        Ok(C::ScalarField::from_le_bytes_mod_order(&bytes))
    })?;
    let k_bits = k_scalar.to_bits_le()?;

    Ok((k_scalar, k_bits))
}

/// Generate challenge c in circuit
pub fn generate_challenge_var<C, GG>(
    cs: ConstraintSystemRef<ConstraintF<C>>,
    pk: &GG,
    h: &GG,
    gamma: &GG,
    u: &GG,
    v: &GG,
) -> Result<
    (
        EmulatedFpVar<C::ScalarField, ConstraintF<C>>,
        Vec<Boolean<ConstraintF<C>>>,
    ),
    SynthesisError,
>
where
    C: CurveGroup,
    GG: CurveVar<C, ConstraintF<C>> + CurveAbsorbGadget<ConstraintF<C>>,
    ConstraintF<C>: PrimeField + Absorb,
    C::ScalarField: PrimeField,
{
    let config = poseidon_config::<ConstraintF<C>>();
    let mut sponge = PoseidonSpongeVar::new(cs.clone(), &config);

    // Use precomputed DST digest as constant (no constraints)
    let dst_digest = dst_challenge_digest::<ConstraintF<C>>();
    let dst_var = FpVar::constant(dst_digest);
    sponge.absorb(&dst_var)?;

    // Absorb all points in order using CurveAbsorbGadget trait
    for p in [pk, h, gamma, u, v] {
        p.curve_absorb_gadget(&mut sponge)?;
    }

    // Squeeze challenge in base field
    let c_base = sponge.squeeze_field_elements(1)?[0].clone();

    // Convert to scalar field (non-native) and get bits
    let c_bytes = c_base.to_bytes_le()?;
    let c_scalar = EmulatedFpVar::<C::ScalarField, ConstraintF<C>>::new_witness(cs, || {
        // Compute the actual value for witness generation
        let bytes = c_bytes
            .iter()
            .map(|b| b.value().unwrap_or_default())
            .collect::<Vec<u8>>();
        Ok(C::ScalarField::from_le_bytes_mod_order(&bytes))
    })?;
    let c_bits = c_scalar.to_bits_le()?;

    Ok((c_scalar, c_bits))
}

/// Compute β from Γ in circuit
pub fn beta_from_gamma_var<C, GG>(
    cs: ConstraintSystemRef<ConstraintF<C>>,
    gamma: &GG,
) -> Result<FpVar<ConstraintF<C>>, SynthesisError>
where
    C: CurveGroup,
    GG: CurveVar<C, ConstraintF<C>> + CurveAbsorbGadget<ConstraintF<C>>,
    ConstraintF<C>: PrimeField + Absorb,
{
    let config = poseidon_config::<ConstraintF<C>>();
    let mut sponge = PoseidonSpongeVar::new(cs, &config);

    // Use precomputed DST digest as constant (no constraints)
    let dst_digest = dst_beta_digest::<ConstraintF<C>>();
    let dst_var = FpVar::constant(dst_digest);
    sponge.absorb(&dst_var)?;

    // Absorb gamma using CurveAbsorbGadget trait
    gamma.curve_absorb_gadget(&mut sponge)?;

    // Squeeze beta in base field
    let beta = sponge.squeeze_field_elements(1)?[0].clone();

    Ok(beta)
}

/// VRF proof generation gadget (cheaper than verification in circuit)
///
/// Computes proof π = (Γ, c, s) and output β inside the circuit
///
/// # Type Parameters
/// * `C` - The curve group
/// * `GG` - The curve gadget type
///
/// # Arguments
/// * `cs` - Constraint system reference
/// * `params` - VRF parameters (Pedersen CRH setup)
/// * `pk` - Public key (as curve variable)
/// * `msg_bytes` - VRF input message (as byte variables)
/// * `x_wit` - Secret key witness (as non-native field variable)
///
/// # Returns
/// * `(gamma, c, s, beta)` - The proof components and VRF output
pub fn prove_vrf_gadget<C, GG>(
    cs: ConstraintSystemRef<ConstraintF<C>>,
    params: &VrfParams<C>,
    msg_bytes: &[UInt8<ConstraintF<C>>],
    x_wit: EmulatedFpVar<C::ScalarField, ConstraintF<C>>,
) -> Result<
    (
        GG,                                            // pk
        GG,                                            // gamma
        EmulatedFpVar<C::ScalarField, ConstraintF<C>>, // c
        EmulatedFpVar<C::ScalarField, ConstraintF<C>>, // s
        FpVar<ConstraintF<C>>,                         // beta
    ),
    SynthesisError,
>
where
    C: CurveGroup,
    GG: CurveVar<C, ConstraintF<C>> + CurveAbsorbGadget<ConstraintF<C>>,
    ConstraintF<C>: PrimeField + Absorb,
    C::ScalarField: PrimeField,
    for<'a> &'a GG: ark_r1cs_std::groups::GroupOpsBounds<'a, C, GG>,
{
    track_constraints!(&cs, "prove_vrf_gadget", LOG_TARGET, {
        // Allocate Pedersen parameters as constants
        let pedersen_params_var = PedersenCRHParamsVar::<C, GG>::new_constant(
            cs.clone(),
            params.pedersen_crh_params.clone(),
        )?;

        // 1. H = HashToCurve(msg)
        let h = track_constraints!(&cs, "hash_to_curve", LOG_TARGET, {
            hash_to_curve_var::<C, GG>(&pedersen_params_var, msg_bytes)?
        });
        tracing::debug!(target: LOG_TARGET, "Hash to curve in SNARK: {:?}", h.value());

        // 2. Compute pk = x * G
        let x_bits = x_wit.to_bits_le()?;
        let g = GG::constant(C::generator());
        let pk = track_constraints!(&cs, "pk = x * G", LOG_TARGET, {
            g.scalar_mul_le(x_bits.iter())?
        });

        // 3. Γ = x * H
        let gamma = track_constraints!(&cs, "x * H", LOG_TARGET, {
            h.scalar_mul_le(x_bits.iter())?
        });
        tracing::debug!(target: LOG_TARGET, "Gamma in SNARK: {:?}", gamma.value());

        // 4. Generate nonce k
        let (k, k_bits) = track_constraints!(&cs, "generate_nonce", LOG_TARGET, {
            generate_nonce_var::<C, GG>(cs.clone(), &x_wit, &h, msg_bytes)?
        });
        tracing::debug!(target: LOG_TARGET, "Generated nonce in SNARK: {:?}", k.value());

        // 5. U = k * G
        let u = track_constraints!(&cs, "k * G", LOG_TARGET, {
            g.scalar_mul_le(k_bits.iter())?
        });

        // 6. V = k * H
        let v = track_constraints!(&cs, "k * H", LOG_TARGET, {
            h.scalar_mul_le(k_bits.iter())?
        });

        // 7. Generate challenge c
        let (c, _c_bits) = track_constraints!(&cs, "generate_challenge", LOG_TARGET, {
            generate_challenge_var::<C, GG>(cs.clone(), &pk, &h, &gamma, &u, &v)?
        });
        tracing::debug!(target: LOG_TARGET, "Generated challenge in SNARK: {:?}", c.value());

        // 8. s = k + c * x (mod r)
        let s = track_constraints!(&cs, "s = k + c * x", LOG_TARGET, {
            // c * x in non-native field
            let cx = c.clone() * &x_wit;
            // s = k + cx
            &k + &cx
        });

        // 9. β = HashToOutput(Γ)
        let beta = track_constraints!(&cs, "beta_from_gamma", LOG_TARGET, {
            beta_from_gamma_var::<C, GG>(cs.clone(), &gamma)?
        });
        tracing::debug!(target: LOG_TARGET, "Generated beta in SNARK {:?}", beta.value());

        Ok((pk, gamma, c, s, beta))
    })
}
