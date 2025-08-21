//! GPU acceleration module for Groth16 proving using ICICLE
//!
//! This module provides GPU-accelerated MSM and NTT operations for arkworks-based
//! Groth16 proving on Apple Silicon (Metal) and NVIDIA (CUDA) GPUs.

pub mod groth16_gpu;

use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use icicle_runtime::{memory::HostSlice, Device};
use std::sync::Once;

static INIT: Once = Once::new();
static mut DEVICE_INITIALIZED: bool = false;

/// Initialize the GPU device (Metal on Apple Silicon, CUDA on NVIDIA)
pub fn init_gpu_device() -> anyhow::Result<()> {
    INIT.call_once(|| {
        // Load the backend from environment or default
        if let Err(e) = icicle_runtime::runtime::load_backend_from_env_or_default() {
            eprintln!("Warning: Failed to load ICICLE backend: {}", e);
            return;
        }

        // Try to set the device
        let device_result = if cfg!(target_os = "macos") {
            // Apple Silicon - use Metal
            icicle_runtime::set_device(&Device::new("METAL", 0))
        } else {
            // Try CUDA first, fallback to CPU
            icicle_runtime::set_device(&Device::new("CUDA", 0))
                .or_else(|_| icicle_runtime::set_device(&Device::new("CPU", 0)))
        };

        match device_result {
            Ok(_) => {
                unsafe {
                    DEVICE_INITIALIZED = true;
                }
                eprintln!("GPU device initialized successfully");
            }
            Err(e) => {
                eprintln!("Warning: Failed to initialize GPU device: {}", e);
            }
        }
    });

    if unsafe { DEVICE_INITIALIZED } {
        Ok(())
    } else {
        Err(anyhow::anyhow!("GPU device not available"))
    }
}

/// Check if GPU is available and initialized
pub fn is_gpu_available() -> bool {
    unsafe { DEVICE_INITIALIZED }
}

// Type conversion utilities for BN254
pub mod bn254_converter {
    use super::*;
    use ark_bn254::{Fq, Fr, G1Affine as ArkG1Affine, G1Projective as ArkG1Projective};
    use icicle_bn254::curve::{
        BaseField as IcicleFq, G1Affine as IcicleG1Affine, G1Projective as IcicleG1Projective,
        ScalarField as IcicleFr,
    };
    use icicle_core::affine::Affine;
    use icicle_core::bignum::BigNum;
    use icicle_core::msm::{msm, MSMConfig};
    use icicle_core::ntt::{ntt, NTTConfig, NTTDir};
    use icicle_core::projective::Projective;

    /// Convert arkworks Fr to ICICLE Fr
    pub fn fr_ark_to_icicle(fr: &Fr) -> IcicleFr {
        let mut bytes = [0u8; 32];
        fr.serialize_uncompressed(&mut bytes[..]).unwrap();
        IcicleFr::from_bytes_le(&bytes)
    }

    /// Convert ICICLE Fr to arkworks Fr
    pub fn fr_icicle_to_ark(fr: &IcicleFr) -> Fr {
        let bytes = fr.to_bytes_le();
        Fr::from_le_bytes_mod_order(&bytes[..])
    }

    /// Convert arkworks Fq to ICICLE Fq
    pub fn fq_ark_to_icicle(fq: &Fq) -> IcicleFq {
        let mut bytes = [0u8; 32];
        fq.serialize_uncompressed(&mut bytes[..]).unwrap();
        IcicleFq::from_bytes_le(&bytes)
    }

    /// Convert arkworks G1Affine to ICICLE G1Affine
    pub fn g1_affine_ark_to_icicle(p: &ArkG1Affine) -> IcicleG1Affine {
        if p.is_zero() {
            return IcicleG1Affine::zero();
        }

        let x = fq_ark_to_icicle(&p.x);
        let y = fq_ark_to_icicle(&p.y);
        IcicleG1Affine::from_xy(x, y)
    }

    /// Convert ICICLE G1Projective to arkworks G1Affine
    pub fn g1_projective_icicle_to_ark(p: &IcicleG1Projective) -> ArkG1Affine {
        let affine = p.to_affine();
        if affine == IcicleG1Affine::zero() {
            return ArkG1Affine::zero();
        }

        let x_bytes = affine.x().to_bytes_le();
        let y_bytes = affine.y().to_bytes_le();
        let x = Fq::from_le_bytes_mod_order(&x_bytes[..]);
        let y = Fq::from_le_bytes_mod_order(&y_bytes[..]);
        ArkG1Affine::new_unchecked(x, y)
    }

    /// Perform MSM on BN254 G1 using GPU
    pub fn msm_g1_gpu(bases: &[ArkG1Affine], scalars: &[Fr]) -> anyhow::Result<ArkG1Projective> {
        // Convert to ICICLE types
        let icicle_bases: Vec<IcicleG1Affine> = bases.iter().map(g1_affine_ark_to_icicle).collect();

        let icicle_scalars: Vec<IcicleFr> = scalars.iter().map(fr_ark_to_icicle).collect();

        // Perform MSM on GPU
        let mut result = vec![IcicleG1Projective::zero(); 1];
        msm(
            HostSlice::from_slice(&icicle_scalars),
            HostSlice::from_slice(&icicle_bases),
            &MSMConfig::default(),
            HostSlice::from_mut_slice(&mut result),
        )?;

        // Convert back to arkworks
        Ok(g1_projective_icicle_to_ark(&result[0]).into())
    }

    /// Perform NTT on BN254 Fr using GPU
    pub fn ntt_fr_gpu(coeffs: &mut [Fr], inverse: bool) -> anyhow::Result<()> {
        // Convert to ICICLE types
        let mut icicle_coeffs: Vec<IcicleFr> = coeffs.iter().map(fr_ark_to_icicle).collect();

        // Configure NTT direction
        let config = NTTConfig::<IcicleFr>::default();
        let dir = if inverse {
            NTTDir::kInverse
        } else {
            NTTDir::kForward
        };

        // Perform NTT on GPU
        let mut output = vec![IcicleFr::zero(); icicle_coeffs.len()];
        ntt(
            HostSlice::from_slice(&icicle_coeffs),
            dir,
            &config,
            HostSlice::from_mut_slice(&mut output),
        )?;
        icicle_coeffs = output;

        // Convert back to arkworks
        for (dst, src) in coeffs.iter_mut().zip(icicle_coeffs.iter()) {
            *dst = fr_icicle_to_ark(src);
        }

        Ok(())
    }
}

// Type conversion utilities for BLS12-381
pub mod bls12_381_converter {
    use super::*;
    use ark_bls12_381::{Fq, Fr, G1Affine as ArkG1Affine, G1Projective as ArkG1Projective};
    use icicle_bls12_381::curve::{
        BaseField as IcicleFq, G1Affine as IcicleG1Affine, G1Projective as IcicleG1Projective,
        ScalarField as IcicleFr,
    };
    use icicle_core::affine::Affine;
    use icicle_core::bignum::BigNum;
    use icicle_core::msm::{msm, MSMConfig};
    use icicle_core::ntt::{ntt, NTTConfig, NTTDir};
    use icicle_core::projective::Projective;

    /// Convert arkworks Fr to ICICLE Fr
    pub fn fr_ark_to_icicle(fr: &Fr) -> IcicleFr {
        let mut bytes = [0u8; 32];
        fr.serialize_uncompressed(&mut bytes[..]).unwrap();
        IcicleFr::from_bytes_le(&bytes)
    }

    /// Convert ICICLE Fr to arkworks Fr
    pub fn fr_icicle_to_ark(fr: &IcicleFr) -> Fr {
        let bytes = fr.to_bytes_le();
        Fr::from_le_bytes_mod_order(&bytes[..])
    }

    /// Convert arkworks Fq to ICICLE Fq
    pub fn fq_ark_to_icicle(fq: &Fq) -> IcicleFq {
        let mut bytes = [0u8; 48]; // BLS12-381 has 48-byte field elements
        fq.serialize_uncompressed(&mut bytes[..]).unwrap();
        IcicleFq::from_bytes_le(&bytes)
    }

    /// Convert arkworks G1Affine to ICICLE G1Affine
    pub fn g1_affine_ark_to_icicle(p: &ArkG1Affine) -> IcicleG1Affine {
        if p.is_zero() {
            return IcicleG1Affine::zero();
        }

        let x = fq_ark_to_icicle(&p.x);
        let y = fq_ark_to_icicle(&p.y);
        IcicleG1Affine::from_xy(x, y)
    }

    /// Convert ICICLE G1Projective to arkworks G1Affine
    pub fn g1_projective_icicle_to_ark(p: &IcicleG1Projective) -> ArkG1Affine {
        let affine = p.to_affine();
        if affine == IcicleG1Affine::zero() {
            return ArkG1Affine::zero();
        }

        let x_bytes = affine.x().to_bytes_le();
        let y_bytes = affine.y().to_bytes_le();
        let x = Fq::from_le_bytes_mod_order(&x_bytes[..]);
        let y = Fq::from_le_bytes_mod_order(&y_bytes[..]);
        ArkG1Affine::new_unchecked(x, y)
    }

    /// Perform MSM on BLS12-381 G1 using GPU
    pub fn msm_g1_gpu(bases: &[ArkG1Affine], scalars: &[Fr]) -> anyhow::Result<ArkG1Projective> {
        // Convert to ICICLE types
        let icicle_bases: Vec<IcicleG1Affine> = bases.iter().map(g1_affine_ark_to_icicle).collect();

        let icicle_scalars: Vec<IcicleFr> = scalars.iter().map(fr_ark_to_icicle).collect();

        // Perform MSM on GPU
        let mut result = vec![IcicleG1Projective::zero(); 1];
        msm(
            HostSlice::from_slice(&icicle_scalars),
            HostSlice::from_slice(&icicle_bases),
            &MSMConfig::default(),
            HostSlice::from_mut_slice(&mut result),
        )?;

        // Convert back to arkworks
        Ok(g1_projective_icicle_to_ark(&result[0]).into())
    }

    /// Perform NTT on BLS12-381 Fr using GPU
    pub fn ntt_fr_gpu(coeffs: &mut [Fr], inverse: bool) -> anyhow::Result<()> {
        // Convert to ICICLE types
        let mut icicle_coeffs: Vec<IcicleFr> = coeffs.iter().map(fr_ark_to_icicle).collect();

        // Configure NTT direction
        let config = NTTConfig::<IcicleFr>::default();
        let dir = if inverse {
            NTTDir::kInverse
        } else {
            NTTDir::kForward
        };

        // Perform NTT on GPU
        let mut output = vec![IcicleFr::zero(); icicle_coeffs.len()];
        ntt(
            HostSlice::from_slice(&icicle_coeffs),
            dir,
            &config,
            HostSlice::from_mut_slice(&mut output),
        )?;
        icicle_coeffs = output;

        // Convert back to arkworks
        for (dst, src) in coeffs.iter_mut().zip(icicle_coeffs.iter()) {
            *dst = fr_icicle_to_ark(src);
        }

        Ok(())
    }
}
