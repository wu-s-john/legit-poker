//! Permutation decomposition for Bayer-Groth (m×r matrix representation)

use super::{M, N, R};

/// Decompose a permutation into row and column indices for m×r matrix
///
/// Maps permutation π: [N] → [N] to matrix coordinates (row, col)
/// where position i maps to position π(i) = row(i) * R + col(i)
#[derive(Clone, Debug)]
pub struct PermutationDecomposition {
    /// Row index for each position (m values, range [0, M))
    pub rows: Vec<usize>,

    /// Column index for each position (r values, range [0, R))
    pub cols: Vec<usize>,
}

impl PermutationDecomposition {
    /// Create decomposition from a permutation
    pub fn from_permutation(perm: &[usize]) -> Self {
        assert_eq!(
            perm.len(),
            N,
            "Permutation must have exactly {} elements",
            N
        );

        let mut rows = Vec::with_capacity(N);
        let mut cols = Vec::with_capacity(N);

        for &target in perm.iter() {
            assert!(target < N, "Permutation value {} out of range", target);

            // Decompose target position into (row, col)
            let row = target / R; // Integer division
            let col = target % R; // Remainder

            rows.push(row);
            cols.push(col);
        }

        Self { rows, cols }
    }

    /// Reconstruct permutation from row/column indices
    pub fn to_permutation(&self) -> Vec<usize> {
        assert_eq!(self.rows.len(), N);
        assert_eq!(self.cols.len(), N);

        let mut perm = Vec::with_capacity(N);

        for i in 0..N {
            let target = self.rows[i] * R + self.cols[i];
            assert!(target < N, "Invalid reconstruction: {} >= {}", target, N);
            perm.push(target);
        }

        perm
    }

    /// Verify that the decomposition represents a valid permutation
    pub fn is_valid_permutation(&self) -> bool {
        let perm = self.to_permutation();

        // Check that it's a bijection (all values appear exactly once)
        let mut seen = vec![false; N];
        for &val in perm.iter() {
            if val >= N || seen[val] {
                return false;
            }
            seen[val] = true;
        }

        seen.iter().all(|&x| x)
    }

    /// Create identity decomposition
    pub fn identity() -> Self {
        let mut rows = Vec::with_capacity(N);
        let mut cols = Vec::with_capacity(N);

        for i in 0..N {
            rows.push(i / R);
            cols.push(i % R);
        }

        Self { rows, cols }
    }

    /// Get the matrix representation (for debugging)
    /// Returns M×R matrix where entry (i,j) = 1 if some element maps there
    pub fn to_matrix(&self) -> Vec<Vec<bool>> {
        let mut matrix = vec![vec![false; R]; M];

        for i in 0..N {
            let row = self.rows[i];
            let col = self.cols[i];
            matrix[row][col] = true;
        }

        matrix
    }
}

/// Helper to generate a random permutation
pub fn random_permutation(n: usize, rng: &mut impl ark_std::rand::Rng) -> Vec<usize> {
    use ark_std::rand::seq::SliceRandom;

    let mut perm: Vec<usize> = (0..n).collect();
    perm.shuffle(rng);
    perm
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::test_rng;

    #[test]
    fn test_identity_decomposition() {
        let decomp = PermutationDecomposition::identity();
        assert!(decomp.is_valid_permutation());

        let perm = decomp.to_permutation();
        for i in 0..N {
            assert_eq!(perm[i], i);
        }
    }

    #[test]
    fn test_decomposition_roundtrip() {
        let mut rng = test_rng();
        let perm = random_permutation(N, &mut rng);

        let decomp = PermutationDecomposition::from_permutation(&perm);
        assert!(decomp.is_valid_permutation());

        let reconstructed = decomp.to_permutation();
        assert_eq!(perm, reconstructed);
    }

    #[test]
    fn test_matrix_representation() {
        let decomp = PermutationDecomposition::identity();
        let matrix = decomp.to_matrix();

        // For identity, first M positions should fill first row
        for i in 0..M {
            for j in 0..R {
                let expected = (i * R + j) < N;
                assert_eq!(matrix[i][j], expected);
            }
        }
    }

    #[test]
    fn test_invalid_permutation_detection() {
        // Create an invalid "permutation" with duplicate
        let invalid = vec![0; N]; // All zeros
        let decomp = PermutationDecomposition::from_permutation(&invalid);
        assert!(!decomp.is_valid_permutation());
    }
}
