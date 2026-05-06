//! Numeric helpers for embedding vectors.

/// Inner / dot product of two equal-length vectors.
///
/// Returns `0.0` when the slices are empty. Truncates to the shorter
/// length when the slices differ.
pub fn dot_product(a: &[f32], b: &[f32]) -> f32 {
    a.iter().zip(b.iter()).map(|(x, y)| x * y).sum()
}

/// L2 (Euclidean) norm of a vector.
pub fn l2_norm(v: &[f32]) -> f32 {
    v.iter().map(|x| x * x).sum::<f32>().sqrt()
}

/// Cosine similarity between two vectors.
///
/// Returns `0.0` if either vector has zero norm. Range is `[-1.0, 1.0]`
/// for non-degenerate inputs.
pub fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    let denom = l2_norm(a) * l2_norm(b);
    if denom == 0.0 {
        return 0.0;
    }
    dot_product(a, b) / denom
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dot_product_basic() {
        assert!((dot_product(&[1.0, 2.0, 3.0], &[4.0, 5.0, 6.0]) - 32.0).abs() < 1e-6);
    }

    #[test]
    fn l2_norm_basic() {
        assert!((l2_norm(&[3.0, 4.0]) - 5.0).abs() < 1e-6);
    }

    #[test]
    fn cosine_similarity_identical_is_one() {
        let v = [1.0, 2.0, 3.0, 4.0];
        assert!((cosine_similarity(&v, &v) - 1.0).abs() < 1e-6);
    }

    #[test]
    fn cosine_similarity_orthogonal_is_zero() {
        assert!((cosine_similarity(&[1.0, 0.0], &[0.0, 1.0])).abs() < 1e-6);
    }

    #[test]
    fn cosine_similarity_handles_zero_vector() {
        assert_eq!(cosine_similarity(&[0.0, 0.0], &[1.0, 1.0]), 0.0);
    }
}
