#![deny(missing_docs)]
#![allow(non_snake_case)]

use ark_ec::AffineRepr;
use ark_std::{vec, vec::Vec, One, Zero};
use clear_on_drop::clear::Clear;

use crate::inner_product_proof::inner_product;

/// Represents a degree-1 vector polynomial \\(\mathbf{a} + \mathbf{b} \cdot x\\).
pub struct VecPoly1<G: AffineRepr>(pub Vec<G::ScalarField>, pub Vec<G::ScalarField>);

/// Represents a degree-2 scalar polynomial \\(a + b \cdot x + c \cdot x^2\\)
pub struct Poly2<G: AffineRepr>(pub G::ScalarField, pub G::ScalarField, pub G::ScalarField);

/// Represents a degree-3 vector polynomial
/// \\(\mathbf{a} + \mathbf{b} \cdot x + \mathbf{c} \cdot x^2 + \mathbf{d} \cdot x^3 \\).
#[cfg(feature = "yoloproofs")]
pub struct VecPoly3<G: AffineRepr>(
    pub Vec<G::ScalarField>,
    pub Vec<G::ScalarField>,
    pub Vec<G::ScalarField>,
    pub Vec<G::ScalarField>,
);

/// Represents a degree-6 scalar polynomial, without the zeroth degree
/// \\(a \cdot x + b \cdot x^2 + c \cdot x^3 + d \cdot x^4 + e \cdot x^5 + f \cdot x^6\\)
#[cfg(feature = "yoloproofs")]
pub struct Poly6<G: AffineRepr> {
    pub t1: G::ScalarField,
    pub t2: G::ScalarField,
    pub t3: G::ScalarField,
    pub t4: G::ScalarField,
    pub t5: G::ScalarField,
    pub t6: G::ScalarField,
}

/// Provides an iterator over the powers of a `Fr`.
///
/// This struct is created by the `exp_iter` function.
pub struct FrExp<G: AffineRepr> {
    x: G::ScalarField,
    next_exp_x: G::ScalarField,
}

impl<G: AffineRepr> Iterator for FrExp<G> {
    type Item = G::ScalarField;

    fn next(&mut self) -> Option<G::ScalarField> {
        let exp_x = self.next_exp_x;
        self.next_exp_x *= self.x;
        Some(exp_x)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (usize::MAX, None)
    }
}

/// Return an iterator of the powers of `x`.
pub fn exp_iter<G: AffineRepr>(x: G::ScalarField) -> FrExp<G> {
    let next_exp_x = G::ScalarField::one();
    FrExp { x, next_exp_x }
}

impl<G: AffineRepr> VecPoly1<G> {
    pub fn zero(n: usize) -> Self {
        VecPoly1(
            vec![G::ScalarField::zero(); n],
            vec![G::ScalarField::zero(); n],
        )
    }

    pub fn inner_product(&self, rhs: &VecPoly1<G>) -> Poly2<G> {
        // Uses Karatsuba's method
        let l = self;
        let r = rhs;

        let t0 = inner_product(&l.0, &r.0);
        let t2 = inner_product(&l.1, &r.1);

        let l0_plus_l1 = add_vec::<G>(&l.0, &l.1);
        let r0_plus_r1 = add_vec::<G>(&r.0, &r.1);

        let t1 = inner_product(&l0_plus_l1, &r0_plus_r1) - t0 - t2;

        Poly2(t0, t1, t2)
    }

    pub fn eval(&self, x: G::ScalarField) -> Vec<G::ScalarField> {
        let n = self.0.len();
        let mut out = vec![G::ScalarField::zero(); n];
        for i in 0..n {
            out[i] = self.0[i] + self.1[i] * x;
        }
        out
    }
}

#[cfg(feature = "yoloproofs")]
impl<G: AffineRepr> VecPoly3<G> {
    pub fn zero(n: usize) -> Self {
        VecPoly3(
            vec![G::ScalarField::zero(); n],
            vec![G::ScalarField::zero(); n],
            vec![G::ScalarField::zero(); n],
            vec![G::ScalarField::zero(); n],
        )
    }

    /// Compute an inner product of `lhs`, `rhs` which have the property that:
    /// - `lhs.0` is zero;
    /// - `rhs.2` is zero;
    /// This is the case in the constraint system proof.
    pub fn special_inner_product(lhs: &Self, rhs: &Self) -> Poly6<G> {
        // TODO: make checks that l_poly.0 and r_poly.2 are zero.

        let t1 = inner_product(&lhs.1, &rhs.0);
        let t2 = inner_product(&lhs.1, &rhs.1) + inner_product(&lhs.2, &rhs.0);
        let t3 = inner_product(&lhs.2, &rhs.1) + inner_product(&lhs.3, &rhs.0);
        let t4 = inner_product(&lhs.1, &rhs.3) + inner_product(&lhs.3, &rhs.1);
        let t5 = inner_product(&lhs.2, &rhs.3);
        let t6 = inner_product(&lhs.3, &rhs.3);

        Poly6 {
            t1,
            t2,
            t3,
            t4,
            t5,
            t6,
        }
    }

    pub fn eval(&self, x: G::ScalarField) -> Vec<G::ScalarField> {
        let n = self.0.len();
        let mut out = vec![G::ScalarField::zero(); n];
        for i in 0..n {
            out[i] = self.0[i] + x * (self.1[i] + x * (self.2[i] + x * self.3[i]));
        }
        out
    }
}

impl<G: AffineRepr> Poly2<G> {
    pub fn eval(&self, x: G::ScalarField) -> G::ScalarField {
        self.0 + x * (self.1 + x * self.2)
    }
}

#[cfg(feature = "yoloproofs")]
impl<G: AffineRepr> Poly6<G> {
    pub fn eval(&self, x: G::ScalarField) -> G::ScalarField {
        x * (self.t1 + x * (self.t2 + x * (self.t3 + x * (self.t4 + x * (self.t5 + x * self.t6)))))
    }
}

#[cfg(feature = "yoloproofs")]
impl<G: AffineRepr> Drop for VecPoly3<G> {
    fn drop(&mut self) {
        for e in self.0.iter_mut() {
            e.clear();
        }
        for e in self.1.iter_mut() {
            e.clear();
        }
        for e in self.2.iter_mut() {
            e.clear();
        }
        for e in self.3.iter_mut() {
            e.clear();
        }
    }
}

#[cfg(feature = "yoloproofs")]
impl<G: AffineRepr> Drop for Poly6<G> {
    fn drop(&mut self) {
        self.t1.clear();
        self.t2.clear();
        self.t3.clear();
        self.t4.clear();
        self.t5.clear();
        self.t6.clear();
    }
}

/// Takes the sum of all the powers of `x`, up to `n`
/// If `n` is a power of 2, it uses the efficient algorithm with `2*lg n` multiplications and additions.
/// If `n` is not a power of 2, it uses the slow algorithm with `n` multiplications and additions.
/// In the Bulletproofs case, all calls to `sum_of_powers` should have `n` as a power of 2.
pub fn sum_of_powers<G: AffineRepr>(x: &G::ScalarField, n: usize) -> G::ScalarField {
    if !n.is_power_of_two() {
        return sum_of_powers_slow::<G>(x, n);
    }
    if n == 0 || n == 1 {
        return G::ScalarField::from(n as u64);
    }
    let mut m = n;
    let mut result = G::ScalarField::one() + x;
    let mut factor = *x;
    while m > 2 {
        factor = factor * factor;
        result = result + factor * result;
        m /= 2;
    }
    result
}

// takes the sum of all of the powers of x, up to n
fn sum_of_powers_slow<G: AffineRepr>(x: &G::ScalarField, n: usize) -> G::ScalarField {
    exp_iter::<G>(*x).take(n).sum()
}

/// Raises `x` to the power `n` using binary exponentiation,
/// with (1 to 2)*lg(n) scalar multiplications.
/// TODO: a consttime version of this would be awfully similar to a Montgomery ladder.
pub fn scalar_exp_vartime<G: AffineRepr>(x: &G::ScalarField, mut n: u64) -> G::ScalarField {
    let mut result = G::ScalarField::one();
    let mut aux = *x; // x, x^2, x^4, x^8, ...
    while n > 0 {
        let bit = n & 1;
        if bit == 1 {
            result *= aux;
        }
        n >>= 1;
        aux = aux * aux; // FIXME: one unnecessary mult at the last step here!
    }
    result
}

/// Raises `x` to the power `n`.
fn scalar_exp_vartime_slow<G: AffineRepr>(x: &G::ScalarField, n: u64) -> G::ScalarField {
    let mut result = G::ScalarField::one();
    for _ in 0..n {
        result *= x;
    }
    result
}

pub fn add_vec<G: AffineRepr>(a: &[G::ScalarField], b: &[G::ScalarField]) -> Vec<G::ScalarField> {
    if a.len() != b.len() {
        // throw some error
        //println!("lengths of vectors don't match for vector addition");
    }
    let mut out = vec![G::ScalarField::zero(); b.len()];
    for i in 0..a.len() {
        out[i] = a[i] + b[i];
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exp_2_is_powers_of_2() {
        type G = ark_secq256k1::Affine;
        type F = ark_secq256k1::Fr;

        let exp_2: Vec<_> = exp_iter::<G>(F::from(2u64)).take(4).collect();

        assert_eq!(exp_2[0], F::from(1u64));
        assert_eq!(exp_2[1], F::from(2u64));
        assert_eq!(exp_2[2], F::from(4u64));
        assert_eq!(exp_2[3], F::from(8u64));
    }

    #[test]
    fn test_inner_product() {
        type F = ark_secq256k1::Fr;

        let a = vec![F::from(1u64), F::from(2u64), F::from(3u64), F::from(4u64)];
        let b = vec![F::from(2u64), F::from(3u64), F::from(4u64), F::from(5u64)];
        assert_eq!(F::from(40u64), inner_product(&a, &b));
    }

    #[test]
    fn vec_of_scalars_clear_on_drop() {
        type F = ark_secq256k1::Fr;

        let mut v = vec![F::from(24u64), F::from(42u64)];

        for e in v.iter_mut() {
            e.clear();
        }

        fn flat_slice<T>(x: &[T]) -> &[u8] {
            use core::mem;
            use core::slice;

            unsafe { slice::from_raw_parts(x.as_ptr() as *const u8, mem::size_of_val(x)) }
        }

        assert_eq!(flat_slice(&v), &[0u8; 64][..]);
        assert_eq!(v[0], F::zero());
        assert_eq!(v[1], F::zero());
    }
}
