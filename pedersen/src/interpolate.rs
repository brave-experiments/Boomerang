//! Polynomial interpolation code for GK proofs. This file just contains the code that implements
//! Lagrange interpolation.

use crate::pedersen_config::PedersenConfig;
use ark_ec::CurveConfig;
use ark_ff::Field;
use ark_std::marker::PhantomData;

pub struct PolynomialInterpolation<P: PedersenConfig> {
    phantom: PhantomData<P>,
}

impl<P: PedersenConfig> PolynomialInterpolation<P> {
    /// evaluate_polynomial. This function evaluates the polynomial specified by `coeff` at `x`.
    /// This function just uses Horner's trick.
    /// # Arguments
    /// * `coeff` - the coefficients.
    /// * `x` - the point at which to evaluate the polynomial.
    fn evaluate_polynomial(
        coeff: &[<P as CurveConfig>::ScalarField],
        x: &<P as CurveConfig>::ScalarField,
    ) -> <P as CurveConfig>::ScalarField {
        let mut ret = <P as CurveConfig>::ScalarField::ZERO;
        for i in coeff.iter().rev() {
            ret = *i + (*x) * ret;
        }
        ret
    }

    /// interpolate. This function applies Lagrange interpolation to the points in `(x, y)`, returning
    /// a vector of coefficients.
    /// # Arguments
    /// * `x` - the x co-ordinates.
    /// * `y` - the y co-ordinates.
    pub fn interpolate(
        x: &[<P as CurveConfig>::ScalarField],
        y: &[<P as CurveConfig>::ScalarField],
    ) -> Vec<<P as CurveConfig>::ScalarField> {
        assert!(x.len() == y.len());
        let n = x.len();
        let zero = <P as CurveConfig>::ScalarField::ZERO;
        let mut s = std::vec::from_elem(zero, n + 1);
        let mut coeff = std::vec::from_elem(zero, n);

        s[n] = <P as CurveConfig>::ScalarField::ONE;
        s[n - 1] = -x[0];
        for (i, x_i) in x.iter().enumerate().take(n).skip(1) {
            for j in n - i - 1..n - 1 {
                s[j] = s[j] - *x_i * s[j + 1];
            }
            s[n - 1] -= x_i;
        }

        for i in 0..n {
            let mut phi = zero;
            let mut run = P::from_u64_to_sf(n.try_into().unwrap());
            for j in (1..n + 1).rev() {
                phi = run * s[j] + x[i] * phi;
                run -= <P as CurveConfig>::ScalarField::ONE;
            }

            let ff = phi.inverse().unwrap();
            let mut b = <P as CurveConfig>::ScalarField::ONE;
            for j in (0..n).rev() {
                coeff[j] += b * ff * y[i];
                b = s[j] + x[i] * b;
            }
        }

        for i in 0..n {
            assert!(y[i] == Self::evaluate_polynomial(&coeff, &x[i]));
        }

        coeff
    }
}
