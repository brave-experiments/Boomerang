//! Definition of linear combinations.

use ark_ff::PrimeField;
use ark_std::{
    iter::FromIterator,
    ops::{Add, Mul, Neg, Sub},
    vec,
    vec::Vec,
};
use core::marker::PhantomData;

/// Represents a variable in a constraint system.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Variable<F: PrimeField> {
    /// Represents an external input specified by a commitment.
    Committed(usize),
    /// Represents the left input of a multiplication gate.
    MultiplierLeft(usize),
    /// Represents the right input of a multiplication gate.
    MultiplierRight(usize),
    /// Represents the output of a multiplication gate.
    MultiplierOutput(usize),
    /// Represents the constant 1.
    One(),
    /// Phantom.
    Phantom(PhantomData<F>),
}

impl<F: PrimeField> From<Variable<F>> for LinearCombination<F> {
    fn from(v: Variable<F>) -> LinearCombination<F> {
        LinearCombination {
            terms: vec![(v, F::one())],
        }
    }
}

impl<F: PrimeField> From<F> for LinearCombination<F> {
    fn from(s: F) -> LinearCombination<F> {
        LinearCombination {
            terms: vec![(Variable::One(), s)],
        }
    }
}

// Arithmetic on variables produces linear combinations

impl<F: PrimeField> Neg for Variable<F> {
    type Output = LinearCombination<F>;

    fn neg(self) -> Self::Output {
        -LinearCombination::from(self)
    }
}

impl<F: PrimeField, L: Into<LinearCombination<F>>> Add<L> for Variable<F> {
    type Output = LinearCombination<F>;

    fn add(self, other: L) -> Self::Output {
        LinearCombination::from(self) + other.into()
    }
}

impl<F: PrimeField, L: Into<LinearCombination<F>>> Sub<L> for Variable<F> {
    type Output = LinearCombination<F>;

    fn sub(self, other: L) -> Self::Output {
        LinearCombination::from(self) - other.into()
    }
}

impl<F: PrimeField, S: Into<F>> Mul<S> for Variable<F> {
    type Output = LinearCombination<F>;

    fn mul(self, other: S) -> Self::Output {
        LinearCombination {
            terms: vec![(self, other.into())],
        }
    }
}

/// Represents a linear combination of
/// [`Variables`](::r1cs::Variable).  Each term is represented by a
/// `(Variable, Fr)` pair.
#[derive(Clone, Debug, PartialEq)]
pub struct LinearCombination<F: PrimeField> {
    pub(super) terms: Vec<(Variable<F>, F)>,
}

impl<F: PrimeField> Default for LinearCombination<F> {
    fn default() -> Self {
        LinearCombination { terms: Vec::new() }
    }
}

impl<F: PrimeField> FromIterator<(Variable<F>, F)> for LinearCombination<F> {
    fn from_iter<T>(iter: T) -> Self
    where
        T: IntoIterator<Item = (Variable<F>, F)>,
    {
        LinearCombination {
            terms: iter.into_iter().collect(),
        }
    }
}

impl<'a, F: PrimeField> FromIterator<&'a (Variable<F>, F)> for LinearCombination<F> {
    fn from_iter<T>(iter: T) -> Self
    where
        T: IntoIterator<Item = &'a (Variable<F>, F)>,
    {
        LinearCombination {
            terms: iter.into_iter().cloned().collect(),
        }
    }
}

// Arithmetic on linear combinations

impl<F: PrimeField, L: Into<LinearCombination<F>>> Add<L> for LinearCombination<F> {
    type Output = Self;

    fn add(mut self, rhs: L) -> Self::Output {
        self.terms.extend(rhs.into().terms.iter().cloned());
        LinearCombination { terms: self.terms }
    }
}

impl<F: PrimeField, L: Into<LinearCombination<F>>> Sub<L> for LinearCombination<F> {
    type Output = Self;

    fn sub(mut self, rhs: L) -> Self::Output {
        self.terms.extend(
            rhs.into()
                .terms
                .iter()
                .map(|(var, coeff)| (*var, coeff.neg())),
        );
        LinearCombination { terms: self.terms }
    }
}

impl<F: PrimeField> Neg for LinearCombination<F> {
    type Output = Self;

    fn neg(mut self) -> Self::Output {
        for (_, s) in self.terms.iter_mut() {
            *s = -*s
        }
        self
    }
}

impl<F: PrimeField, S: Into<F>> Mul<S> for LinearCombination<F> {
    type Output = Self;

    fn mul(mut self, other: S) -> Self::Output {
        let other = other.into();
        for (_, s) in self.terms.iter_mut() {
            *s *= other
        }
        self
    }
}
