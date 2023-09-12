#[macro_export]
#[doc(hidden)]
macro_rules! __derive_conversion {
    ($config: ty, $dim: expr, $OtherCurve: ty, $G2_X: ident, $G2_Y: ident, $fr: ty, $fr_config: ty, $other_q: ty, $other_r: ty, $other_q_conf: ty, $other_r_conf: ty, $affine: ty, $GSX: expr, $GSY: expr) => {
        // Define the conversion functions for this particular
        // mapping.
        type OtherBaseField = <$OtherCurve as CurveConfig>::BaseField;
        type OtherScalarField = <$OtherCurve as CurveConfig>::ScalarField;

        macro_rules! StrToFq {
            ($c0:expr) => {{
                let (is_positive, limbs) = ark_ff_macros::to_sign_and_limbs!($c0);
                <$other_q>::from_sign_and_limbs(is_positive, &limbs)
            }};
        }

        macro_rules! StrToFr {
            ($c0:expr) => {{
                let (is_positive, limbs) = ark_ff_macros::to_sign_and_limbs!($c0);
                <$other_r>::from_sign_and_limbs(is_positive, &limbs)
            }};
        }

        struct FrStruct($fr);
        impl FrStruct {
            pub fn new(x: $fr) -> FrStruct {
                FrStruct(x)
            }

            pub fn as_fr(&self) -> $fr {
                self.0
            }
        }

        impl From<BigInt<$dim>> for FrStruct {
            fn from(x: BigInt<$dim>) -> Self {
                let x_t = <$fr_config>::from_bigint(x).unwrap();
                FrStruct::new(x_t)
            }
        }

        impl From<FrStruct> for BigInt<$dim> {
            fn from(val: FrStruct) -> Self {
                FrConfig::into_bigint(val.0)
            }
        }

        struct OtherBase(OtherBaseField);
        impl OtherBase {
            pub fn new(x: $other_q) -> OtherBase {
                OtherBase(x)
            }
        }

        impl From<OtherBase> for BigInt<$dim> {
            fn from(x: OtherBase) -> Self {
                <$other_q_conf>::into_bigint(x.0)
            }
        }

        impl From<BigInt<$dim>> for OtherBase {
            fn from(x: BigInt<$dim>) -> OtherBase {
                let x_t = <$other_q_conf>::from_bigint(x).unwrap();
                OtherBase::new(x_t)
            }
        }

        struct OtherScalar(OtherScalarField);
        impl OtherScalar {
            pub fn new(x: $other_r) -> OtherScalar {
                OtherScalar(x)
            }
        }

        impl From<OtherScalar> for BigInt<$dim> {
            fn from(x: OtherScalar) -> Self {
                <$other_r_conf>::into_bigint(x.0)
            }
        }

        impl From<BigInt<$dim>> for OtherScalar {
            fn from(x: BigInt<$dim>) -> OtherScalar {
                let x_t = <$other_r_conf>::from_bigint(x).unwrap();
                OtherScalar::new(x_t)
            }
        }

        // Define the Pedersen commitment type.
        impl PedersenConfig for $config {
            type OCurve = $OtherCurve;
            /// GENERATOR2 = (G2_X, G2_Y)
            const GENERATOR2: $affine = <$affine>::new_unchecked($G2_X, $G2_Y);

            fn from_ob_to_sf(x: OtherBaseField) -> <$config as CurveConfig>::ScalarField {
                let x_t: BigInt<$dim> = x.into();
                let x_v: FrStruct = FrStruct::from(x_t);
                x_v.as_fr()
            }

            fn from_os_to_sf(x: OtherScalarField) -> <$config as CurveConfig>::ScalarField {
                let x_t: BigInt<$dim> = x.into();
                let x_v: FrStruct = FrStruct::from(x_t);
                x_v.as_fr()
            }

            fn from_bf_to_sf(
                x: <Self as CurveConfig>::BaseField,
            ) -> <Self as CurveConfig>::ScalarField {
                let x_t: BigInt<$dim> = x.into();
                let x_v: FrStruct = FrStruct::from(x_t);
                x_v.as_fr()
            }

            fn from_sf_to_os(
                x: <Self as CurveConfig>::ScalarField,
            ) -> <Self::OCurve as CurveConfig>::ScalarField {
                let x_t: BigInt<$dim> = x.into();
                <$other_r_conf>::from_bigint(x_t).unwrap()
            }

            const O_TWO: $other_r = StrToFr!("2");
            const OGENERATOR2: sw::Affine<Self::OCurve> =
                sw::Affine::<Self::OCurve>::new_unchecked(StrToFq!($GSX), StrToFq!($GSY));
        }
    };
}

#[macro_export]
macro_rules! derive_conversion {
    ($config: ty, $dim: expr, $OtherCurve: ty, $G2_X: ident, $G2_Y: ident, $fr: ty, $fr_config: ty, $other_q: ty, $other_r: ty, $other_q_conf: ty, $other_r_conf: ty, $affine: ty, $GSX: expr, $GSY: expr) => {
        use ark_ff::BigInt;
        use ark_ff::{Field, MontConfig, MontFp};
        use ark_ff_macros::to_sign_and_limbs;
        use pedersen::pedersen_config::PedersenConfig;

        $crate::__derive_conversion!(
            $config,
            $dim,
            $OtherCurve,
            $G2_X,
            $G2_Y,
            $fr,
            $fr_config,
            $other_q,
            $other_r,
            $other_q_conf,
            $other_r_conf,
            $affine,
            $GSX,
            $GSY
        );
    };
}
