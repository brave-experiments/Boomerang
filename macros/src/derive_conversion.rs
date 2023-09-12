#[macro_export]
#[doc(hidden)]
macro_rules! __derive_conversion {
    ($config: ty, $dim: expr, $OtherCurve: ty, $G2_X: ident, $G2_Y: ident, $fr: ty, $fr_config: ty, $other_q: ty, $other_conf: ty, $affine: ty) => {
        // Define the conversion functions for this particular
        // mapping.
        type OtherBaseField = <$OtherCurve as CurveConfig>::BaseField;
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
                <$other_conf>::into_bigint(x.0)
            }
        }

        impl From<BigInt<$dim>> for OtherBase {
            fn from(x: BigInt<$dim>) -> OtherBase {
                let x_t = <$other_conf>::from_bigint(x).unwrap();
                OtherBase::new(x_t)
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
        }
    };
}

#[macro_export]
macro_rules! derive_conversion {
    ($config: ty, $dim: expr, $OtherCurve: ty, $G2_X: ident, $G2_Y: ident, $fr: ty, $fr_config: ty, $other_q: ty, $other_conf: ty, $affine: ty) => {
        use ark_ff::BigInt;
        use ark_ff::{Field, MontConfig, MontFp};
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
            $other_conf,
            $affine
        );
    };
}
