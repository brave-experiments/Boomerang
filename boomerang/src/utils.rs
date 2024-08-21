pub mod rewards {
    use crate::config::BoomerangConfig;
    use ark_bulletproofs::{inner_product, BulletproofGens, LinearProof, PedersenGens, RangeProof};
    use ark_ec::models::{
        short_weierstrass::{self as sw},
        CurveConfig,
    };
    use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use ark_std::UniformRand;
    use merlin::Transcript;
    use rand::Rng;
    use std::convert::TryInto;

    fn extract_u64_from_compressed_data(compressed_data: &[u8]) -> Result<u64, &'static str> {
        // Ensure we have at least 8 bytes to extract a u64
        if compressed_data.len() < 8 {
            return Err("Insufficient bytes to extract u64");
        }

        let first_eight_bytes = compressed_data
            .get(0..8)
            .ok_or("Failed to extract first 8 bytes")?;

        Ok(u64::from_le_bytes(first_eight_bytes.try_into().unwrap()))
    }

    pub fn inner_product_to_u64<B: CurveConfig>(
        a: &[<B as CurveConfig>::ScalarField],
        b: &[<B as CurveConfig>::ScalarField],
    ) -> Result<(u64, B::ScalarField), String> {
        let res = inner_product(a, b);

        let mut compressed_bytes = Vec::new();
        if let Err(e) = res.serialize_compressed(&mut compressed_bytes) {
            return Err(format!("Serialization error: {}", e));
        }
        let extracted_u64 = extract_u64_from_compressed_data(&compressed_bytes)?;

        Ok((extracted_u64, res))
    }

    // Rewards proof struct
    #[derive(CanonicalSerialize, CanonicalDeserialize)]
    pub struct BRewardsProof<B: BoomerangConfig> {
        // the range proof
        pub range_proof: RangeProof<sw::Affine<B>>,
        // the pc gens for range proof
        pub range_gensp_r: PedersenGens<sw::Affine<B>>,
        // the bp gens for range proof
        pub range_gensb_r: BulletproofGens<sw::Affine<B>>,
        // the commitment of range proof
        pub r_comms: sw::Affine<B>,
        // the linear proof
        pub linear_proof: LinearProof<sw::Affine<B>>,
        // the pc gens for linear proof
        pub range_gensp_l: PedersenGens<sw::Affine<B>>,
        // the bp gens for linear proof
        pub range_gensb_l: BulletproofGens<sw::Affine<B>>,
        // the commitment of linear proof
        pub l_comms: sw::Affine<B>,
    }

    impl<B: BoomerangConfig> Clone for BRewardsProof<B> {
        fn clone(&self) -> Self {
            BRewardsProof {
                range_proof: self.range_proof.clone(),
                range_gensp_r: self.range_gensp_r,
                range_gensb_r: self.range_gensb_r.clone(),
                r_comms: self.r_comms,
                linear_proof: self.linear_proof.clone(),
                range_gensp_l: self.range_gensp_r,
                range_gensb_l: self.range_gensb_r.clone(),
                l_comms: self.l_comms,
            }
        }
    }

    impl<B: BoomerangConfig> BRewardsProof<B> {
        pub fn prove(
            spend_state: &[<B as CurveConfig>::ScalarField],
            policy_state: &[<B as CurveConfig>::ScalarField],
            reward_u64: u64,
            reward: <B as CurveConfig>::ScalarField,
            rng: &mut impl Rng,
        ) -> Result<Self, String> {
            // Prove that the reward falls between the range
            let max_reward = 64; // TODO: should be app specific as it defines the maximum ammount of rewards

            let pc_gens_r: PedersenGens<sw::Affine<B>> = PedersenGens::default();
            let bp_gens_r = BulletproofGens::new(max_reward, 1);
            let mut transcript_r = Transcript::new(b"Boomerang verify range proof");
            let blind = <B as CurveConfig>::ScalarField::rand(rng);
            let (r_proof, r_comms) = RangeProof::prove_single(
                &bp_gens_r,
                &pc_gens_r,
                &mut transcript_r,
                reward_u64,
                &blind,
                max_reward,
            )
            .map_err(|e| format!("Range proof error: {:?}", e))?;

            let pc_gens_l: PedersenGens<sw::Affine<B>> = PedersenGens::default();
            let bp_gens_l = BulletproofGens::new(max_reward, 1);
            let g: Vec<_> = bp_gens_l
                .share(0)
                .G(spend_state.len())
                .cloned()
                .collect::<Vec<sw::Affine<B>>>();

            let f = pc_gens_l.B;
            let b = pc_gens_l.B_blinding;

            // c_t = <a, g> + blind_l * b + c * f
            // the policy_state is the witness and it is private
            let blind_l = <B as CurveConfig>::ScalarField::rand(rng);
            let combined_scalars: Vec<B::ScalarField> = policy_state
                .iter()
                .cloned()
                .chain(Some(blind_l))
                .chain(Some(reward))
                .collect();
            let combined_points: Vec<_> = g.iter().cloned().chain(Some(b)).chain(Some(f)).collect();
            let c_t =
                <sw::Affine<B> as AffineRepr>::Group::msm(&combined_points, &combined_scalars)
                    .unwrap()
                    .into_affine();

            let mut transcript_l = Transcript::new(b"Boomerang verify linear proof");
            let l_proof = LinearProof::<sw::Affine<B>>::create(
                &mut transcript_l,
                rng,
                &c_t,
                blind_l,
                policy_state.to_vec(),
                spend_state.to_vec(),
                g.clone(),
                &f,
                &b,
            )
            .map_err(|e| format!("Linear proof error: {:?}", e))?;

            Ok(Self {
                range_proof: r_proof,
                range_gensp_r: pc_gens_r,
                range_gensb_r: bp_gens_r,
                r_comms,
                linear_proof: l_proof,
                range_gensp_l: pc_gens_l,
                range_gensb_l: bp_gens_l,
                l_comms: c_t,
            })
        }

        pub fn verify(
            &self,
            spend_state: &[<B as CurveConfig>::ScalarField],
        ) -> Result<(), String> {
            let max_reward = 64;

            // Verify the range proof
            let mut transcript_r = Transcript::new(b"Boomerang verify range proof");
            self.range_proof
                .verify_single(
                    &self.range_gensb_r,
                    &self.range_gensp_r,
                    &mut transcript_r,
                    &self.r_comms,
                    max_reward,
                )
                .map_err(|e| {
                    format!(
                        "Boomerang verification: reward range proof verification failed: {}",
                        e
                    )
                })?;

            let g: Vec<_> = self
                .range_gensb_l
                .share(0)
                .G(spend_state.len())
                .cloned()
                .collect::<Vec<sw::Affine<B>>>();
            let f = self.range_gensp_l.B;
            let b = self.range_gensp_l.B_blinding;
            let mut transcript_l = Transcript::new(b"Boomerang verify linear proof");

            // Verify the linear proof
            self.linear_proof
                .verify(
                    &mut transcript_l,
                    &self.l_comms,
                    &g,
                    &f,
                    &b,
                    spend_state.to_vec(),
                )
                .map_err(|e| {
                    format!(
                        "Boomerang verification: reward linear proof verification failed: {}",
                        e
                    )
                })?;

            // Return Ok if both verifications succeed
            Ok(())
        }
    }
}
