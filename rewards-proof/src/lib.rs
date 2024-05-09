use ark_bulletproofs::{BulletproofGens, PedersenGens};
use ark_ec::{models::short_weierstrass::SWCurveConfig, short_weierstrass::Affine};

pub mod api;

#[derive(Clone)]
pub struct RewardsGenerators<C: SWCurveConfig> {
    /// PedersenGenerators
    pub pedersen_gens: Vec<PedersenGens<Affine<C>>>,
    /// Bulletproof Generators
    pub bulletproof_gens: Vec<BulletproofGens<Affine<C>>>,
}

impl<C: SWCurveConfig> RewardsGenerators<C> {
    /// Creates some default generators for the rewards proof
    pub fn create() -> Self {
        let incentive_catalog_size: u64 = 64;
        let (pedersen_gens, bulletproof_gens) =
            crate::api::rewards_proof_setup(incentive_catalog_size);
        Self {
            pedersen_gens,
            bulletproof_gens,
        }
    }
}

#[derive(Clone)]
pub struct RewardsProof<C: SWCurveConfig> {
    /// the range proof
    pub range_proof: Vec<u8>,
    /// the linear proof
    pub linear_proof: Vec<u8>,
    /// the range proof commitments
    pub range_comm: Vec<u8>,
    /// the linear proof commitments
    pub linear_comm: Vec<u8>,
    /// the rewards generators
    pub rewards_gens: RewardsGenerators<C>,
}

impl<C: SWCurveConfig> RewardsProof<C> {
    /// Creates a new Rewards proof
    pub fn create(
        rewards_gens: RewardsGenerators<C>,
        reward: u64,
        state: Vec<C::ScalarField>,
        policy_vector: Vec<C::ScalarField>,
    ) -> Self {
        let incentive_catalog_size: u64 = 64;
        let (range_proof, linear_proof, range_comm, linear_comm) =
            crate::api::rewards_proof_generation(
                rewards_gens.pedersen_gens.clone(),
                rewards_gens.bulletproof_gens.clone(),
                reward,
                state,
                policy_vector,
                incentive_catalog_size,
            );
        Self {
            range_proof,
            linear_proof,
            range_comm,
            linear_comm,
            rewards_gens,
        }
    }

    /// Verifies the rewards proof
    pub fn verify(self, policy_vector: Vec<C::ScalarField>) -> bool {
        crate::api::rewards_proof_verification(
            &self.rewards_gens.pedersen_gens,
            &self.rewards_gens.bulletproof_gens,
            self.range_proof,
            self.range_comm,
            self.linear_proof,
            policy_vector,
            self.linear_comm,
        )
    }
}
