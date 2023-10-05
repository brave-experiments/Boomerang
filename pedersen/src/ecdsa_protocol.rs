//! This file contains a protocol for proving knowledge of an ECDSA signature against
//! a committed-to public key.

use ark_ec::{
    short_weierstrass::{self as sw, SWCurveConfig},
    CurveConfig, CurveGroup,
};
use merlin::Transcript;

use ark_ff::Field;
use ark_serialize::CanonicalSerialize;
use ark_std::ops::Mul;
use rand::{CryptoRng, RngCore};

use crate::{
    collective::Collective,
    fs_scalar_mul_protocol::{FSECScalarMulProof, FSECScalarMulProofIntermediate},
    pedersen_config::{PedersenComm, PedersenConfig},
    point_add::PointAddProtocol,
    transcript::ECDSASignatureTranscript,
};

pub struct ECDSASigProof<P: PedersenConfig, PT: Collective<P>> {
    /// r: the signature value (i.e R = u1g + u2q).
    /// This is entirely random.
    pub r: sw::Affine<P::OCurve>,

    /// cq_x: the commitment to the public key's x co-ordinate.
    pub cq_x: sw::Affine<P>,

    /// cq_y: the commitment to the public key's y co-ordinate.
    pub cq_y: sw::Affine<P>,

    pub c_lhs_x: sw::Affine<P>,
    pub c_lhs_y: sw::Affine<P>,
    pub cz: sw::Affine<P::OCurve>,

    /// cs_x: the commitment to tr^{-1}g's x co-ordinate.
    pub cs_x: sw::Affine<P>,
    /// cs_xr: the randomness used when making cs_x.
    pub cs_xr: P::ScalarField,

    /// cs_y: the commitment to tr^{-1}g's y co-ordinate.
    pub cs_y: sw::Affine<P>,
    /// cs_yr: the randomness used when making cs_y.
    pub cs_yr: P::ScalarField,

    /// scalar_mul: the proof of validity for zR.
    pub scalar_mul: FSECScalarMulProof<P, PT::ScalarMul>,

    /// point_add: the proof that the commitment to `tr^{-1}g + Q` == a value.
    pub point_add: PT::PointAdd,
}

pub struct ECDSASigProofIntermediate<P: PedersenConfig, PT: Collective<P>> {
    /// r: the signature value (i.e R = u1g + u2q).
    /// This is entirely random.
    pub r: sw::Affine<P::OCurve>,

    /// cq_x: the commitment to the public key's x co-ordinate.
    pub cq_x: PedersenComm<P>,

    /// cq_y: the commitment to the public key's y co-ordinate.
    pub cq_y: PedersenComm<P>,

    pub cz: sw::Affine<P::OCurve>,
    pub cr: <P::OCurve as CurveConfig>::ScalarField,

    pub c_lhs_x: PedersenComm<P>,
    pub c_lhs_y: PedersenComm<P>,

    /// cs_x: the commitment to tr^{-1}g's x co-ordinate.
    pub cs_x: PedersenComm<P>,

    /// cs_y: the commitment to tr^{-1}g's y co-ordinate.
    pub cs_y: PedersenComm<P>,

    /// mpi: the intermediates for the Fiat-Shamir multiplication proof.
    pub mpi: FSECScalarMulProofIntermediate<P, PT::ScalarMul>,

    /// addpi: the intermediates for the point addition proof.
    pub addpi: <PT::PointAdd as PointAddProtocol<P>>::Intermediate,

    /// trm1g: the value of tr^{-1}g. Only used later for generating proofs.
    pub trm1g: sw::Affine<P::OCurve>,

    /// sum: the value of tr^{-1}g + q. Only used later for generating proofs.
    pub sum: sw::Affine<P::OCurve>,

    /// z: the scalar that's used. Only here for easier proof generation.
    pub z: <<P as PedersenConfig>::OCurve as CurveConfig>::ScalarField,
}

impl<P: PedersenConfig, PT: Collective<P>> ECDSASigProof<P, PT> {
    /// make_transcript. This function adds all of the intermediate commitments to the public
    /// transcript.
    /// # Arguments
    /// * `transcript` - the transcript object.
    /// * `r` - the public R value.
    /// * `cq_x` - the commitment to the public key Q's x co-ordinate.
    /// * `cq_x` - the commitment to the public key Q's x co-ordinate.
    /// * `cs_x` - the commitment to the tr^{-1}g's x co-ordinate.
    /// * `cs_y` - the commitment to the tr^{-1}g's y co-ordinate.
    #[allow(clippy::too_many_arguments)]
    pub fn make_transcript(
        transcript: &mut Transcript,
        r: &sw::Affine<<P as PedersenConfig>::OCurve>,
        cq_x: &sw::Affine<P>,
        cq_y: &sw::Affine<P>,
        cs_x: &sw::Affine<P>,
        cs_y: &sw::Affine<P>,
    ) {
        transcript.domain_sep();
        let mut compressed_bytes = Vec::new();

        r.serialize_compressed(&mut compressed_bytes).unwrap();
        transcript.append_point(b"r", &compressed_bytes[..]);

        cq_x.serialize_compressed(&mut compressed_bytes).unwrap();
        transcript.append_point(b"cq_x", &compressed_bytes[..]);

        cq_y.serialize_compressed(&mut compressed_bytes).unwrap();
        transcript.append_point(b"cq_y", &compressed_bytes[..]);

        cs_x.serialize_compressed(&mut compressed_bytes).unwrap();
        transcript.append_point(b"cs_x", &compressed_bytes[..]);

        cs_y.serialize_compressed(&mut compressed_bytes).unwrap();
        transcript.append_point(b"cs_y", &compressed_bytes[..]);
    }

    /// make_trgm1_and_r_inv. This function returns tr^{-1}g as a point in the OCurve's affine space,
    /// as well as r_inv.
    /// # Arguments
    /// * `t` - the `t` parameter (this corresponds to the hash of the message).
    /// * `r` - the `r` parameter (this corresponds to part of the ECDSA signature).
    fn make_trm1g_and_r_inv(
        t: &<<P as PedersenConfig>::OCurve as CurveConfig>::ScalarField,
        r: &<<P as PedersenConfig>::OCurve as CurveConfig>::ScalarField,
    ) -> (
        <<P as PedersenConfig>::OCurve as CurveConfig>::ScalarField,
        sw::Affine<P::OCurve>,
    ) {
        let r_inv = r.inverse().unwrap();
        (
            r_inv,
            <<P as PedersenConfig>::OCurve as SWCurveConfig>::GENERATOR
                .mul(t.mul(r_inv))
                .into_affine(),
        )
    }

    /// create_intermediates. This function creates the intermediate values for ECDSA signature
    /// verification. This is typically useful when the transcript needs to have more information
    /// appended before the full proof is made.
    /// # Arguments
    /// * `transcript` - the transcript object.
    /// * `rng` - the cryptographically random number generator.
    /// * `t` - the hash of the message.
    /// * `r` - the R value from the ECDSA signature verification equation.
    /// * `r_x` - the truncated `x` co-ordinate of `R`.
    /// * `s` - the other part of the ECDSA signature.
    /// * `q` - the public key.
    pub fn create_intermediates<T: RngCore + CryptoRng>(
        transcript: &mut Transcript,
        rng: &mut T,
        t: &<<P as PedersenConfig>::OCurve as CurveConfig>::ScalarField,
        r: &sw::Affine<<P as PedersenConfig>::OCurve>,
        r_x: &<<P as PedersenConfig>::OCurve as CurveConfig>::ScalarField,
        s: &<<P as PedersenConfig>::OCurve as CurveConfig>::ScalarField,
        q: &sw::Affine<<P as PedersenConfig>::OCurve>,
    ) -> ECDSASigProofIntermediate<P, PT> {
        // To begin we essentially have to compute the various portions of the ECDSA
        // signature verification.
        let (_, trm1g) = Self::make_trm1g_and_r_inv(t, r_x);
        // We now compute the commitments to tr^{-1}g
        let cs_x = P::make_commitment_from_other(trm1g.x, rng);
        let cs_y = P::make_commitment_from_other(trm1g.y, rng);

        // And now the ones to the public key.
        let cq_x = PedersenComm::new(P::from_ob_to_sf(q.x), rng);
        let cq_y = PedersenComm::new(P::from_ob_to_sf(q.y), rng);

        // z = sr^{-1}.
        let z = *s / *r_x;
        let (cz, cr) = P::create_commit_other(&z, rng);

        // N.B We do not need to compute zR, as it's implicit from knowledge of trm1g + q for
        // honest provers.

        // and then make the transcript for the parts we've built so far.
        Self::make_transcript(
            transcript, r, &cq_x.comm, &cq_y.comm, &cs_x.comm, &cs_y.comm,
        );

        // This is the lhs for the proof (i.e we are proving that tr^{-1}g + q = zR).
        let lhs = (trm1g + q).into_affine();

        // Commit to the point.
        let c_lhs_x = PedersenComm::new(<P as PedersenConfig>::from_ob_to_sf(lhs.x), rng);
        let c_lhs_y = PedersenComm::new(<P as PedersenConfig>::from_ob_to_sf(lhs.y), rng);

        // Prove that zr = trm1g + q.
        let mpi = FSECScalarMulProof::<P, PT::ScalarMul>::create_intermediate(
            transcript, rng, &lhs, &z, r, &cz, &cr, &c_lhs_x, &c_lhs_y,
        );

        // Prove that lhs = trm1g + q from our already existing commitments.
        let addpi = PT::PointAdd::create_intermediates_with_existing_commitments(
            transcript, rng, trm1g, *q, lhs, &cs_x, &cs_y, &cq_x, &cq_y, &c_lhs_x, &c_lhs_y,
        );

        ECDSASigProofIntermediate {
            r: (*r),
            cq_x,
            cq_y,
            cs_x,
            cs_y,
            c_lhs_x,
            c_lhs_y,
            cz,
            cr,
            mpi,
            addpi,
            sum: lhs,
            trm1g,
            z,
        }
    }

    /// create. This function creates a proof of ECDSA signature under a committed public key `q`.
    /// Namely, this proof shows that the prover knows a pair (r, s) such that (r,s) is a valid signature
    /// on a public message that verifies under some particular public key.
    /// # Arguments
    /// * `transcript` - the transcript object.
    /// * `rng` - the cryptographically random number generator.
    /// * `t` - the hash of the message.
    /// * `r` - the R value from the ECDSA signature verification equation.
    /// * `r_x` - the truncated `x` co-ordinate of `R`.
    /// * `s` - the other part of the ECDSA signature.
    /// * `q` - the public key.    
    pub fn create<T: RngCore + CryptoRng>(
        transcript: &mut Transcript,
        rng: &mut T,
        t: &<<P as PedersenConfig>::OCurve as CurveConfig>::ScalarField,
        r: &sw::Affine<<P as PedersenConfig>::OCurve>,
        r_x: &<<P as PedersenConfig>::OCurve as CurveConfig>::ScalarField,
        s: &<<P as PedersenConfig>::OCurve as CurveConfig>::ScalarField,
        q: &sw::Affine<<P as PedersenConfig>::OCurve>,
    ) -> Self {
        // We just make the intermediates and delegate to the
        // rest.
        let inter = Self::create_intermediates(transcript, rng, t, r, r_x, s, q);
        Self::create_proof(transcript, r, &inter, q)
    }

    /// create_proof. This function takes a pre-existing set of intermediates (`inter`) and builds
    /// an ECDSA signature verification proof from them.
    /// Note that this function generates each sub-challenge internally.
    /// # Arguments
    /// * `transcript` - the transcript object.
    /// * `r` - the R value from the ECDSA signature verification equation.
    /// * `inter` - the pre-generated intermediate values.
    pub fn create_proof(
        transcript: &mut Transcript,
        r: &sw::Affine<<P as PedersenConfig>::OCurve>,
        inter: &ECDSASigProofIntermediate<P, PT>,
        q: &sw::Affine<<P as PedersenConfig>::OCurve>,
    ) -> Self {
        // N.B We allow the sub-callers to generate their own challenges here. This is primarily
        // to make the API easier to handle across various security levels / parameters.
        Self {
            r: *r,
            cq_x: inter.cq_x.comm,
            cq_y: inter.cq_y.comm,
            // N.B We verify the cs commitments by just revealing the randomness
            // and comparing.
            cs_x: inter.cs_x.comm,
            cs_xr: inter.cs_x.r,
            cs_y: inter.cs_y.comm,
            cs_yr: inter.cs_y.r,
            cz: inter.cz,
            c_lhs_x: inter.c_lhs_x.comm,
            c_lhs_y: inter.c_lhs_y.comm,

            scalar_mul: FSECScalarMulProof::<P, PT::ScalarMul>::create_proof_own_challenge(
                transcript,
                &inter.sum,
                &inter.z,
                r,
                &inter.mpi,
                &inter.cz,
                &inter.cr,
                &inter.c_lhs_x,
                &inter.c_lhs_y,
            ),

            point_add: PT::PointAdd::create_proof_own_challenge(
                transcript,
                inter.trm1g,
                *q,
                inter.sum,
                &inter.addpi,
                &inter.cs_x,
                &inter.cs_y,
                &inter.cq_x,
                &inter.cq_y,
                &inter.c_lhs_x,
                &inter.c_lhs_y,
            ),
        }
    }

    /// verify_trm1g_commitments. This function returns true if the commitments
    /// to the tr^{-1}g values open successfully and false otherwise.
    /// # Arguments
    /// * `self` - the proof object.
    /// * `r` - the `R` point in the ECDSA proof.
    /// * `t` - the hash of the message.
    pub fn verify_trm1g_commitments(
        &self,
        r: &sw::Affine<<P as PedersenConfig>::OCurve>,
        t: &<<P as PedersenConfig>::OCurve as CurveConfig>::ScalarField,
    ) -> bool {
        // We just rebuild each of the commitments and then check if they line up.
        let (_, trm1g) = Self::make_trm1g_and_r_inv(t, &P::from_ob_to_os(r.x));
        // N.B This whole thing can be done faster by either a) using MSM or b)
        // by just sending the commitments as g^{x}. This is the same as implicitly
        // setting the randomness value to 0.
        let gx = (P::GENERATOR.mul(P::from_ob_to_sf(trm1g.x)) + P::GENERATOR2.mul(self.cs_xr))
            .into_affine();
        let gy = (P::GENERATOR.mul(P::from_ob_to_sf(trm1g.y)) + P::GENERATOR2.mul(self.cs_yr))
            .into_affine();
        gx == self.cs_x && gy == self.cs_y
    }

    /// verify. This function returns true if the proof held by `self` is a valid proof
    /// and false otherwise.
    /// # Arguments
    /// * `self` - the proof object.
    /// * `transcript` - the transcript object to use.
    /// * `r` - the previously agreed, public point.
    /// * `t` - the hash of the message.
    pub fn verify(
        &self,
        transcript: &mut Transcript,
        r: &sw::Affine<<P as PedersenConfig>::OCurve>,
        t: &<<P as PedersenConfig>::OCurve as CurveConfig>::ScalarField,
    ) -> bool {
        // Part 1: rebuild the transcript. This needs to be done in order, or the challenges won't
        // match up.
        Self::make_transcript(
            transcript, &self.r, &self.cq_x, &self.cq_y, &self.cs_x, &self.cs_y,
        );

        self.scalar_mul
            .add_to_transcript(transcript, &self.cz, &self.c_lhs_x, &self.c_lhs_y);
        self.point_add.add_proof_to_transcript(
            transcript,
            &self.cs_x,
            &self.cs_y,
            &self.cq_x,
            &self.cq_y,
            &self.c_lhs_x,
            &self.c_lhs_y,
        );

        // Part 2: we verify.
        // This should be read as:
        // 1) We verify the scalar multiplication
        // 2) We verify the point addition.
        // 3) We check the commitments to tr^{-1}g.
        // N.B These all need to use functions that do not modify the transcript object further.
        // I.e these functions should call verify_proof or verify_proof_own_challenge where appropriate.
        self.scalar_mul
            .verify_proof(transcript, r, &self.cz, &self.c_lhs_x, &self.c_lhs_y)
            && self.point_add.verify_proof_own_challenge(
                transcript,
                &self.cs_x,
                &self.cs_y,
                &self.cq_x,
                &self.cq_y,
                &self.c_lhs_x,
                &self.c_lhs_y,
            )
            && self.verify_trm1g_commitments(r, t)
    }

    /// serialized_size. Returns the number of bytes needed to represent this proof object once serialised.
    /// # Arguments
    /// * `self` - the proof object.
    pub fn serialized_size(&self) -> usize {
        self.r.compressed_size()
            + self.cq_x.compressed_size()
            + self.cq_y.compressed_size()
            + self.cs_x.compressed_size()
            + self.cs_xr.compressed_size()
            + self.cs_y.compressed_size()
            + self.cs_yr.compressed_size()
            + self.cz.compressed_size()
            + self.c_lhs_x.compressed_size()
            + self.c_lhs_y.compressed_size()
            + self.scalar_mul.serialized_size()
    }
}
