//! Defines a protocol for proof of elliptic curve point addition.
//! Namely, this protocol proves that A + B = T, for A, B, T \in E(F_{q}).
//! This protocol is the same as the protocol described in Theorem 4 of the paper.

use ark_ec::{CurveConfig,
             short_weierstrass::{self as sw},
             CurveGroup,
             AffineRepr};
use merlin::Transcript;

use ark_ff::fields::Field;
use ark_serialize::CanonicalSerialize;

use rand::{CryptoRng, RngCore};

use crate::{
    mul_protocol::MulProof, opening_protocol::OpeningProof, pedersen_config::PedersenComm,
    pedersen_config::PedersenConfig, transcript::ECPointAdditionTranscript,
    transcript::EC_POINT_CHALLENGE_SIZE,
};

pub struct ECPointAddProof<P: PedersenConfig> {
    /// c1: the commitment to a_x.
    pub c1: sw::Affine<P>,
    /// c2: the commitment to a_y.
    pub c2: sw::Affine<P>,
    /// c3: the commitment to b_x.
    pub c3: sw::Affine<P>,
    /// c4: the commitment to b_y.
    pub c4: sw::Affine<P>,
    /// c5: the commitment to t_x.
    pub c5: sw::Affine<P>,
    /// c6: the commitment to t_y.
    pub c6: sw::Affine<P>,

    /// c7: the commitment to tau = (b_y - a_y)/(b_x - a_x)
    pub c7: sw::Affine<P>,

    /// mp1: the multiplication proof that verifies that equation 1 holds.
    pub mp1: MulProof<P>,

    /// mp2: the multiplication proof that verifies that equation 2 holds.
    pub mp2: MulProof<P>,

    /// mp3: the multiplication proof that verifies that equation 3 holds.
    pub mp3: MulProof<P>,

    /// op: the opening proof of C2.
    pub op: OpeningProof<P>,
}

impl<P: PedersenConfig> ECPointAddProof<P> {    
    /// This is just to circumvent an annoying issue with Rust's current generics system.
    const MPSIZE: usize = MulProof::<P>::CHAL_SIZE;
    const OPSIZE: usize = OpeningProof::<P>::CHAL_SIZE;    
    pub const CHAL_SIZE: usize = 3*Self::MPSIZE + Self::OPSIZE;
    
    fn make_transcript(
        transcript: &mut Transcript,
        c1: &sw::Affine<P>,
        c2: &sw::Affine<P>,
        c3: &sw::Affine<P>,
        c4: &sw::Affine<P>,
        c5: &sw::Affine<P>,
        c6: &sw::Affine<P>,
        c7: &sw::Affine<P>,
    ) {
        // This function just builds the transcript for both the create and verify functions.
        // N.B Because of how we define the serialisation API to handle different numbers,
        // we use a temporary buffer here.
        ECPointAdditionTranscript::domain_sep(transcript);

        let mut compressed_bytes = Vec::new();
        c1.serialize_compressed(&mut compressed_bytes).unwrap();
        ECPointAdditionTranscript::append_point(transcript, b"C1", &compressed_bytes[..]);

        c2.serialize_compressed(&mut compressed_bytes).unwrap();
        ECPointAdditionTranscript::append_point(transcript, b"C2", &compressed_bytes[..]);

        c3.serialize_compressed(&mut compressed_bytes).unwrap();
        ECPointAdditionTranscript::append_point(transcript, b"C3", &compressed_bytes[..]);

        c4.serialize_compressed(&mut compressed_bytes).unwrap();
        ECPointAdditionTranscript::append_point(transcript, b"C4", &compressed_bytes[..]);

        c5.serialize_compressed(&mut compressed_bytes).unwrap();
        ECPointAdditionTranscript::append_point(transcript, b"C5", &compressed_bytes[..]);

        c6.serialize_compressed(&mut compressed_bytes).unwrap();
        ECPointAdditionTranscript::append_point(transcript, b"C6", &compressed_bytes[..]);

        c7.serialize_compressed(&mut compressed_bytes).unwrap();
        ECPointAdditionTranscript::append_point(transcript, b"C7", &compressed_bytes[..]);
    }

    fn make_commitment<T: RngCore + CryptoRng>(
        val: <<P as PedersenConfig>::OCurve as CurveConfig>::BaseField,
        rng: &mut T,
    ) -> PedersenComm<P> {
        let val_p = <P as PedersenConfig>::from_ob_to_sf(val);
        PedersenComm::new(val_p, rng)
    }

    pub fn create<T: RngCore + CryptoRng>(
        transcript: &mut Transcript,
        rng: &mut T,
        a_x: <<P as PedersenConfig>::OCurve as CurveConfig>::BaseField,
        a_y: <<P as PedersenConfig>::OCurve as CurveConfig>::BaseField,
        b_x: <<P as PedersenConfig>::OCurve as CurveConfig>::BaseField,
        b_y: <<P as PedersenConfig>::OCurve as CurveConfig>::BaseField,
        t_x: <<P as PedersenConfig>::OCurve as CurveConfig>::BaseField,
        t_y: <<P as PedersenConfig>::OCurve as CurveConfig>::BaseField,
    ) -> Self {
        // Commit to each of the co-ordinate pairs.
        let c1 = Self::make_commitment(a_x, rng);
        let c2 = Self::make_commitment(a_y, rng);
        let c3 = Self::make_commitment(b_x, rng);
        let c4 = Self::make_commitment(b_y, rng);
        let c5 = Self::make_commitment(t_x, rng);
        let c6 = Self::make_commitment(t_y, rng);

        // c7 is the commitment to tau, the gradient.
        let tau = (b_y - a_y) * ((b_x - a_x).inverse().unwrap());
        let taua = <P as PedersenConfig>::from_ob_to_sf(tau);
        let c7 = PedersenComm::new(taua, rng);

        // Now we begin the stage of incorporating everything into the
        // transcript. We do this by creating the intermediates for each
        // proof (which adds to the transcript in turn), before generating a long
        // challenge (with enough space for each sub-proof). We then, finally,
        // split up this challenge into smaller slices that can be used by each
        // individual proof.
        Self::make_transcript(transcript, &c1.comm, &c2.comm, &c3.comm, &c4.comm, &c5.comm, &c6.comm, &c7.comm);

        // These are the temporaries for the first multiplication proof, which
        // verifies that (b_x - a_x)*tau = b_y - a_y.
        let z1 = &c3 - &c1; // This is the commitment for b_x - a_x.
        let z2 = &c4 - &c2; // This is the commitment for b_y - a_y.

        let x1 = <P as PedersenConfig>::from_ob_to_sf(b_x - a_x);
        let mpi1 = MulProof::create_intermediates(transcript, rng, &z1, &c7, &z2);

        // These are the temporaries for the second multiplication proof, which verifies that
        // tau^2 = a_x + b_x + t_x.
        let z4 = &c1 + &c3 + &c5; // This is the commitment to a_x + b_x + t_x.
        let mpi2 = MulProof::create_intermediates(transcript, rng, &c7, &c7, &z4);
        
        // These are the temporaries for the third multiplication proof, which verifies that
        // tau*(a_x - t_x) = a_y + t_y.
        let x3 = <P as PedersenConfig>::from_ob_to_sf(a_x - t_x); // Value of a_x - t_x
        let z5 = &c1 - &c5; // The commitment to a_x - t_x
        let z6 = &c2 + &c6; // The commitment to a_y + t_y.        
        let mpi3 = MulProof::create_intermediates(transcript, rng, &c7, &z5, &z6);

        // And, finally, the intermediates for the Opening proof.
        // This proves that C2 opens to a_y.
        let ay_sf = <P as PedersenConfig>::from_ob_to_sf(a_y);
        let opi = OpeningProof::create_intermediates(transcript, rng, &c2);

        // Now we make a very large challenge and create the various proofs from the
        // intermediates.
        let chal_buf = ECPointAdditionTranscript::challenge_scalar(transcript, b"c");

        // Make sure it all lines up.
        assert!(Self::CHAL_SIZE == EC_POINT_CHALLENGE_SIZE);

        // Make the sub-challenges.        
        let mp1chal = &chal_buf[0..Self::MPSIZE];
        let mp2chal = &chal_buf[Self::MPSIZE..2*Self::MPSIZE];
        let mp3chal = &chal_buf[2*Self::MPSIZE..3*Self::MPSIZE];
        let opchal  = &chal_buf[3*Self::MPSIZE..];

        // And now we build the sub-proofs before returning.
        let mp1 = MulProof::create_proof(&x1, &taua, &mpi1, &z1, &c7, &z2, mp1chal);
        let mp2 = MulProof::create_proof(&taua, &taua, &mpi2, &c7, &c7, &z4, mp2chal);
        let mp3 = MulProof::create_proof(&taua, &x3, &mpi3, &c7, &z5, &z6, mp3chal);
        let op  = OpeningProof::create_proof(&ay_sf, &opi, &c2, opchal);
                    
        // And now we just return.
        Self {
            c1: c1.comm,
            c2: c2.comm,
            c3: c3.comm,
            c4: c4.comm,
            c5: c5.comm,
            c6: c6.comm,
            c7: c7.comm,
            mp1: mp1,                
            mp2: mp2,            
            mp3: mp3,            
            op:  op,            
        }
    }

    pub fn verify(&self, transcript: &mut Transcript) -> bool {
        Self::make_transcript(
            transcript, &self.c1, &self.c2, &self.c3, &self.c4, &self.c5, &self.c6, &self.c7,
        );
        
        let z1 = (self.c3.into_group() - self.c1).into_affine();
        let z2 = &self.c7;
        let z3 = (self.c4.into_group() - self.c2).into_affine();
        let z4 = (self.c1 + self.c3 + self.c5).into_affine();
        let z5 = (self.c1.into_group() - self.c5).into_affine();
        let z6 = (self.c2.into_group() + self.c6).into_affine();

        // Rebuild the rest of the transcript.        
        self.mp1.add_to_transcript(transcript, &z1, &z2, &z3);
        self.mp2.add_to_transcript(transcript, &self.c7, &self.c7, &z4);
        self.mp3.add_to_transcript(transcript, &z2, &z5, &z6);
        self.op.add_to_transcript(transcript, &self.c2);

        // Make the challenges and sub-challenges.
        let chal_buf = ECPointAdditionTranscript::challenge_scalar(transcript, b"c");
        let mp1chal = &chal_buf[0..Self::MPSIZE];
        let mp2chal = &chal_buf[Self::MPSIZE..2*Self::MPSIZE];
        let mp3chal = &chal_buf[2*Self::MPSIZE..3*Self::MPSIZE];
        let opchal  = &chal_buf[3*Self::MPSIZE..];

        self.mp1.verify_with_challenge(&z1, &z2, &z3, mp1chal)
            && self.mp2.verify_with_challenge(&self.c7, &self.c7, &z4, mp2chal)
            && self.mp3.verify_with_challenge(&z2, &z5, &z6, mp3chal)
            && self.op.verify_with_challenge(&self.c2, opchal)
    }
}
