//! Defines a point addition protocol using ZKAttest's proof of point addition.
//! Note that this particular implementation is defined in the same way as the ZKAttest implementation, and not as per the ZKAttest paper.

use merlin::Transcript;
use ark_ec::{
    CurveConfig,
    short_weierstrass::{self as sw, SWCurveConfig},
    CurveGroup,
    AffineRepr,
};

use ark_serialize::{CanonicalSerialize};
use ark_ff::fields::Field;
use rand::{RngCore, CryptoRng};

use crate::{pedersen_config::PedersenConfig, pedersen_config::PedersenComm,
            mul_protocol::MulProof, equality_protocol::EqualityProof,
            transcript::ZKAttestECPointAdditionTranscript};

pub struct ZKAttestPointAddProof<P:PedersenConfig> {
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

    // We do not need c7: Pedersen Commitments are additively
    // homomorphic.
    //pub c7 : sw::Affine<P>,
    
    /// c8: the commitment to (b_x - a_x)^-1
    pub c8 : sw::Affine<P>,

    // pub c9 : sw::Affine<P>

    /// c10: the commitment to (b_y - a_y) / (b_x - a_x).
    pub c10 : sw::Affine<P>,

    /// c11: the commitment to ((b_y - a_y) / (b_x - a_x))^2
    pub c11 : sw::Affine<P>,

    // pub c12: sw::Affine<P>,

    /// c13: the commitment to (b_y - a_y)/(b_x-a_x) *
    /// (a_x-t_x)
    pub c13 : sw::Affine<P>,
    
    pub mp1 : MulProof<P>,
    pub mp2 : MulProof<P>,

    pub mp3 : MulProof<P>,
    pub mp4 : MulProof<P>,
    pub e1  : EqualityProof<P>,
    pub e2  : EqualityProof<P>,
}

impl <P: PedersenConfig> ZKAttestPointAddProof<P> {

    fn make_transcript(transcript: &mut Transcript,
                       c1: &sw::Affine<P>,
                       c2: &sw::Affine<P>,
                       c3: &sw::Affine<P>,
                       c4: &sw::Affine<P>,
                       c5: &sw::Affine<P>,
                       c6: &sw::Affine<P>) {

        ZKAttestECPointAdditionTranscript::domain_sep(transcript);
        
        let mut compressed_bytes = Vec::new();
        c1.serialize_compressed(&mut compressed_bytes).unwrap();
        ZKAttestECPointAdditionTranscript::append_point(transcript, b"C1", &compressed_bytes[..]);
        
        c2.serialize_compressed(&mut compressed_bytes).unwrap();
        ZKAttestECPointAdditionTranscript::append_point(transcript, b"C2", &compressed_bytes[..]);

        c3.serialize_compressed(&mut compressed_bytes).unwrap();
        ZKAttestECPointAdditionTranscript::append_point(transcript, b"C3", &compressed_bytes[..]);
        
        c4.serialize_compressed(&mut compressed_bytes).unwrap();
        ZKAttestECPointAdditionTranscript::append_point(transcript, b"C4", &compressed_bytes[..]);

        c5.serialize_compressed(&mut compressed_bytes).unwrap();
        ZKAttestECPointAdditionTranscript::append_point(transcript, b"C5", &compressed_bytes[..]);

        c6.serialize_compressed(&mut compressed_bytes).unwrap();
        ZKAttestECPointAdditionTranscript::append_point(transcript, b"C6", &compressed_bytes[..]);        
    }

    fn make_commitment<T: RngCore + CryptoRng> (val: <<P as PedersenConfig>::OCurve as CurveConfig>::BaseField, rng: &mut T) -> PedersenComm<P> {
        let val_p = <P as PedersenConfig>::from_ob_to_sf(val);
        PedersenComm::new(val_p, rng)
    }

    pub fn create<T: RngCore + CryptoRng>(transcript: &mut Transcript,
                                          rng: &mut T,
                                          a_x: <<P as PedersenConfig>::OCurve as CurveConfig>::BaseField,
                                          a_y: <<P as PedersenConfig>::OCurve as CurveConfig>::BaseField,
                                          b_x: <<P as PedersenConfig>::OCurve as CurveConfig>::BaseField,
                                          b_y: <<P as PedersenConfig>::OCurve as CurveConfig>::BaseField,
                                          t_x: <<P as PedersenConfig>::OCurve as CurveConfig>::BaseField,
                                          t_y: <<P as PedersenConfig>::OCurve as CurveConfig>::BaseField) -> Self {
        // Commit to each of the co-ordinate pairs.                
        let c1 = Self::make_commitment(a_x, rng);
        let c2 = Self::make_commitment(a_y, rng);
        let c3 = Self::make_commitment(b_x, rng);
        let c4 = Self::make_commitment(b_y, rng);
        let c5 = Self::make_commitment(t_x, rng);
        let c6 = Self::make_commitment(t_y, rng);

        Self::make_transcript(transcript, &c1.comm, &c2.comm, &c3.comm, &c4.comm, &c5.comm, &c6.comm);

        // Now make the proof that there's an inverse for b_x - a_x.
        let z1 = <P as PedersenConfig>::from_ob_to_sf(b_x - a_x);
        let z2 = <P as PedersenConfig>::from_ob_to_sf((b_x - a_x).inverse().unwrap());
        
        let c7 = &c3 - &c1;
        let c8 = PedersenComm::new(z2, rng);
        
        // Make the multiplication proof for c8.
        let commit_one = PedersenComm{comm: <P as SWCurveConfig>::GENERATOR, r: <P as CurveConfig>::ScalarField::ZERO};
        let mp1 = MulProof::create(transcript, rng, &z1, &z2, &c7, &c8, &commit_one);

        // Proof of c10
        let z3 = <P as PedersenConfig>::from_ob_to_sf(b_y - a_y);                    
        let c9 = &c4 - &c2;

        let z4 = z3 * z2; // b_y - a_y / b_x - a_x
        let c10 = PedersenComm::new(z4, rng);

        let mp2 = MulProof::create(transcript, rng, &z3, &z2, &c9, &c8, &c10);
        
        // Proof of c11
        let z5 = z4 * z4;  
        let c11 = PedersenComm::new(z5, rng);
        let mp3 = MulProof::create(transcript, rng, &z4, &z4, &c10, &c10, &c11);

        // Proof of c13.
        let z6 = <P as PedersenConfig>::from_ob_to_sf(a_x - t_x);
        let c12 = &c1 - &c5;
        
        let z7 = z4 * z6; // z4 = b_y - a_y / (b_x - a_x), z6 = (a_x - t_x)
        let c13 = PedersenComm::new(z7, rng);

        let mp4 = MulProof::create(transcript, rng, &z4, &z6, &c10, &c12, &c13);

        // And now the remaining equality proofs.
        let c14 = &c5 + &c1 + &c3;
        let eq1 = EqualityProof::create(transcript, rng, &c14, &c11);

        // This is the corrected one.
        let c15 = &c6 + &c2;
        let eq2 = EqualityProof::create(transcript, rng, &c13, &c15);

        Self { c1: c1.comm, c2: c2.comm, c3: c3.comm, c4: c4.comm, c5: c5.comm, c6: c6.comm, c8: c8.comm, c10: c10.comm,               
               c11: c11.comm, c13: c13.comm, mp1: mp1, mp2: mp2, mp3: mp3, mp4: mp4, e1: eq1, e2: eq2}

    }

    pub fn verify(&self, transcript: &mut Transcript) -> bool {
        // This function just needs to verify that everything else works as it should.
        Self::make_transcript(transcript, &self.c1, &self.c2, &self.c3, &self.c4, &self.c5, &self.c6);

        // Check that the multiplication proof holds for proving that c7 * c8 == 1
        // We recover c7 as c3 - c1
        let c7 = (self.c3.into_group() - self.c1).into_affine();        

        // Now we verify that c8 * c7 is a commitment to 1.
        // N.B We use the same fixed commitment to 1 as above.
        let commit_one = PedersenComm{comm: <P as SWCurveConfig>::GENERATOR, r: <P as CurveConfig>::ScalarField::ZERO};
        let first = self.mp1.verify(transcript, &c7, &self.c8, &commit_one.comm);

        // Proof of c10 = c9 * c10.
        // We recover c9 as c4 - c2.
        let c9 = (self.c4.into_group() - self.c2).into_affine();
        let second = self.mp2.verify(transcript, &c9, &self.c8, &self.c10);

        // Proof of c11 = c10*c10
        let third = self.mp3.verify(transcript, &self.c10, &self.c10, &self.c11);

        // Proof of c13 = c10 * c12.
        // We recover c12 as c1 - c5
        let c12 = (self.c1.into_group() - self.c5).into_affine();
        let fourth = self.mp4.verify(transcript, &self.c10, &c12, &self.c13);

        // Verify that c5 + c1 + c3 == c11
        let c14 = (self.c5 + self.c1 + self.c3).into_affine();
        let fifth = self.e1.verify(transcript, &c14, &self.c11);

        // Verify that c13 == c6 + c2.
        let c15 = (self.c6 + self.c2).into_affine();
        let sixth = self.e2.verify(transcript, &self.c13, &c15);        
        first && second && third && fourth && fifth && sixth
    }    
}
     
