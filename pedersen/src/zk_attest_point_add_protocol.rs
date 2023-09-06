//! Defines a point addition protocol using ZKAttest's proof of point addition.
//! Note that this particular implementation is defined in the same way as the ZKAttest implementation, and not as per the ZKAttest paper.

use merlin::Transcript;
use ark_ec::{
    CurveConfig,
};

use ark_serialize::{CanonicalSerialize};
use ark_ff::fields::Field;
use rand::{RngCore, CryptoRng};

use crate::{pedersen_config::PedersenConfig, pedersen_config::PedersenComm, transcript::ECPointAdditionTranscript, mul_protocol::MulProof, opening_protocol::OpeningProof, transcript::ZKAttestECPointAdditionTranscript};

pub struct ZKAttestPointAddProof<P:PedersenConfig> {
    /// c1: the commitment to a_x.
    pub c1: PedersenComm<P>,
    /// c2: the commitment to a_y.
    pub c2: PedersenComm<P>,
    /// c3: the commitment to b_x.
    pub c3: PedersenComm<P>,
    /// c4: the commitment to b_y.
    pub c4: PedersenComm<P>,
    /// c5: the commitment to t_x.
    pub c5: PedersenComm<P>,
    /// c6: the commitment to t_y.
    pub c6: PedersenComm<P>,

    // We do not need c7: Pedersen Commitments are additively
    // homomorphic.
    //pub c7 : PedersenComm<P>,
    
    /// c8: the commitment to (b_x - a_x)^-1
    pub c8 : PedersenComm<P>,

    // pub c9 : PedersenComm<P>

    /// c10: the commitment to (b_y - a_y) / (b_x - a_x).
    pub c10 : PedersenComm<P>,

    /// c11: the commitment to ((b_y - a_y) / (b_x - a_x))^2
    pub c11 : PedersenComm<P>,

    // pub c12: PedersenComm<P>,

    /// c13: the commitment to (b_y - a_y)/(b_x-a_x) *
    /// (a_x-t_x)
    pub c13 : PedersenComm<P>,

    pub mp1 : MulProof<P>,        
}

impl <P: PedersenConfig> ZKAttestPointAddProof<P> {

    fn make_transcript(transcript: &mut Transcript,
                       c1: &PedersenComm<P>,
                       c2: &PedersenComm<P>,
                       c3: &PedersenComm<P>,
                       c4: &PedersenComm<P>,
                       c5: &PedersenComm<P>,
                       c6: &PedersenComm<P>) {

        ZKAttestECPointAdditionTranscript::domain_sep(transcript);
        
        let mut compressed_bytes = Vec::new();
        c1.comm.serialize_compressed(&mut compressed_bytes).unwrap();
        ZKAttestECPointAdditionTranscript::append_point(transcript, b"C1", &compressed_bytes[..]);
        
        c2.comm.serialize_compressed(&mut compressed_bytes).unwrap();
        ZKAttestECPointAdditionTranscript::append_point(transcript, b"C2", &compressed_bytes[..]);

        c3.comm.serialize_compressed(&mut compressed_bytes).unwrap();
        ZKAttestECPointAdditionTranscript::append_point(transcript, b"C3", &compressed_bytes[..]);
        
        c4.comm.serialize_compressed(&mut compressed_bytes).unwrap();
        ZKAttestECPointAdditionTranscript::append_point(transcript, b"C4", &compressed_bytes[..]);

        c5.comm.serialize_compressed(&mut compressed_bytes).unwrap();
        ZKAttestECPointAdditionTranscript::append_point(transcript, b"C5", &compressed_bytes[..]);

        c6.comm.serialize_compressed(&mut compressed_bytes).unwrap();
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

        Self::make_transcript(transcript, &c1, &c2, &c3, &c4, &c5, &c6);


        // Now make the proof that there's an inverse for b_x - a_x.
        let z1 = <P as PedersenConfig>::from_ob_to_sf(b_x - a_x);
        let z2 = <P as PedersenConfig>::from_ob_to_sf((b_x - a_x).inverse().unwrap());
        
        let c7 = &c3 - &c1;
        let c8 = PedersenComm::new(z2, rng);
        
        // Make the multiplication proof for c8.
        let commit_one = PedersenComm::new(<P as CurveConfig>::ScalarField::ONE, rng);        
        let mp1 = MulProof::create(transcript, rng, &z1, &z2, &c7, &c8, &commit_one);

        // Proof of C10
        let z3 = <P as PedersenConfig>::from_ob_to_sf(b_y - a_y);
        let c9 = PedersenComm::new(z3, rng);        
        let z4 = z3 * z2;
        let c10 = PedersenComm::new(z4, rng);
        let mp2 = MulProof::create(transcript, rng, &z3, &z4, &c8, &c9, &c10);

        // Proof of c11
        let z5 = z4 * z4;
        let c11 = PedersenComm::new(z5, rng);
        let mp3 = MulProof::create(transcript, rng, &z4, &z4, &c10, &c10, &c11);

        // Proof of c13.
        let z6 = <P as PedersenConfig>::from_ob_to_sf(b_x - t_x);
        let c12 = PedersenComm::new(z6, rng);
        let z7 = z4 * z6;
        let c13 = PedersenComm::new(z7, rng);

        let mp4 = MulProof::create(transcript, rng, &z4, &z6, &c10, &c12, &c13);

        // 
        
    }    
}
     
