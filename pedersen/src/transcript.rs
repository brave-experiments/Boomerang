//! Declares a series of transcript types for Merlin transcripts.
//! WARNING: This trait differs slightly from how Merlin defines the same traits. Essentially, rather than
//! re-instantiating this type for each different point type that we use, we simply traffic bytes in and out for e.g
//! appending points or producing challenges. It is the responsibility of the caller to realise this functionality.

use merlin::Transcript;

pub const CHALLENGE_SIZE: usize = 64;

pub trait EqualityTranscript {
    /// Append a domain separator.
    fn domain_sep(&mut self);

    /// Append a point.
    fn append_point(&mut self, label: &'static [u8], point: &[u8]);

    /// Produce the challenge.
    fn challenge_scalar(&mut self, label: &'static [u8]) -> [u8; CHALLENGE_SIZE];
}

impl EqualityTranscript for Transcript {
    fn domain_sep(&mut self) {
        self.append_message(b"dom-sep", b"equality-proof")
    }

    fn append_point(&mut self, label: &'static [u8], point: &[u8]) {
        self.append_message(label, point);
    }

    fn challenge_scalar(&mut self, label: &'static [u8]) -> [u8; CHALLENGE_SIZE] {
        let mut buf = [0u8; CHALLENGE_SIZE];
        self.challenge_bytes(label, &mut buf);
        buf
    }
}

pub trait OpeningTranscript {
    /// Append a domain separator.
    fn domain_sep(&mut self);

    /// Append a point.
    fn append_point(&mut self, label: &'static [u8], point: &[u8]);

    /// Produce the challenge.
    fn challenge_scalar(&mut self, label: &'static [u8]) -> [u8; CHALLENGE_SIZE];
}

impl OpeningTranscript for Transcript {
    fn domain_sep(&mut self) {
        self.append_message(b"dom-sep", b"open-proof")
    }

    fn append_point(&mut self, label: &'static [u8], point: &[u8]) {
        self.append_message(label, point);
    }

    fn challenge_scalar(&mut self, label: &'static [u8]) -> [u8; CHALLENGE_SIZE] {
        let mut buf = [0u8; CHALLENGE_SIZE];
        self.challenge_bytes(label, &mut buf);
        buf
    }
}

pub trait MulTranscript {
    /// Append a domain separator.
    fn domain_sep(&mut self);

    /// Append a point.
    fn append_point(&mut self, label: &'static [u8], point: &[u8]);

    /// Produce the challenge.
    fn challenge_scalar(&mut self, label: &'static [u8]) -> [u8; CHALLENGE_SIZE];
}

impl MulTranscript for Transcript {
    fn domain_sep(&mut self) {
        self.append_message(b"dom-sep", b"mul-proof")
    }

    fn append_point(&mut self, label: &'static [u8], point: &[u8]) {
        self.append_message(label, point);
    }

    fn challenge_scalar(&mut self, label: &'static [u8]) -> [u8; CHALLENGE_SIZE] {
        let mut buf = [0u8; CHALLENGE_SIZE];
        self.challenge_bytes(label, &mut buf);
        buf
    }
}

pub trait ECPointAdditionTranscript {
    /// Append a domain separator.
    fn domain_sep(&mut self);

    /// Append a point.
    fn append_point(&mut self, label: &'static [u8], point: &[u8]);

    /// Produce the challenge.
    fn challenge_scalar(&mut self, label: &'static [u8]) -> [u8; CHALLENGE_SIZE];
}

impl ECPointAdditionTranscript for Transcript {
    fn domain_sep(&mut self) {
        self.append_message(b"dom-sep", b"ec-point-addition-proof");
    }

    fn append_point(&mut self, label: &'static [u8], point: &[u8]) {
        self.append_message(label, point);
    }

    fn challenge_scalar(&mut self, label: &'static [u8]) -> [u8; CHALLENGE_SIZE] {
        let mut buf = [0u8; CHALLENGE_SIZE];
        self.challenge_bytes(label, &mut buf);
        buf
    }
}

pub trait ZKAttestECPointAdditionTranscript {
    /// Append a domain separator.
    fn domain_sep(&mut self);

    /// Append a point.
    fn append_point(&mut self, label: &'static [u8], point: &[u8]);

    /// Produce the challenge.
    fn challenge_scalar(&mut self, label: &'static [u8]) -> [u8; CHALLENGE_SIZE];
}

impl ZKAttestECPointAdditionTranscript for Transcript {
    fn domain_sep(&mut self) {
        self.append_message(b"dom-sep", b"zk-attest-ec-point-addition-proof");
    }

    fn append_point(&mut self, label: &'static [u8], point: &[u8]) {
        self.append_message(label, point);
    }

    fn challenge_scalar(&mut self, label: &'static [u8]) -> [u8; CHALLENGE_SIZE] {
        let mut buf = [0u8; 64];
        self.challenge_bytes(label, &mut buf);
        buf
    }
}
pub trait ECScalarMulTranscript {
    /// Append a domain separator.
    fn domain_sep(&mut self);

    /// Append a point.
    fn append_point(&mut self, label: &'static [u8], point: &[u8]);

    /// Produce the challenge.
    fn challenge_scalar(&mut self, label: &'static [u8]) -> [u8; CHALLENGE_SIZE];
}

impl ECScalarMulTranscript for Transcript {
    fn domain_sep(&mut self) {
        self.append_message(b"dom-sep", b"ec-point-scalar-addition-proof");
    }

    fn append_point(&mut self, label: &'static [u8], point: &[u8]) {
        self.append_message(label, point);
    }

    fn challenge_scalar(&mut self, label: &'static [u8]) -> [u8; CHALLENGE_SIZE] {
        let mut buf = [0u8; CHALLENGE_SIZE];
        self.challenge_bytes(label, &mut buf);
        buf
    }
}

pub trait FSECScalarMulTranscript {
    /// Append a domain separator.
    fn domain_sep(&mut self);

    /// Append a point.
    fn append_point(&mut self, label: &'static [u8], point: &[u8]);

    /// Produce the challenge.
    /// N.B 16 byte challenge -> 128 bits.
    fn challenge_scalar(&mut self, label: &'static [u8]) -> [u8; 16];
}

impl FSECScalarMulTranscript for Transcript {
    fn domain_sep(&mut self) {
        self.append_message(b"dom-sep", b"fs-ec-point-scalar-addition-proof");
    }

    fn append_point(&mut self, label: &'static [u8], point: &[u8]) {
        self.append_message(label, point);
    }

    fn challenge_scalar(&mut self, label: &'static [u8]) -> [u8; 16] {
        let mut buf = [0u8; 16];
        self.challenge_bytes(label, &mut buf);
        buf
    }
}
