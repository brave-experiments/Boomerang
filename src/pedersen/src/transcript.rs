//! Declares a series of transcript types for Merlin transcripts.
//! WARNING: This trait differs slightly from how Merlin defines the same traits. Essentially, rather than
//! re-instantiating this type for each different point type that we use, we simply traffic bytes in and out for e.g
//! appending points or producing challenges. It is the responsibility of the caller to realise this functionality.

use merlin::Transcript;

pub trait EqualityTranscript {
    /// Append a domain separator.
    fn domain_sep(&mut self);

    /// Append a point.
    fn append_point(&mut self, label: &'static[u8], point: &[u8]);

    /// Produce the challenge.
    fn challenge_scalar(&mut self, label: &'static[u8]) -> [u8; 64];
}

impl EqualityTranscript for Transcript {
    fn domain_sep(&mut self) {
        self.append_message(b"dom-sep", b"equality-proof")
    }

    fn append_point(&mut self, label: &'static[u8], point: &[u8]) {
        self.append_message(label, point);
    }

    fn challenge_scalar(&mut self, label: &'static[u8]) -> [u8; 64] {
        let mut buf = [0u8; 64];
        self.challenge_bytes(label, &mut buf);
        buf
    }
}


pub trait OpeningTranscript {
    /// Append a domain separator.
    fn domain_sep(&mut self);

    /// Append a point.
    fn append_point(&mut self, label: &'static[u8], point: &[u8]);

    /// Produce the challenge.
    fn challenge_scalar(&mut self, label: &'static[u8]) -> [u8; 64];
}

impl OpeningTranscript for Transcript {
    fn domain_sep(&mut self) {
        self.append_message(b"dom-sep", b"open-proof")
    }

    fn append_point(&mut self, label: &'static[u8], point: &[u8]) {
        self.append_message(label, point);
    }

    fn challenge_scalar(&mut self, label: &'static[u8]) -> [u8; 64] {
        let mut buf = [0u8; 64];
        self.challenge_bytes(label, &mut buf);
        buf
    }
}

pub trait MulTranscript {
    /// Append a domain separator.
    fn domain_sep(&mut self);

    /// Append a point.
    fn append_point(&mut self, label: &'static[u8], point: &[u8]);

    /// Produce the challenge.
    fn challenge_scalar(&mut self, label: &'static[u8]) -> [u8; 64];
}

impl MulTranscript for Transcript {
    fn domain_sep(&mut self) {
        self.append_message(b"dom-sep", b"mul-proof")
    }

    fn append_point(&mut self, label: &'static[u8], point: &[u8]) {
        self.append_message(label, point);
    }

    fn challenge_scalar(&mut self, label: &'static[u8]) -> [u8; 64] {
        let mut buf = [0u8; 64];
        self.challenge_bytes(label, &mut buf);
        buf
    }
}

pub trait ECPointAdditionTranscript {

    /// Append a domain separator.
    fn domain_sep(&mut self);

    /// Append a point.
    fn append_point(&mut self, label: &'static[u8], point: &[u8]);

    /// Produce the challenge.
    fn challenge_scalar(&mut self, label: &'static[u8]) -> [u8; 64];
}

impl ECPointAdditionTranscript for Transcript {

    fn domain_sep(&mut self) {
        self.append_message(b"dom-sep", b"ec-point-addition-proof");        
    }

    fn append_point(&mut self, label: &'static[u8], point: &[u8]) {
        self.append_message(label, point);
    }

    fn challenge_scalar(&mut self, label: &'static[u8]) -> [u8; 64] {
        let mut buf = [0u8; 64];
        self.challenge_bytes(label, &mut buf);
        buf
    }
}
