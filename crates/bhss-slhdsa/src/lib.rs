//! CRYPTO-1..CRYPTO-3: the only signature scheme for new outputs is
//! SLH-DSA-SHA2-128s with the FIPS 205 *pure* interface and an empty context
//! string. Public key = 32 bytes, signature = 7 856 bytes, secret key = 64 bytes.

use bhss_primitives::types::{SLH_PUBKEY_LEN, SLH_SIG_LEN};
use slh_dsa::{Sha2_128s, Signature, SigningKey, VerifyingKey};

pub const SECRET_KEY_LEN: usize = 64;

#[derive(Clone)]
pub struct SecretKey(SigningKey<Sha2_128s>);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicKey(pub [u8; SLH_PUBKEY_LEN]);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlhError;

impl SecretKey {
    pub fn generate(rng: &mut impl rand_core::CryptoRngCore) -> Self {
        Self(SigningKey::new(rng))
    }
    /// Deterministic key from three 16-byte seeds (FIPS 205 slh_keygen_internal).
    pub fn from_seeds(sk_seed: &[u8; 16], sk_prf: &[u8; 16], pk_seed: &[u8; 16]) -> Self {
        Self(SigningKey::slh_keygen_internal(sk_seed, sk_prf, pk_seed))
    }
    pub fn from_bytes(b: &[u8]) -> Result<Self, SlhError> {
        if b.len() != SECRET_KEY_LEN {
            return Err(SlhError);
        }
        SigningKey::try_from(b).map(Self).map_err(|_| SlhError)
    }
    pub fn to_bytes(&self) -> [u8; SECRET_KEY_LEN] {
        let v = self.0.to_vec();
        let mut out = [0u8; SECRET_KEY_LEN];
        out.copy_from_slice(&v);
        out
    }
    pub fn public_key(&self) -> PublicKey {
        let vk: &VerifyingKey<Sha2_128s> = self.0.as_ref();
        let v = vk.to_vec();
        let mut out = [0u8; SLH_PUBKEY_LEN];
        out.copy_from_slice(&v);
        PublicKey(out)
    }
    /// Deterministic signature (CRYPTO-2: pure mode, empty context, no randomizer).
    pub fn sign(&self, msg: &[u8]) -> alloc::vec::Vec<u8> {
        let sig: Signature<Sha2_128s> = self.0.try_sign_with_context(msg, &[], None).expect("empty ctx fits");
        sig.to_vec()
    }
}

impl PublicKey {
    pub fn from_bytes(b: &[u8]) -> Result<Self, SlhError> {
        let arr: [u8; SLH_PUBKEY_LEN] = b.try_into().map_err(|_| SlhError)?;
        Ok(Self(arr))
    }
    /// CRYPTO-3: verify a pure-mode signature with empty context.
    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        if sig.len() != SLH_SIG_LEN {
            return false;
        }
        let vk = match VerifyingKey::<Sha2_128s>::try_from(&self.0[..]) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let sig = match Signature::<Sha2_128s>::try_from(sig) {
            Ok(s) => s,
            Err(_) => return false,
        };
        vk.try_verify_with_context(msg, &[], &sig).is_ok()
    }
    pub fn hash(&self) -> bhss_primitives::Hash32 {
        bhss_primitives::types::slh_pubkey_hash(&self.0)
    }
}

extern crate alloc;

/// Verify with raw bytes (used by consensus).
pub fn verify(pubkey: &[u8; SLH_PUBKEY_LEN], msg: &[u8], sig: &[u8]) -> bool {
    PublicKey(*pubkey).verify(msg, sig)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip() {
        let sk = SecretKey::from_seeds(&[1u8; 16], &[2u8; 16], &[3u8; 16]);
        let pk = sk.public_key();
        let sig = sk.sign(b"hello");
        assert_eq!(sig.len(), SLH_SIG_LEN);
        assert!(pk.verify(b"hello", &sig));
        assert!(!pk.verify(b"hellp", &sig));
        let sk2 = SecretKey::from_bytes(&sk.to_bytes()).unwrap();
        assert_eq!(sk2.public_key(), pk);
        // deterministic
        assert_eq!(sk2.sign(b"hello"), sig);
    }
}
