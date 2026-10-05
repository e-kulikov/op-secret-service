//! Secret Service session encryption: `plain` and
//! `dh-ietf1024-sha256-aes128-cbc-pkcs7`.

use aes::Aes128;
use cbc::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit, block_padding::Pkcs7};
use hkdf::Hkdf;
use num_bigint::BigUint;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::{Error, Result};

pub const ALGORITHM_PLAIN: &str = "plain";
pub const ALGORITHM_DH: &str = "dh-ietf1024-sha256-aes128-cbc-pkcs7";

/// Second Oakley Group (RFC 2409, 1024 bits); the generator is 2.
const PRIME_HEX: &str = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF";
const PRIME_LEN: usize = 128;

fn prime() -> BigUint {
    BigUint::parse_bytes(PRIME_HEX.as_bytes(), 16).expect("valid prime constant")
}

fn random_bytes<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes)
        .map_err(|error| Error::Internal(format!("random source: {error}")))?;
    Ok(bytes)
}

fn to_fixed_be(value: &BigUint) -> Vec<u8> {
    let bytes = value.to_bytes_be();
    let mut out = vec![0u8; PRIME_LEN - bytes.len()];
    out.extend_from_slice(&bytes);
    out
}

/// One side of the Diffie-Hellman exchange.
pub struct DhKeypair {
    private: BigUint,
    pub public: Vec<u8>,
}

impl DhKeypair {
    pub fn generate() -> Result<Self> {
        let p = prime();
        let private = BigUint::from_bytes_be(&random_bytes::<PRIME_LEN>()?) % (&p - 3u8) + 2u8;
        let public = to_fixed_be(&BigUint::from(2u8).modpow(&private, &p));
        Ok(Self { private, public })
    }

    /// Derives the AES key from the peer's public value.
    pub fn derive_key(&self, peer_public: &[u8]) -> Result<Zeroizing<[u8; 16]>> {
        let p = prime();
        let peer = BigUint::from_bytes_be(peer_public);
        if peer <= BigUint::from(1u8) || peer >= &p - 1u8 {
            return Err(Error::Invalid("peer public key is out of range".into()));
        }
        let shared = Zeroizing::new(to_fixed_be(&peer.modpow(&self.private, &p)));
        let mut key = Zeroizing::new([0u8; 16]);
        Hkdf::<Sha256>::new(None, &shared)
            .expand(&[], key.as_mut())
            .map_err(|error| Error::Internal(format!("key derivation: {error}")))?;
        Ok(key)
    }
}

/// The cipher negotiated for one session.
pub enum SessionCipher {
    Plain,
    Aes(Zeroizing<[u8; 16]>),
}

/// Result of `OpenSession`: the cipher and the bytes sent back to the client.
pub struct Negotiated {
    pub cipher: SessionCipher,
    pub output: Vec<u8>,
}

/// Negotiates a session for `algorithm`; `input` is the client's variant payload as bytes.
pub fn negotiate(algorithm: &str, input: &[u8]) -> Result<Negotiated> {
    match algorithm {
        ALGORITHM_PLAIN => Ok(Negotiated {
            cipher: SessionCipher::Plain,
            output: Vec::new(),
        }),
        ALGORITHM_DH => {
            let server = DhKeypair::generate()?;
            let key = server.derive_key(input)?;
            Ok(Negotiated {
                cipher: SessionCipher::Aes(key),
                output: server.public,
            })
        }
        other => Err(Error::NotSupported(format!("session algorithm `{other}`"))),
    }
}

impl SessionCipher {
    /// Returns `(parameters, value)` for a `Secret` structure.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        match self {
            SessionCipher::Plain => Ok((Vec::new(), plaintext.to_vec())),
            SessionCipher::Aes(key) => {
                let iv = random_bytes::<16>()?;
                let value = cbc::Encryptor::<Aes128>::new(&(**key).into(), &iv.into())
                    .encrypt_padded_vec::<Pkcs7>(plaintext);
                Ok((iv.to_vec(), value))
            }
        }
    }

    pub fn decrypt(&self, parameters: &[u8], value: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        match self {
            SessionCipher::Plain => Ok(Zeroizing::new(value.to_vec())),
            SessionCipher::Aes(key) => {
                let iv: [u8; 16] = parameters
                    .try_into()
                    .map_err(|_| Error::Invalid("initialization vector must be 16 bytes".into()))?;
                cbc::Decryptor::<Aes128>::new(&(**key).into(), &iv.into())
                    .decrypt_padded_vec::<Pkcs7>(value)
                    .map(Zeroizing::new)
                    .map_err(|_| Error::Invalid("secret could not be decrypted".into()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prime_is_a_1024_bit_probable_prime() {
        let p = prime();
        assert_eq!(p.bits(), 1024);
        assert_eq!(
            BigUint::from(2u8).modpow(&(&p - 1u8), &p),
            BigUint::from(1u8)
        );
    }

    #[test]
    fn plain_session_passes_data_through() {
        let negotiated = negotiate(ALGORITHM_PLAIN, b"").unwrap();
        assert!(negotiated.output.is_empty());
        let (parameters, value) = negotiated.cipher.encrypt(b"secret").unwrap();
        assert!(parameters.is_empty());
        assert_eq!(
            &*negotiated.cipher.decrypt(&parameters, &value).unwrap(),
            b"secret"
        );
    }

    #[test]
    fn dh_client_and_server_derive_the_same_key() {
        let client = DhKeypair::generate().unwrap();
        let negotiated = negotiate(ALGORITHM_DH, &client.public).unwrap();
        let client_cipher = SessionCipher::Aes(client.derive_key(&negotiated.output).unwrap());

        let (iv, value) = client_cipher.encrypt(b"top secret").unwrap();
        assert_eq!(iv.len(), 16);
        assert_ne!(value, b"top secret");
        assert_eq!(
            &*negotiated.cipher.decrypt(&iv, &value).unwrap(),
            b"top secret"
        );

        let (iv, value) = negotiated.cipher.encrypt(b"").unwrap();
        assert_eq!(value.len(), 16, "empty plaintext still pads to one block");
        assert!(client_cipher.decrypt(&iv, &value).unwrap().is_empty());
    }

    #[test]
    fn dh_rejects_degenerate_public_keys() {
        assert!(negotiate(ALGORITHM_DH, &[]).is_err());
        assert!(negotiate(ALGORITHM_DH, &[1]).is_err());
        let p_minus_one = to_fixed_be(&(prime() - 1u8));
        assert!(negotiate(ALGORITHM_DH, &p_minus_one).is_err());
        assert!(negotiate(ALGORITHM_DH, &to_fixed_be(&prime())).is_err());
    }

    #[test]
    fn dh_decrypt_rejects_bad_input() {
        let client = DhKeypair::generate().unwrap();
        let negotiated = negotiate(ALGORITHM_DH, &client.public).unwrap();
        assert!(negotiated.cipher.decrypt(&[0u8; 3], &[0u8; 16]).is_err());
        assert!(negotiated.cipher.decrypt(&[0u8; 16], &[0u8; 5]).is_err());
        assert!(negotiated.cipher.decrypt(&[0u8; 16], &[0u8; 16]).is_err());
    }

    #[test]
    fn unknown_algorithm_is_not_supported() {
        let error = negotiate("rot13", b"").err().unwrap();
        assert!(matches!(error, Error::NotSupported(_)));
    }
}
