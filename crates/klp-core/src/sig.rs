//! Manifest signatures in minisign format (Ed25519, prehashed with
//! BLAKE2b-512).
//!
//! Verification uses `minisign-verify`, so any signature made with the
//! standard `minisign -S` tool (also from an offline machine or a signing
//! runner) is accepted. The optional `sign` feature contains a small
//! compatible signer for CI and tests.

use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use minisign_verify::{PublicKey, Signature};

/// A named public key from the trust store.
pub struct TrustedKey {
    pub name: String,
    pub key: PublicKey,
    pub key_id: String,
}

/// Set of trusted manifest keys, normally `/etc/pve-klp/trusted.d/*.pub`.
///
/// Several keys may be trusted at the same time; that is how rotation
/// works: ship the new key, sign with it, remove the old key later.
#[derive(Default)]
pub struct TrustStore {
    keys: Vec<TrustedKey>,
}

impl TrustStore {
    pub fn load_dir(dir: &Path) -> Result<Self> {
        let mut store = TrustStore::default();
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(store),
            Err(e) => return Err(e).with_context(|| format!("reading {}", dir.display())),
        };
        let mut paths: Vec<_> = entries
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|x| x == "pub"))
            .collect();
        paths.sort();
        for p in paths {
            let text = std::fs::read_to_string(&p).with_context(|| format!("reading {}", p.display()))?;
            let name = p.file_stem().unwrap_or_default().to_string_lossy().into_owned();
            store.add(&name, &text).with_context(|| format!("parsing public key {}", p.display()))?;
        }
        Ok(store)
    }

    /// Add a key given as minisign public key file content or bare base64.
    pub fn add(&mut self, name: &str, text: &str) -> Result<()> {
        let b64 = text
            .lines()
            .map(str::trim)
            .find(|l| !l.is_empty() && !l.starts_with("untrusted comment:"))
            .ok_or_else(|| anyhow!("empty public key"))?;
        let raw = B64.decode(b64).context("public key is not base64")?;
        if raw.len() != 42 || &raw[..2] != b"Ed" {
            bail!("not a minisign Ed25519 public key");
        }
        let key_id = key_id_hex(&raw[2..10]);
        let key = PublicKey::from_base64(b64).map_err(|e| anyhow!("{e}"))?;
        self.keys.push(TrustedKey { name: name.to_owned(), key, key_id });
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    pub fn keys(&self) -> impl Iterator<Item = &TrustedKey> {
        self.keys.iter()
    }

    /// Verify `data` against a minisign signature. Returns the name of the
    /// key that signed it. Legacy (non-prehashed) signatures are rejected.
    pub fn verify(&self, data: &[u8], signature_text: &str) -> Result<&TrustedKey> {
        if self.keys.is_empty() {
            bail!("no trusted keys configured");
        }
        let sig = Signature::decode(signature_text).map_err(|e| anyhow!("malformed signature: {e}"))?;
        for k in &self.keys {
            if k.key.verify(data, &sig, false).is_ok() {
                return Ok(k);
            }
        }
        bail!("signature does not verify against any trusted key")
    }
}

/// minisign prints key ids as the little-endian 64-bit number in upper hex.
fn key_id_hex(keynum: &[u8]) -> String {
    keynum.iter().rev().map(|b| format!("{b:02X}")).collect()
}

#[cfg(feature = "sign")]
pub use signer::SecretKey;

#[cfg(feature = "sign")]
mod signer {
    use super::*;
    use blake2::{Blake2b512, Digest};
    use ed25519_dalek::{Signer, SigningKey};

    const SECRET_HEADER: &str = "pve-klp secret key v1";

    /// Unencrypted Ed25519 key in a tiny own format. Meant for CI signing
    /// runners and tests; for an offline or hardware-backed key use the
    /// standard `minisign` tool, the agent accepts both.
    pub struct SecretKey {
        keynum: [u8; 8],
        signing: SigningKey,
    }

    impl SecretKey {
        pub fn generate() -> Result<Self> {
            let mut buf = [0u8; 40];
            fill_random(&mut buf)?;
            let mut keynum = [0u8; 8];
            keynum.copy_from_slice(&buf[..8]);
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&buf[8..]);
            Ok(Self { keynum, signing: SigningKey::from_bytes(&seed) })
        }

        pub fn from_seed(keynum: [u8; 8], seed: [u8; 32]) -> Self {
            Self { keynum, signing: SigningKey::from_bytes(&seed) }
        }

        pub fn to_file_string(&self) -> String {
            let mut raw = self.keynum.to_vec();
            raw.extend_from_slice(&self.signing.to_bytes());
            format!("{SECRET_HEADER}\n{}\n", B64.encode(raw))
        }

        pub fn from_file_string(s: &str) -> Result<Self> {
            let mut lines = s.lines();
            if lines.next().map(str::trim) != Some(SECRET_HEADER) {
                bail!("not a pve-klp secret key");
            }
            let raw = B64.decode(lines.next().unwrap_or_default().trim()).context("secret key is not base64")?;
            if raw.len() != 40 {
                bail!("secret key has wrong length");
            }
            let mut keynum = [0u8; 8];
            keynum.copy_from_slice(&raw[..8]);
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&raw[8..]);
            Ok(Self::from_seed(keynum, seed))
        }

        pub fn key_id(&self) -> String {
            key_id_hex(&self.keynum)
        }

        /// minisign-compatible public key file.
        pub fn public_key_file(&self) -> String {
            let mut raw = b"Ed".to_vec();
            raw.extend_from_slice(&self.keynum);
            raw.extend_from_slice(self.signing.verifying_key().as_bytes());
            format!("untrusted comment: minisign public key {}\n{}\n", self.key_id(), B64.encode(raw))
        }

        /// minisign-compatible prehashed signature file.
        pub fn sign(&self, data: &[u8], trusted_comment: &str) -> Result<String> {
            if trusted_comment.contains('\n') || trusted_comment.contains('\r') {
                bail!("trusted comment must be a single line");
            }
            let digest = Blake2b512::digest(data);
            let sig = self.signing.sign(&digest).to_bytes();
            let mut global_msg = sig.to_vec();
            global_msg.extend_from_slice(trusted_comment.as_bytes());
            let global = self.signing.sign(&global_msg).to_bytes();

            let mut sig_box = b"ED".to_vec();
            sig_box.extend_from_slice(&self.keynum);
            sig_box.extend_from_slice(&sig);
            Ok(format!(
                "untrusted comment: signature from pve-klp key {}\n{}\ntrusted comment: {}\n{}\n",
                self.key_id(),
                B64.encode(sig_box),
                trusted_comment,
                B64.encode(global)
            ))
        }
    }

    fn fill_random(buf: &mut [u8]) -> Result<()> {
        use std::io::Read;
        std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(buf)).context("reading /dev/urandom")
    }
}

#[cfg(all(test, feature = "sign"))]
mod tests {
    use super::*;

    fn key(n: u8) -> SecretKey {
        SecretKey::from_seed([n; 8], [n; 32])
    }

    #[test]
    fn sign_and_verify() {
        let k = key(1);
        let mut store = TrustStore::default();
        store.add("project", &k.public_key_file()).unwrap();
        let sig = k.sign(b"hello", "kernel:7.3.5-1-pve level:3").unwrap();
        let who = store.verify(b"hello", &sig).unwrap();
        assert_eq!(who.name, "project");
        assert_eq!(who.key_id, k.key_id());
    }

    #[test]
    fn tampered_data_is_rejected() {
        let k = key(1);
        let mut store = TrustStore::default();
        store.add("project", &k.public_key_file()).unwrap();
        let sig = k.sign(b"hello", "x").unwrap();
        assert!(store.verify(b"hellO", &sig).is_err());
    }

    #[test]
    fn tampered_trusted_comment_is_rejected() {
        let k = key(1);
        let mut store = TrustStore::default();
        store.add("project", &k.public_key_file()).unwrap();
        let sig = k.sign(b"hello", "level:3").unwrap().replace("level:3", "level:9");
        assert!(store.verify(b"hello", &sig).is_err());
    }

    #[test]
    fn untrusted_key_is_rejected() {
        let mut store = TrustStore::default();
        store.add("project", &key(1).public_key_file()).unwrap();
        let sig = key(2).sign(b"hello", "x").unwrap();
        assert!(store.verify(b"hello", &sig).is_err());
    }

    #[test]
    fn rotation_accepts_any_trusted_key() {
        let mut store = TrustStore::default();
        store.add("old", &key(1).public_key_file()).unwrap();
        store.add("new", &key(2).public_key_file()).unwrap();
        let sig = key(2).sign(b"hello", "x").unwrap();
        assert_eq!(store.verify(b"hello", &sig).unwrap().name, "new");
    }

    #[test]
    fn empty_store_rejects() {
        let store = TrustStore::default();
        assert!(store.verify(b"x", &key(1).sign(b"x", "x").unwrap()).is_err());
    }

    #[test]
    fn secret_key_file_roundtrip() {
        let k = key(7);
        let back = SecretKey::from_file_string(&k.to_file_string()).unwrap();
        assert_eq!(back.public_key_file(), k.public_key_file());
    }
}
