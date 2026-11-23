//! Keys and encrypted objects: AES-256-GCM symmetric keys, RSA-OAEP private keys, the JWE-like
//! "encrypted object" envelope, and personal keysets (white paper §5, §8.3, Figures 8.5–8.7).

use std::fmt;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::RngCore;
use rsa::{BigUint as RsaBigUint, Oaep, RsaPrivateKey};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::b64;
use crate::error::{Error, Result};

/// The "encrypted object" envelope used everywhere in 1Password:
/// `{"kid":…,"enc":"A256GCM","cty":"b5+jwk+json","iv":…,"data":…}`, plus `alg`/`p2s`/`p2c` when
/// the key is derived from the account password (`kid == "mp"`).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptedObject {
    /// ID of the key this is encrypted with (`"mp"` = the Account Unlock Key).
    pub kid: String,
    /// Content encryption, always `"A256GCM"` so far.
    pub enc: String,
    /// Content type of the plaintext, e.g. `"b5+jwk+json"` (a JWK) or `"b5+json"`.
    pub cty: String,
    /// 12-byte GCM nonce, base64url (empty for RSA-OAEP objects).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub iv: String,
    /// Ciphertext with the 16-byte GCM tag appended, base64url.
    pub data: String,
    /// Key derivation algorithm when `kid == "mp"`, e.g. `"PBES2g-HS256"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    /// Key derivation salt (base64url) when `kid == "mp"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub p2s: Option<String>,
    /// PBKDF2 iteration count when `kid == "mp"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub p2c: Option<u32>,
}

impl EncryptedObject {
    /// Decrypts with an AES-256-GCM key. Fails if the key ID doesn't match or the tag is wrong.
    pub fn decrypt(&self, key: &SymmetricKey) -> Result<Zeroizing<Vec<u8>>> {
        if self.enc != "A256GCM" {
            return Err(Error::Unsupported(format!("encryption {:?}", self.enc)));
        }
        if self.kid != key.kid {
            return Err(Error::Decrypt(format!(
                "object is encrypted with key {:?}, not {:?}",
                self.kid, key.kid
            )));
        }
        let iv = b64::decode(&self.iv)?;
        if iv.len() != 12 {
            return Err(Error::Malformed(format!(
                "GCM nonce is {} bytes, expected 12",
                iv.len()
            )));
        }
        let data = b64::decode(&self.data)?;
        let cipher = Aes256Gcm::new_from_slice(key.key.as_ref()).expect("32-byte key");
        cipher
            .decrypt(Nonce::from_slice(&iv), data.as_ref())
            .map(Zeroizing::new)
            .map_err(|_| {
                Error::Decrypt(format!(
                    "authentication failed for object encrypted with {:?}",
                    self.kid
                ))
            })
    }

    /// Decrypts and parses the plaintext as JSON.
    pub fn decrypt_json<T: serde::de::DeserializeOwned>(&self, key: &SymmetricKey) -> Result<T> {
        let plain = self.decrypt(key)?;
        Ok(serde_json::from_slice(&plain)?)
    }

    /// Encrypts `plaintext` with a fresh random nonce.
    pub fn encrypt(key: &SymmetricKey, cty: &str, plaintext: &[u8]) -> Self {
        let mut iv = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut iv);
        let cipher = Aes256Gcm::new_from_slice(key.key.as_ref()).expect("32-byte key");
        let data = cipher
            .encrypt(Nonce::from_slice(&iv), plaintext)
            .expect("AES-GCM encryption cannot fail");
        EncryptedObject {
            kid: key.kid.clone(),
            enc: "A256GCM".into(),
            cty: cty.into(),
            iv: b64::encode(&iv),
            data: b64::encode(&data),
            alg: None,
            p2s: None,
            p2c: None,
        }
    }
}

/// An AES-256-GCM key with its key ID. Zeroed on drop, redacted in `Debug`.
#[derive(Clone)]
pub struct SymmetricKey {
    kid: String,
    key: Zeroizing<[u8; 32]>,
}

impl SymmetricKey {
    /// Wraps raw key bytes.
    pub fn new(kid: impl Into<String>, key: [u8; 32]) -> Self {
        SymmetricKey {
            kid: kid.into(),
            key: Zeroizing::new(key),
        }
    }

    /// Parses an `oct` JWK (`{"kty":"oct","alg":"A256GCM","k":…,"kid":…}`).
    pub fn from_jwk(jwk: &Jwk) -> Result<Self> {
        if jwk.kty != "oct" {
            return Err(Error::Unsupported(format!(
                "expected an oct JWK, got {:?}",
                jwk.kty
            )));
        }
        let k = b64::decode(
            jwk.k
                .as_deref()
                .ok_or_else(|| Error::Malformed("JWK without k".into()))?,
        )?;
        let key: [u8; 32] = k.as_slice().try_into().map_err(|_| {
            Error::Malformed(format!("symmetric key is {} bytes, expected 32", k.len()))
        })?;
        Ok(SymmetricKey::new(jwk.kid.clone().unwrap_or_default(), key))
    }

    /// The key ID.
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// Raw key bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.key
    }
}

impl fmt::Debug for SymmetricKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SymmetricKey({:?}, <redacted>)", self.kid)
    }
}

/// A JSON Web Key, as far as 1Password uses them. Private fields are zeroed on drop.
#[derive(Clone, Deserialize, Serialize)]
pub struct Jwk {
    /// Key type: `"oct"` or `"RSA"`.
    pub kty: String,
    /// Key ID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    /// Algorithm: `"A256GCM"`, `"RSA-OAEP-256"` or `"RSA-OAEP"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    /// Symmetric key material (oct).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub k: Option<String>,
    /// RSA modulus.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub n: Option<String>,
    /// RSA public exponent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub e: Option<String>,
    /// RSA private exponent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub d: Option<String>,
    /// RSA first prime.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub p: Option<String>,
    /// RSA second prime.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub q: Option<String>,
}

impl Drop for Jwk {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.k.zeroize();
        self.d.zeroize();
        self.p.zeroize();
        self.q.zeroize();
    }
}

impl fmt::Debug for Jwk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Jwk(kty={:?}, kid={:?}, alg={:?}, <key material redacted>)",
            self.kty, self.kid, self.alg
        )
    }
}

/// Which hash RSA-OAEP uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OaepHash {
    Sha1,
    Sha256,
}

/// An RSA-OAEP private key (2048-bit in practice), used to unwrap vault keys.
#[derive(Clone)]
pub struct PrivateKey {
    kid: String,
    key: RsaPrivateKey,
    hash: OaepHash,
}

impl PrivateKey {
    /// Parses an RSA private JWK.
    pub fn from_jwk(jwk: &Jwk) -> Result<Self> {
        if jwk.kty != "RSA" {
            return Err(Error::Unsupported(format!(
                "expected an RSA JWK, got {:?}",
                jwk.kty
            )));
        }
        let int = |name: &str, v: &Option<String>| -> Result<RsaBigUint> {
            let s = v
                .as_deref()
                .ok_or_else(|| Error::Malformed(format!("RSA JWK without {name}")))?;
            Ok(RsaBigUint::from_bytes_be(&b64::decode(s)?))
        };
        let key = RsaPrivateKey::from_components(
            int("n", &jwk.n)?,
            int("e", &jwk.e)?,
            int("d", &jwk.d)?,
            vec![int("p", &jwk.p)?, int("q", &jwk.q)?],
        )
        .map_err(|e| Error::Malformed(format!("RSA key: {e}")))?;
        let hash = match jwk.alg.as_deref() {
            Some("RSA-OAEP-256") | None => OaepHash::Sha256,
            Some("RSA-OAEP") => OaepHash::Sha1,
            Some(other) => return Err(Error::Unsupported(format!("RSA algorithm {other:?}"))),
        };
        Ok(PrivateKey {
            kid: jwk.kid.clone().unwrap_or_default(),
            key,
            hash,
        })
    }

    /// The key ID.
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// Decrypts an RSA-OAEP ciphertext.
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let res = match self.hash {
            OaepHash::Sha256 => self.key.decrypt(Oaep::new::<sha2::Sha256>(), ciphertext),
            OaepHash::Sha1 => self.key.decrypt(Oaep::new::<sha1::Sha1>(), ciphertext),
        };
        res.map(Zeroizing::new)
            .map_err(|_| Error::Decrypt(format!("RSA-OAEP with key {:?}", self.kid)))
    }

    /// Decrypts an RSA-encrypted object (`enc` = `"RSA-OAEP"` / `"RSA-OAEP-256"`), as used for
    /// vault keys, and parses the plaintext as a JWK.
    pub fn decrypt_object_jwk(&self, obj: &EncryptedObject) -> Result<Jwk> {
        if obj.kid != self.kid {
            return Err(Error::Decrypt(format!(
                "object is encrypted with key {:?}, not {:?}",
                obj.kid, self.kid
            )));
        }
        let ct = b64::decode(&obj.data)?;
        // The object's `enc` says which OAEP hash was used; fall back to the key's own `alg`.
        let res = match obj.enc.as_str() {
            "RSA-OAEP-256" => self.key.decrypt(Oaep::new::<sha2::Sha256>(), &ct),
            "RSA-OAEP" => self.key.decrypt(Oaep::new::<sha1::Sha1>(), &ct),
            other => {
                return Err(Error::Unsupported(format!(
                    "vault key encryption {other:?}"
                )));
            }
        };
        let plain = res
            .map(Zeroizing::new)
            .map_err(|_| Error::Decrypt(format!("RSA-OAEP with key {:?}", self.kid)))?;
        Ok(serde_json::from_slice(&plain)?)
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PrivateKey({:?}, {:?}, <redacted>)", self.kid, self.hash)
    }
}

/// A personal keyset as returned by the server: a symmetric key and an RSA key pair, the
/// symmetric key encrypted by `encrypted_by` (the AUK `"mp"` for the primary keyset).
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedKeyset {
    /// Keyset UUID (also the `kid` of its symmetric and private keys).
    pub uuid: String,
    /// `kid` of the key that encrypts `enc_sym_key`.
    pub encrypted_by: String,
    /// The symmetric key, encrypted.
    pub enc_sym_key: EncryptedObject,
    /// The RSA private key, encrypted with the symmetric key.
    pub enc_pri_key: EncryptedObject,
    /// The RSA public key (JWK).
    #[serde(default)]
    pub pub_key: serde_json::Value,
    /// Sequence number; the newest keyset has the highest.
    #[serde(default)]
    pub sn: Option<u64>,
}

/// A decrypted keyset.
#[derive(Clone, Debug)]
pub struct Keyset {
    /// Keyset UUID.
    pub uuid: String,
    /// Symmetric key.
    pub sym: SymmetricKey,
    /// RSA private key.
    pub private: PrivateKey,
}

impl EncryptedKeyset {
    /// Decrypts the keyset with a symmetric key (the AUK for the primary keyset).
    pub fn decrypt(&self, by: &SymmetricKey) -> Result<Keyset> {
        let sym_jwk: Jwk = self.enc_sym_key.decrypt_json(by)?;
        self.finish(&sym_jwk)
    }

    /// Decrypts the keyset with another, already decrypted keyset: its symmetric key if
    /// `encSymKey` is AES-GCM, or its RSA private key if `encSymKey` is RSA-OAEP (how group and
    /// older keysets are wrapped).
    pub fn decrypt_with_keyset(&self, by: &Keyset) -> Result<Keyset> {
        let sym_jwk: Jwk = if self.enc_sym_key.enc.starts_with("RSA-OAEP") {
            by.private.decrypt_object_jwk(&self.enc_sym_key)?
        } else {
            self.enc_sym_key.decrypt_json(&by.sym)?
        };
        self.finish(&sym_jwk)
    }

    fn finish(&self, sym_jwk: &Jwk) -> Result<Keyset> {
        let mut sym = SymmetricKey::from_jwk(sym_jwk)?;
        if sym.kid.is_empty() {
            sym.kid = self.uuid.clone();
        }
        let pri_jwk: Jwk = self.enc_pri_key.decrypt_json(&sym)?;
        let mut private = PrivateKey::from_jwk(&pri_jwk)?;
        if private.kid.is_empty() {
            private.kid = self.uuid.clone();
        }
        Ok(Keyset {
            uuid: self.uuid.clone(),
            sym,
            private,
        })
    }
}

/// Decrypts a list of keysets, starting from the one(s) encrypted by the Account Unlock Key and
/// following `encrypted_by` links (other keysets are wrapped by already-decrypted ones, with
/// AES-GCM or RSA-OAEP).
///
/// A keyset encrypted by the AUK that fails to decrypt is an error (wrong password or Secret
/// Key). Other keysets that can't be decrypted are skipped; they only gate access to some vaults.
pub fn decrypt_keysets(sets: &[EncryptedKeyset], auk: &SymmetricKey) -> Result<Vec<Keyset>> {
    let mut done: Vec<Keyset> = Vec::new();
    let mut pending: Vec<&EncryptedKeyset> = sets.iter().collect();
    loop {
        let before = pending.len();
        let mut i = 0;
        while i < pending.len() {
            let ks = pending[i];
            let result = if ks.encrypted_by == auk.kid() {
                Some(ks.decrypt(auk))
            } else {
                done.iter()
                    .find(|d| d.uuid == ks.encrypted_by)
                    .map(|by| ks.decrypt_with_keyset(by))
            };
            match result {
                Some(Ok(k)) => {
                    done.push(k);
                    pending.remove(i);
                }
                Some(Err(e)) if ks.encrypted_by == auk.kid() => return Err(e),
                Some(Err(_)) => {
                    pending.remove(i); // unusable non-primary keyset: skip
                }
                None => i += 1,
            }
        }
        if pending.is_empty() || pending.len() == before {
            if done.is_empty() {
                return Err(Error::Protocol(
                    "no keyset could be decrypted with the account password".into(),
                ));
            }
            return Ok(done);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypted_object_round_trip() {
        let key = SymmetricKey::new("abc", [7u8; 32]);
        let obj = EncryptedObject::encrypt(&key, "b5+json", br#"{"hello":"world"}"#);
        assert_eq!(obj.kid, "abc");
        let v: serde_json::Value = obj.decrypt_json(&key).unwrap();
        assert_eq!(v["hello"], "world");
    }

    #[test]
    fn decrypts_1password_session_payload_vector() {
        // Known answer from 1Password's burp-1password-session-analyzer EncryptedMessageTests (BSD-3):
        // a server response encrypted with the SRP session key, kid = session ID.
        let obj: EncryptedObject = serde_json::from_str(
            r#"{"kid":"YKQRP2M3HZFPZDNXTHQBYFPB5M","enc":"A256GCM","cty":"b5+jwk+json",
                "iv":"tYENu1VjK9bH7Ppn","data":"ajyndPzqt8mnc2R4x_ZGJSmRY6qqbOKKiEljvvNce1xtHNmc_jdbm5oBbQ=="}"#,
        )
        .unwrap();
        let k: [u8; 32] = b64::decode("6fsZq-Md2jvAM7Bk8qLv0z59y68np5IxLK4RLgI_zog")
            .unwrap()
            .try_into()
            .unwrap();
        let key = SymmetricKey::new("YKQRP2M3HZFPZDNXTHQBYFPB5M", k);
        assert_eq!(
            obj.decrypt(&key).unwrap().as_slice(),
            br#"{"users":[],"totalCount":0}"#
        );
    }

    #[test]
    fn wrong_key_or_tamper_fails() {
        let key = SymmetricKey::new("abc", [7u8; 32]);
        let mut obj = EncryptedObject::encrypt(&key, "b5+json", b"secret");
        assert!(obj.decrypt(&SymmetricKey::new("abc", [8u8; 32])).is_err());
        assert!(obj.decrypt(&SymmetricKey::new("other", [7u8; 32])).is_err());
        let mut data = b64::decode(&obj.data).unwrap();
        data[0] ^= 1;
        obj.data = b64::encode(&data);
        assert!(obj.decrypt(&key).is_err());
    }

    #[test]
    fn parses_white_paper_encrypted_object() {
        // Shape of Figure 8.6 (data shortened, so only parsing is checked).
        let json = r#"{"kid":"mp","enc":"A256GCM","cty":"b5+jwk+json","iv":"X3uQ83tlrdNIT_MG",
            "data":"gd9fzh8lqq5BYdGZpypXvMzIfkS","alg":"PBES2g-HS256","p2c":650000,"p2s":"5UMfnZ23QaNVpyeKEusdwg"}"#;
        let obj: EncryptedObject = serde_json::from_str(json).unwrap();
        assert_eq!(obj.p2c, Some(650000));
        assert_eq!(b64::decode(obj.p2s.as_deref().unwrap()).unwrap().len(), 16);
        assert_eq!(b64::decode(&obj.iv).unwrap().len(), 12);
    }

    #[test]
    fn keyset_chain_round_trip() {
        // Build a keyset the way the 1Password clients do, then decrypt it again.
        let mut rng = rand::thread_rng();
        let auk = SymmetricKey::new("mp", [1u8; 32]);
        let sym = SymmetricKey::new("ks1", [2u8; 32]);
        let rsa = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let enc = |n: &RsaBigUint| b64::encode(&n.to_bytes_be());
        use rsa::traits::{PrivateKeyParts, PublicKeyParts};
        let pri = serde_json::json!({
            "kty": "RSA", "kid": "ks1", "alg": "RSA-OAEP-256",
            "n": enc(rsa.n()), "e": enc(rsa.e()), "d": enc(rsa.d()),
            "p": enc(&rsa.primes()[0]), "q": enc(&rsa.primes()[1]),
        });
        let sym_jwk = serde_json::json!({"kty":"oct","alg":"A256GCM","kid":"ks1","k": b64::encode(sym.as_bytes())});
        let ks = EncryptedKeyset {
            uuid: "ks1".into(),
            encrypted_by: "mp".into(),
            enc_sym_key: EncryptedObject::encrypt(
                &auk,
                "b5+jwk+json",
                sym_jwk.to_string().as_bytes(),
            ),
            enc_pri_key: EncryptedObject::encrypt(&sym, "b5+jwk+json", pri.to_string().as_bytes()),
            pub_key: serde_json::Value::Null,
            sn: Some(1),
        };
        let out = decrypt_keysets(&[ks], &auk).unwrap();
        assert_eq!(out[0].sym.as_bytes(), sym.as_bytes());

        // Vault key wrapped with RSA-OAEP-256, as for vault access.
        let vault_key = br#"{"kty":"oct","alg":"A256GCM","kid":"vault1","k":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"}"#;
        let ct = rsa
            .to_public_key()
            .encrypt(&mut rng, Oaep::new::<sha2::Sha256>(), vault_key)
            .unwrap();
        let wrapped = EncryptedObject {
            kid: "ks1".into(),
            enc: "RSA-OAEP-256".into(),
            cty: "b5+jwk+json".into(),
            iv: String::new(),
            data: b64::encode(&ct),
            alg: None,
            p2s: None,
            p2c: None,
        };
        let vk =
            SymmetricKey::from_jwk(&out[0].private.decrypt_object_jwk(&wrapped).unwrap()).unwrap();
        assert_eq!(vk.kid(), "vault1");
        assert_eq!(vk.as_bytes(), &[1u8; 32]);
    }
}
