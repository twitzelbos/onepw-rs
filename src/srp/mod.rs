//! SRP-6a client, in the variant 1Password uses.
//!
//! This follows 1Password's open-source Go implementation (github.com/1Password/srp, Apache-2.0),
//! which deliberately deviates from RFC 5054 / RFC 2945 in a few places:
//!
//! * `u = SHA256(hex(A) ‖ hex(B))` over the *lowercase hex strings* of A and B with leading `0`
//!   characters stripped (not the padded big-endian bytes).
//! * The session key is `K = SHA256(hex(S))`, again over the lowercase hex string of S.
//! * The multiplier `k` is supplied by the caller (1Password derives it from the session); when
//!   absent, `k = SHA256(N ‖ g)` with *unpadded* g.
//! * Proofs use SHA-256 over unpadded big-endian integers and the **server proves first**:
//!   `M = SHA256((H(N) ⊕ H(g)) ‖ H(I) ‖ salt ‖ A ‖ B ‖ K)`, then the client answers with
//!   `SHA256(A ‖ M ‖ K)`.
//!
//! `x` is not computed here: in 1Password it comes from two-secret key derivation (see
//! [`crate::kdf`]).
//!
//! # Constant time
//!
//! Everything that involves a secret (the ephemeral `a`, the password-derived `x`, and the
//! premaster secret `S`) is computed with `crypto-bigint` in Montgomery form, with exponents
//! processed over a fixed 1024 bits ([`EXP_BITS`]), so timing doesn't depend on their values.
//! Public values (N, g, k, A, B, u, the verifier) use `num-bigint-dig` for convenience. Not
//! constant time: the hex encoding of `S` for `K = SHA256(hex(S))` strips leading zero digits,
//! as 1Password's protocol requires, which can leak how many leading zero nibbles S has.

/// 4096-bit Montgomery form (the group modulus).
type Monty = FixedMontyForm<{ U4096::LIMBS }>;
type MontyParams = FixedMontyParams<{ U4096::LIMBS }>;

/// Bit length every secret exponent (`a`, `x`, `u·x + a`) is processed with. `a` is at most
/// 304 bits, `x` and `u` 256, so `u·x + a` < 2^513.
pub const EXP_BITS: u32 = 1024;

use crypto_bigint::modular::{FixedMontyForm, FixedMontyParams};
use crypto_bigint::{Odd, U1024, U4096};
use num_bigint_dig::BigUint;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// A Diffie-Hellman group for SRP.
#[derive(Clone, Debug)]
pub struct Group {
    n: BigUint,
    g: BigUint,
    /// Size of the random client exponent `a`, in bytes.
    exponent_size: usize,
    /// Label used by 1Password's Go library, e.g. `"5054A4096"`.
    pub label: &'static str,
    params: MontyParams,
}

/// RFC 3526 group 16 / RFC 5054 4096-bit group, g = 5. This is what `"SRPg-4096"` refers to.
pub fn rfc5054_4096() -> Group {
    const N_HEX: &str = concat!(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08",
        "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B",
        "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9",
        "A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6",
        "49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8",
        "FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D",
        "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C",
        "180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718",
        "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D",
        "04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7D",
        "B3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D226",
        "1AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200C",
        "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFC",
        "E0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B26",
        "99C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB",
        "04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2",
        "233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127",
        "D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199",
        "FFFFFFFFFFFFFFFF",
    );
    let n = BigUint::parse_bytes(N_HEX.as_bytes(), 16).expect("valid group prime");
    let odd = Odd::new(public_u4096(&n)).expect("N is odd");
    Group {
        n,
        g: BigUint::from(5u32),
        exponent_size: 38,
        label: "5054A4096",
        // The modulus is public, so the variable-time setup is fine.
        params: MontyParams::new_vartime(odd),
    }
}

impl Group {
    /// Looks up the group for a 1Password SRP method string such as `"SRPg-4096"`.
    pub fn for_method(method: &str) -> Result<Group> {
        match method {
            "SRPg-4096" => Ok(rfc5054_4096()),
            other => Err(Error::Unsupported(format!("SRP method {other:?}"))),
        }
    }

    /// The prime modulus N.
    pub fn n(&self) -> &BigUint {
        &self.n
    }

    /// The generator g.
    pub fn g(&self) -> &BigUint {
        &self.g
    }

    /// `k = SHA256(N ‖ PAD(g))`, g left-padded to the length of N (RFC 5054). Used by the
    /// current login flow.
    pub fn standard_k(&self) -> BigUint {
        let mut h = Sha256::new();
        h.update(self.n.to_bytes_be());
        h.update(self.pad(&self.g));
        BigUint::from_bytes_be(&h.finalize())
    }

    /// `value mod N` as big-endian bytes, left-padded to the byte length of N.
    fn pad(&self, value: &BigUint) -> Vec<u8> {
        let len = self.n.bits().div_ceil(8);
        let bytes = (value % &self.n).to_bytes_be();
        let mut out = vec![0u8; len.saturating_sub(bytes.len())];
        out.extend_from_slice(&bytes);
        out
    }

    /// `k = SHA256(N ‖ g)` with unpadded g (the 1Password Go library's non-standard default).
    pub fn default_k(&self) -> BigUint {
        let mut h = Sha256::new();
        h.update(self.n.to_bytes_be());
        h.update(self.g.to_bytes_be());
        BigUint::from_bytes_be(&h.finalize())
    }
}

/// A public value as a 4096-bit integer. Panics if it has more than 4096 bits (callers reduce
/// mod N first).
fn public_u4096(v: &BigUint) -> U4096 {
    let bytes = v.to_bytes_be();
    assert!(bytes.len() <= 512, "value exceeds 4096 bits");
    let mut buf = [0u8; 512];
    buf[512 - bytes.len()..].copy_from_slice(&bytes);
    U4096::from_be_slice(&buf)
}

/// A secret big-endian integer (at most 64 bytes) as a 1024-bit exponent.
fn secret_exponent(bytes: &[u8]) -> Zeroizing<U1024> {
    assert!(bytes.len() <= 64, "secret exponent longer than 512 bits");
    let mut buf = Zeroizing::new([0u8; 128]);
    buf[128 - bytes.len()..].copy_from_slice(bytes);
    Zeroizing::new(U1024::from_be_slice(buf.as_ref()))
}

impl Group {
    fn monty(&self, v: &BigUint) -> Monty {
        Monty::new(&public_u4096(&(v % &self.n)), &self.params)
    }

    /// `g^e mod N` in constant time over [`EXP_BITS`] exponent bits.
    fn g_pow_secret(&self, e: &U1024) -> Monty {
        self.monty(&self.g).pow_bounded_exp(e, EXP_BITS)
    }
}

/// Lowercase hex digit for a nibble, branch-free: `'0' + n`, plus 39 more for `a`–`f`.
fn hex_digit(n: u8) -> u8 {
    let n = n & 0x0f;
    // (9 - n) >> 7 is 1 when n > 9 (wrapping subtraction sets the top bit), else 0.
    let above_nine = 9u8.wrapping_sub(n) >> 7;
    b'0' + n + above_nine * 39
}

fn monty_to_biguint(m: &Monty) -> BigUint {
    BigUint::from_bytes_be(m.retrieve().to_be_bytes().as_ref())
}

/// Which generation of 1Password's SRP math to use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Variant {
    /// Current login flow (`v3/auth/start` → `v2/auth` → `v2/auth/confirm-key`):
    /// `k = SHA256(N ‖ PAD(g))`, `u = SHA256(PAD(A) ‖ PAD(B))`, client proves first.
    Standard,
    /// Older flow and the Go library's default: caller-supplied `k` (or `SHA256(N ‖ g)`),
    /// `u` over hex strings, server proves first.
    Legacy,
}

/// Client side of one SRP exchange.
pub struct Client {
    variant: Variant,
    group: Group,
    x: Zeroizing<Vec<u8>>,
    k: BigUint,
    a: Zeroizing<Vec<u8>>,
    big_a: BigUint,
}

impl Client {
    /// Starts an exchange with a fresh random ephemeral secret.
    ///
    /// `x` is the 32-byte SRP secret from 2SKD. `k` is the multiplier; `None` uses
    /// [`Group::default_k`].
    ///
    /// # Panics
    ///
    /// If `x` is longer than 64 bytes (the constant-time maths is sized for at most 512-bit
    /// secrets; 1Password's `x` is 32 bytes).
    pub fn new(group: Group, x: &[u8], k: Option<BigUint>) -> Self {
        use rand::Rng;
        let mut a = Zeroizing::new(vec![0u8; group.exponent_size.max(32)]);
        rand::rng().fill_bytes(&mut a);
        Self::with_ephemeral(group, x, k, &a)
    }

    /// Starts an exchange for the **current** 1Password login flow ([`Variant::Standard`]).
    pub fn new_standard(group: Group, x: &[u8]) -> Self {
        let mut c = Self::new(group, x, None);
        c.variant = Variant::Standard;
        c.k = c.group.standard_k();
        c
    }

    /// Like [`Client::new_standard`] with a fixed ephemeral secret. For tests only.
    pub fn standard_with_ephemeral(group: Group, x: &[u8], a: &[u8]) -> Self {
        let mut c = Self::with_ephemeral(group, x, None, a);
        c.variant = Variant::Standard;
        c.k = c.group.standard_k();
        c
    }

    /// The SRP variant in use.
    pub fn variant(&self) -> Variant {
        self.variant
    }

    /// A as the server expects it on the wire: lowercase hex, leading zeros stripped.
    pub fn public_a_hex(&self) -> String {
        server_hex(&self.big_a)
    }

    /// Starts an exchange with a given ephemeral secret `a` (big-endian). For tests only.
    ///
    /// # Panics
    ///
    /// If `x` or `a` is longer than 64 bytes.
    pub fn with_ephemeral(group: Group, x: &[u8], k: Option<BigUint>, a: &[u8]) -> Self {
        let k = k.unwrap_or_else(|| group.default_k());
        let big_a = monty_to_biguint(&group.g_pow_secret(&secret_exponent(a)));
        Client {
            variant: Variant::Legacy,
            group,
            x: Zeroizing::new(x.to_vec()),
            k,
            a: Zeroizing::new(a.to_vec()),
            big_a,
        }
    }

    /// The client's public value A, sent to the server.
    pub fn public_a(&self) -> &BigUint {
        &self.big_a
    }

    /// The verifier `v = g^x mod N`. A client only needs this when registering or changing
    /// credentials.
    pub fn verifier(&self) -> BigUint {
        monty_to_biguint(&self.group.g_pow_secret(&secret_exponent(&self.x)))
    }

    /// Computes the shared session key from the server's public value B.
    pub fn session_key(&self, big_b: &BigUint) -> Result<SessionKey> {
        let u = match self.variant {
            Variant::Legacy => compute_u(&self.big_a, big_b),
            Variant::Standard => {
                let mut h = Sha256::new();
                h.update(self.group.pad(&self.big_a));
                h.update(self.group.pad(big_b));
                BigUint::from_bytes_be(&h.finalize())
            }
        };
        self.session_key_with_u(big_b, &u)
    }

    /// Current flow: the client's proof `M1 = SHA256((H(N) ⊕ H(g)) ‖ H(I) ‖ salt ‖ A ‖ B ‖ K)`,
    /// sent first. `identity` is [`identity`]`(email, account_id)`.
    pub fn client_proof(
        &self,
        big_b: &BigUint,
        key: &SessionKey,
        identity: &str,
        salt: &[u8],
    ) -> [u8; 32] {
        self.server_proof(big_b, key, identity, salt)
    }

    /// Current flow: checks the server's answer `SHA256(A ‖ M1 ‖ K)`.
    pub fn verify_server_confirmation(
        &self,
        m1: &[u8; 32],
        key: &SessionKey,
        server_hash: &[u8],
    ) -> Result<()> {
        let mut h = Sha256::new();
        h.update(self.big_a.to_bytes_be());
        h.update(m1);
        h.update(key.as_bytes());
        let expected: [u8; 32] = h.finalize().into();
        if bool::from(expected.as_slice().ct_eq(server_hash)) {
            Ok(())
        } else {
            Err(Error::Protocol(
                "server SRP confirmation did not verify".into(),
            ))
        }
    }

    fn session_key_with_u(&self, big_b: &BigUint, u: &BigUint) -> Result<SessionKey> {
        let n = &self.group.n;
        let b_mod = big_b % n;
        if b_mod == BigUint::from(0u32) || b_mod == BigUint::from(1u32) {
            return Err(Error::Protocol(
                "server sent an invalid SRP public value B".into(),
            ));
        }
        if *u == BigUint::from(0u32) {
            return Err(Error::Protocol("SRP scrambling parameter u is zero".into()));
        }
        // S = (B - k·g^x)^(u·x + a) mod N, all secret-dependent steps in constant time.
        let x = secret_exponent(&self.x);
        let a = secret_exponent(&self.a);
        let kgx = Zeroizing::new(self.group.monty(&self.k) * self.group.g_pow_secret(&x));
        let base = Zeroizing::new(self.group.monty(&b_mod) - *kgx);
        // u is public; u·x + a < 2^513, so 1024-bit wrapping arithmetic is exact.
        let u = secret_exponent(&u.to_bytes_be());
        let exponent = Zeroizing::new(u.wrapping_mul(&*x).wrapping_add(&*a));
        let s = Zeroizing::new(base.pow_bounded_exp(&*exponent, EXP_BITS));
        let s_bytes = Zeroizing::new(s.retrieve().to_be_bytes());
        // Hex without data-dependent branches (`{:02x}` branches on each digit).
        let mut hex = Zeroizing::new(vec![0u8; s_bytes.as_ref().len() * 2]);
        for (i, b) in s_bytes.as_ref().iter().enumerate() {
            hex[2 * i] = hex_digit(b >> 4);
            hex[2 * i + 1] = hex_digit(b & 0x0f);
        }
        let s_hex = std::str::from_utf8(&hex).expect("ASCII hex");
        let trimmed = s_hex.trim_start_matches('0');
        let mut key: [u8; 32] =
            Sha256::digest(if trimmed.is_empty() { "0" } else { trimmed }.as_bytes()).into();
        Ok(SessionKey(crate::locked::Locked::take(&mut key)))
    }

    /// Checks the server's proof `M` (the server proves first in 1Password's variant) and, if it
    /// is valid, returns the client's proof `SHA256(A ‖ M ‖ K)` to send back.
    pub fn verify_server_and_prove(
        &self,
        big_b: &BigUint,
        key: &SessionKey,
        username: &str,
        salt: &[u8],
        server_proof: &[u8],
    ) -> Result<[u8; 32]> {
        let expected = self.server_proof(big_b, key, username, salt);
        if !bool::from(expected.as_slice().ct_eq(server_proof)) {
            return Err(Error::Protocol("server SRP proof did not verify".into()));
        }
        let mut h = Sha256::new();
        h.update(self.big_a.to_bytes_be());
        h.update(expected);
        h.update(key.as_bytes());
        Ok(h.finalize().into())
    }

    /// The proof the server is expected to send: `SHA256((H(N) ⊕ H(g)) ‖ H(I) ‖ salt ‖ A ‖ B ‖ K)`.
    pub fn server_proof(
        &self,
        big_b: &BigUint,
        key: &SessionKey,
        username: &str,
        salt: &[u8],
    ) -> [u8; 32] {
        let hn = Sha256::digest(self.group.n.to_bytes_be());
        let hg = Sha256::digest(self.group.g.to_bytes_be());
        let xor: Vec<u8> = hn.iter().zip(hg.iter()).map(|(a, b)| a ^ b).collect();
        let mut h = Sha256::new();
        h.update(xor);
        h.update(Sha256::digest(username.as_bytes()));
        h.update(salt);
        h.update(self.big_a.to_bytes_be());
        h.update(big_b.to_bytes_be());
        h.update(key.as_bytes());
        h.finalize().into()
    }
}

/// The SRP identity `I` of the current flow:
/// `base64url(SHA256(SHA256(account_id) ‖ SHA256(lowercase(NFKD(trim(email))))))`.
pub fn identity(email: &str, account_id: &str) -> String {
    use unicode_normalization::UnicodeNormalization;
    let email: String = email.trim().nfkd().collect::<String>().to_lowercase();
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(&Sha256::digest(account_id.as_bytes()));
    buf.extend_from_slice(&Sha256::digest(email.as_bytes()));
    crate::b64::encode(&Sha256::digest(&buf))
}

/// Lowercase hex without leading zeros ("0" for zero), the server's wire encoding.
pub fn server_hex(v: &BigUint) -> String {
    let h = format!("{v:x}");
    let t = h.trim_start_matches('0');
    if t.is_empty() { "0".into() } else { t.into() }
}

/// Parses a value in the server's hex encoding.
pub fn from_server_hex(h: &str) -> Result<BigUint> {
    if h.is_empty() || h.len() > 1024 || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Error::Protocol("invalid SRP value from server".into()));
    }
    BigUint::parse_bytes(h.as_bytes(), 16)
        .ok_or_else(|| Error::Protocol("invalid SRP value from server".into()))
}

/// `u = SHA256(hex(A) ‖ hex(B))`, lowercase hex with leading zeros stripped.
pub fn compute_u(big_a: &BigUint, big_b: &BigUint) -> BigUint {
    let ha = format!("{big_a:x}");
    let hb = format!("{big_b:x}");
    let mut h = Sha256::new();
    h.update(ha.trim_start_matches('0').as_bytes());
    h.update(hb.trim_start_matches('0').as_bytes());
    BigUint::from_bytes_be(&h.finalize())
}

/// The 32-byte SRP session key `K`. In locked memory, zeroed on drop and never printed.
pub struct SessionKey(crate::locked::Locked<32>);

impl SessionKey {
    /// Raw key bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for SessionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SessionKey(<redacted>)")
    }
}

#[cfg(test)]
mod u_vectors;

#[cfg(test)]
mod tests {
    use super::*;

    /// A uniformly random integer of `bits` bits (test helper).
    fn random_biguint(bits: usize) -> BigUint {
        use rand::Rng;
        let mut b = vec![0u8; bits.div_ceil(8)];
        rand::rng().fill_bytes(&mut b);
        BigUint::from_bytes_be(&b)
    }

    fn int(h: &str) -> BigUint {
        BigUint::parse_bytes(h.as_bytes(), 16).unwrap()
    }

    // Vectors from github.com/1Password/srp srp_test.go (Apache-2.0).
    const X: &str = "740299d2306764ad9e87f37cd54179e388fd45c85fea3b030eb425d7adcb2773";

    #[test]
    fn verifier_4096_matches_1password_go() {
        let expected = concat!(
            "d05240ed513a4f267608e64cf2a84f5106741ddbf1435707a84f530207409d7",
            "af1e671182f9d77855b61c628df2b8f6ba8e9b6068fbc84fab80b4542f44c666e17358ebffa8d6fb00fd7037a",
            "b9ee450413f240ab1e4b586e48bf43ce38f41ad7e406d0150ea83c8f216db4dec06ec5d9fb1cbfd049f70438f",
            "c14a2faa2a920ad1b298bb1c70989d17163cf52632f202e77824d71c0ff2dd2ef63ebdcd6140beb471b9a7f7b",
            "14e2d45478994dac95d27f2b45404e564c90eb65655bf6a789bfd665035f711b7cf766a380b921a666dfcfee0",
            "238b27eafdd8a953a50cc2c4f291458d48ef9fd0740da59aa325b9165ebb97d125511b03e1056bd448b322d7d",
            "250816783462cff6f9ecd40813522dac10329b7c4bcd0c8f0ceec2eb2c46ba442ac62a84994e2fcdb94cbfe05",
            "7cad578c5e4d28822cd283e8430b8a1e1106f6e2536e8596b8a0de46717fbd4e9f06b796364aa930bbcf87433",
            "cbbbf15b077b2998569027edcae71d09112857d0fac06d9f9f70371f43f8581a229c290ade4e63251f8d8a0c9",
            "61e20d357069472db3ff422c3ecacf6ff9b2af54003d6aa344a37e7a7f04a1a667d5299475cea6b02c09b5850",
            "5c895efbd86703a0a375ccdf81616e8bee6cfc947467c4bcbe4a7d3e245df32cd7192e212ffe635ff8ac9727d",
            "6fe05ede8338f6f3bc18b5359ea8afc13ce3952cd426fb0934c5ea54e71e10bf81028f",
        );
        let c = Client::new(rfc5054_4096(), &int(X).to_bytes_be(), None);
        assert_eq!(c.verifier(), int(expected));
    }

    #[test]
    fn session_key_4096_matches_1password_go() {
        let a = int("f1ecc95bb29e8a360e9b257d5688c83d503506a6a6eba683f1e06");
        let b = int(concat!(
            "780a5495cbf731d2463fd01d28822e7d9ccf697c4239d5151f85666aa06b3767e0301b54cfad3bd2b526d4d8a1d9",
            "6492e59c8d8ecddca96b7e288f186155ffa57b50df6bc2103b6004400b797334a22d9dd234b40142a5ab714ea607",
            "0d2ed55096049f50efba99862b72f7e7aee51ed71ba6663fff570cc713d456316f3535630e87a245f09b0791c6e6",
            "87baa65bf2dfb5c17e50c250256cdad4c9851a2484e88326888060ae9578b5a60e0c85143b25f4fb4fca794e266a",
            "4359642da085672d6a3b881649a387875685aeb1ae3d809bf7818dcad596c6e29d566ae87c0ad645a0fcc2eb4f06",
            "6c097670adf48cf0954918fda4dc30588261321d592f890eed87a950d387b48cf6b4a49f9d497323f683091ae6a4",
            "efe675d6bfc4393c0c3d54c9adad65b8dd3a7b7e85cd5d31e97bebc8f23b370348dab53903ec5085cbf65de5e549",
            "1f417e5bf9953f081e788f36c26cbe00664a1256c4befb00765ea7e432af189521442c186f14442b1957e444426f",
            "740f363ebda943da2bb3b18a13e2f41be9cc3ca0a1b111f6983f9b8d0ee0f4b573c6042fbc0ca029821ebe517ed0",
            "755a94f42d32b0abef9240af0f37b5fe0e90c4ca83acf91d28a7f3acff5657bf69fdb7747e380b23fd437f637da2",
            "f7ebcf8733a69a75715fe3894e1799906b48e3ae818332cf5f9533e7af5a1f065f907c8f31fe778fa2da853e6992",
            "6fc551d6b3ae",
        ));
        let u = int("dad353365f78590c1857b29f16e3a947df4707868e2dd2d2b4eafd35c8c854a1");
        // k as used in the Go test: the raw ASCII bytes of a 1Password session ID.
        let k = BigUint::from_bytes_be(b"H27JRK5M4NBJXOBCOETCVXJHFA");
        let c = Client::with_ephemeral(
            rfc5054_4096(),
            &int(X).to_bytes_be(),
            Some(k),
            &a.to_bytes_be(),
        );
        let key = c.session_key_with_u(&b, &u).unwrap();
        assert_eq!(
            hex::encode(key.as_bytes()),
            "f6bef3d6fa5a08a849bf61041cd5b3185c16aede851c819a3644fa7e918c4da6"
        );
    }

    #[test]
    fn u_matches_1password_go() {
        for (a, b, expected) in u_vectors::U_VECTORS {
            let u = compute_u(&int(a), &int(b));
            assert_eq!(hex::encode(u.to_bytes_be()), expected, "u({a}, {b})");
        }
    }

    #[test]
    fn standard_k_matches_1password_go() {
        // group_test.go: SHA256(N ‖ PAD(g)) for the 4096-bit group.
        assert_eq!(
            hex::encode(rfc5054_4096().standard_k().to_bytes_be()),
            "3509477ea9fca66eadb7cf7b1bd0eb508f54d3989a9c988006a7d0b338374dd2"
        );
    }

    #[test]
    fn standard_exchange_round_trip() {
        let g = rfc5054_4096();
        let x = [3u8; 32];
        let client = Client::new_standard(g.clone(), &x);
        let v = client.verifier();
        let k = g.standard_k();
        let b = random_biguint(256);
        let big_b = ((&k * &v) % g.n() + g.g().modpow(&b, g.n())) % g.n();
        let mut h = Sha256::new();
        h.update(g.pad(client.public_a()));
        h.update(g.pad(&big_b));
        let u = BigUint::from_bytes_be(&h.finalize());
        let s_server = ((v.modpow(&u, g.n()) * client.public_a()) % g.n()).modpow(&b, g.n());
        let k_server: [u8; 32] = Sha256::digest(server_hex(&s_server).as_bytes()).into();
        let key = client.session_key(&big_b).unwrap();
        assert_eq!(key.as_bytes(), &k_server);

        let id = identity(" Patty@Dogs.Example ", "8MMQJN");
        assert_eq!(id, identity("patty@dogs.example", "8MMQJN"));
        let m1 = client.client_proof(&big_b, &key, &id, b"salt");
        let mut hs = Sha256::new();
        hs.update(client.public_a().to_bytes_be());
        hs.update(m1);
        hs.update(key.as_bytes());
        let server_hash: [u8; 32] = hs.finalize().into();
        assert!(
            client
                .verify_server_confirmation(&m1, &key, &server_hash)
                .is_ok()
        );
        assert!(
            client
                .verify_server_confirmation(&m1, &key, &[0u8; 32])
                .is_err()
        );
    }

    #[test]
    fn identity_is_hash_of_hashes() {
        let id = identity(" Patty@Dogs.Example ", "8MMQJN");
        let mut inner = Sha256::digest(b"8MMQJN").to_vec();
        inner.extend_from_slice(&Sha256::digest(b"patty@dogs.example"));
        assert_eq!(id, crate::b64::encode(&Sha256::digest(&inner)));
        assert_eq!(id.len(), 43, "base64url of a 32-byte digest, unpadded");
    }

    #[test]
    fn branch_free_hex_digits() {
        for n in 0..16u8 {
            assert_eq!(
                hex_digit(n) as char,
                format!("{n:x}").chars().next().unwrap()
            );
        }
    }

    #[test]
    fn server_hex_round_trip() {
        let v = int("000abc");
        assert_eq!(server_hex(&v), "abc");
        assert_eq!(from_server_hex("abc").unwrap(), v);
        assert!(from_server_hex("xyz").is_err());
        assert!(from_server_hex("").is_err());
    }

    #[test]
    fn rejects_degenerate_b() {
        let g = rfc5054_4096();
        let n = g.n().clone();
        let c = Client::new(g, &[7u8; 32], None);
        assert!(c.session_key(&n).is_err());
        assert!(c.session_key(&(n + 1u32)).is_err());
    }

    #[test]
    fn full_exchange_round_trip() {
        // Simulate the server side to check client and server agree on K and on the proofs.
        let g = rfc5054_4096();
        let x = [42u8; 32];
        let client = Client::new(g.clone(), &x, None);
        let v = client.verifier();
        let k = g.default_k();
        let b = random_biguint(38 * 8);
        let big_b = ((&k * &v) % g.n() + g.g().modpow(&b, g.n())) % g.n();

        let u = compute_u(client.public_a(), &big_b);
        let s_server = ((v.modpow(&u, g.n()) * client.public_a()) % g.n()).modpow(&b, g.n());
        let k_server: [u8; 32] = Sha256::digest(format!("{s_server:x}").as_bytes()).into();

        let key = client.session_key(&big_b).unwrap();
        assert_eq!(key.as_bytes(), &k_server);

        let m = client.server_proof(&big_b, &key, "polly@cracker.example", b"salt");
        assert!(
            client
                .verify_server_and_prove(&big_b, &key, "polly@cracker.example", b"salt", &m)
                .is_ok()
        );
        assert!(
            client
                .verify_server_and_prove(&big_b, &key, "polly@cracker.example", b"salt", &[0u8; 32])
                .is_err()
        );
    }
}
