//! End-to-end test against a simulated 1Password server: the server side of SRP (standard
//! variant), MAC checking on every authenticated request, session encryption of bodies, and a
//! real encrypted keyset → vault key → item chain.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use num_bigint_dig::BigUint;
use onepw::keys::{EncryptedObject, SymmetricKey};
use onepw::{Account, Credentials, SecretKey, SignInOptions, kdf, mac, srp};
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use rsa::{Oaep, PrivateKey as RsaPrivateKey};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};
use zeroize::Zeroizing;

const EMAIL: &str = "patty@dogs.example";
const PASSWORD: &str = "correct horse battery staple";
const SECRET_KEY: &str = "A3-8MMQJN-MZ64CY-2SDB4-RPX3T-V52Q3-N2C84";
const SESSION_ID: &str = "TRYYDRPO2FDWRITHY7BETQZPN4";

fn b64(b: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(b)
}
fn unb64(s: &str) -> Vec<u8> {
    URL_SAFE_NO_PAD.decode(s.trim_end_matches('=')).unwrap()
}
/// A uniformly random integer of `bits` bits (test helper).
fn random_biguint(bits: usize) -> BigUint {
    use rand::Rng;
    let mut b = vec![0u8; bits.div_ceil(8)];
    rand::rng().fill_bytes(&mut b);
    BigUint::from_bytes_be(&b)
}

fn pad(n: &BigUint, v: &BigUint) -> Vec<u8> {
    let len = n.bits().div_ceil(8);
    let bytes = (v % n).to_bytes_be();
    let mut out = vec![0u8; len - bytes.len()];
    out.extend_from_slice(&bytes);
    out
}

#[derive(Default)]
struct State {
    starts: u32,
    device_registered: bool,
    big_a: Option<BigUint>,
    big_b: Option<BigUint>,
    session_key: Option<[u8; 32]>,
    confirmed: bool,
    last_request_id: Option<u32>,
    macs_checked: u32,
    /// Simulate an interceptor: answer `v1/account` in plaintext.
    plaintext_account: bool,
    /// Answer `v1/account` with a redirect to this URL.
    redirect_account: Option<String>,
    /// Answer `v1/account` with a body over the size limit.
    huge_account: bool,
    /// Require an authenticator-app (TOTP) code, and this is the right one.
    totp_code: Option<&'static str>,
    /// Require a second factor onepw doesn't support (Duo).
    duo_required: bool,
    /// Requests to `v1/auth/mfa`, and whether one had the right code.
    mfa_requests: u32,
    mfa_passed: bool,
    /// Requests to `v1/account/keysets` (the first thing after 2FA).
    keysets_served: u32,
}

struct Fixture {
    verifier: BigUint,
    srp_salt: Vec<u8>,
    keysets: Value,
    account: Value,
    items: Value,
}

fn fixture() -> Fixture {
    let sk = SecretKey::parse(SECRET_KEY).unwrap();
    let mut rng = rand::rng();

    // SRP verifier for the account.
    let srp_salt = vec![5u8; 16];
    let x = kdf::srp_x(PASSWORD, &sk, EMAIL, "SRPg-4096", &srp_salt, 1000).unwrap();
    let group = srp::rfc5054_4096();
    let verifier = group
        .g()
        .modpow(&BigUint::from_bytes_be(x.as_ref()), group.n());

    // Keyset: sym key encrypted by the AUK, RSA key encrypted by the sym key.
    let p2s = vec![6u8; 16];
    let auk = kdf::account_unlock_key(PASSWORD, &sk, EMAIL, "PBES2g-HS256", &p2s, 900).unwrap();
    let ks_uuid = "c4pxet7agzqqhqg9yvxc2hkg8g";
    let sym = SymmetricKey::new(ks_uuid, [2u8; 32]);
    let rsa = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let e = |n: &rsa::BoxedUint| b64(&n.to_be_bytes_trimmed_vartime());
    let pri_jwk = json!({"kty":"RSA","kid":ks_uuid,"alg":"RSA-OAEP-256","n":e(rsa.n().as_ref()),"e":e(rsa.e()),
        "d":e(rsa.d()),"p":e(rsa.primes()[0].as_ref()),"q":e(rsa.primes()[1].as_ref())});
    let sym_jwk = json!({"kty":"oct","alg":"A256GCM","kid":ks_uuid,"k":b64(sym.as_bytes())});
    let mut enc_sym = serde_json::to_value(EncryptedObject::encrypt(
        &auk,
        "b5+jwk+json",
        sym_jwk.to_string().as_bytes(),
    ))
    .unwrap();
    enc_sym["alg"] = "PBES2g-HS256".into();
    enc_sym["p2s"] = b64(&p2s).into();
    enc_sym["p2c"] = 900.into(); // differs from the SRP count (1000) so each check is tested
    let enc_pri = EncryptedObject::encrypt(&sym, "b5+jwk+json", pri_jwk.to_string().as_bytes());
    // A second (group-style) keyset whose symmetric key is RSA-OAEP-wrapped by the first one,
    // as on real accounts. It holds the key of a second, shared vault.
    let g_uuid = "groupkeyset0000000000000000";
    let g_sym = SymmetricKey::new(g_uuid, [4u8; 32]);
    let g_rsa = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let g_pri_jwk = json!({"kty":"RSA","kid":g_uuid,"alg":"RSA-OAEP-256","n":e(g_rsa.n().as_ref()),"e":e(g_rsa.e()),
        "d":e(g_rsa.d()),"p":e(g_rsa.primes()[0].as_ref()),"q":e(g_rsa.primes()[1].as_ref())});
    let g_sym_jwk = json!({"kty":"oct","alg":"A256GCM","kid":g_uuid,"k":b64(g_sym.as_bytes())});
    let g_wrapped = rsa
        .to_public_key()
        .encrypt(
            &mut rng,
            Oaep::<sha1::Sha1>::new(),
            g_sym_jwk.to_string().as_bytes(),
        )
        .unwrap();
    let keysets = json!({"keysets": [
        {"uuid": g_uuid, "encryptedBy": ks_uuid, "sn": 2,
         "encSymKey": {"kid": ks_uuid, "enc": "RSA-OAEP", "cty": "b5+jwk+json", "data": b64(&g_wrapped)},
         "encPriKey": EncryptedObject::encrypt(&g_sym, "b5+jwk+json", g_pri_jwk.to_string().as_bytes()),
         "pubKey": {"kty":"RSA","alg":"RSA-OAEP-256"}},
        {"uuid": ks_uuid, "encryptedBy": "mp", "sn": 1,
         "encSymKey": enc_sym, "encPriKey": enc_pri, "pubKey": {"kty":"RSA","alg":"RSA-OAEP-256"}}
    ]});
    let shared_key = SymmetricKey::new("vk2", [5u8; 32]);
    let shared_jwk =
        json!({"kty":"oct","alg":"A256GCM","kid":"vk2","k":b64(shared_key.as_bytes())});
    let shared_wrapped = g_rsa
        .to_public_key()
        .encrypt(
            &mut rng,
            Oaep::<sha2::Sha256>::new(),
            shared_jwk.to_string().as_bytes(),
        )
        .unwrap();

    // Vault key wrapped with RSA-OAEP (SHA-1, as on older accounts) for the keyset.
    let vault_uuid = "p3nfd4jax622nqjos7licewuyn";
    let vault_key = SymmetricKey::new("vk1", [3u8; 32]);
    let vk_jwk = json!({"kty":"oct","alg":"A256GCM","kid":"vk1","k":b64(vault_key.as_bytes())});
    let wrapped = rsa
        .to_public_key()
        .encrypt(
            &mut rng,
            Oaep::<sha1::Sha1>::new(),
            vk_jwk.to_string().as_bytes(),
        )
        .unwrap();
    let account = json!({"vaults": [
        {"uuid": vault_uuid, "type": "P", "activeItemCount": 2,
         "encAttrs": EncryptedObject::encrypt(&vault_key, "b5+json", br#"{"name":"Private","desc":""}"#),
         "access": [{"acl": 0x0FF_FFF, "accessorUuid": "me",
                     "encVaultKey": {"kid": ks_uuid, "enc": "RSA-OAEP", "cty": "b5+jwk+json", "data": b64(&wrapped)}}]},
        {"uuid": "sharedvault", "type": "U",
         "encAttrs": EncryptedObject::encrypt(&shared_key, "b5+json", br#"{"name":"Shared"}"#),
         "access": [{"acl": 0x0FF_FFF, "encVaultKey": {"kid": g_uuid, "enc": "RSA-OAEP-256", "cty": "b5+jwk+json", "data": b64(&shared_wrapped)}}]},
        {"uuid": "noaccessvault", "type": "U",
         "access": [{"acl": 0, "encVaultKey": {"kid": ks_uuid, "enc": "RSA-OAEP", "cty": "b5+jwk+json", "data": "AAAA"}}]}
    ]});

    let item = |uuid: &str, title: &str, details: Value, trashed: &str| {
        json!({"uuid": uuid, "templateUuid": "001", "trashed": trashed, "encryptedBy": "vk1",
            "encOverview": EncryptedObject::encrypt(&vault_key, "b5+json", json!({"title": title}).to_string().as_bytes()),
            "encDetails": EncryptedObject::encrypt(&vault_key, "b5+json", details.to_string().as_bytes())})
    };
    let items = json!({"contentVersion": 7, "batchComplete": true, "items": [
        item("i1", "Anthropic API", json!({"sections":[{"fields":[{"n":"credential","t":"credential","v":"sk-test-123","k":"concealed"}]}]}), "N"),
        item("i2", "GitHub", json!({"fields":[{"designation":"username","name":"username","value":"patty"},
                                               {"designation":"password","name":"password","value":"hunter2"}]}), "N"),
        item("i3", "Old", json!({"password":"gone"}), "Y"),
    ]});
    Fixture {
        verifier,
        srp_salt,
        keysets,
        account,
        items,
    }
}

struct Server {
    state: Arc<Mutex<State>>,
    fx: Arc<Fixture>,
    handler: fn(&Server, &Request) -> ResponseTemplate,
}

impl Respond for Server {
    fn respond(&self, req: &Request) -> ResponseTemplate {
        (self.handler)(self, req)
    }
}

impl Server {
    fn key(&self) -> SymmetricKey {
        SymmetricKey::new(
            SESSION_ID,
            self.state.lock().unwrap().session_key.expect("session key"),
        )
    }

    /// Checks the MAC header the way the server does, and that request IDs increase.
    fn check_mac(&self, req: &Request) -> bool {
        let Some(h) = req
            .headers
            .get("x-agilebits-mac")
            .and_then(|v| v.to_str().ok())
        else {
            return false;
        };
        let id: u32 = h
            .split('|')
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let mut st = self.state.lock().unwrap();
        // Like the real server, sign over the Host the client actually used.
        let mut url = req.url.clone();
        let host = req
            .headers
            .get("host")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("localhost");
        url.set_host(Some(host.split(':').next().unwrap())).unwrap();
        let expected = mac::request_mac(
            &st.session_key.unwrap(),
            SESSION_ID,
            id,
            req.method.as_str(),
            &url,
        );
        let fresh = st.last_request_id.is_none_or(|last| id == last + 1);
        st.last_request_id = Some(id);
        st.macs_checked += 1;
        if h != expected || !fresh {
            eprintln!(
                "MAC mismatch: got {h}, expected {expected}, url {}, fresh {fresh}",
                req.url
            );
        }
        h == expected && fresh
    }

    fn encrypted(&self, v: &Value) -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_json(EncryptedObject::encrypt(
            &self.key(),
            "b5+jwk+json",
            v.to_string().as_bytes(),
        ))
    }
}

fn auth_start(s: &Server, req: &Request) -> ResponseTemplate {
    let body: Value = serde_json::from_slice(&req.body).unwrap();
    assert_eq!(body["skid"], "8MMQJN");
    assert_eq!(body["skFormat"], "A3");
    let mut st = s.state.lock().unwrap();
    st.starts += 1;
    let status = if st.device_registered {
        "ok"
    } else {
        "device-not-registered"
    };
    ResponseTemplate::new(200).set_body_json(json!({
        "status": status, "sessionID": SESSION_ID, "accountKeyFormat": "A3", "accountKeyUuid": "8MMQJN",
        "userAuth": {"method": "SRPg-4096", "alg": "PBES2g-HS256", "iterations": 1000, "salt": b64(&s.fx.srp_salt)}
    }))
}

fn device(s: &Server, req: &Request) -> ResponseTemplate {
    assert_eq!(
        req.headers.get("x-agilebits-session-id").unwrap(),
        SESSION_ID
    );
    let body: Value = serde_json::from_slice(&req.body).unwrap();
    assert_eq!(body["name"], "onepw");
    s.state.lock().unwrap().device_registered = true;
    ResponseTemplate::new(200).set_body_json(json!({"success": 1}))
}

fn srp_auth(s: &Server, req: &Request) -> ResponseTemplate {
    let body: Value = serde_json::from_slice(&req.body).unwrap();
    let g = srp::rfc5054_4096();
    let big_a = srp::from_server_hex(body["userA"].as_str().unwrap()).unwrap();
    let b = random_biguint(256);
    let v = &s.fx.verifier;
    let big_b = ((g.standard_k() * v) % g.n() + g.g().modpow(&b, g.n())) % g.n();
    let mut h = Sha256::new();
    h.update(pad(g.n(), &big_a));
    h.update(pad(g.n(), &big_b));
    let u = BigUint::from_bytes_be(&h.finalize());
    let premaster = ((v.modpow(&u, g.n()) * &big_a) % g.n()).modpow(&b, g.n());
    let key: [u8; 32] = Sha256::digest(srp::server_hex(&premaster).as_bytes()).into();
    let mut st = s.state.lock().unwrap();
    st.last_request_id = None; // request IDs are tracked per session
    st.session_key = Some(key);
    st.big_a = Some(big_a);
    st.big_b = Some(big_b.clone());
    ResponseTemplate::new(200).set_body_json(json!({"userB": srp::server_hex(&big_b)}))
}

fn confirm_key(s: &Server, req: &Request) -> ResponseTemplate {
    let body: Value = serde_json::from_slice(&req.body).unwrap();
    let client_hash = unb64(body["clientVerifyHash"].as_str().unwrap());
    let g = srp::rfc5054_4096();
    let mut st = s.state.lock().unwrap();
    let (a, b, k) = (
        st.big_a.clone().unwrap(),
        st.big_b.clone().unwrap(),
        st.session_key.unwrap(),
    );
    let hn = Sha256::digest(g.n().to_bytes_be());
    let hg = Sha256::digest(g.g().to_bytes_be());
    let mut m = Sha256::new();
    m.update(
        hn.iter()
            .zip(hg.iter())
            .map(|(x, y)| x ^ y)
            .collect::<Vec<u8>>(),
    );
    // Server-side identity, written out independently of the client's srp::identity():
    // I = base64url(SHA256(SHA256(skid) ‖ SHA256(email))).
    let mut inner = Sha256::digest(b"8MMQJN").to_vec();
    inner.extend_from_slice(&Sha256::digest(EMAIL.as_bytes()));
    let identity = b64(&Sha256::digest(&inner));
    m.update(Sha256::digest(identity.as_bytes()));
    m.update(&s.fx.srp_salt);
    m.update(a.to_bytes_be());
    m.update(b.to_bytes_be());
    m.update(k);
    let expected: [u8; 32] = m.finalize().into();
    if expected.as_slice() != client_hash.as_slice() {
        return ResponseTemplate::new(401).set_body_json(json!({}));
    }
    st.confirmed = true;
    let mut sh = Sha256::new();
    sh.update(a.to_bytes_be());
    sh.update(client_hash);
    sh.update(k);
    ResponseTemplate::new(200).set_body_json(json!({"serverVerifyHash": b64(&sh.finalize())}))
}

fn auth_complete(s: &Server, req: &Request) -> ResponseTemplate {
    assert!(s.check_mac(req), "bad MAC on auth/complete");
    let env: EncryptedObject = serde_json::from_slice(&req.body).unwrap();
    let body: Value = env.decrypt_json(&s.key()).unwrap();
    assert_eq!(body["device"]["name"], "onepw");
    let st = s.state.lock().unwrap();
    let mfa = json!({
        "totp": {"enabled": st.totp_code.is_some()},
        "duo": {"enabled": st.duo_required},
    });
    drop(st);
    s.encrypted(&json!({"userUuid": "USER1", "accountUuid": "ACC1", "mfa": mfa}))
}

/// `v1/auth/mfa`: checks the TOTP code. Like the real server, later requests in the session are
/// refused until the second factor is passed.
fn auth_mfa(s: &Server, req: &Request) -> ResponseTemplate {
    assert!(s.check_mac(req), "bad MAC on auth/mfa");
    let env: EncryptedObject = serde_json::from_slice(&req.body).unwrap();
    let body: Value = env.decrypt_json(&s.key()).unwrap();
    assert_eq!(body["sessionID"], SESSION_ID);
    assert!(
        body["client"].as_str().is_some_and(|c| c.contains('/')),
        "client name/version"
    );
    let mut st = s.state.lock().unwrap();
    st.mfa_requests += 1;
    if Some(body["totp"]["code"].as_str().unwrap()) != st.totp_code {
        return ResponseTemplate::new(401)
            .set_body_json(json!({"errorCode": 102, "errorMessage": "Incorrect code"}));
    }
    st.mfa_passed = true;
    drop(st);
    s.encrypted(&json!({}))
}

fn keysets(s: &Server, req: &Request) -> ResponseTemplate {
    assert!(s.check_mac(req), "bad MAC on keysets");
    let mut st = s.state.lock().unwrap();
    st.keysets_served += 1;
    if (st.totp_code.is_some() || st.duo_required) && !st.mfa_passed {
        return ResponseTemplate::new(401)
            .set_body_json(json!({"errorCode": 102, "errorMessage": "Second factor required"}));
    }
    drop(st);
    s.encrypted(&s.fx.keysets)
}

fn account(s: &Server, req: &Request) -> ResponseTemplate {
    assert!(s.check_mac(req), "bad MAC on account");
    let st = s.state.lock().unwrap();
    if st.plaintext_account {
        return ResponseTemplate::new(200).set_body_json(&s.fx.account);
    }
    if let Some(to) = &st.redirect_account {
        return ResponseTemplate::new(302).insert_header("Location", to.as_str());
    }
    if st.huge_account {
        return ResponseTemplate::new(200).set_body_string("x".repeat((64 << 20) + 1));
    }
    drop(st);
    s.encrypted(&s.fx.account)
}

fn items(s: &Server, req: &Request) -> ResponseTemplate {
    assert!(s.check_mac(req), "bad MAC on items");
    s.encrypted(&s.fx.items)
}

async fn mount(
    server: &MockServer,
    m: &'static str,
    p: &str,
    regex: bool,
    state: &Arc<Mutex<State>>,
    fx: &Arc<Fixture>,
    handler: fn(&Server, &Request) -> ResponseTemplate,
) {
    let responder = Server {
        state: state.clone(),
        fx: fx.clone(),
        handler,
    };
    let mock = if regex {
        Mock::given(method(m)).and(path_regex(p))
    } else {
        Mock::given(method(m)).and(path(p))
    };
    mock.respond_with(responder).mount(server).await;
}

fn creds(password: &str) -> Credentials {
    Credentials {
        email: "Patty@Dogs.Example".into(),
        password: Zeroizing::new(password.into()),
        secret_key: SecretKey::parse(SECRET_KEY).unwrap(),
        sign_in_address: "unused".into(),
    }
}

async fn setup() -> (MockServer, Arc<Mutex<State>>) {
    let server = MockServer::start().await;
    let state = Arc::new(Mutex::new(State::default()));
    let fx = Arc::new(fixture());
    mount(
        &server,
        "POST",
        "/api/v3/auth/start",
        false,
        &state,
        &fx,
        auth_start,
    )
    .await;
    mount(
        &server,
        "POST",
        "/api/v1/device",
        false,
        &state,
        &fx,
        device,
    )
    .await;
    mount(
        &server,
        "POST",
        "/api/v2/auth",
        false,
        &state,
        &fx,
        srp_auth,
    )
    .await;
    mount(
        &server,
        "POST",
        "/api/v2/auth/confirm-key",
        false,
        &state,
        &fx,
        confirm_key,
    )
    .await;
    mount(
        &server,
        "POST",
        "/api/v2/auth/complete",
        false,
        &state,
        &fx,
        auth_complete,
    )
    .await;
    mount(
        &server,
        "POST",
        "/api/v1/auth/mfa",
        false,
        &state,
        &fx,
        auth_mfa,
    )
    .await;
    mount(
        &server,
        "GET",
        "/api/v1/account/keysets",
        false,
        &state,
        &fx,
        keysets,
    )
    .await;
    mount(
        &server,
        "GET",
        "/api/v1/account",
        false,
        &state,
        &fx,
        account,
    )
    .await;
    mount(
        &server,
        "GET",
        r"^/api/v1/vault/[a-z0-9]+/0/items$",
        true,
        &state,
        &fx,
        items,
    )
    .await;
    (server, state)
}

fn opts(server: &MockServer) -> SignInOptions {
    let mut o = SignInOptions::new();
    o.base_url = Some(format!("{}/api/", server.uri()).parse().unwrap());
    o.min_kdf_iterations = 900; // the fixture uses few iterations (SRP 1000, AUK 900) to keep tests fast
    o
}

/// `opts` with a TOTP callback that returns `code` and counts its calls.
fn opts_with_totp(server: &MockServer, code: &'static str) -> (SignInOptions, Arc<AtomicU32>) {
    let calls = Arc::new(AtomicU32::new(0));
    let c = calls.clone();
    let mut o = opts(server);
    o.totp = Some(Box::new(move || {
        c.fetch_add(1, Ordering::SeqCst);
        Ok(code.to_string())
    }));
    (o, calls)
}

#[tokio::test]
async fn totp_code_is_sent_before_anything_else() {
    let (server, state) = setup().await;
    state.lock().unwrap().totp_code = Some("123456");
    // Whitespace around the code (as typed) is trimmed.
    let (o, calls) = opts_with_totp(&server, " 123456\n");
    let account = Account::sign_in(&creds(PASSWORD), o)
        .await
        .expect("sign in with 2FA");
    assert_eq!(calls.load(Ordering::SeqCst), 1, "asked for the code once");
    {
        let st = state.lock().unwrap();
        assert_eq!(st.mfa_requests, 1);
        assert!(st.mfa_passed);
        assert_eq!(st.keysets_served, 1, "keysets only fetched after 2FA");
    }
    assert_eq!(account.vaults().await.unwrap().len(), 2);
}

#[tokio::test]
async fn totp_code_also_needed_with_saved_unlock_keys() {
    let (server, state) = setup().await;
    let keys = Account::sign_in(&creds(PASSWORD), opts(&server))
        .await
        .expect("sign in without 2FA")
        .unlock_keys()
        .clone();
    state.lock().unwrap().totp_code = Some("654321");
    let (o, calls) = opts_with_totp(&server, "654321");
    let sk = SecretKey::parse(SECRET_KEY).unwrap();
    Account::sign_in_with_keys(EMAIL, "unused", &sk, &keys, o)
        .await
        .expect("Touch ID-style sign-in with 2FA");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(state.lock().unwrap().mfa_passed);
}

#[tokio::test]
async fn wrong_totp_code_fails_sign_in() {
    let (server, state) = setup().await;
    state.lock().unwrap().totp_code = Some("123456");
    let (o, _) = opts_with_totp(&server, "000000");
    let err = Account::sign_in(&creds(PASSWORD), o).await.unwrap_err();
    assert!(matches!(err, onepw::Error::InvalidInput(_)), "{err}");
    assert!(err.to_string().contains("2FA code not accepted"), "{err}");
    let st = state.lock().unwrap();
    assert_eq!(st.mfa_requests, 1);
    assert_eq!(st.keysets_served, 0, "sign-in stops at the wrong code");
}

#[tokio::test]
async fn missing_or_unsupported_second_factor_is_reported() {
    // TOTP required, but no callback to ask for the code: fail before sending anything.
    let (server, state) = setup().await;
    state.lock().unwrap().totp_code = Some("123456");
    let err = Account::sign_in(&creds(PASSWORD), opts(&server))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("needs a 2FA code"), "{err}");
    assert_eq!(state.lock().unwrap().mfa_requests, 0);

    // Only Duo: not supported, and no code is asked for.
    let (server, state) = setup().await;
    state.lock().unwrap().duo_required = true;
    let (o, calls) = opts_with_totp(&server, "123456");
    let err = Account::sign_in(&creds(PASSWORD), o).await.unwrap_err();
    assert!(err.to_string().contains("only authenticator-app"), "{err}");
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(state.lock().unwrap().keysets_served, 0);
}

#[tokio::test]
async fn plaintext_response_after_sign_in_is_refused() {
    let (server, state) = setup().await;
    let account = Account::sign_in(&creds(PASSWORD), opts(&server))
        .await
        .expect("sign in");
    state.lock().unwrap().plaintext_account = true;
    let err = account.vaults().await.unwrap_err();
    assert!(err.to_string().contains("not encrypted"), "{err}");
}

#[tokio::test]
async fn redirects_are_not_followed() {
    let (server, state) = setup().await;
    let elsewhere = MockServer::start().await;
    Mock::given(wiremock::matchers::any())
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .expect(0) // verified when `elsewhere` is dropped
        .mount(&elsewhere)
        .await;
    let account = Account::sign_in(&creds(PASSWORD), opts(&server))
        .await
        .expect("sign in");
    state.lock().unwrap().redirect_account = Some(format!("{}/api/v1/account", elsewhere.uri()));
    let err = account.vaults().await.unwrap_err();
    assert!(err.to_string().contains("302"), "{err}");
}

#[tokio::test]
async fn oversized_response_is_refused() {
    let (server, state) = setup().await;
    let account = Account::sign_in(&creds(PASSWORD), opts(&server))
        .await
        .expect("sign in");
    state.lock().unwrap().huge_account = true;
    let err = account.vaults().await.unwrap_err();
    assert!(err.to_string().contains("too large"), "{err}");
}

#[tokio::test]
async fn non_onepassword_address_is_refused() {
    let mut o = SignInOptions::new();
    o.min_kdf_iterations = 1000;
    let mut c = creds(PASSWORD);
    c.sign_in_address = "my.1passw0rd.com".into();
    let err = Account::sign_in(&c, o).await.unwrap_err();
    assert!(err.to_string().contains("not a 1Password domain"), "{err}");
}

#[tokio::test]
async fn low_account_unlock_key_iterations_are_refused() {
    let (server, _state) = setup().await;
    let mut o = opts(&server);
    o.min_kdf_iterations = 950; // SRP's 1000 passes, the AUK's 900 must not
    let err = Account::sign_in(&creds(PASSWORD), o).await.unwrap_err();
    assert!(
        err.to_string().contains("900 key-derivation iterations"),
        "{err}"
    );
}

#[tokio::test]
async fn low_kdf_iteration_count_is_refused() {
    let (server, _state) = setup().await;
    let mut o = opts(&server);
    o.min_kdf_iterations = onepw::client::MIN_KDF_ITERATIONS; // fixture sends 1000
    let err = Account::sign_in(&creds(PASSWORD), o).await.unwrap_err();
    assert!(err.to_string().contains("iterations"), "{err}");
}

#[tokio::test]
async fn full_sign_in_and_read() {
    let (server, state) = setup().await;
    let account = Account::sign_in(&creds(PASSWORD), opts(&server))
        .await
        .expect("sign in");
    assert_eq!(account.user_uuid(), Some("USER1"));
    {
        let st = state.lock().unwrap();
        assert!(st.device_registered, "device registration path ran");
        assert_eq!(st.starts, 2);
        assert!(st.confirmed);
    }

    let vaults = account.vaults().await.unwrap();
    assert_eq!(vaults.len(), 2, "vault without read ACL is skipped");
    assert_eq!(vaults[0].name(), "Private");
    assert_eq!(
        vaults[1].name(),
        "Shared",
        "vault reached through an RSA-wrapped group keyset"
    );

    let items = account.items(&vaults[0]).await.unwrap();
    assert_eq!(items.len(), 3);
    let gh = items.iter().find(|i| i.title() == "GitHub").unwrap();
    let field = |name: &str| gh.field(name).unwrap().map(|v| v.to_string());
    assert_eq!(field("username").as_deref(), Some("patty"));
    assert_eq!(field("password").as_deref(), Some("hunter2"));
    assert_eq!(field("nope"), None);

    // Secrets never show up in Debug output.
    let fields = gh.fields().unwrap();
    assert!(fields.iter().any(|f| f.value.as_str() == "hunter2"));
    for dbg in [
        format!("{gh:?}"),
        format!("{fields:?}"),
        format!("{:?}", gh.details().unwrap()),
        format!("{items:?}"),
    ] {
        assert!(!dbg.contains("hunter2"), "secret leaked in Debug: {dbg}");
        assert!(!dbg.contains("patty"), "value leaked in Debug: {dbg}");
    }
    assert!(format!("{gh:?}").contains("GitHub"));

    let key = account
        .read("op://Private/Anthropic API/credential")
        .await
        .unwrap();
    assert_eq!(key.as_str(), "sk-test-123");
    assert!(
        account.read("op://Private/Old/password").await.is_err(),
        "trashed items are not resolved"
    );

    assert!(state.lock().unwrap().macs_checked >= 6);
}

#[tokio::test]
async fn wrong_password_is_reported() {
    let (server, _state) = setup().await;
    let err = Account::sign_in(&creds("wrong password"), opts(&server))
        .await
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("wrong account password or Secret Key"),
        "{err}"
    );
}

#[tokio::test]
async fn sign_in_with_saved_unlock_keys() {
    let (server, _state) = setup().await;
    let first = Account::sign_in(&creds(PASSWORD), opts(&server))
        .await
        .expect("password sign-in");
    let saved = first.unlock_keys().to_bytes();

    // Second sign-in: no password, only the stored keys.
    let keys = onepw::UnlockKeys::from_bytes(saved.as_ref()).unwrap();
    let sk = SecretKey::parse(SECRET_KEY).unwrap();
    let again = Account::sign_in_with_keys(EMAIL, "unused", &sk, &keys, opts(&server))
        .await
        .expect("keys sign-in");
    assert_eq!(
        again
            .read("op://Private/GitHub/password")
            .await
            .unwrap()
            .as_str(),
        "hunter2"
    );

    // Stale keys (e.g. after a password change) give a clear error.
    let mut bad = *saved;
    bad[0] ^= 1;
    let stale = onepw::UnlockKeys::from_bytes(&bad).unwrap();
    let err = Account::sign_in_with_keys(EMAIL, "unused", &sk, &stale, opts(&server))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("out of date"), "{err}");
}
