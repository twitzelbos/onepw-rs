//! The `X-AgileBits-MAC` request header.
//!
//! Construction as specified by 1Password's own session analyzer
//! (github.com/1Password/burp-1password-session-analyzer, BSD-3-Clause):
//!
//! ```text
//! mac_key = HMAC-SHA256(K, "He never wears a Mac, in the pouring rain. Very strange.")
//! message = "{sessionID}|{METHOD}|{host}/{path without leading /}?{query}|v1|{requestId}"
//! header  = "v1|{requestId}|" + base64url(HMAC-SHA256(mac_key, message)[..12])
//! ```
//!
//! `host` is lowercase and without the port; `?` is always present. The body is not covered.

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::b64;

const DERIVATION_MESSAGE: &[u8] = b"He never wears a Mac, in the pouring rain. Very strange.";

/// Computes the header value for one request.
pub fn request_mac(
    session_key: &[u8; 32],
    session_id: &str,
    request_id: u32,
    method: &str,
    url: &reqwest::Url,
) -> String {
    let mut derive = <Hmac<Sha256> as Mac>::new_from_slice(session_key).expect("any key length");
    derive.update(DERIVATION_MESSAGE);
    let mac_key = derive.finalize().into_bytes();

    let host = url.host_str().unwrap_or_default().to_ascii_lowercase();
    let path = url.path().trim_start_matches('/');
    let query = url.query().unwrap_or("");
    let message = format!("{session_id}|{}|{host}/{path}?{query}|v1|{request_id}", method.to_ascii_uppercase());

    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&mac_key).expect("any key length");
    mac.update(message.as_bytes());
    let tag = mac.finalize().into_bytes();
    format!("v1|{request_id}|{}", b64::encode(&tag[..12]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(s: &str) -> [u8; 32] {
        b64::decode(s).unwrap().try_into().unwrap()
    }

    // Known answers from 1Password's burp-1password-session-analyzer RequestMACTests.java (BSD-3).
    #[test]
    fn matches_1password_vectors() {
        let cases: [(&str, &str, u32, &str, &str, &str); 5] = [
            ("v1|6|oBnE8JLpG2Othzgy", "RDPMIFQWUJBWZFDBKURHNRFVRA", 6, "GET",
             "https://my.b5local.com:3000/api/v1/invites", "ETmGs4U7ReMolW1J64ZAmmksXbQFFbeyRPW6zPWj3VM"),
            ("v1|7|E2w1PDPlDRKaVEQs", "RDPMIFQWUJBWZFDBKURHNRFVRA", 7, "GET",
             "https://my.b5local.com:3000/api/v2/users?limit=25&states=P&types=G,R", "ETmGs4U7ReMolW1J64ZAmmksXbQFFbeyRPW6zPWj3VM"),
            ("v1|7|JDqt1exoqPCjZiAJ", "QVLABIG34RB3TMH7ZJEW47CCKE", 7, "GET",
             "https://my.b5local.com:3000/api/v1/vaults?permission=read&attrs=accessor-previews%2Ccombined-access",
             "-K_oZ-mtamTiLJODQn5cVhXQX-nFmPI2kosmWmOWfZg"),
            ("v1|3907223784|Htb-Sn_9k4u59wOz", "VADBXWG7FVC6FIOKOJ4DBGE4SY", 3907223784, "DELETE",
             "https://awesome.b5dev.com/api/v1/vault/p3nfd4jax622nqjos7licewuyn", "xvoJlJo7KkJGQ55-mjd7tOBE6YvRYnGBNpPoo3_F2M0"),
            ("v1|781158249|kkvpSd6stufwwlsZ", "2UG2ZGCDLFAWRHPETAV325EL5U", 781158249, "GET",
             "https://awesome.b5dev.com/api/v1/auditevents/0/older?object_types=gva,invite", "WDs9nvg0DYYmQmucwPZ25FV6uUSaYsJUgse7apbs6rk"),
        ];
        for (expected, sid, rid, method, url, k) in cases {
            let url = reqwest::Url::parse(url).unwrap();
            assert_eq!(request_mac(&key(k), sid, rid, method, &url), expected, "{url}");
        }
    }
}
