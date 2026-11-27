//! The engine's own calls between its services (Collector → Generator → Decision) carry a token
//! in [`HEADER`] when one is set (`WITHHUMAN_INTERNAL_TOKEN`, or `withhuman-local`'s, made new at
//! each start), and the Generator and Decision then take nothing else but `/healthz`. Without one
//! they take every call, as inside a cluster's own network.

use std::env;

/// The header the token travels in.
pub const HEADER: &str = "x-withhuman-internal";

/// `WITHHUMAN_INTERNAL_TOKEN`, when set and not empty.
pub fn token_from_env() -> Option<String> {
    env::var("WITHHUMAN_INTERNAL_TOKEN")
        .ok()
        .map(|token| token.trim().to_owned())
        .filter(|token| !token.is_empty())
}

/// Whether `given` is `token`, compared in time that does not depend on where they differ.
pub fn matches(given: &str, token: &str) -> bool {
    let (a, b) = (given.as_bytes(), token.as_bytes());
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |diff, (x, y)| diff | (x ^ y)) == 0
}

/// Whether a request for `path` with `given` in [`HEADER`] may go on, when `token` is required.
pub fn admits(path: &str, given: Option<&str>, token: &str) -> bool {
    path == "/healthz" || given.is_some_and(|given| matches(given, token))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_token_or_the_health_check_goes_through() {
        assert!(admits("/v1/clients", Some("s3cret"), "s3cret"));
        assert!(!admits("/v1/clients", Some("s3cre"), "s3cret"));
        assert!(!admits("/v1/clients", Some("s3creT"), "s3cret"));
        assert!(!admits("/v1/clients", None, "s3cret"));
        assert!(admits("/healthz", None, "s3cret"));
    }
}
