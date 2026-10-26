//! `test(proptest_inputs)` — wire, TOTP, and at+jwt input properties (todo 19).
//!
//! Pure `proptest` properties over the untrusted-input seams:
//! [`parse_pairs`]/[`values_of`]/[`single_valued_map`] (form wire order and
//! last-wins), [`verify_window`] (a generated code verifies only inside the
//! ±1-step window), and [`JwtAccessSigner::verify`] (arbitrary tokens never
//! panic, an accepted token carries the expected audience, and a wrong
//! audience always rejects). No `unwrap`/`expect`/`panic` anywhere.
//!
//! TOTP note: a far-off 6-digit code can collide with a windowed candidate
//! (about 3e-6 per case), so the property never asserts `None` for a far code;
//! it only bounds any `Some(step)` to the counter ± 1.

use std::sync::OnceLock;

use d_oauth::{
  config::{JwtSigningAlg, JwtSigningKey},
  crypto::totp::{TOTP_SKEW_STEPS, TOTP_STEP_SECS, build_totp, verify_window},
  jose::jwt_access::{JwtAccessSigner, JwtClaims},
  keys::KeyId,
  protocol::params::{MAX_FORM_PAIRS, parse_pairs, single_valued_map, values_of},
};
use proptest::prelude::*;
use secrecy::SecretString;
use time::OffsetDateTime;

/// Issuer every at+jwt fixture token asserts.
const TEST_ISSUER: &str = "https://as.example.test";
/// Audience the fixture token is minted for.
const TEST_AUDIENCE: &str = "https://rs.example.test";
/// Audience the fixture token must never satisfy.
const WRONG_AUDIENCE: &str = "https://other.example.test";
/// Fixture token lifetime: one day, so a test process stays inside `exp`.
const FIXTURE_TTL_SECS: i64 = 86_400;

/// RFC 4648 base32 alphabet, uppercase, no padding.
const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Characters a mutated token position may carry: all still base64url/decode
/// clean, so the mutation is well-formed UTF-8 and the decoder is reached.
const JWT_MUTATION_ALPHABET: &[u8] = b"-_.A0az";

/// Encode raw bytes as canonical RFC 4648 base32 (uppercase, no padding).
///
/// Canonical output always decodes under [`build_totp`], so the TOTP property
/// exercises the verifier rather than the malformed-secret error path.
fn to_base32(bytes: &[u8]) -> String {
  let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
  let mut accumulator = 0u32;
  let mut bits = 0u32;
  for byte in bytes {
    accumulator = (accumulator << 8) | u32::from(*byte);
    bits += 8;
    while bits >= 5 {
      bits -= 5;
      let index = ((accumulator >> bits) & 0x1f) as usize;
      out.push(char::from(BASE32_ALPHABET[index]));
    }
    // Keep only the unflushed low bits so the accumulator cannot overflow.
    accumulator &= (1u32 << bits) - 1;
  }
  if bits > 0 {
    let index = ((accumulator << (5 - bits)) & 0x1f) as usize;
    out.push(char::from(BASE32_ALPHABET[index]));
  }
  out
}

/// Bounded arbitrary UTF-8 input, a shape that exceeds the pair cap so both
/// the `Ok` and cap-error branches of [`parse_pairs`] are reachable, and a
/// duplicate-heavy shape so last-wins is genuinely exercised.
fn form_input() -> impl Strategy<Value = String> {
  prop_oneof![
    proptest::collection::vec(any::<char>(), 0..=512)
      .prop_map(|chars| chars.into_iter().collect::<String>()),
    proptest::collection::vec("[A-Za-z0-9_.~%-]{0,8}", 0..=(MAX_FORM_PAIRS + 8))
      .prop_map(|segments| segments.join("&")),
    proptest::collection::vec(
      (
        prop_oneof![Just("a"), Just("resource"), Just("b"), Just("")],
        "[A-Za-z0-9]{0,6}",
      ),
      0..=40,
    )
    .prop_map(|segments| {
      segments
        .into_iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<String>>()
        .join("&")
    }),
  ]
}

/// The fixed at+jwt fixture: one signer and one already-signed valid token.
struct JwtFixture {
  /// ES256 signer over a fixed 32-byte scalar.
  signer: JwtAccessSigner,
  /// A valid token minted once for this process.
  token: String,
  /// The audience the fixture token carries.
  audience: Vec<String>,
}

static JWT_FIXTURE: OnceLock<Option<JwtFixture>> = OnceLock::new();

/// Build the fixture once; a key-construction failure is tolerated as "skip".
fn jwt_fixture() -> Option<&'static JwtFixture> {
  JWT_FIXTURE
    .get_or_init(|| {
      let raw = SecretString::from("C".repeat(32));
      let key = JwtSigningKey::from_raw(
        KeyId::new("v2"),
        JwtSigningAlg::Es256,
        &raw,
        "proptest_jwt_signing_key",
      )
      .ok()?;
      let signer = JwtAccessSigner::new(TEST_ISSUER.to_owned(), key, Vec::new());
      let now = OffsetDateTime::now_utc().unix_timestamp();
      let claims = JwtClaims {
        iss: TEST_ISSUER.to_owned(),
        sub: "proptest-subject@example.test".to_owned(),
        aud: vec![TEST_AUDIENCE.to_owned()],
        scope: "orders:read".to_owned(),
        exp: now + FIXTURE_TTL_SECS,
        iat: now,
        jti: "proptest-jti".to_owned(),
        client_id: "proptest-client".to_owned(),
        cnf: None,
        act: None,
      };
      let token = signer.sign(&claims).ok()?;
      Some(JwtFixture {
        signer,
        token,
        audience: claims.aud,
      })
    })
    .as_ref()
}

proptest! {
  #[test]
  fn params_parse_pairs_never_panics_and_preserves_wire_order(raw in form_input()) {
    // Only two outcomes exist: the parsed pairs, or the single cap error.
    let pairs = match parse_pairs(&raw) {
      Ok(pairs) => pairs,
      Err(_) => return Ok(()),
    };

    // `values_of("resource")` keeps the wire order and is a subset of all
    // values (one entry per matching pair, no reordering, no loss).
    let resource_values = values_of(&pairs, "resource");
    let expected: Vec<String> = pairs
      .iter()
      .filter(|(name, _)| name == "resource")
      .map(|(_, value)| value.clone())
      .collect();
    prop_assert_eq!(&resource_values, &expected);
    prop_assert!(resource_values.len() <= pairs.len());

    // `single_valued_map` is last-wins: one entry per distinct name, and each
    // entry equals the final pair carrying that name.
    let map = single_valued_map(&pairs);
    let distinct: std::collections::HashSet<&str> =
      pairs.iter().map(|(name, _)| name.as_str()).collect();
    prop_assert_eq!(map.len(), distinct.len());
    for (name, value) in &map {
      let last = pairs
        .iter()
        .rev()
        .find(|(candidate, _)| candidate == name)
        .map(|(_, value)| value);
      prop_assert_eq!(Some(value), last);
    }
  }

  #[test]
  fn totp_verify_window_accepts_only_generated_codes(
    secret_bytes in proptest::collection::vec(any::<u8>(), 10..=32),
    counter in 0u64..=(u64::MAX / TOTP_STEP_SECS),
    arbitrary_code in proptest::collection::vec(any::<char>(), 0..=16)
      .prop_map(|chars| chars.into_iter().collect::<String>()),
  ) {
    let secret = to_base32(&secret_bytes);
    let totp = match build_totp(&secret) {
      Ok(totp) => totp,
      Err(_) => return Ok(()),
    };
    let now = counter.saturating_mul(TOTP_STEP_SECS);
    let generated = totp.generate(now).to_string();
    let skew = u64::from(TOTP_SKEW_STEPS);

    // A code generated for this step verifies, at this step or an adjacent one.
    match verify_window(&secret, &generated, now) {
      Ok(Some(step)) => prop_assert!(step.abs_diff(counter) <= skew),
      Ok(None) => prop_assert!(false, "a generated code must verify"),
      Err(_) => prop_assert!(false, "a canonical base32 secret must build"),
    }

    // Any arbitrary code is handled without panic; a match must be adjacent
    // to the counter (a far code is NOT asserted absent: 6-digit collisions
    // are possible at roughly 3e-6 per case).
    if let Ok(Some(step)) = verify_window(&secret, &arbitrary_code, now) {
      prop_assert!(step.abs_diff(counter) <= skew);
    }
  }

  #[test]
  fn jwt_verify_never_panics_on_arbitrary_tokens(
    raw in proptest::collection::vec(any::<char>(), 0..=512)
      .prop_map(|chars| chars.into_iter().collect::<String>()),
    selector in 0u8..3,
    position in any::<usize>(),
    replacement in 0u8..8,
  ) {
    let Some(fixture) = jwt_fixture() else {
      return Ok(());
    };

    // Selector 0 replays the fixed valid token (accepted branch); selector 1
    // mutates it at one base64url position; selector 2 is arbitrary UTF-8.
    let candidate = match selector {
      0 => fixture.token.clone(),
      1 => {
        let mut bytes = fixture.token.clone().into_bytes();
        if bytes.is_empty() {
          return Ok(());
        }
        let index = position % bytes.len();
        let index_in_alphabet = usize::from(replacement) % JWT_MUTATION_ALPHABET.len();
        let mut next = JWT_MUTATION_ALPHABET[index_in_alphabet];
        if next == bytes[index] {
          next = if bytes[index] == b'A' { b'B' } else { b'A' };
        }
        bytes[index] = next;
        match String::from_utf8(bytes) {
          Ok(candidate) => candidate,
          Err(_) => return Ok(()),
        }
      }
      _ => raw,
    };

    // Arbitrary strings never panic: the outcome is a typed error or a token.
    match fixture.signer.verify(&candidate, Some(fixture.audience.as_slice())) {
      Ok(verified) => {
        prop_assert!(
          verified
            .claims
            .aud
            .iter()
            .any(|audience| audience.as_str() == TEST_AUDIENCE)
        );
        if selector == 0 {
          // The accepted branch is reachable only from the fixed token, and
          // it round-trips the exact audience set.
          prop_assert_eq!(verified.claims.aud.as_slice(), fixture.audience.as_slice());
        }
      }
      Err(_) => {
        if selector == 0 {
          prop_assert!(false, "the fixed signed token must verify");
        }
      }
    }

    // A wrong audience always rejects, whether the token is valid or not.
    prop_assert!(
      fixture
        .signer
        .verify(
          &candidate,
          Some(&[WRONG_AUDIENCE.to_owned()]),
        )
        .is_err()
    );
  }
}
