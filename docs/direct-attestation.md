# Direct-node V3 attestation

This contribution adds `SecureClient::new_direct` and `Client::new_direct` for a fixed
hostname and caller-approved current/staged releases. It follows the V3
envelope and legacy code/platform collateral used by Tinfoil CLI v0.19.7 and its
exact Go dependency `4e83c0ce632fe33253b36e9f553ad3eeb373acf3`.
Tinfoil documents this V3 verification path as beta during deployment. This
implementation is a scoped port with its own tests, not a claim of complete
Go SDK or PKIX conformance.

## Supported path

- AMD SEV-SNP with explicit Genoa/Turin product roots and report appraisal.
- V3 nonce-bound envelope, with omitted or explicit
  `https://tinfoil.sh/predicate/attestation-collaterals/v2` collateral.
- Signed code release and platform endorsements, authenticated freshness
  witnesses, mandatory AMD CRL and the machine's complete endorsed SNP policy.
- Direct TLS with CA/hostname validation, attested SPKI fingerprint, HTTPS and
  origin binding, no ambient proxy, and request-level freshness enforcement.

TDX and newer config/runtime collateral v3 fail explicitly. There is no automatic
fallback to legacy verification or shared-router discovery. Existing constructors
keep the existing legacy path; this change does not make the new mode global.
EHBP remains the separate upstream option for body encryption through an
intermediary. Direct mode uses Tinfoil's established attested TLS approach.

## Approved identity

Build a `DirectPolicy` from `ApprovedRelease` entries. Each entry requires an
explicit repository, tag, SHA-256 release digest and SNP or multiplatform
measurement. Supply reviewed values from the release qualification process;
never learn the allowlist from the unverified endpoint. A current and staged
release can coexist while a node is upgraded.

```rust,ignore
use tinfoil::{ApprovedRelease, Client, DirectPolicy, Measurement, PinnedRelease};

let policy = DirectPolicy::new(vec![ApprovedRelease {
    release: PinnedRelease {
        repo: approved_repo,
        tag: approved_tag,
        digest: approved_sha256,
    },
    measurement: approved_measurement,
}])?;
let client = Client::new_direct(node_hostname, application_api_key, policy).await?;
let response = client.http_client()?
    .get(format!("https://{}/health", client.enclave()))
    .send().await?;
```

Attestation runs before the application credential is used. The bootstrap request
contains a fresh 32-byte nonce and no API key. Supplied release hints must match a
caller-approved entry, then satisfy code signature, identity, measurement,
platform-policy and freshness checks. Candidate machine-policy selection uses the
same CPU report subsequently signature-verified; untrusted metadata cannot add a
trusted machine or policy.

Crypto/device sections are hashed over their exact base64-decoded bytes without
JSON reserialization. The CPU quote must bind the nonce and both hashes via the
standard `https://tinfoil.sh/report-data/v1` derivation. Only then may the TLS/HPKE
keys be trusted. GPU evidence is hash-bound into this CPU evidence; it is not
independently NVIDIA-signature-appraised by this client. The measured CVM runtime
owns that verification, matching the referenced Go/CLI assurance boundary.

## Expiry and refresh

Witness age is bounded to seven days with five minutes of permitted future clock
skew. Expiry derives from the older authenticated witness timestamp, not local
verification time. Reverification of unchanged witnesses does not renew expiry.

New requests fail at expiry, including requests using an existing pooled TLS
connection, cloned raw clients, split builders and typed calls. The transport
also uses a monotonic deadline to prevent local clock rollback extending an
already established authorization. In-flight streams may finish. Failed
reverification revokes previously escaped direct transports. The application
owns refresh scheduling and any separately authorized retry policy; direct mode
does not replay inference POSTs as part of attestation refresh.

## Qualification

The library tests use offline fixtures and local mock servers. Existing
integration tests elsewhere in this repository contact live services; run
those separately in a suitable environment.

```sh
cargo test --locked --lib
cargo test --locked --test verification_negative test_not_verified
```

The `direct_node_probe` example runs only with explicit operator arguments and
sends no inference requests or credentials:

```sh
cargo run --locked --example direct_node_probe -- \
  offline POLICY.json CAPTURED_DOCUMENT.json ORIGINAL_NONCE_HEX
cargo run --locked --example direct_node_probe -- \
  live POLICY.json NODE_HOSTNAME
```

Policy file schema:

```json
{
  "approved": [{
    "repo": "owner/model-config",
    "tag": "v1.0.0",
    "digest": "REPLACE_WITH_64_LOWERCASE_HEX_CHARACTERS",
    "measurement": {
      "type": "https://tinfoil.sh/predicate/sev-snp-guest/v2",
      "registers": ["REPLACE_WITH_96_LOWERCASE_HEX_CHARACTERS"]
    }
  }]
}
```

The live probe verifies V3 and then requests `/health` and `/v1/models` through
the pinned transport. It rejects plaintext and alternate-port requests before
dispatch. Select only infrastructure you are authorized to test. Captured
documents are challenge-specific evidence, not a substitute for a fresh live
nonce. Keep private deployment captures outside this public repository.

The CPU certificate path retains the upstream Rust implementation's manual
X.509 validation rather than replicating every Go PKIX rule. Per-product AMD
roots/intermediate pins, chain/report signatures, TCB/HWID/policy and mandatory
CRL checks are tested. This is not a comprehensive cryptographic audit or a
claim of support for arbitrary future AMD certificate layouts.

## Reference implementations

- [CLI v0.19.7](https://github.com/tinfoilsh/tinfoil-cli/tree/v0.19.7)
- [Exact Go dependency](https://github.com/tinfoilsh/tinfoil-go/tree/4e83c0ce632fe33253b36e9f553ad3eeb373acf3)
- [Tinfoil go-sev-guest](https://github.com/tinfoilsh/go-sev-guest/tree/bec7bdb637fdd93ee5b0ed63b350683b4dc19959)
- [Verification feature status](https://docs.tinfoil.sh/resources/feature-status)
- [Container connections](https://docs.tinfoil.sh/containers/connecting)
