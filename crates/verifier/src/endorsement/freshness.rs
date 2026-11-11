//! Freshness witnesses of the repository-release flow: a statement, signed
//! by the witness workflow and logged, that a release was current when the
//! log recorded it.

use std::time::Duration;

use super::EndorsementError;
use super::provenance::ProvenanceClient;
use super::reference::AuthenticatedArtifact;
use crate::instant::Instant;
use crate::json::Value;
use crate::stub::pending;

/// The predicate type and format of a freshness witness.
pub const FRESHNESS_PREDICATE_FORMAT: &str = "https://tinfoil.sh/predicate/freshness-witness/v1";
/// The greatest age of a witness when the caller sets none: seven days.
pub const MAX_FRESHNESS_AGE: Duration = Duration::from_secs(7 * 24 * 60 * 60);
/// How far ahead of the appraisal time a witness may be dated: five minutes.
pub const MAX_FRESHNESS_FUTURE_SKEW: Duration = Duration::from_secs(5 * 60);

impl ProvenanceClient {
    /// Authenticates a freshness witness for an authenticated release, and
    /// returns the time at which the transparency log recorded the witness.
    ///
    /// `max_age` of `None` selects [`MAX_FRESHNESS_AGE`]. In order:
    ///
    /// 1. `expected` has its form ([`AuthenticatedArtifact::validate`]);
    /// 2. the bundle verifies for
    ///    [`WorkflowIdentity::freshness_witness`](super::reference::WorkflowIdentity::freshness_witness)
    ///    and `expected.digest`, with the first-subject rule;
    /// 3. the payload is a strict JSON statement with a closed set of
    ///    members at every level: `_type` is the in-toto v1 statement type;
    ///    `predicateType` and the predicate's `format` are
    ///    [`FRESHNESS_PREDICATE_FORMAT`]; there is exactly one subject,
    ///    whose name is `expected.subject_name` and whose SHA-256 digest is
    ///    `expected.digest`, compared exactly;
    /// 4. the predicate's `endorses` names the release: `repo`, `tag` and
    ///    `commit` equal those of `expected`, and its `subject` has the
    ///    expected name and the digest `sha256:` followed by
    ///    `expected.digest`;
    /// 5. the witness time is the earliest verified transparency-log time
    ///    of the bundle
    ///    ([`VerifiedBundle::earliest_log_time`](crate::sigstore::certificate::VerifiedBundle::earliest_log_time));
    ///    a bundle without one is rejected;
    /// 6. the witness time is not more than
    ///    [`MAX_FRESHNESS_FUTURE_SKEW`] after `now`, and `now` is not more
    ///    than the greatest age after it.
    pub fn authenticate_freshness(
        &self,
        bundle: &Value,
        expected: &AuthenticatedArtifact,
        now: Instant,
        max_age: Option<Duration>,
    ) -> Result<Instant, EndorsementError> {
        pending("endorsement::freshness::ProvenanceClient::authenticate_freshness")
    }
}
