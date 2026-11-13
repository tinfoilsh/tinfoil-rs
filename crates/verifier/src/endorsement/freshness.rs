//! Freshness witnesses of the repository-release flow: a statement, signed
//! by the witness workflow and logged, that a release was current when the
//! log recorded it.

use std::time::Duration;

use super::EndorsementError;
use super::provenance::ProvenanceClient;
use super::reference::{AuthenticatedArtifact, WorkflowIdentity};
use super::wire;
use crate::instant::Instant;
use crate::json::Value;
use crate::sigstore::statement::{DIGEST_ALGORITHM, STATEMENT_TYPE};

/// The predicate type and format of a freshness witness.
pub const FRESHNESS_PREDICATE_FORMAT: &str = "https://tinfoil.sh/predicate/freshness-witness/v1";
/// The greatest age of a witness when the caller sets none: seven days.
pub const MAX_FRESHNESS_AGE: Duration = Duration::from_secs(7 * 24 * 60 * 60);
/// How far ahead of the appraisal time a witness may be dated: five minutes.
pub const MAX_FRESHNESS_FUTURE_SKEW: Duration = Duration::from_secs(5 * 60);

/// What a freshness witness says that it endorses. A member that the
/// witness leaves out is empty.
#[derive(Debug, Default)]
struct Witness<'a> {
    format: &'a str,
    repo: &'a str,
    tag: &'a str,
    commit: &'a str,
    subject_name: &'a str,
    subject_digest: &'a str,
}

impl<'a> Witness<'a> {
    /// Reads the predicate of a witness statement: an object with `format`
    /// and `endorses` only, where `endorses` has `repo`, `tag`, `commit`
    /// and `subject` only, and `subject` has `name` and `digest` only.
    /// Every leaf is a string.
    fn from_predicate(predicate: &'a Value) -> Result<Self, EndorsementError> {
        let predicate = wire::object(Some(predicate), "predicate", &["format", "endorses"])?;
        let endorses = wire::object(
            predicate.and_then(|predicate| predicate.get("endorses")),
            "endorses",
            &["repo", "tag", "commit", "subject"],
        )?;
        let subject = wire::object(
            endorses.and_then(|endorses| endorses.get("subject")),
            "subject",
            &["name", "digest"],
        )?;
        Ok(Self {
            format: wire::text(predicate, "format")?,
            repo: wire::text(endorses, "repo")?,
            tag: wire::text(endorses, "tag")?,
            commit: wire::text(endorses, "commit")?,
            subject_name: wire::text(subject, "name")?,
            subject_digest: wire::text(subject, "digest")?,
        })
    }
}

impl ProvenanceClient {
    /// Authenticates a freshness witness for an authenticated release, and
    /// returns the time at which the transparency log recorded the witness.
    ///
    /// `max_age` of `None` selects [`MAX_FRESHNESS_AGE`]; a given duration
    /// is used as it is, so a zero age accepts only a witness logged at or
    /// after `now`. In order:
    ///
    /// 1. `expected` has its form ([`AuthenticatedArtifact::validate`]);
    /// 2. the bundle verifies for
    ///    [`WorkflowIdentity::freshness_witness`](super::reference::WorkflowIdentity::freshness_witness)
    ///    and `expected.digest`, with the first-subject rule;
    /// 3. the statement has a closed set of members at every level, the
    ///    predicate included, and every leaf of the predicate is a string;
    /// 4. `_type` is the in-toto v1 statement type; `predicateType` and the
    ///    predicate's `format` are [`FRESHNESS_PREDICATE_FORMAT`]; there is
    ///    exactly one subject, whose name is `expected.subject_name` and
    ///    whose SHA-256 digest is `expected.digest`, compared exactly;
    /// 5. the predicate's `endorses` names the release: `repo`, `tag` and
    ///    `commit` equal those of `expected`, and its `subject` has the
    ///    expected name and the digest `sha256:` followed by
    ///    `expected.digest`;
    /// 6. the witness time is the earliest verified transparency-log time
    ///    of the bundle
    ///    ([`VerifiedBundle::earliest_log_time`](crate::sigstore::certificate::VerifiedBundle::earliest_log_time));
    ///    a bundle without one is rejected;
    /// 7. the witness time is not more than
    ///    [`MAX_FRESHNESS_FUTURE_SKEW`] after `now`, and `now` is not more
    ///    than the greatest age after it.
    pub fn authenticate_freshness(
        &self,
        bundle: &Value,
        expected: &AuthenticatedArtifact,
        now: Instant,
        max_age: Option<Duration>,
    ) -> Result<Instant, EndorsementError> {
        expected.validate()?;
        let verified = self
            .verify_bundle_for_subject(
                bundle,
                &WorkflowIdentity::freshness_witness(),
                &expected.digest,
                None,
            )
            .map_err(|cause| cause.within("verifying freshness witness bundle"))?;
        let statement = &verified.statement;
        let witness = Witness::from_predicate(&statement.predicate)
            .map_err(|cause| cause.within("parsing freshness statement"))?;
        if statement.statement_type != STATEMENT_TYPE {
            return Err(EndorsementError::new(format!(
                "unexpected freshness statement type {:?}",
                statement.statement_type
            )));
        }
        if statement.predicate_type != FRESHNESS_PREDICATE_FORMAT
            || witness.format != FRESHNESS_PREDICATE_FORMAT
        {
            return Err(EndorsementError::new(
                "unexpected freshness predicate format",
            ));
        }
        let subject_matches = match statement.subjects.as_slice() {
            [subject] => {
                subject.name == expected.subject_name
                    && subject.digest.get(DIGEST_ALGORITHM) == Some(&expected.digest)
            }
            _ => false,
        };
        if !subject_matches {
            return Err(EndorsementError::new(
                "freshness statement subject does not match authenticated artifact",
            ));
        }
        let endorses_expected = witness.repo == expected.repo
            && witness.tag == expected.tag
            && witness.commit == expected.commit
            && witness.subject_name == expected.subject_name
            && witness
                .subject_digest
                .strip_prefix("sha256:")
                .is_some_and(|digest| digest == expected.digest);
        if !endorses_expected {
            return Err(EndorsementError::new(
                "freshness witness does not match authenticated artifact",
            ));
        }
        let Some(logged_at) = verified.earliest_log_time() else {
            return Err(EndorsementError::new(
                "freshness witness has no verified transparency-log timestamp",
            ));
        };
        check_witness_time(logged_at, now, max_age.unwrap_or(MAX_FRESHNESS_AGE))?;
        Ok(logged_at)
    }
}

/// The age rule of a witness logged at `logged_at`, appraised at `now`.
fn check_witness_time(
    logged_at: Instant,
    now: Instant,
    max_age: Duration,
) -> Result<(), EndorsementError> {
    // An appraisal time so late that the skew leaves the supported years
    // has no instant after it.
    if now
        .checked_add(MAX_FRESHNESS_FUTURE_SKEW)
        .is_some_and(|latest| logged_at > latest)
    {
        return Err(EndorsementError::new(
            "freshness witness timestamp is in the future",
        ));
    }
    if now
        .duration_since(logged_at)
        .is_some_and(|age| age > max_age)
    {
        return Err(EndorsementError::new("freshness witness is stale"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(text: &str) -> Instant {
        Instant::parse_rfc3339(text).unwrap()
    }

    #[test]
    fn the_age_rule_is_closed_at_both_ends() {
        let now = at("2026-08-06T00:00:00Z");
        let nanosecond = Duration::from_nanos(1);
        let age = MAX_FRESHNESS_AGE;
        let oldest = now.checked_sub(age).unwrap();
        let latest = now.checked_add(MAX_FRESHNESS_FUTURE_SKEW).unwrap();
        for (logged_at, accepted) in [
            (oldest.checked_add(nanosecond).unwrap(), true),
            (oldest, true),
            (oldest.checked_sub(nanosecond).unwrap(), false),
            (latest.checked_sub(nanosecond).unwrap(), true),
            (latest, true),
            (latest.checked_add(nanosecond).unwrap(), false),
        ] {
            assert_eq!(
                check_witness_time(logged_at, now, age).is_ok(),
                accepted,
                "{logged_at}"
            );
        }
    }

    #[test]
    fn the_greatest_age_is_the_callers() {
        let now = at("2026-08-06T00:00:00Z");
        let day_old = now.checked_sub(Duration::from_secs(25 * 3600)).unwrap();
        let day = Duration::from_secs(24 * 3600);
        assert!(check_witness_time(day_old, now, day).is_err());
        assert!(check_witness_time(day_old, now, 30 * day).is_ok());
        assert!(check_witness_time(now, now, Duration::ZERO).is_ok());
        assert!(check_witness_time(day_old, now, Duration::ZERO).is_err());
    }

    #[test]
    fn a_witness_predicate_is_closed_and_made_of_strings() {
        let parse = |text: &str| {
            let value = crate::json::parse(text.as_bytes()).unwrap();
            Witness::from_predicate(&value).map(|witness| {
                [
                    witness.format,
                    witness.repo,
                    witness.tag,
                    witness.commit,
                    witness.subject_name,
                    witness.subject_digest,
                ]
                .map(str::to_string)
            })
        };
        assert_eq!(
            parse(
                r#"{"format":"f","endorses":{"repo":"r","tag":"t","commit":"c","subject":{"name":"n","digest":"d"}}}"#
            )
            .unwrap(),
            ["f", "r", "t", "c", "n", "d"]
        );
        assert_eq!(parse("{}").unwrap(), [""; 6]);
        assert_eq!(
            parse(r#"{"format":null,"endorses":{"subject":null}}"#).unwrap(),
            [""; 6]
        );
        for rejected in [
            r#"{"other":1}"#,
            r#"{"format":1}"#,
            r#"{"endorses":[]}"#,
            r#"{"endorses":{"extra":""}}"#,
            r#"{"endorses":{"subject":{"name":"n","digest":"d","uri":""}}}"#,
            r#"{"endorses":{"subject":{"digest":{"sha256":"d"}}}}"#,
            r#"{"endorses":{"repo":false}}"#,
        ] {
            assert!(parse(rejected).is_err(), "{rejected}");
        }
    }
}
