//! The age rule of approvals.

use std::time::Duration;

use super::EndorsementError;
use crate::instant::Instant;
use crate::sigstore::timestamp::AppraisalWindow;

/// The greatest age of an approval when the caller sets none: seven days.
pub const DEFAULT_MAX_AGE: Duration = Duration::from_secs(7 * 24 * 60 * 60);
/// How far ahead of the appraisal time a timestamp may lie when the caller
/// sets no skew: five minutes.
pub const DEFAULT_FUTURE_SKEW: Duration = Duration::from_secs(5 * 60);

/// The window in which an approval's timestamp must fall when appraised at
/// `now`: from `now` less the greatest age to `now` plus the clock skew.
///
/// `None` selects [`DEFAULT_MAX_AGE`] or [`DEFAULT_FUTURE_SKEW`]; a given
/// duration is used as it is, so a zero age accepts only timestamps at or
/// after `now`. An error when an end of the window is not a representable
/// instant.
pub fn approval_window(
    now: Instant,
    max_age: Option<Duration>,
    future_skew: Option<Duration>,
) -> Result<AppraisalWindow, EndorsementError> {
    let out_of_range = || EndorsementError::new("appraisal window is out of range");
    Ok(AppraisalWindow {
        earliest: now
            .checked_sub(max_age.unwrap_or(DEFAULT_MAX_AGE))
            .ok_or_else(out_of_range)?,
        latest: now
            .checked_add(future_skew.unwrap_or(DEFAULT_FUTURE_SKEW))
            .ok_or_else(out_of_range)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(text: &str) -> Instant {
        Instant::parse_rfc3339(text).unwrap()
    }

    #[test]
    fn the_default_window_is_seven_days_back_and_five_minutes_ahead() {
        let window = approval_window(at("2026-05-13T19:23:33Z"), None, None).unwrap();
        assert_eq!(window.earliest, at("2026-05-06T19:23:33Z"));
        assert_eq!(window.latest, at("2026-05-13T19:28:33Z"));
    }

    #[test]
    fn given_durations_are_used_as_they_are() {
        let now = at("2026-05-13T19:23:33Z");
        let window = approval_window(
            now,
            Some(Duration::from_secs(3600)),
            Some(Duration::from_millis(1500)),
        )
        .unwrap();
        assert_eq!(window.earliest, at("2026-05-13T18:23:33Z"));
        assert_eq!(window.latest, at("2026-05-13T19:23:34.5Z"));

        let exact = approval_window(now, Some(Duration::ZERO), Some(Duration::ZERO)).unwrap();
        assert_eq!((exact.earliest, exact.latest), (now, now));
    }

    #[test]
    fn a_window_that_leaves_the_supported_years_is_an_error() {
        assert!(approval_window(at("0000-01-01T00:00:00Z"), None, None).is_err());
        assert!(approval_window(at("9999-12-31T23:59:59Z"), None, None).is_err());
        assert!(approval_window(Instant::UNIX_EPOCH, Some(Duration::MAX), None).is_err());
    }
}
