//! How long an OpenAI call waits before it is sent again.

use std::time::{Duration, SystemTime};

use reqwest::header::{HeaderMap, RETRY_AFTER};

use crate::internal::Clock;

#[cfg(test)]
#[path = "retry_tests.rs"]
mod tests;

/// How often a call is sent again after the first attempt.
pub(crate) const MAX_RETRIES: u32 = 2;

/// The longest wait that a response can ask for. A response that asks for
/// more is not waited for at all.
pub(crate) const MAX_RETRY_AFTER: Duration = Duration::from_secs(120);

/// The wait before the first retry when the response names none. It
/// doubles with each retry.
const BACKOFF: Duration = Duration::from_millis(500);

/// The longest wait of the backoff.
const MAX_BACKOFF: Duration = Duration::from_secs(8);

/// A wait in milliseconds. It is preferred to `Retry-After`.
const RETRY_AFTER_MS: &str = "retry-after-ms";

/// Decides the wait between the attempts of a call.
///
/// A response that is to be tried again names its wait in `Retry-After-Ms`
/// (milliseconds) or else in `Retry-After` (seconds, or an HTTP date).
/// Either number may have a fraction. Both headers arrive from whoever
/// answered, which in [`TransportMode::Ehbp`](crate::TransportMode::Ehbp)
/// can be a proxy, so neither is obeyed beyond the limit: the smaller of
/// [`MAX_RETRY_AFTER`] and the client's `timeout` option.
///
/// - A wait within the limit is waited for. A date in the past is no wait.
/// - A wait beyond the limit ends the call: the response is the call's
///   result, and no further attempt is made.
/// - A value that is negative, not a number, or neither a number nor a
///   date is ignored, and so is a missing one. The wait is then the
///   backoff: half a second before the first retry and a second before the
///   next, each shortened at random by up to a quarter and never longer
///   than the limit.
#[derive(Clone)]
pub(crate) struct Waits {
    /// The client's `timeout` option.
    pub(crate) timeout: Option<Duration>,
    /// The wall clock that a date in `Retry-After` is compared with.
    pub(crate) clock: Clock,
}

impl Waits {
    /// The wait before retry number `retry` (from zero) of a call whose
    /// last response had `headers`, or `None` when the response asks for a
    /// longer wait than the limit.
    pub(crate) fn before_retry(&self, headers: &HeaderMap, retry: u32) -> Option<Duration> {
        let limit = self
            .timeout
            .map_or(MAX_RETRY_AFTER, |timeout| timeout.min(MAX_RETRY_AFTER));
        match asked(headers, (self.clock)(), limit) {
            Some(Asked::Wait(wait)) => Some(wait),
            Some(Asked::TooLong) => None,
            None => Some(shortened(backoff(retry).min(limit), random())),
        }
    }
}

/// What a response asks for.
#[derive(Debug, PartialEq)]
enum Asked {
    /// To be tried again after this long, which is within the limit.
    Wait(Duration),
    /// To be tried again after more than the limit.
    TooLong,
}

/// The wait that `headers` ask for, or `None` when they name none that can
/// be read.
fn asked(headers: &HeaderMap, now: SystemTime, limit: Duration) -> Option<Asked> {
    let within = |wait: Duration| {
        if wait > limit {
            Asked::TooLong
        } else {
            Asked::Wait(wait)
        }
    };
    let text = |name: &str| {
        let value = headers.get(name)?.to_str().ok()?.trim();
        (!value.is_empty()).then_some(value)
    };
    for (name, unit) in [(RETRY_AFTER_MS, 0.001), (RETRY_AFTER.as_str(), 1.0)] {
        let Some(value) = text(name) else { continue };
        match value.parse::<f64>() {
            Ok(number) if number.is_nan() || number < 0.0 => {}
            Ok(number) => {
                // A number too large for a duration, infinity included,
                // is beyond any limit.
                return Some(
                    Duration::try_from_secs_f64(number * unit).map_or(Asked::TooLong, within),
                );
            }
            Err(_) if name == RETRY_AFTER_MS => {}
            Err(_) => {
                if let Some(at) = http_date(value) {
                    // A date that has passed is no wait.
                    return Some(within(at.duration_since(now).unwrap_or_default()));
                }
            }
        }
    }
    None
}

/// The backoff before retry number `retry`, before it is shortened.
fn backoff(retry: u32) -> Duration {
    BACKOFF
        .saturating_mul(2_u32.saturating_pow(retry))
        .min(MAX_BACKOFF)
}

/// `wait` less a part of its quarter that `random` picks, so that clients
/// that failed together do not return together.
fn shortened(wait: Duration, random: u64) -> Duration {
    let quarter = u64::try_from(wait.as_nanos() / 4).unwrap_or(u64::MAX);
    match random.checked_rem(quarter) {
        Some(less) => wait.saturating_sub(Duration::from_nanos(less)),
        None => wait,
    }
}

/// A random number, or zero when the system has none to give: the wait is
/// then not shortened.
fn random() -> u64 {
    getrandom::u64().unwrap_or(0)
}

/// The instant that an HTTP date in the preferred format names, as in
/// `Sun, 06 Nov 1994 08:49:37 GMT`. The name of the day is not compared
/// with the date.
fn http_date(text: &str) -> Option<SystemTime> {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let (weekday, rest) = text.split_once(", ")?;
    if weekday.len() != 3 || !weekday.bytes().all(|byte| byte.is_ascii_alphabetic()) {
        return None;
    }
    let mut fields = rest.split(' ');
    let (day, month, year, time, zone) = (
        fields.next()?,
        fields.next()?,
        fields.next()?,
        fields.next()?,
        fields.next()?,
    );
    if fields.next().is_some() || !matches!(zone, "GMT" | "UTC") {
        return None;
    }
    let mut clock = time.split(':');
    let (hour, minute, second) = (clock.next()?, clock.next()?, clock.next()?);
    if clock.next().is_some() {
        return None;
    }
    let digits = |field: &str, length: usize| -> Option<u64> {
        (field.len() == length && field.bytes().all(|byte| byte.is_ascii_digit()))
            .then(|| field.parse().ok())?
    };
    let day = digits(day, 2)?;
    let month = u64::try_from(MONTHS.iter().position(|name| *name == month)?).ok()?;
    let year = digits(year, 4)?;
    let (hour, minute, second) = (digits(hour, 2)?, digits(minute, 2)?, digits(second, 2)?);
    if year < 1970 || !(1..=31).contains(&day) || hour > 23 || minute > 59 || second > 60 {
        return None;
    }

    // The days from 1970-01-01 to the date, counted in years that start in
    // March, so that the leap day is the last day of its year.
    let (year, month) = if month < 2 {
        (year.checked_sub(1)?, month.checked_add(10)?)
    } else {
        (year, month.checked_sub(2)?)
    };
    let in_year = month
        .checked_mul(153)?
        .checked_add(2)?
        .checked_div(5)?
        .checked_add(day)?
        .checked_sub(1)?;
    let days = year
        .checked_mul(365)?
        .checked_add(year.checked_div(4)?)?
        .checked_sub(year.checked_div(100)?)?
        .checked_add(year.checked_div(400)?)?
        .checked_add(in_year)?
        // The days from 0000-03-01 to 1970-01-01.
        .checked_sub(719_468)?;
    let seconds = days
        .checked_mul(24)?
        .checked_add(hour)?
        .checked_mul(60)?
        .checked_add(minute)?
        .checked_mul(60)?
        .checked_add(second)?;
    SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(seconds))
}
