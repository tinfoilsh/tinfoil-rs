//! The verifier's time type: an instant in UTC at nanosecond resolution.
//!
//! Every time-dependent check in the crate takes an [`Instant`] from its
//! caller. Nothing in the crate reads a clock except the one sample that the
//! public verification entry point takes on the caller's behalf.
//!
//! An instant is a count of seconds since 1970-01-01T00:00:00Z plus a
//! nanosecond fraction, restricted to the years 0000 to 9999 so that every
//! instant has an RFC 3339 form and a certificate time form. Arithmetic is
//! checked: a result outside that range is `None`, never a wrapped value.

use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const NANOS_PER_SECOND: u32 = 1_000_000_000;
const SECONDS_PER_DAY: i64 = 86_400;

/// 0000-01-01T00:00:00Z in seconds since the Unix epoch.
const MIN_SECONDS: i64 = -62_167_219_200;
/// 9999-12-31T23:59:59Z in seconds since the Unix epoch.
const MAX_SECONDS: i64 = 253_402_300_799;

/// A point in time in UTC, with nanosecond resolution.
///
/// Instants order chronologically, so `<`, `<=` and `==` compare times.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Instant {
    seconds: i64,
    nanos: u32,
}

/// Text that is not an RFC 3339 timestamp in the accepted form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstantError {
    message: String,
}

impl InstantError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for InstantError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for InstantError {}

/// A calendar date and time of day in UTC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Civil {
    /// The year, 0 to 9999.
    pub year: u16,
    /// The month, 1 to 12.
    pub month: u8,
    /// The day of the month, 1 to 31.
    pub day: u8,
    /// The hour, 0 to 23.
    pub hour: u8,
    /// The minute, 0 to 59.
    pub minute: u8,
    /// The second, 0 to 59. Leap seconds have no representation.
    pub second: u8,
    /// The fraction of the second in nanoseconds, below one billion.
    pub nanos: u32,
}

impl Instant {
    /// 1970-01-01T00:00:00Z.
    pub const UNIX_EPOCH: Instant = Instant {
        seconds: 0,
        nanos: 0,
    };

    /// The instant `seconds` after the Unix epoch (before it, when negative)
    /// plus `nanos` nanoseconds. `None` when `nanos` is a second or more, or
    /// the instant falls outside the years 0000 to 9999.
    pub fn from_unix(seconds: i64, nanos: u32) -> Option<Self> {
        if nanos >= NANOS_PER_SECOND || !(MIN_SECONDS..=MAX_SECONDS).contains(&seconds) {
            return None;
        }
        Some(Self { seconds, nanos })
    }

    /// The instant of a system time. `None` when it falls outside the years
    /// 0000 to 9999.
    pub fn from_system_time(time: SystemTime) -> Option<Self> {
        match time.duration_since(UNIX_EPOCH) {
            Ok(after) => Self::UNIX_EPOCH.checked_add(after),
            Err(error) => Self::UNIX_EPOCH.checked_sub(error.duration()),
        }
    }

    /// The system time of this instant. `None` when the platform's system
    /// time cannot represent it.
    pub fn to_system_time(self) -> Option<SystemTime> {
        let nanos = Duration::from_nanos(u64::from(self.nanos));
        if self.seconds >= 0 {
            let seconds = Duration::from_secs(self.seconds.unsigned_abs());
            UNIX_EPOCH.checked_add(seconds)?.checked_add(nanos)
        } else {
            let seconds = Duration::from_secs(self.seconds.unsigned_abs());
            UNIX_EPOCH.checked_sub(seconds)?.checked_add(nanos)
        }
    }

    /// Whole seconds since the Unix epoch, rounded toward the past.
    pub fn unix_seconds(self) -> i64 {
        self.seconds
    }

    /// The nanoseconds past [`Instant::unix_seconds`], below one billion.
    pub fn subsec_nanos(self) -> u32 {
        self.nanos
    }

    /// This instant with its fraction of a second dropped.
    pub fn truncated_to_seconds(self) -> Self {
        Self {
            seconds: self.seconds,
            nanos: 0,
        }
    }

    /// The instant `duration` later. `None` when it falls after the year
    /// 9999.
    pub fn checked_add(self, duration: Duration) -> Option<Self> {
        let whole = i64::try_from(duration.as_secs()).ok()?;
        let mut seconds = self.seconds.checked_add(whole)?;
        let mut nanos = self.nanos.checked_add(duration.subsec_nanos())?;
        if nanos >= NANOS_PER_SECOND {
            nanos = nanos.checked_sub(NANOS_PER_SECOND)?;
            seconds = seconds.checked_add(1)?;
        }
        Self::from_unix(seconds, nanos)
    }

    /// The instant `duration` earlier. `None` when it falls before the year
    /// 0000.
    pub fn checked_sub(self, duration: Duration) -> Option<Self> {
        let whole = i64::try_from(duration.as_secs()).ok()?;
        let mut seconds = self.seconds.checked_sub(whole)?;
        let nanos = match self.nanos.checked_sub(duration.subsec_nanos()) {
            Some(nanos) => nanos,
            None => {
                seconds = seconds.checked_sub(1)?;
                self.nanos
                    .checked_add(NANOS_PER_SECOND)?
                    .checked_sub(duration.subsec_nanos())?
            }
        };
        Self::from_unix(seconds, nanos)
    }

    /// The time elapsed from `earlier` to this instant. `None` when
    /// `earlier` is in fact later.
    pub fn duration_since(self, earlier: Instant) -> Option<Duration> {
        if earlier > self {
            return None;
        }
        let mut seconds = self.seconds.checked_sub(earlier.seconds)?;
        let nanos = match self.nanos.checked_sub(earlier.nanos) {
            Some(nanos) => nanos,
            None => {
                seconds = seconds.checked_sub(1)?;
                self.nanos
                    .checked_add(NANOS_PER_SECOND)?
                    .checked_sub(earlier.nanos)?
            }
        };
        Some(Duration::new(u64::try_from(seconds).ok()?, nanos))
    }

    /// The instant of a calendar date and time in UTC. `None` when a field
    /// is out of range or the date does not exist.
    pub fn from_civil(civil: Civil) -> Option<Self> {
        if civil.year > 9999
            || civil.hour > 23
            || civil.minute > 59
            || civil.second > 59
            || civil.nanos >= NANOS_PER_SECOND
            || civil.day == 0
            || civil.day > days_in_month(civil.year, civil.month)?
        {
            return None;
        }
        let days = days_from_civil(civil.year, civil.month, civil.day)?;
        let time_of_day = i64::from(civil.hour)
            .checked_mul(3600)?
            .checked_add(i64::from(civil.minute).checked_mul(60)?)?
            .checked_add(i64::from(civil.second))?;
        let seconds = days
            .checked_mul(SECONDS_PER_DAY)?
            .checked_add(time_of_day)?;
        Self::from_unix(seconds, civil.nanos)
    }

    /// The calendar date and time of this instant in UTC.
    pub fn to_civil(self) -> Civil {
        let days = self.seconds.div_euclid(SECONDS_PER_DAY);
        let time_of_day = self.seconds.rem_euclid(SECONDS_PER_DAY);
        let (year, month, day) = civil_from_days(days);
        Civil {
            year,
            month,
            day,
            hour: narrow(time_of_day / 3600),
            minute: narrow(time_of_day % 3600 / 60),
            second: narrow(time_of_day % 60),
            nanos: self.nanos,
        }
    }

    /// Parses an RFC 3339 timestamp.
    ///
    /// The accepted form is `YYYY-MM-DDTHH:MM:SS`, an optional fraction of
    /// one or more digits after a `.`, and a zone that is either `Z` or a
    /// numeric offset `+HH:MM` or `-HH:MM` with hours up to 23 and minutes
    /// up to 59. The letters are uppercase. Digits of the fraction past the
    /// ninth are dropped. A second of 60, an hour of 24 and a date that does
    /// not exist are errors, as is anything before or after the timestamp.
    pub fn parse_rfc3339(text: &str) -> Result<Self, InstantError> {
        let invalid = || InstantError::new(format!("{text:?} is not an RFC 3339 timestamp"));
        let bytes = text.as_bytes();
        let mut cursor = Cursor { bytes, at: 0 };

        let year = cursor.digits(4).ok_or_else(invalid)?;
        cursor.literal(b'-').ok_or_else(invalid)?;
        let month = cursor.digits(2).ok_or_else(invalid)?;
        cursor.literal(b'-').ok_or_else(invalid)?;
        let day = cursor.digits(2).ok_or_else(invalid)?;
        cursor.literal(b'T').ok_or_else(invalid)?;
        let hour = cursor.digits(2).ok_or_else(invalid)?;
        cursor.literal(b':').ok_or_else(invalid)?;
        let minute = cursor.digits(2).ok_or_else(invalid)?;
        cursor.literal(b':').ok_or_else(invalid)?;
        let second = cursor.digits(2).ok_or_else(invalid)?;

        let mut nanos = 0u32;
        if cursor.literal(b'.').is_some() {
            nanos = cursor.fraction().ok_or_else(invalid)?;
        }

        // The offset is the local time's distance east of UTC, so the
        // instant is the local time minus the offset.
        let offset_seconds: i64 = match cursor.next().ok_or_else(invalid)? {
            b'Z' => 0,
            sign @ (b'+' | b'-') => {
                let hours = cursor.digits(2).ok_or_else(invalid)?;
                cursor.literal(b':').ok_or_else(invalid)?;
                let minutes = cursor.digits(2).ok_or_else(invalid)?;
                if hours > 23 || minutes > 59 {
                    return Err(invalid());
                }
                let magnitude = i64::from(hours)
                    .checked_mul(3600)
                    .and_then(|h| h.checked_add(i64::from(minutes).checked_mul(60)?))
                    .ok_or_else(invalid)?;
                if sign == b'-' {
                    magnitude.checked_neg().ok_or_else(invalid)?
                } else {
                    magnitude
                }
            }
            _ => return Err(invalid()),
        };
        if cursor.at != bytes.len() {
            return Err(invalid());
        }

        let local = Self::from_civil(Civil {
            year: u16::try_from(year).map_err(|_| invalid())?,
            month: u8::try_from(month).map_err(|_| invalid())?,
            day: u8::try_from(day).map_err(|_| invalid())?,
            hour: u8::try_from(hour).map_err(|_| invalid())?,
            minute: u8::try_from(minute).map_err(|_| invalid())?,
            second: u8::try_from(second).map_err(|_| invalid())?,
            nanos,
        })
        .ok_or_else(invalid)?;
        let seconds = local
            .seconds
            .checked_sub(offset_seconds)
            .ok_or_else(invalid)?;
        Self::from_unix(seconds, nanos).ok_or_else(invalid)
    }

    /// The RFC 3339 form in UTC: `YYYY-MM-DDTHH:MM:SSZ`, with the fraction
    /// of the second after a `.` when it is not zero, trailing zeros
    /// removed.
    pub fn to_rfc3339(self) -> String {
        let mut text = self.date_time();
        if self.nanos != 0 {
            let fraction = format!("{:09}", self.nanos);
            text.push('.');
            text.push_str(fraction.trim_end_matches('0'));
        }
        text.push('Z');
        text
    }

    /// The RFC 3339 form in UTC at second precision; a fraction of a second
    /// is dropped, not rounded.
    pub fn to_rfc3339_seconds(self) -> String {
        let mut text = self.date_time();
        text.push('Z');
        text
    }

    fn date_time(self) -> String {
        let c = self.to_civil();
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
            c.year, c.month, c.day, c.hour, c.minute, c.second
        )
    }
}

impl fmt::Debug for Instant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Instant({})", self.to_rfc3339())
    }
}

impl fmt::Display for Instant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_rfc3339())
    }
}

/// Reads fixed-width fields from the front of a timestamp.
struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Cursor<'_> {
    fn next(&mut self) -> Option<u8> {
        let byte = *self.bytes.get(self.at)?;
        self.at = self.at.checked_add(1)?;
        Some(byte)
    }

    fn literal(&mut self, want: u8) -> Option<()> {
        if *self.bytes.get(self.at)? != want {
            return None;
        }
        self.at = self.at.checked_add(1)?;
        Some(())
    }

    /// Exactly `count` decimal digits, as a number.
    fn digits(&mut self, count: usize) -> Option<u32> {
        let mut value = 0u32;
        for _ in 0..count {
            let byte = self.next()?;
            if !byte.is_ascii_digit() {
                return None;
            }
            value = value
                .checked_mul(10)?
                .checked_add(u32::from(byte.wrapping_sub(b'0')))?;
        }
        Some(value)
    }

    /// One or more decimal digits as nanoseconds; digits past the ninth are
    /// read and dropped.
    fn fraction(&mut self) -> Option<u32> {
        let mut nanos = 0u32;
        let mut count = 0u32;
        while let Some(byte) = self.bytes.get(self.at).copied() {
            if !byte.is_ascii_digit() {
                break;
            }
            if count < 9 {
                nanos = nanos
                    .checked_mul(10)?
                    .checked_add(u32::from(byte.wrapping_sub(b'0')))?;
            }
            count = count.saturating_add(1);
            self.at = self.at.checked_add(1)?;
        }
        if count == 0 {
            return None;
        }
        for _ in count..9 {
            nanos = nanos.checked_mul(10)?;
        }
        Some(nanos)
    }
}

fn is_leap_year(year: u16) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}

fn days_in_month(year: u16, month: u8) -> Option<u8> {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => Some(31),
        4 | 6 | 9 | 11 => Some(30),
        2 if is_leap_year(year) => Some(29),
        2 => Some(28),
        _ => None,
    }
}

/// Days from 1970-01-01 to the given date in the proleptic Gregorian
/// calendar. The date must exist.
fn days_from_civil(year: u16, month: u8, day: u8) -> Option<i64> {
    // Count from 1 March of year 0 so that the leap day is the last day of
    // the shifted year; eras of 400 years have a fixed number of days.
    let shifted_year = if month <= 2 {
        i64::from(year).checked_sub(1)?
    } else {
        i64::from(year)
    };
    let era = shifted_year.div_euclid(400);
    let year_of_era = shifted_year.rem_euclid(400);
    let shifted_month = if month > 2 {
        i64::from(month).checked_sub(3)?
    } else {
        i64::from(month).checked_add(9)?
    };
    let day_of_year = shifted_month
        .checked_mul(153)?
        .checked_add(2)?
        .div_euclid(5)
        .checked_add(i64::from(day))?
        .checked_sub(1)?;
    let day_of_era = year_of_era
        .checked_mul(365)?
        .checked_add(year_of_era / 4)?
        .checked_sub(year_of_era / 100)?
        .checked_add(day_of_year)?;
    era.checked_mul(146_097)?
        .checked_add(day_of_era)?
        .checked_sub(719_468)
}

/// The date that is `days` days after 1970-01-01. The caller keeps `days`
/// within the years 0000 to 9999.
fn civil_from_days(days: i64) -> (u16, u8, u8) {
    let shifted = days.saturating_add(719_468);
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era = day_of_era
        .saturating_sub(day_of_era / 1_460)
        .saturating_add(day_of_era / 36_524)
        .saturating_sub(day_of_era / 146_096)
        / 365;
    let day_of_year = day_of_era.saturating_sub(
        year_of_era
            .saturating_mul(365)
            .saturating_add(year_of_era / 4)
            .saturating_sub(year_of_era / 100),
    );
    let shifted_month = day_of_year.saturating_mul(5).saturating_add(2) / 153;
    let day = day_of_year
        .saturating_sub(shifted_month.saturating_mul(153).saturating_add(2) / 5)
        .saturating_add(1);
    let month = if shifted_month < 10 {
        shifted_month.saturating_add(3)
    } else {
        shifted_month.saturating_sub(9)
    };
    let year = year_of_era
        .saturating_add(era.saturating_mul(400))
        .saturating_add(i64::from(month <= 2));
    (narrow(year), narrow(month), narrow(day))
}

/// Converts a calendar field that is known to be small and not negative.
/// A value that does not fit becomes zero.
fn narrow<T: TryFrom<i64> + Default>(value: i64) -> T {
    T::try_from(value).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(text: &str) -> Instant {
        Instant::parse_rfc3339(text).unwrap()
    }

    #[test]
    fn the_epoch_is_zero() {
        assert_eq!(at("1970-01-01T00:00:00Z"), Instant::UNIX_EPOCH);
        assert_eq!(Instant::UNIX_EPOCH.unix_seconds(), 0);
        assert_eq!(Instant::UNIX_EPOCH.to_rfc3339(), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn known_instants_convert_both_ways() {
        let cases = [
            ("2021-01-12T11:53:27Z", 1_610_452_407),
            ("2022-12-31T23:59:59Z", 1_672_531_199),
            ("2026-05-13T19:23:33Z", 1_778_700_213),
            ("2000-02-29T00:00:00Z", 951_782_400),
            ("1969-12-31T23:59:59Z", -1),
            ("0000-01-01T00:00:00Z", MIN_SECONDS),
            ("9999-12-31T23:59:59Z", MAX_SECONDS),
            ("2038-01-19T03:14:08Z", 2_147_483_648),
        ];
        for (text, seconds) in cases {
            let instant = at(text);
            assert_eq!(instant.unix_seconds(), seconds, "{text}");
            assert_eq!(instant.to_rfc3339(), text);
            assert_eq!(Instant::from_unix(seconds, 0).unwrap(), instant);
        }
    }

    #[test]
    fn every_day_of_four_centuries_round_trips() {
        let mut days = days_from_civil(1900, 1, 1).unwrap();
        let end = days_from_civil(2300, 1, 1).unwrap();
        let mut previous = None;
        while days < end {
            let (year, month, day) = civil_from_days(days);
            assert_eq!(days_from_civil(year, month, day).unwrap(), days);
            assert!(day >= 1 && day <= days_in_month(year, month).unwrap());
            if let Some(previous) = previous {
                assert!((year, month, day) > previous);
            }
            previous = Some((year, month, day));
            days += 1;
        }
    }

    #[test]
    fn fractions_keep_nine_digits_and_drop_the_rest() {
        let instant = at("2022-12-31T23:59:59.999Z");
        assert_eq!(instant.subsec_nanos(), 999_000_000);
        assert_eq!(instant.to_rfc3339(), "2022-12-31T23:59:59.999Z");
        assert_eq!(instant.to_rfc3339_seconds(), "2022-12-31T23:59:59Z");

        assert_eq!(at("2020-01-01T00:00:00.5Z").subsec_nanos(), 500_000_000);
        assert_eq!(at("2020-01-01T00:00:00.000000001Z").subsec_nanos(), 1);
        assert_eq!(
            at("2020-01-01T00:00:00.1234567899999Z").subsec_nanos(),
            123_456_789
        );
        assert_eq!(
            at("2020-01-01T00:00:00.000000000Z"),
            at("2020-01-01T00:00:00Z")
        );
    }

    #[test]
    fn offsets_shift_to_utc() {
        assert_eq!(at("2020-01-01T01:30:00+01:30"), at("2020-01-01T00:00:00Z"));
        assert_eq!(at("2019-12-31T19:00:00-05:00"), at("2020-01-01T00:00:00Z"));
        assert_eq!(at("2020-01-01T00:00:00+00:00"), at("2020-01-01T00:00:00Z"));
        assert_eq!(at("2020-01-01T00:00:00-00:00"), at("2020-01-01T00:00:00Z"));
    }

    #[test]
    fn malformed_timestamps_are_rejected() {
        let cases = [
            "",
            "2020-01-01",
            "2020-01-01T00:00:00",
            "2020-01-01T00:00:00z",
            "2020-01-01t00:00:00Z",
            "2020-01-01 00:00:00Z",
            "2020-01-01T00:00:00Z ",
            " 2020-01-01T00:00:00Z",
            "2020-01-01T00:00:00ZZ",
            "2020-1-01T00:00:00Z",
            "20200-01-01T00:00:00Z",
            "2020-01-01T0:00:00Z",
            "2020-01-01T00:00Z",
            "2020-01-01T00:00:00.Z",
            "2020-01-01T00:00:00,5Z",
            "2020-01-01T00:00:60Z",
            "2020-01-01T24:00:00Z",
            "2020-01-01T00:60:00Z",
            "2020-13-01T00:00:00Z",
            "2020-00-01T00:00:00Z",
            "2020-01-00T00:00:00Z",
            "2020-01-32T00:00:00Z",
            "2021-02-29T00:00:00Z",
            "1900-02-29T00:00:00Z",
            "2020-04-31T00:00:00Z",
            "2020-01-01T00:00:00+0100",
            "2020-01-01T00:00:00+01",
            "2020-01-01T00:00:00+24:00",
            "2020-01-01T00:00:00+01:60",
            "2020-01-01T00:00:00+1:00",
            "+2020-01-01T00:00:00Z",
            "2020-01-01T00:00:00Z\n",
            "２０２０-01-01T00:00:00Z",
        ];
        for text in cases {
            assert!(Instant::parse_rfc3339(text).is_err(), "{text:?}");
        }
    }

    #[test]
    fn an_offset_cannot_leave_the_supported_years() {
        assert!(Instant::parse_rfc3339("0000-01-01T00:00:00+00:01").is_err());
        assert!(Instant::parse_rfc3339("9999-12-31T23:59:59-00:01").is_err());
        assert!(Instant::parse_rfc3339("0000-01-01T00:00:00-00:01").is_ok());
    }

    #[test]
    fn leap_years_follow_the_gregorian_rule() {
        assert!(Instant::parse_rfc3339("2000-02-29T00:00:00Z").is_ok());
        assert!(Instant::parse_rfc3339("2024-02-29T00:00:00Z").is_ok());
        assert!(Instant::parse_rfc3339("2100-02-29T00:00:00Z").is_err());
        assert!(Instant::parse_rfc3339("0000-02-29T00:00:00Z").is_ok());
    }

    #[test]
    fn instants_order_by_time() {
        let earlier = at("2020-01-01T00:00:00.999999999Z");
        let later = at("2020-01-01T00:00:01Z");
        assert!(earlier < later);
        assert!(at("1969-12-31T23:59:59.5Z") < Instant::UNIX_EPOCH);
        assert_eq!(
            at("1969-12-31T23:59:59.5Z"),
            Instant::from_unix(-1, 500_000_000).unwrap()
        );
    }

    #[test]
    fn arithmetic_carries_and_borrows_nanoseconds() {
        let base = at("2020-01-01T00:00:00.75Z");
        assert_eq!(
            base.checked_add(Duration::new(1, 500_000_000)).unwrap(),
            at("2020-01-01T00:00:02.25Z")
        );
        assert_eq!(
            base.checked_sub(Duration::new(0, 800_000_000)).unwrap(),
            at("2019-12-31T23:59:59.95Z")
        );
        assert_eq!(
            base.checked_sub(Duration::from_secs(7 * 86_400)).unwrap(),
            at("2019-12-25T00:00:00.75Z")
        );
        assert_eq!(base.checked_add(Duration::ZERO).unwrap(), base);
    }

    #[test]
    fn arithmetic_stops_at_the_supported_range() {
        let last = at("9999-12-31T23:59:59Z");
        assert!(
            last.checked_add(Duration::from_nanos(999_999_999))
                .is_some()
        );
        assert!(last.checked_add(Duration::from_secs(1)).is_none());
        let first = at("0000-01-01T00:00:00Z");
        assert!(first.checked_sub(Duration::from_nanos(1)).is_none());
        assert!(Instant::UNIX_EPOCH.checked_add(Duration::MAX).is_none());
        assert!(Instant::UNIX_EPOCH.checked_sub(Duration::MAX).is_none());
    }

    #[test]
    fn duration_since_is_none_for_a_later_instant() {
        let earlier = at("2020-01-01T00:00:00.9Z");
        let later = at("2020-01-01T00:00:02.1Z");
        assert_eq!(
            later.duration_since(earlier).unwrap(),
            Duration::new(1, 200_000_000)
        );
        assert_eq!(later.duration_since(later).unwrap(), Duration::ZERO);
        assert!(earlier.duration_since(later).is_none());
    }

    #[test]
    fn out_of_range_parts_are_rejected() {
        assert!(Instant::from_unix(0, 1_000_000_000).is_none());
        assert!(Instant::from_unix(MAX_SECONDS + 1, 0).is_none());
        assert!(Instant::from_unix(MIN_SECONDS - 1, 0).is_none());
        assert!(Instant::from_unix(MAX_SECONDS, 999_999_999).is_some());
    }

    #[test]
    fn system_times_convert_both_ways() {
        let time = UNIX_EPOCH + Duration::new(1_778_700_213, 250);
        let instant = Instant::from_system_time(time).unwrap();
        assert_eq!(instant, at("2026-05-13T19:23:33.00000025Z"));
        assert_eq!(instant.to_system_time().unwrap(), time);

        let before = UNIX_EPOCH - Duration::new(1, 250_000_000);
        let instant = Instant::from_system_time(before).unwrap();
        assert_eq!(instant, at("1969-12-31T23:59:58.75Z"));
        assert_eq!(instant.to_system_time().unwrap(), before);
    }

    #[test]
    fn civil_fields_are_checked() {
        let civil = Civil {
            year: 2026,
            month: 5,
            day: 13,
            hour: 19,
            minute: 23,
            second: 33,
            nanos: 0,
        };
        let instant = Instant::from_civil(civil).unwrap();
        assert_eq!(instant.unix_seconds(), 1_778_700_213);
        assert_eq!(instant.to_civil(), civil);
        assert!(
            Instant::from_civil(Civil {
                second: 60,
                ..civil
            })
            .is_none()
        );
        assert!(
            Instant::from_civil(Civil {
                month: 2,
                day: 30,
                ..civil
            })
            .is_none()
        );
        assert!(
            Instant::from_civil(Civil {
                year: 10_000,
                ..civil
            })
            .is_none()
        );
    }

    #[test]
    fn debug_and_display_show_the_timestamp() {
        let instant = at("2020-01-01T00:00:00.5Z");
        assert_eq!(instant.to_string(), "2020-01-01T00:00:00.5Z");
        assert_eq!(format!("{instant:?}"), "Instant(2020-01-01T00:00:00.5Z)");
    }

    #[test]
    fn truncation_drops_the_fraction() {
        assert_eq!(
            at("2020-01-01T00:00:00.999Z").truncated_to_seconds(),
            at("2020-01-01T00:00:00Z")
        );
        assert_eq!(
            at("1969-12-31T23:59:59.5Z")
                .truncated_to_seconds()
                .unix_seconds(),
            -1
        );
    }
}
