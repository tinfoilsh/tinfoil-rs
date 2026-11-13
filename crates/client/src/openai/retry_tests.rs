//! The wait before a retry, as a function of the response's headers, the
//! clock and the limit.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use reqwest::header::{HeaderMap, HeaderValue};

use super::{Asked, MAX_RETRY_AFTER, Waits, asked, backoff, http_date, shortened};

fn at(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(seconds)
}

fn headers(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for (name, value) in pairs {
        headers.append(*name, HeaderValue::from_static(value));
    }
    headers
}

#[test]
fn an_http_date_is_read_in_the_preferred_format_only() {
    assert_eq!(http_date("Thu, 01 Jan 1970 00:00:00 GMT"), Some(at(0)));
    assert_eq!(
        http_date("Sun, 06 Nov 1994 08:49:37 GMT"),
        Some(at(784_111_777))
    );
    assert_eq!(
        http_date("Fri, 15 Jan 2027 08:00:00 GMT"),
        Some(at(1_800_000_000))
    );
    assert_eq!(
        http_date("Fri, 15 Jan 2027 08:00:00 UTC"),
        Some(at(1_800_000_000))
    );
    // The leap day, the day after it, and the turn of a year.
    assert_eq!(
        http_date("Thu, 29 Feb 2024 12:00:00 GMT"),
        Some(at(1_709_208_000))
    );
    assert_eq!(
        http_date("Fri, 01 Mar 2024 00:00:00 GMT"),
        Some(at(1_709_251_200))
    );
    assert_eq!(
        http_date("Wed, 31 Dec 2025 23:59:59 GMT"),
        Some(at(1_767_225_599))
    );
    assert_eq!(
        http_date("Thu, 01 Jan 2026 00:00:00 GMT"),
        Some(at(1_767_225_600))
    );
    assert_eq!(
        http_date("Sat, 01 Jan 2000 00:00:00 GMT"),
        Some(at(946_684_800))
    );
    // The last day of each kind of month, and the leap day of a century
    // year that has one.
    for (date, seconds) in [
        ("Tue, 29 Feb 2000 00:00:00 GMT", 951_782_400),
        ("Sun, 28 Feb 2027 00:00:00 GMT", 1_803_772_800),
        ("Fri, 30 Apr 2027 00:00:00 GMT", 1_809_043_200),
        ("Sun, 31 Jan 2027 00:00:00 GMT", 1_801_353_600),
        ("Fri, 31 Dec 2027 00:00:00 GMT", 1_830_211_200),
    ] {
        assert_eq!(http_date(date), Some(at(seconds)), "{date}");
    }
    assert_eq!(
        http_date("Fri, 31 Dec 9999 23:59:59 GMT"),
        Some(at(253_402_300_799))
    );

    for unread in [
        "",
        "7",
        "Sunday, 06-Nov-94 08:49:37 GMT",
        "Sun Nov  6 08:49:37 1994",
        "Sun, 06 Nov 1994 08:49:37",
        "Sun, 06 Nov 1994 08:49:37 PST",
        "Sun, 06 Nov 1994 08:49:37 +0000",
        "Sun, 06 Nov 1994 08:49:37 GMT ",
        "Sun, 06 Nov 1994 08:49 GMT",
        "Sun, 06 Nov 1994 24:00:00 GMT",
        "Sun, 06 Nov 1994 08:60:00 GMT",
        "Sun, 00 Nov 1994 08:49:37 GMT",
        "Sun, 32 Nov 1994 08:49:37 GMT",
        // Days that their month does not have.
        "Wed, 31 Nov 1994 08:49:37 GMT",
        "Sat, 31 Apr 2027 00:00:00 GMT",
        "Thu, 31 Jun 2027 00:00:00 GMT",
        "Fri, 31 Sep 2027 00:00:00 GMT",
        "Wed, 30 Feb 2028 00:00:00 GMT",
        "Wed, 31 Feb 2027 00:00:00 GMT",
        "Mon, 29 Feb 2027 00:00:00 GMT",
        "Thu, 29 Feb 2100 00:00:00 GMT",
        "Sun, 32 Jan 2027 00:00:00 GMT",
        "Sun, 6 Nov 1994 08:49:37 GMT",
        "Sun, 06 Nov 94 08:49:37 GMT",
        "Sun, 06 Nov 1969 08:49:37 GMT",
        "Sun, 06 nov 1994 08:49:37 GMT",
        "Sun, +6 Nov 1994 08:49:37 GMT",
        "Sun,06 Nov 1994 08:49:37 GMT",
        "S0n, 06 Nov 1994 08:49:37 GMT",
    ] {
        assert_eq!(http_date(unread), None, "{unread:?}");
    }
}

#[test]
fn a_wait_is_read_from_the_headers_against_the_limit() {
    let now = at(1_800_000_000);
    let limit = Duration::from_secs(120);
    let ask = |pairs: &[(&'static str, &'static str)]| asked(&headers(pairs), now, limit);
    let wait = |millis| Some(Asked::Wait(Duration::from_millis(millis)));

    assert_eq!(ask(&[]), None);
    assert_eq!(ask(&[("retry-after", "7")]), wait(7_000));
    assert_eq!(ask(&[("retry-after", " 7 ")]), wait(7_000));
    assert_eq!(ask(&[("retry-after", "0.25")]), wait(250));
    assert_eq!(ask(&[("retry-after", "120")]), wait(120_000));
    assert_eq!(ask(&[("retry-after-ms", "120000")]), wait(120_000));
    assert_eq!(ask(&[("retry-after", "-0")]), wait(0));
    // The first value of a repeated header.
    assert_eq!(
        ask(&[("retry-after", "3"), ("retry-after", "9")]),
        wait(3_000)
    );

    for too_long in [
        "120.5",
        "121",
        "1e9",
        "1e400",
        "inf",
        "+infinity",
        "4000000000",
    ] {
        assert_eq!(
            ask(&[("retry-after", too_long)]),
            Some(Asked::TooLong),
            "{too_long}"
        );
    }
    for ignored in ["-1", "-inf", "nan", "NaN", "soon", "1 2", "1s", ""] {
        assert_eq!(ask(&[("retry-after", ignored)]), None, "{ignored:?}");
        assert_eq!(ask(&[("retry-after-ms", ignored)]), None, "{ignored:?}");
    }

    assert_eq!(
        ask(&[("retry-after", "Fri, 15 Jan 2027 08:02:00 GMT")]),
        wait(120_000)
    );
    assert_eq!(
        ask(&[("retry-after", "Fri, 15 Jan 2027 08:02:01 GMT")]),
        Some(Asked::TooLong)
    );
    assert_eq!(
        ask(&[("retry-after", "Fri, 15 Jan 2027 07:00:00 GMT")]),
        wait(0)
    );
    // A date is not a number of milliseconds.
    assert_eq!(
        ask(&[("retry-after-ms", "Fri, 15 Jan 2027 08:02:00 GMT")]),
        None
    );
}

#[test]
fn the_backoff_doubles_to_its_ceiling_and_is_shortened_by_less_than_a_quarter() {
    assert_eq!(backoff(0), Duration::from_millis(500));
    assert_eq!(backoff(1), Duration::from_secs(1));
    assert_eq!(backoff(4), Duration::from_secs(8));
    assert_eq!(backoff(5), Duration::from_secs(8));
    assert_eq!(backoff(u32::MAX), Duration::from_secs(8));

    let wait = Duration::from_secs(1);
    assert_eq!(shortened(wait, 0), wait);
    assert_eq!(
        shortened(wait, 249_999_999),
        Duration::from_nanos(750_000_001)
    );
    assert_eq!(shortened(wait, 250_000_000), wait);
    for random in [1, 7, u64::MAX, u64::MAX / 3] {
        let shortened = shortened(wait, random);
        assert!(shortened > Duration::from_millis(750) && shortened <= wait);
    }
    // Too short to have a quarter.
    assert_eq!(
        shortened(Duration::from_nanos(3), 99),
        Duration::from_nanos(3)
    );
    assert_eq!(shortened(Duration::ZERO, 99), Duration::ZERO);
}

#[test]
fn the_limit_is_the_smaller_of_the_fixed_one_and_the_timeout() {
    let waits = |timeout| Waits {
        timeout,
        clock: Arc::new(|| at(1_800_000_000)),
    };
    let after = |seconds: &'static str| headers(&[("retry-after", seconds)]);
    assert_eq!(MAX_RETRY_AFTER, Duration::from_secs(120));
    assert_eq!(
        waits(None).before_retry(&after("120"), 0),
        Some(Duration::from_secs(120))
    );
    assert_eq!(waits(None).before_retry(&after("121"), 0), None);
    let hour = Some(Duration::from_secs(3600));
    assert_eq!(waits(hour).before_retry(&after("121"), 0), None);
    let five = Some(Duration::from_secs(5));
    assert_eq!(
        waits(five).before_retry(&after("5"), 1),
        Some(Duration::from_secs(5))
    );
    assert_eq!(waits(five).before_retry(&after("5.5"), 1), None);
    // The backoff never exceeds the limit either.
    let brief = Some(Duration::from_millis(10));
    for retry in 0..2 {
        let wait = waits(brief).before_retry(&HeaderMap::new(), retry).unwrap();
        assert!(wait <= Duration::from_millis(10), "{wait:?}");
        let wait = waits(None).before_retry(&HeaderMap::new(), retry).unwrap();
        let whole = Duration::from_millis(500) * 2_u32.pow(retry);
        assert!(wait <= whole && wait > whole * 3 / 4, "{wait:?}");
    }
}
