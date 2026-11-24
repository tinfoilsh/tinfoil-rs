//! Semantic versions with a leading `v`, such as `v1.2.3-rc.1+build`.
//!
//! The grammar is Semantic Versioning 2.0.0 after the `v`, extended with the
//! shorthands `vMAJOR` and `vMAJOR.MINOR`. A shorthand is valid but not full.

use std::cmp::Ordering;

/// A valid version, split into its parts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Version<'a> {
    /// The major number, without leading zeros.
    pub major: &'a str,
    /// The minor number; `0` when the version leaves it out.
    pub minor: &'a str,
    /// The patch number; `0` when the version leaves it out.
    pub patch: &'a str,
    /// The prerelease with its leading `-`, or empty.
    pub prerelease: &'a str,
    /// The build metadata with its leading `+`, or empty.
    pub build: &'a str,
    /// Whether the version spells out major, minor and patch.
    pub full: bool,
}

impl Version<'_> {
    /// Orders two versions by precedence: major, minor and patch as numbers,
    /// then a prerelease below its release, and two prereleases by their
    /// identifiers. Build metadata does not count.
    pub fn precedence(&self, other: &Version<'_>) -> Ordering {
        number_key(self.major)
            .cmp(&number_key(other.major))
            .then_with(|| number_key(self.minor).cmp(&number_key(other.minor)))
            .then_with(|| number_key(self.patch).cmp(&number_key(other.patch)))
            .then_with(|| compare_prereleases(self.prerelease, other.prerelease))
    }
}

/// The key that orders decimal numbers without leading zeros by value,
/// whatever their length.
fn number_key(digits: &str) -> (usize, &str) {
    (digits.len(), digits)
}

/// Orders two prereleases, each with its leading `-`, or empty for a release.
fn compare_prereleases(a: &str, b: &str) -> Ordering {
    match (a.strip_prefix('-'), b.strip_prefix('-')) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Greater,
        (Some(_), None) => Ordering::Less,
        // The first identifier that differs decides. When none does, the
        // prerelease with more identifiers is the later one.
        (Some(a), Some(b)) => a
            .split('.')
            .map(identifier_key)
            .cmp(b.split('.').map(identifier_key)),
    }
}

/// The key that orders prerelease identifiers: a numeric one comes before
/// any other, numeric ones go by value, and the others in ASCII order.
fn identifier_key(identifier: &str) -> (bool, (usize, &str)) {
    if identifier.bytes().all(|byte| byte.is_ascii_digit()) {
        (false, number_key(identifier))
    } else {
        (true, (0, identifier))
    }
}

/// Parses `v`, or returns `None` when it is not a valid version.
pub fn parse(v: &str) -> Option<Version<'_>> {
    let rest = v.strip_prefix('v')?;
    let (major, rest) = number(rest)?;
    let short = |minor, patch| Version {
        major,
        minor,
        patch,
        prerelease: "",
        build: "",
        full: false,
    };
    if rest.is_empty() {
        return Some(short("0", "0"));
    }
    let (minor, rest) = number(rest.strip_prefix('.')?)?;
    if rest.is_empty() {
        return Some(short(minor, "0"));
    }
    let (patch, rest) = number(rest.strip_prefix('.')?)?;

    let (prerelease, rest) = if rest.starts_with('-') {
        let end = rest.find('+').unwrap_or(rest.len());
        let (prerelease, rest) = rest.split_at_checked(end)?;
        let identifiers = prerelease.strip_prefix('-')?;
        if !identifiers.split('.').all(is_prerelease_identifier) {
            return None;
        }
        (prerelease, rest)
    } else {
        ("", rest)
    };
    let build = if rest.starts_with('+') {
        let identifiers = rest.strip_prefix('+')?;
        if !identifiers.split('.').all(is_identifier) {
            return None;
        }
        rest
    } else if rest.is_empty() {
        ""
    } else {
        return None;
    };
    Some(Version {
        major,
        minor,
        patch,
        prerelease,
        build,
        full: true,
    })
}

/// Whether `v` is a valid version that spells out major, minor and patch.
pub fn is_full(v: &str) -> bool {
    parse(v).is_some_and(|version| version.full)
}

/// Splits a decimal number without leading zeros off the front of `v`.
fn number(v: &str) -> Option<(&str, &str)> {
    let end = v
        .bytes()
        .position(|byte| !byte.is_ascii_digit())
        .unwrap_or(v.len());
    let (digits, rest) = v.split_at_checked(end)?;
    if digits.is_empty() || (digits.len() > 1 && digits.starts_with('0')) {
        return None;
    }
    Some((digits, rest))
}

/// A non-empty run of ASCII letters, digits and hyphens.
fn is_identifier(identifier: &str) -> bool {
    !identifier.is_empty()
        && identifier
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

/// An identifier that, if numeric, has no leading zero.
fn is_prerelease_identifier(identifier: &str) -> bool {
    let numeric = identifier.bytes().all(|byte| byte.is_ascii_digit());
    is_identifier(identifier) && !(numeric && identifier.len() > 1 && identifier.starts_with('0'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_parts() {
        let version = parse("v1.20.3-rc.1+build.5").unwrap();
        assert_eq!(
            version,
            Version {
                major: "1",
                minor: "20",
                patch: "3",
                prerelease: "-rc.1",
                build: "+build.5",
                full: true,
            }
        );
        let short = parse("v2").unwrap();
        assert_eq!((short.major, short.minor, short.patch), ("2", "0", "0"));
        assert!(!short.full);
        let short = parse("v2.1").unwrap();
        assert_eq!((short.major, short.minor, short.patch), ("2", "1", "0"));
        assert!(!short.full);
    }

    #[test]
    fn precedence_orders_versions() {
        // Each version is below every one after it.
        let ascending = [
            "v0.9.9",
            "v0.10.0-0",
            "v0.10.0-2",
            "v0.10.0-11",
            "v0.10.0--",
            "v0.10.0-alpha",
            "v0.10.0-alpha.1",
            "v0.10.0-alpha.1.0",
            "v0.10.0-alpha.beta",
            "v0.10.0-beta",
            "v0.10.0-beta.2",
            "v0.10.0-beta.11",
            "v0.10.0-rc.1",
            "v0.10.0",
            "v0.10.1",
            "v0.10.10",
            "v0.11.0",
            "v2.0.0-rc.1",
            "v2.0.0",
            "v10.0.0",
            "v99999999999999999999.0.0",
            "v100000000000000000000.0.0",
        ];
        for (index, low) in ascending.iter().enumerate() {
            let low_version = parse(low).unwrap();
            assert_eq!(low_version.precedence(&low_version), Ordering::Equal);
            for high in &ascending[index + 1..] {
                let high_version = parse(high).unwrap();
                assert_eq!(
                    low_version.precedence(&high_version),
                    Ordering::Less,
                    "{low} {high}"
                );
                assert_eq!(
                    high_version.precedence(&low_version),
                    Ordering::Greater,
                    "{high} {low}"
                );
            }
        }
    }

    #[test]
    fn precedence_ignores_build_metadata_and_shorthand() {
        for (a, b) in [
            ("v1.2.3+gpu", "v1.2.3"),
            ("v1.2.3+a", "v1.2.3+b"),
            ("v1.2.3-rc.1+gpu", "v1.2.3-rc.1"),
            ("v1", "v1.0.0"),
            ("v1.2", "v1.2.0+mini"),
        ] {
            let (a, b) = (parse(a).unwrap(), parse(b).unwrap());
            assert_eq!(a.precedence(&b), Ordering::Equal, "{a:?} {b:?}");
        }
    }

    #[test]
    fn full_versions() {
        for v in [
            "v0.0.0",
            "v1.2.3",
            "v0.15.0-rc.1",
            "v1.2.3-0",
            "v1.2.3-alpha-1.x-y",
            "v1.2.3+meta",
            "v1.2.3+007",
            "v1.2.3-rc.1+build.5",
            "v1.2.3--",
            "v10.20.30",
        ] {
            assert!(is_full(v), "{v}");
        }
    }

    #[test]
    fn valid_shorthands_are_not_full() {
        for v in ["v1", "v1.2", "v0", "v0.15"] {
            assert!(parse(v).is_some(), "{v}");
            assert!(!is_full(v), "{v}");
        }
    }

    #[test]
    fn invalid_versions() {
        for v in [
            "",
            "v",
            "1.2.3",
            "V1.2.3",
            "v01.2.3",
            "v1.02.3",
            "v1.2.03",
            "v1.2.3.4",
            "v1.2.",
            "v1..3",
            "v1.2.3-",
            "v1.2.3-01",
            "v1.2.3-a..b",
            "v1.2.3-a.",
            "v1.2.3-a_b",
            "v1.2.3+",
            "v1.2.3+a..b",
            "v1.2.3+a+b",
            "v1.2.3+mini/other",
            "v1.2.3 ",
            " v1.2.3",
            "v1.2-rc.1",
            "v1-rc",
            "v1.2.3-\u{e9}",
            "v1.2.x",
            "v-1.2.3",
            "v+1.2.3",
        ] {
            assert!(parse(v).is_none(), "{v:?}");
            assert!(!is_full(v), "{v:?}");
        }
    }
}
