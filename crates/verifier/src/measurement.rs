//! The register values that verification reports and accepts: what a CPU
//! measured at launch, and the registers that a release or a caller expects
//! it to have measured.

use std::fmt;
use std::str::FromStr;

use crate::canonical;
use crate::error::{Error, UsageError};

/// The size in bytes of every SEV-SNP and TDX measurement register.
pub const REGISTER_SIZE: usize = 48;

/// One measurement register. Its text form is lowercase hex.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Register([u8; REGISTER_SIZE]);

impl Register {
    /// A register with the given bytes.
    pub const fn new(bytes: [u8; REGISTER_SIZE]) -> Self {
        Self(bytes)
    }

    /// The register's bytes.
    pub const fn as_bytes(&self) -> &[u8; REGISTER_SIZE] {
        &self.0
    }
}

impl From<[u8; REGISTER_SIZE]> for Register {
    fn from(bytes: [u8; REGISTER_SIZE]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for Register {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Parses a register from hex in either case.
///
/// The length is checked first, so an oversized input is rejected without
/// being decoded.
impl FromStr for Register {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_register(s).map_err(|message| UsageError::new(message).into())
    }
}

/// Parses a register from hex in either case; the error is a message.
pub(crate) fn parse_register(s: &str) -> Result<Register, String> {
    let want = REGISTER_SIZE.saturating_mul(2);
    if s.len() != want {
        return Err(format!(
            "register must be {want} hex characters, got {}",
            s.len()
        ));
    }
    canonical::decode_hex(s)
        .and_then(|bytes| <[u8; REGISTER_SIZE]>::try_from(bytes).ok())
        .map(Register)
        .ok_or_else(|| "register is not hex".to_owned())
}

/// Parses one expected register; the empty string leaves it unconstrained.
fn parse_expected(label: &str, value: &str) -> Result<Option<Register>, Error> {
    if value.is_empty() {
        return Ok(None);
    }
    match parse_register(value) {
        Ok(register) => Ok(Some(register)),
        Err(message) => Err(UsageError::new(format!("{label}: {message}")).into()),
    }
}

impl fmt::Display for Register {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&canonical::encode_lower_hex(&self.0))
    }
}

impl fmt::Debug for Register {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Register({self})")
    }
}

/// The registers that a CPU measured at launch.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Measurement {
    /// An AMD SEV-SNP launch measurement.
    SevSnp {
        /// The launch digest.
        launch: Register,
    },
    /// An Intel TDX build-time measurement and its four runtime registers.
    Tdx {
        /// The build-time measurement of the trust domain.
        mrtd: Register,
        /// Runtime measurement register 0.
        rtmr0: Register,
        /// Runtime measurement register 1.
        rtmr1: Register,
        /// Runtime measurement register 2.
        rtmr2: Register,
        /// Runtime measurement register 3.
        rtmr3: Register,
    },
}

impl Measurement {
    /// Expectations that pin every register of the measurement.
    pub fn expected(&self) -> Expected {
        match *self {
            Measurement::SevSnp { launch } => Expected::SevSnp {
                launch: Some(launch),
            },
            Measurement::Tdx {
                mrtd,
                rtmr0,
                rtmr1,
                rtmr2,
                rtmr3,
            } => Expected::Tdx {
                mrtd: Some(mrtd),
                rtmr0: Some(rtmr0),
                rtmr1: Some(rtmr1),
                rtmr2: Some(rtmr2),
                rtmr3: Some(rtmr3),
            },
        }
    }
}

/// The platform name, then one labelled register per line.
impl fmt::Display for Measurement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.expected().fmt(f)
    }
}

/// A set of registers that a measurement must match, where `None` leaves a
/// register unconstrained: the registers that a release fixes, or a caller's
/// pins.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Expected {
    /// Constrains an SEV-SNP launch measurement.
    SevSnp {
        /// The launch digest.
        launch: Option<Register>,
    },
    /// Constrains a TDX measurement register by register.
    Tdx {
        /// The build-time measurement of the trust domain.
        mrtd: Option<Register>,
        /// Runtime measurement register 0.
        rtmr0: Option<Register>,
        /// Runtime measurement register 1.
        rtmr1: Option<Register>,
        /// Runtime measurement register 2.
        rtmr2: Option<Register>,
        /// Runtime measurement register 3.
        rtmr3: Option<Register>,
    },
}

impl Expected {
    /// Parses the launch measurement from hex in either case. An empty string
    /// leaves it unconstrained.
    pub fn parse_sev_snp(launch: &str) -> Result<Self, Error> {
        Ok(Expected::SevSnp {
            launch: parse_expected("Launch", launch)?,
        })
    }

    /// Parses each register from hex in either case. An empty string leaves
    /// that register unconstrained.
    pub fn parse_tdx(
        mrtd: &str,
        rtmr0: &str,
        rtmr1: &str,
        rtmr2: &str,
        rtmr3: &str,
    ) -> Result<Self, Error> {
        Ok(Expected::Tdx {
            mrtd: parse_expected("MRTD", mrtd)?,
            rtmr0: parse_expected("RTMR0", rtmr0)?,
            rtmr1: parse_expected("RTMR1", rtmr1)?,
            rtmr2: parse_expected("RTMR2", rtmr2)?,
            rtmr3: parse_expected("RTMR3", rtmr3)?,
        })
    }
}

/// The platform name, then one labelled register per line, with `any` for an
/// unconstrained register.
impl fmt::Display for Expected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (platform, registers): (&str, &[(&str, &Option<Register>)]) = match self {
            Expected::SevSnp { launch } => ("SEV-SNP", &[("Launch", launch)]),
            Expected::Tdx {
                mrtd,
                rtmr0,
                rtmr1,
                rtmr2,
                rtmr3,
            } => (
                "TDX",
                &[
                    ("MRTD", mrtd),
                    ("RTMR0", rtmr0),
                    ("RTMR1", rtmr1),
                    ("RTMR2", rtmr2),
                    ("RTMR3", rtmr3),
                ],
            ),
        };
        f.write_str(platform)?;
        for (label, register) in registers {
            match register {
                Some(register) => write!(f, "\n{label:<6} {register}")?,
                None => write!(f, "\n{label:<6} any")?,
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn register(first: u8) -> Register {
        let mut bytes = [0; REGISTER_SIZE];
        bytes[0] = first;
        Register(bytes)
    }

    fn tdx() -> Measurement {
        Measurement::Tdx {
            mrtd: register(1),
            rtmr0: register(2),
            rtmr1: register(3),
            rtmr2: register(4),
            rtmr3: register(5),
        }
    }

    #[test]
    fn parse_register() {
        let mut bytes = [0; REGISTER_SIZE];
        bytes[0] = 0xab;
        bytes[1] = 0xcd;
        let want = Register(bytes);
        let lower = "abcd".to_owned() + &"00".repeat(REGISTER_SIZE - 2);
        for input in [lower.clone(), lower.to_uppercase()] {
            assert_eq!(input.parse::<Register>().unwrap(), want);
        }
        assert_eq!(want.to_string(), lower, "the text form is lowercase");
        assert_eq!(want.as_bytes(), &bytes);
        assert_eq!(Register::from(bytes), want);
        assert_eq!(Register::new(bytes).as_ref(), &bytes[..]);
        assert_eq!(format!("{want:?}"), format!("Register({lower})"));

        // The length is checked before decoding.
        let cases = [
            ("not hex", "zz".repeat(REGISTER_SIZE), "not hex"),
            (
                "too short",
                "ab".repeat(REGISTER_SIZE - 1),
                "96 hex characters",
            ),
            (
                "too long",
                "ab".repeat(REGISTER_SIZE + 1),
                "96 hex characters",
            ),
            (
                "too long, no hex",
                "zz".repeat(REGISTER_SIZE + 1),
                "96 hex characters",
            ),
            ("empty", String::new(), "96 hex characters"),
            (
                "non-ASCII of the right length",
                "\u{e9}".repeat(REGISTER_SIZE),
                "not hex",
            ),
        ];
        for (name, input, want) in cases {
            let error = input.parse::<Register>().unwrap_err();
            assert!(matches!(error, Error::Usage(_)), "{name}");
            assert!(error.to_string().contains(want), "{name}: {error}");
        }
    }

    #[test]
    fn register_text_round_trips() {
        let register = register(0x01);
        let text = register.to_string();
        assert!(text.starts_with("01"));
        assert_eq!(text.len(), REGISTER_SIZE * 2);
        assert_eq!(text.parse::<Register>().unwrap(), register);
        assert!("zz".parse::<Register>().is_err());
    }

    #[test]
    fn parse_expected_registers() {
        let Measurement::Tdx {
            mrtd,
            rtmr0,
            rtmr1,
            rtmr2,
            rtmr3,
        } = tdx()
        else {
            unreachable!()
        };
        let all = Expected::parse_tdx(
            &mrtd.to_string(),
            &rtmr0.to_string(),
            &rtmr1.to_string(),
            &rtmr2.to_string(),
            &rtmr3.to_string(),
        )
        .unwrap();
        assert_eq!(all, tdx().expected(), "arguments are in register order");

        let sparse =
            Expected::parse_tdx("", "", "", "", &rtmr3.to_string().to_uppercase()).unwrap();
        let want = Expected::Tdx {
            mrtd: None,
            rtmr0: None,
            rtmr1: None,
            rtmr2: None,
            rtmr3: Some(rtmr3),
        };
        assert_eq!(
            sparse, want,
            "an empty string leaves a register unconstrained"
        );

        let sev = Measurement::SevSnp {
            launch: register(1),
        };
        let launch = Expected::parse_sev_snp(&register(1).to_string()).unwrap();
        assert_eq!(launch, sev.expected());
        let unpinned = Expected::parse_sev_snp("").unwrap();
        assert_eq!(unpinned, Expected::SevSnp { launch: None });

        let error = Expected::parse_tdx("", "", "", "abcd", "").unwrap_err();
        assert!(matches!(error, Error::Usage(_)));
        assert!(
            error
                .to_string()
                .contains("RTMR2: register must be 96 hex characters"),
            "{error}"
        );
        let error = Expected::parse_sev_snp(&"zz".repeat(REGISTER_SIZE)).unwrap_err();
        assert!(
            error.to_string().contains("Launch: register is not hex"),
            "{error}"
        );
    }

    #[test]
    fn expected_pins_every_register() {
        assert_eq!(
            tdx().expected(),
            Expected::Tdx {
                mrtd: Some(register(1)),
                rtmr0: Some(register(2)),
                rtmr1: Some(register(3)),
                rtmr2: Some(register(4)),
                rtmr3: Some(register(5)),
            }
        );
        let sev = Measurement::SevSnp {
            launch: register(1),
        };
        assert_eq!(
            sev.expected(),
            Expected::SevSnp {
                launch: Some(register(1))
            }
        );
    }

    #[test]
    fn display() {
        let register = register(0xab);
        assert_eq!(
            Measurement::SevSnp { launch: register }.to_string(),
            format!("SEV-SNP\nLaunch {register}")
        );
        let expected = Expected::Tdx {
            mrtd: None,
            rtmr0: None,
            rtmr1: Some(register),
            rtmr2: None,
            rtmr3: None,
        };
        assert_eq!(
            expected.to_string(),
            format!("TDX\nMRTD   any\nRTMR0  any\nRTMR1  {register}\nRTMR2  any\nRTMR3  any")
        );
        assert_eq!(
            Expected::SevSnp { launch: None }.to_string(),
            "SEV-SNP\nLaunch any"
        );
        assert!(tdx().to_string().starts_with("TDX\nMRTD   01"));
    }

    #[test]
    fn a_clone_is_equal_and_independent() {
        let original = Expected::Tdx {
            mrtd: None,
            rtmr0: None,
            rtmr1: Some(register(0xab)),
            rtmr2: None,
            rtmr3: None,
        };
        let mut clone = original.clone();
        assert_eq!(original, clone);
        if let Expected::Tdx { rtmr1, .. } = &mut clone {
            *rtmr1 = Some(register(0xcd));
        }
        assert_ne!(original, clone);
    }
}
