//! Product selection and AMD TCB layouts, matching Tinfoil's go-sev-guest fork.
use crate::error::{Error, Result};
use crate::verifier::attestation::constants::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Product {
    Genoa,
    Turin,
}

impl Product {
    /// CPUID fields are inside the signed report. Older reports lack them and
    /// may only use the legacy Genoa path; the V3 path requires report v3+.
    pub(super) fn from_report(report: &[u8], require_cpuid: bool) -> Result<Self> {
        let version = u32::from_le_bytes(report[..4].try_into().unwrap());
        if version < 3 {
            if require_cpuid {
                return Err(err(
                    "Report carries no CPUID product identity (want report v3+)",
                ));
            }
            return Ok(Self::Genoa);
        }
        match (report[0x188], report[0x189]) {
            (0x19, 0x11) => Ok(Self::Genoa),
            (0x1a, 0x02) => Ok(Self::Turin),
            (family, model) => Err(err(&format!(
                "Unsupported SEV CPUID family 0x{family:x}/model 0x{model:x}"
            ))),
        }
    }
    pub(super) fn name(self) -> &'static str {
        match self {
            Self::Genoa => "Genoa",
            Self::Turin => "Turin",
        }
    }
    pub(super) fn ark_fingerprint(self) -> &'static str {
        match self {
            Self::Genoa => AMD_ARK_GENOA_SPKI_FINGERPRINT,
            Self::Turin => AMD_ARK_TURIN_SPKI_FINGERPRINT,
        }
    }
    pub(super) fn chain(self) -> &'static [u8] {
        match self {
            Self::Genoa => crate::verifier::embedded::GENOA_CERT_CHAIN,
            Self::Turin => crate::verifier::embedded::TURIN_CERT_CHAIN,
        }
    }
    pub(super) fn hwid_len(self) -> usize {
        match self {
            Self::Genoa => 64,
            Self::Turin => 8,
        }
    }
    pub(super) fn struct_version(self) -> u8 {
        match self {
            Self::Genoa => 0,
            Self::Turin => 1,
        }
    }
    pub(super) fn tcb(self, raw: u64) -> Result<Tcb> {
        match self {
            Self::Genoa => {
                if raw & 0x0000_ffff_ffff_0000 != 0 {
                    return Err(err("Nonzero reserved bits in Genoa TCB"));
                }
                Ok(Tcb {
                    fmc: None,
                    bl: raw as u8,
                    tee: (raw >> 8) as u8,
                    snp: (raw >> 48) as u8,
                    ucode: (raw >> 56) as u8,
                })
            }
            Self::Turin => {
                if raw & 0x00ff_ffff_0000_0000 != 0 {
                    return Err(err("Nonzero reserved bits in Turin TCB"));
                }
                Ok(Tcb {
                    fmc: Some(raw as u8),
                    bl: (raw >> 8) as u8,
                    tee: (raw >> 16) as u8,
                    snp: (raw >> 24) as u8,
                    ucode: (raw >> 56) as u8,
                })
            }
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Tcb {
    pub fmc: Option<u8>,
    pub bl: u8,
    pub tee: u8,
    pub snp: u8,
    pub ucode: u8,
}
impl Tcb {
    pub(super) fn le(self, other: Self) -> bool {
        self.fmc.is_some() == other.fmc.is_some()
            && self.fmc.unwrap_or(0) <= other.fmc.unwrap_or(0)
            && self.bl <= other.bl
            && self.tee <= other.tee
            && self.snp <= other.snp
            && self.ucode <= other.ucode
    }
}
fn err(s: &str) -> Error {
    Error::AttestationVerification(s.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn product_and_tcb_are_bound_to_report_cpuid() {
        let mut r = vec![0; REPORT_SIZE];
        r[..4].copy_from_slice(&5u32.to_le_bytes());
        r[0x188] = 0x1a;
        r[0x189] = 2;
        let p = Product::from_report(&r, true).unwrap();
        assert_eq!(p, Product::Turin);
        assert_eq!(
            p.tcb(0x5200_0000_0401_0101).unwrap(),
            Tcb {
                fmc: Some(1),
                bl: 1,
                tee: 1,
                snp: 4,
                ucode: 82
            }
        );
        assert!(p.tcb(0x5200_0001_0401_0101).is_err());
        r[0x188] = 0x19;
        r[0x189] = 0x11;
        assert_eq!(Product::from_report(&r, true).unwrap(), Product::Genoa);
        assert!(Product::Genoa.tcb(0x5200_0000_0401_0101).is_err());
        r[0x189] = 0xff;
        assert!(Product::from_report(&r, true).is_err());
        r[..4].copy_from_slice(&2u32.to_le_bytes());
        assert!(Product::from_report(&r, true).is_err());
    }
}
