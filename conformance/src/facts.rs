//! The facts of a full verification, laid out for the wire. Full
//! verification of a recorded document and of a running enclave report the
//! same facts through these functions.

use tinfoil_verifier::{Expected, Layer, Measurement as Registers, Register, Verification};

use crate::{
    AcceptOutputs, CODE_ENVELOPE_REJECTED, CODE_POLICY_REJECTED, CODE_PROVENANCE_REJECTED,
    CODE_QUOTE_REJECTED, Measurement,
};

/// The measurement type of an SEV-SNP quote on the wire.
pub(crate) const SEV_SNP_MEASUREMENT_TYPE: &str = "https://tinfoil.sh/predicate/sev-snp-guest/v2";
/// The measurement type of a TDX quote on the wire.
pub(crate) const TDX_MEASUREMENT_TYPE: &str = "https://tinfoil.sh/predicate/tdx-guest/v2";

/// Lays out authenticated registers for the wire, in platform order.
/// `None` for a measurement of a platform that the wire contract does not
/// know.
pub(crate) fn measurement(registers: &Registers) -> Option<Measurement> {
    Some(match registers {
        Registers::SevSnp { launch } => Measurement {
            kind: SEV_SNP_MEASUREMENT_TYPE.to_owned(),
            registers: vec![launch.to_string()],
        },
        Registers::Tdx {
            mrtd,
            rtmr0,
            rtmr1,
            rtmr2,
            rtmr3,
        } => Measurement {
            kind: TDX_MEASUREMENT_TYPE.to_owned(),
            registers: [mrtd, rtmr0, rtmr1, rtmr2, rtmr3]
                .into_iter()
                .map(ToString::to_string)
                .collect(),
        },
        _ => return None,
    })
}

/// Lays out expected registers for the wire, in platform order, with an
/// empty string for a register that is left unconstrained. `None` for a
/// platform that the wire contract does not know.
pub(crate) fn expected(registers: &Expected) -> Option<Measurement> {
    let hex = |register: &Option<Register>| {
        register
            .map(|register| register.to_string())
            .unwrap_or_default()
    };
    Some(match registers {
        Expected::SevSnp { launch } => Measurement {
            kind: SEV_SNP_MEASUREMENT_TYPE.to_owned(),
            registers: vec![hex(launch)],
        },
        Expected::Tdx {
            mrtd,
            rtmr0,
            rtmr1,
            rtmr2,
            rtmr3,
        } => Measurement {
            kind: TDX_MEASUREMENT_TYPE.to_owned(),
            registers: [mrtd, rtmr0, rtmr1, rtmr2, rtmr3]
                .into_iter()
                .map(hex)
                .collect(),
        },
        _ => return None,
    })
}

/// The rejection code of a verifier layer. `None` for a layer that the
/// wire contract does not know.
pub(crate) fn layer_code(layer: Layer) -> Option<&'static str> {
    match layer {
        Layer::Envelope => Some(CODE_ENVELOPE_REJECTED),
        Layer::Provenance => Some(CODE_PROVENANCE_REJECTED),
        Layer::Quote => Some(CODE_QUOTE_REJECTED),
        Layer::Policy => Some(CODE_POLICY_REJECTED),
        _ => None,
    }
}

/// The facts of a verification. `None` when it endorses no usable TLS or
/// HPKE key: such a document is of no use to a client, which binds its
/// traffic to those keys.
pub(crate) fn verified(verification: &Verification) -> Option<AcceptOutputs> {
    let (Some(tls_public_key_fp), Some(hpke_public_key)) = (
        verification.tls_public_key_fp(),
        verification.hpke_public_key(),
    ) else {
        return None;
    };
    Some(AcceptOutputs {
        code_digest: verification.code_digest().to_owned(),
        code_measurement: expected(verification.code_measurement()),
        enclave_measurement: measurement(verification.enclave_measurement()),
        tls_public_key_fp: tls_public_key_fp.to_owned(),
        hpke_public_key: hpke_public_key.to_owned(),
        ..AcceptOutputs::default()
    })
}
