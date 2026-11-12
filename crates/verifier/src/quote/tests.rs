//! Tests of policy assembly: how reference values, caller pins and the
//! document's challenge resolve into the expected state of a quote.

use sha2::{Digest, Sha256};

use super::resolve::{apply_pins, complete};
use super::{
    Authenticated, ConfigReferenceValues, LegacyReferenceValues, ReferenceValues, VendorRoots,
    assemble, assemble_with_report_data, authenticate,
};
use crate::canonical::encode_lower_hex;
use crate::differential_tests::{Fixture, instant, member, object, text};
use crate::document::{self, Document};
use crate::endorsement::ProvenanceClient;
use crate::measurement::{Expected, Measurement, REGISTER_SIZE, Register};
use crate::policy::{self, ARTIFACT_FORMAT, Artifact, Policy, Shape};
use crate::runtime::{Measurements, decode_manifest};

fn register(byte: u8) -> Register {
    Register::new([byte; REGISTER_SIZE])
}

fn tdx(registers: [Option<Register>; 5]) -> Expected {
    let [mrtd, rtmr0, rtmr1, rtmr2, rtmr3] = registers;
    Expected::Tdx {
        mrtd,
        rtmr0,
        rtmr1,
        rtmr2,
        rtmr3,
    }
}

fn sev_snp(launch: Option<Register>) -> Expected {
    Expected::SevSnp { launch }
}

#[test]
fn a_pin_fills_an_open_register_and_may_repeat_a_fixed_one() {
    let r = register(0xab);
    let release = tdx([None, None, Some(r), Some(r), None]);
    assert_eq!(apply_pins(&release, None).unwrap(), release);
    assert_eq!(
        apply_pins(&release, Some(&tdx([None, None, None, None, Some(r)]))).unwrap(),
        tdx([None, None, Some(r), Some(r), Some(r)])
    );
    let launch = sev_snp(Some(r));
    assert_eq!(apply_pins(&launch, Some(&launch)).unwrap(), launch);
    assert_eq!(apply_pins(&launch, Some(&sev_snp(None))).unwrap(), launch);
    assert_eq!(
        apply_pins(&sev_snp(None), Some(&launch)).unwrap(),
        launch,
        "a pin fills the launch measurement that nothing else fixes"
    );
}

#[test]
fn a_pin_that_differs_from_a_fixed_register_is_refused_by_name() {
    let (r, other) = (register(0xab), register(0xcd));
    let measured = tdx([Some(r); 5]);
    assert_eq!(
        apply_pins(&measured, Some(&tdx([None, None, Some(r), None, None]))).unwrap(),
        measured
    );
    let cases = [
        (tdx([Some(other), None, None, None, None]), "MRTD"),
        (tdx([None, Some(other), None, None, None]), "RTMR0"),
        (tdx([None, None, Some(other), None, None]), "RTMR1"),
        (tdx([None, None, None, Some(other), None]), "RTMR2"),
        (tdx([None, None, None, None, Some(other)]), "RTMR3"),
        // The first register that disagrees is the one that is named.
        (tdx([None, None, Some(other), Some(other), None]), "RTMR1"),
    ];
    for (pins, name) in cases {
        let error = apply_pins(&measured, Some(&pins)).unwrap_err();
        assert_eq!(
            error.to_string(),
            format!("pinned {name} does not match the signed release measurement")
        );
    }
    let error = apply_pins(&sev_snp(Some(r)), Some(&sev_snp(Some(other)))).unwrap_err();
    assert_eq!(
        error.to_string(),
        "pinned launch measurement does not match the signed release measurement"
    );
}

#[test]
fn pins_for_the_other_platform_are_refused_in_both_directions() {
    let r = register(0xab);
    // Even when the pinned value equals a register that the release fixes.
    let error = apply_pins(
        &tdx([None, None, Some(r), Some(r), None]),
        Some(&sev_snp(Some(r))),
    )
    .unwrap_err();
    assert_eq!(
        error.to_string(),
        "pinned registers are for sev-snp, but the enclave is tdx"
    );
    let error = apply_pins(
        &sev_snp(Some(r)),
        Some(&tdx([None, None, Some(r), None, None])),
    )
    .unwrap_err();
    assert_eq!(
        error.to_string(),
        "pinned registers are for tdx, but the enclave is sev-snp"
    );
    // Pins that set nothing are still for one platform.
    assert!(apply_pins(&sev_snp(Some(r)), Some(&tdx([None; 5]))).is_err());
}

#[test]
fn assembly_needs_a_value_for_every_register() {
    let r = register(0xab);
    assert_eq!(
        complete(&tdx([Some(r); 5])).unwrap(),
        Measurement::Tdx {
            mrtd: r,
            rtmr0: r,
            rtmr1: r,
            rtmr2: r,
            rtmr3: r
        }
    );
    assert_eq!(
        complete(&sev_snp(Some(r))).unwrap(),
        Measurement::SevSnp { launch: r }
    );
    let error = complete(&tdx([None, None, Some(r), Some(r), None])).unwrap_err();
    assert_eq!(
        error.to_string(),
        "nothing fixes the expected MRTD, RTMR0, RTMR3"
    );
    let error = complete(&sev_snp(None)).unwrap_err();
    assert_eq!(
        error.to_string(),
        "nothing fixes the expected launch measurement"
    );
}

/// A recorded case with its parsed document and authenticated quote.
struct Quoted {
    document: Document,
    quote: Authenticated,
}

fn quoted(fixture: &Fixture, name: &str) -> Quoted {
    let case = fixture.case(name);
    let bytes = fixture.document(text(case, "doc")).unwrap();
    let document = document::parse(&bytes, &Fixture::nonce(case)).unwrap();
    let roots = VendorRoots::dangerous_test_only(
        fixture.root(text(case, "amd")),
        fixture.root(text(case, "intel")),
    );
    let quote = authenticate(
        document.cpu_evidence(),
        document.cpu_endorsements(),
        instant(case),
        &roots,
    )
    .unwrap();
    Quoted { document, quote }
}

/// The embedded references of a recorded case: the config's hash, the
/// runtime's measurements and the platform policy artifact.
fn config_references(fixture: &Fixture, name: &str) -> ([u8; 32], Measurements, Artifact) {
    let options = object(member(fixture.case(name), "options"));
    let embedded = object(member(options, "embedded"));
    let config = fixture.blob(embedded, "config_b64").unwrap();
    let manifest = fixture.blob(embedded, "runtime_b64").unwrap();
    let platform = fixture.blob(embedded, "platform_b64").unwrap();
    (
        Sha256::digest(&config).into(),
        decode_manifest(&manifest).unwrap().measurements,
        policy::parse(&platform).unwrap(),
    )
}

/// The platform policy artifact that a recorded code-release document
/// carries, authenticated under the synthetic trusted root.
fn legacy_artifact(fixture: &Fixture, document: &Document) -> Artifact {
    let client =
        ProvenanceClient::from_trusted_root_json(&fixture.root("synthetic").unwrap()).unwrap();
    let reference = document.sigstore_platform().unwrap();
    client
        .authenticate_platform_endorsements(
            &reference.bundle,
            &reference.repo,
            &reference.tag,
            &reference.digest,
            ARTIFACT_FORMAT,
        )
        .unwrap()
        .policy
}

#[test]
fn a_config_resolves_the_runtime_registers_and_binds_its_hash() {
    let fixture = Fixture::load();
    for (name, platform) in [
        ("config-sev/embedded-all", "sev-snp"),
        ("config-tdx/embedded-all", "tdx"),
    ] {
        let Quoted { document, quote } = quoted(&fixture, name);
        assert_eq!(quote.platform(), platform);
        let (hash, runtime, artifact) = config_references(&fixture, name);
        let references = ConfigReferenceValues {
            endorsements: &artifact,
            runtime: &runtime,
            hash,
        };
        let resolved = references.resolve(&quote, None).unwrap();
        assert_eq!(resolved.code, resolved.expected, "{name}");
        assert_eq!(resolved.platform_measurement_name, None);
        let zero = Some(register(0));
        match &quote {
            Authenticated::SevSnp(_) => {
                assert_eq!(resolved.host_data, encode_lower_hex(&hash));
                assert_eq!(resolved.config_id, [0; 48]);
                let launch = runtime.snp_launch.measurement.parse().unwrap();
                assert_eq!(resolved.expected, sev_snp(Some(launch)));
            }
            Authenticated::Tdx(_) => {
                assert_eq!(resolved.host_data, "");
                assert_eq!(resolved.config_id[..32], hash);
                assert_eq!(resolved.config_id[32..], [0; 16]);
                let mrtd = runtime.tdx_launch.mrtd.parse().unwrap();
                assert_eq!(resolved.expected, tdx([Some(mrtd), zero, zero, zero, zero]));
            }
        }

        // A pin that differs from what the runtime fixes is refused.
        let other = Some(register(0xcd));
        let pins = match &quote {
            Authenticated::SevSnp(_) => sev_snp(other),
            Authenticated::Tdx(_) => tdx([other, None, None, None, None]),
        };
        let error = references.resolve(&quote, Some(&pins)).unwrap_err();
        assert!(error.to_string().contains("does not match"), "{error}");

        // The whole policy assembles for the document and validates.
        let references = ReferenceValues::Config(references);
        let assembled = assemble(&document, &references, None, &quote).unwrap();
        assembled.validate().unwrap();
        assert_eq!(assembled.code_measurement(), &resolved.expected);

        // A config with another hash assembles, and the quote fails it.
        let mut wrong = hash;
        wrong[0] ^= 1;
        let references = ReferenceValues::Config(ConfigReferenceValues {
            endorsements: &artifact,
            runtime: &runtime,
            hash: wrong,
        });
        let assembled = assemble(&document, &references, None, &quote).unwrap();
        assert!(assembled.validate().is_err(), "{name}");

        // A policy that carries workload values of its own cannot be
        // combined with a config.
        let mut workload = artifact.clone();
        for policy in workload.policies.values_mut() {
            match policy {
                Policy::SevSnp(policy) => policy.host_data = "00".repeat(32),
                Policy::Tdx(policy) => policy.platform_measurements.push("m1".to_owned()),
            }
        }
        let error = ConfigReferenceValues {
            endorsements: &workload,
            runtime: &runtime,
            hash,
        }
        .resolve(&quote, None)
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("cannot be combined with platform"),
            "{error}"
        );

        // A machine that the artifact does not list is not endorsed.
        let mut unendorsed = artifact.clone();
        unendorsed.machines.clear();
        let error = ConfigReferenceValues {
            endorsements: &unendorsed,
            runtime: &runtime,
            hash,
        }
        .resolve(&quote, None)
        .unwrap_err();
        assert!(error.to_string().contains("is not endorsed"), "{error}");
    }
}

#[test]
fn a_release_on_tdx_takes_its_platform_registers_from_the_artifact() {
    let fixture = Fixture::load();
    let Quoted { document, quote } = quoted(&fixture, "legacy-tdx/default");
    let artifact = legacy_artifact(&fixture, &document);
    let Measurement::Tdx {
        mrtd,
        rtmr0,
        rtmr1,
        rtmr2,
        ..
    } = quote.measurement()
    else {
        panic!("a TDX quote");
    };
    let shape = Shape {
        cpus: 8,
        memory_mb: 32768,
        gpus: Some(1),
        disks: 2,
    };
    let references = LegacyReferenceValues {
        endorsements: &artifact,
        sev_snp_launch: register(0xab),
        tdx_rtmr1: rtmr1,
        tdx_rtmr2: rtmr2,
        shape: &shape,
    };
    let resolved = references.resolve(&quote, None).unwrap();
    assert_eq!(
        resolved.code,
        tdx([None, None, Some(rtmr1), Some(rtmr2), None])
    );
    assert_eq!(
        resolved.expected,
        tdx([
            Some(mrtd),
            Some(rtmr0),
            Some(rtmr1),
            Some(rtmr2),
            Some(register(0))
        ]),
        "the artifact supplies MRTD and RTMR0, and an unpinned RTMR3 is zero"
    );
    assert_eq!(resolved.platform_measurement_name.as_deref(), Some("m1"));
    assert_eq!(resolved.policy_name, "tdx-policy");

    // A pin wins over the platform's value and over the zero RTMR3.
    let pinned = Some(register(0xcd));
    let pins = tdx([pinned, None, None, None, pinned]);
    let resolved = references.resolve(&quote, Some(&pins)).unwrap();
    assert_eq!(
        resolved.expected,
        tdx([pinned, Some(rtmr0), Some(rtmr1), Some(rtmr2), pinned])
    );

    // Only measurements for the release's VM shape are candidates.
    let other_shape = Shape { cpus: 2, ..shape };
    let error = LegacyReferenceValues {
        shape: &other_shape,
        ..references.clone()
    }
    .resolve(&quote, None)
    .unwrap_err();
    assert!(error.to_string().contains("VM shape"), "{error}");

    let values = ReferenceValues::Legacy(references);
    assemble(&document, &values, None, &quote)
        .unwrap()
        .validate()
        .unwrap();
}

#[test]
fn a_release_on_sev_snp_takes_its_host_data_from_the_policy() {
    let fixture = Fixture::load();
    let Quoted { document, quote } = quoted(&fixture, "legacy-sev/default");
    let artifact = legacy_artifact(&fixture, &document);
    let Measurement::SevSnp { launch } = quote.measurement() else {
        panic!("an SEV-SNP quote");
    };
    // The VM shape is not consulted on SEV-SNP.
    let shape = Shape {
        cpus: 1,
        memory_mb: 1,
        gpus: None,
        disks: 1,
    };
    let references = LegacyReferenceValues {
        endorsements: &artifact,
        sev_snp_launch: launch,
        tdx_rtmr1: register(1),
        tdx_rtmr2: register(2),
        shape: &shape,
    };
    let resolved = references.resolve(&quote, None).unwrap();
    assert_eq!(resolved.expected, sev_snp(Some(launch)));
    assert_eq!(resolved.host_data, "00".repeat(32));
    assert_eq!(resolved.platform_measurement_name, None);

    let report_data = document.expected_report_data().unwrap();
    let values = ReferenceValues::Legacy(references.clone());
    assemble_with_report_data(&values, None, &report_data, &quote)
        .unwrap()
        .validate()
        .unwrap();

    // Other report data assembles, and the quote fails it.
    let mut wrong = report_data;
    wrong[0] ^= 0xff;
    let assembled = assemble_with_report_data(&values, None, &wrong, &quote).unwrap();
    assert!(assembled.validate().is_err());

    // A release with another launch measurement assembles, and the quote
    // fails it.
    let other = ReferenceValues::Legacy(LegacyReferenceValues {
        sev_snp_launch: register(0xab),
        ..references
    });
    let assembled = assemble(&document, &other, None, &quote).unwrap();
    assert!(assembled.validate().is_err());
}

#[test]
fn assembly_needs_a_document_that_was_checked_against_a_nonce() {
    let fixture = Fixture::load();
    let name = "config-sev/embedded-all";
    let Quoted { quote, .. } = quoted(&fixture, name);
    let (hash, runtime, artifact) = config_references(&fixture, name);
    let references = ReferenceValues::Config(ConfigReferenceValues {
        endorsements: &artifact,
        runtime: &runtime,
        hash,
    });
    let case = fixture.case(name);
    let bytes = fixture.document(text(case, "doc")).unwrap();
    let unbound = document::decode(&bytes).unwrap();
    let error = assemble(&unbound, &references, None, &quote).unwrap_err();
    assert!(
        error.to_string().contains("checked against a nonce"),
        "{error}"
    );
}

#[test]
fn a_quote_is_not_appraised_against_another_document() {
    let fixture = Fixture::load();
    let name = "config-sev/embedded-all";
    let Quoted { document, .. } = quoted(&fixture, name);
    let (hash, runtime, artifact) = config_references(&fixture, name);
    let references = ReferenceValues::Config(ConfigReferenceValues {
        endorsements: &artifact,
        runtime: &runtime,
        hash,
    });
    for other in ["legacy-sev/default", "config-tdx/embedded-all"] {
        let Quoted { quote, .. } = quoted(&fixture, other);
        let error = assemble(&document, &references, None, &quote).unwrap_err();
        assert_eq!(
            error.to_string(),
            "authenticated quote is not this document's CPU evidence",
            "{other}"
        );
    }
}
