//! Replays recorded authentication cases: quotes and collateral, minted
//! under a test root or taken from production, each with the outcome that
//! an independent implementation of the same checks gave.
//!
//! A case names its quote, its recorded responses, the verification time
//! and the trust anchor. Byte strings live in a pool; an entry is either
//! the bytes in base64 or another entry with splices applied.

use std::collections::BTreeMap;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

use super::authenticate::{Evidence, authenticate};
use crate::document::collateral::PcsResponse;
use crate::instant::Instant;
use crate::json::{self, Value};
use crate::measurement::Measurement;

const CASES: &str = include_str!("../../../tests/data/quote-tdx/authenticate_differential.json");

pub(super) struct Pool<'a> {
    entries: &'a [Value],
    resolved: Vec<Option<Vec<u8>>>,
}

pub(super) fn member<'a>(value: &'a Value, name: &str) -> &'a Value {
    value
        .as_object()
        .unwrap()
        .get(name)
        .unwrap_or_else(|| panic!("no member {name}"))
}

pub(super) fn integer(value: &Value) -> i64 {
    value.as_number().unwrap().to_i64().unwrap()
}

pub(super) fn index(value: &Value) -> usize {
    usize::try_from(integer(value)).unwrap()
}

impl<'a> Pool<'a> {
    pub(super) fn new(document: &'a Value) -> Self {
        let entries = member(document, "pool").as_array().unwrap();
        Pool {
            entries,
            resolved: vec![None; entries.len()],
        }
    }

    pub(super) fn get(&mut self, at: usize) -> Vec<u8> {
        if let Some(bytes) = &self.resolved[at] {
            return bytes.clone();
        }
        let entry = self.entries[at].as_object().unwrap();
        let bytes = match (entry.get("b"), entry.get("p")) {
            (Some(encoded), _) => STANDARD.decode(encoded.as_str().unwrap()).unwrap(),
            // An entry with neither is the empty byte string.
            (None, None) => Vec::new(),
            (None, Some(base)) => {
                let mut bytes = self.get(index(base));
                let splices = entry.get("e").unwrap().as_array().unwrap();
                // Offsets refer to the base, so apply from the back.
                for splice in splices.iter().rev() {
                    let splice = splice.as_array().unwrap();
                    let at = index(&splice[0]);
                    let removed = index(&splice[1]);
                    let inserted = STANDARD.decode(splice[2].as_str().unwrap()).unwrap();
                    bytes.splice(at..at + removed, inserted);
                }
                bytes
            }
        };
        self.resolved[at] = Some(bytes.clone());
        bytes
    }
}

fn response(pool: &mut Pool<'_>, recorded: &Value) -> PcsResponse {
    let mut headers = BTreeMap::new();
    for (name, values) in member(recorded, "h").as_object().unwrap().iter() {
        let values = values
            .as_array()
            .unwrap()
            .iter()
            .map(|value| String::from_utf8(pool.get(index(value))).unwrap())
            .collect();
        headers.insert(name.to_string(), values);
    }
    PcsResponse {
        url: String::from_utf8(pool.get(index(member(recorded, "u")))).unwrap(),
        headers,
        body: pool.get(index(member(recorded, "b"))),
    }
}

/// The MRTD and the four RTMRs, one after the other.
fn registers(measurement: &Measurement) -> Vec<u8> {
    let Measurement::Tdx {
        mrtd,
        rtmr0,
        rtmr1,
        rtmr2,
        rtmr3,
    } = measurement
    else {
        panic!("not a TDX measurement");
    };
    [mrtd, rtmr0, rtmr1, rtmr2, rtmr3]
        .iter()
        .flat_map(|register| register.as_bytes().iter().copied())
        .collect()
}

/// Replays the recorded cases whose identifier starts with one of
/// `prefixes` and returns how many there were.
///
/// Every case must have the recorded outcome. Where the record says that
/// the other implementation accepted and this one is known to be stricter
/// (`rust` is `reject`, with the reason in `why`), the rejection is pinned
/// too, so that a change in either direction shows.
fn replay(prefixes: &[&str]) -> usize {
    let document = json::parse(CASES.as_bytes()).unwrap();
    let mut pool = Pool::new(&document);
    let responses = member(&document, "responses").as_array().unwrap();
    let mut failures = Vec::new();
    let mut replayed = 0;
    for case in member(&document, "cases").as_array().unwrap() {
        let id = member(case, "id").as_str().unwrap();
        if !prefixes.iter().any(|prefix| id.starts_with(prefix)) {
            continue;
        }
        replayed += 1;
        let now = member(case, "now").as_array().unwrap();
        let now = Instant::from_unix(integer(&now[0]), u32::try_from(integer(&now[1])).unwrap());
        let root = integer(member(case, "root"));
        let root = (root >= 0).then(|| pool.get(usize::try_from(root).unwrap()));
        let quote = pool.get(index(member(case, "quote")));
        let pcs: Vec<PcsResponse> = member(case, "pcs")
            .as_array()
            .unwrap()
            .iter()
            .map(|at| response(&mut pool, &responses[index(at)]))
            .collect();
        let recorded = member(case, "reference").as_str().unwrap();
        let stricter = case.as_object().unwrap().get("rust").is_some();

        let outcome = match now {
            Some(now) => authenticate(
                Evidence {
                    quote: &quote,
                    pcs: &pcs,
                },
                now,
                root.as_deref(),
            )
            .map_err(|error| error.to_string()),
            // A time that the verifier cannot represent is never accepted.
            None => Err("verification time is out of range".to_string()),
        };
        match (&outcome, recorded, stricter) {
            (Ok(quote), "accept", false) => {
                let tcb = integer(member(case, "tcb"));
                if quote.identity() != member(case, "identity").as_str().unwrap()
                    || registers(&quote.measurement()) != pool.get(index(member(case, "m")))
                    || quote.tcb_evaluation_data_number() != tcb
                {
                    failures.push(format!("{id}: accepted with other facts"));
                }
            }
            (Err(_), "accept", true) | (Err(_), "reject" | "crash", false) => {}
            (Ok(_), "accept", true) => {
                failures.push(format!("{id}: accepted, recorded as stricter"));
            }
            (Ok(_), _, _) => failures.push(format!("{id}: accepted, recorded {recorded}")),
            (Err(error), _, _) => {
                failures.push(format!("{id}: rejected ({error}), recorded {recorded}"));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    replayed
}

// The cases are replayed in groups, so that the groups run side by side.
const GROUPS: [&[&str]; 7] = [
    &["base", "quote/", "time/"],
    &["chain/"],
    &["pcs/"],
    &[
        "json/tcb-info/levels/",
        "json/tcb-info/identity/",
        "json/tcb-info/module",
    ],
    &["json/tcb-info/"],
    &["json/qe-identity/", "json/swapped"],
    &["real/", "vector/"],
];

#[test]
fn recorded_quote_and_time_cases() {
    assert!(replay(GROUPS[0]) > 300);
}

#[test]
fn recorded_certificate_chain_cases() {
    assert!(replay(GROUPS[1]) > 150);
}

#[test]
fn recorded_response_cases() {
    assert!(replay(GROUPS[2]) > 300);
}

#[test]
fn recorded_tcb_level_cases() {
    assert!(replay(GROUPS[3]) > 200);
}

#[test]
fn recorded_tcb_info_cases() {
    // The group above is part of this prefix; it is replayed once, there.
    let document = json::parse(CASES.as_bytes()).unwrap();
    let others: Vec<&str> = member(&document, "cases")
        .as_array()
        .unwrap()
        .iter()
        .map(|case| member(case, "id").as_str().unwrap())
        .filter(|id| GROUPS[4].iter().any(|prefix| id.starts_with(prefix)))
        .filter(|id| !GROUPS[3].iter().any(|prefix| id.starts_with(prefix)))
        .collect();
    assert!(others.len() > 150);
    // Identifiers are unique, so each is its own prefix here.
    assert_eq!(replay(&others), others.len());
}

#[test]
fn recorded_qe_identity_cases() {
    assert!(replay(GROUPS[5]) > 200);
}

#[test]
fn recorded_production_and_vector_cases() {
    assert!(replay(GROUPS[6]) > 150);
}

#[test]
fn every_recorded_case_is_in_a_group() {
    let document = json::parse(CASES.as_bytes()).unwrap();
    for case in member(&document, "cases").as_array().unwrap() {
        let id = member(case, "id").as_str().unwrap();
        assert!(
            GROUPS
                .iter()
                .flat_map(|group| group.iter())
                .any(|prefix| id.starts_with(prefix)),
            "{id} is in no group"
        );
    }
}

/// A quote cut short at every length, as it is and with its stated sizes
/// adjusted to the cut, has the recorded outcome and never panics.
#[test]
fn truncated_quotes_have_their_recorded_outcome() {
    let document = json::parse(CASES.as_bytes()).unwrap();
    let mut pool = Pool::new(&document);
    let cases = member(&document, "cases").as_array().unwrap();
    let base = cases
        .iter()
        .find(|case| member(case, "id").as_str() == Some("base"))
        .unwrap();
    let quote = pool.get(index(member(base, "quote")));
    let root = pool.get(index(member(base, "root")));
    let responses = member(&document, "responses").as_array().unwrap();
    let pcs: Vec<PcsResponse> = member(base, "pcs")
        .as_array()
        .unwrap()
        .iter()
        .map(|at| response(&mut pool, &responses[index(at)]))
        .collect();
    let now = member(base, "now").as_array().unwrap();
    let now = Instant::from_unix(integer(&now[0]), 0).unwrap();

    let mut failures = Vec::new();
    let mut total = 0;
    for sweep in member(&document, "sweeps").as_array().unwrap() {
        let patches: Vec<(usize, usize)> = member(sweep, "patches")
            .as_array()
            .unwrap()
            .iter()
            .map(|patch| {
                let patch = patch.as_array().unwrap();
                (index(&patch[0]), index(&patch[1]))
            })
            .collect();
        let from = index(member(sweep, "from"));
        let outcomes = member(sweep, "outcomes").as_str().unwrap().as_bytes();
        for (offset, recorded) in outcomes.iter().enumerate() {
            let length = from + offset;
            let mut cut = quote[..length].to_vec();
            for (field, start) in &patches {
                if length >= *start {
                    let stated = u32::try_from(length - start).unwrap();
                    cut[*field..field + 4].copy_from_slice(&stated.to_le_bytes());
                }
            }
            let accepted = authenticate(
                Evidence {
                    quote: &cut,
                    pcs: &pcs,
                },
                now,
                Some(&root),
            )
            .is_ok();
            total += 1;
            // `a` is accepted; `r` is rejected; `c` is a crash, which here
            // must be a rejection.
            if accepted != (*recorded == b'a') {
                failures.push(format!(
                    "length {length} with {} sizes adjusted: accepted = {accepted}, recorded {}",
                    patches.len(),
                    char::from(*recorded)
                ));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    assert!(total > 10_000);
}
