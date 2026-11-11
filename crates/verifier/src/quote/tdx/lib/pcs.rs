//! The collateral of Intel's Provisioning Certification Service, and the
//! SGX extensions of a PCK certificate.

use ::der::asn1::ObjectIdentifier;

use crate::canonical;
use crate::instant::Instant;
use crate::json::{self, Object, Value};
use crate::quote::QuoteError;
use crate::x509::Certificate;
use crate::x509::der::{
    DerReader, Element, TAG_BOOLEAN, TAG_INTEGER, TAG_OCTET_STRING, TAG_OID, TAG_SEQUENCE, TAG_SET,
    boolean, check_integer, single_element,
};
use crate::x509::extension::object_identifier;

/// The base URL of the TDX collateral endpoints.
pub const PCS_TDX_BASE_URL: &str = "https://api.trustedservices.intel.com/tdx/certification/v4";
/// The base URL of the SGX collateral endpoints, which serve the PCK
/// revocation lists.
pub const PCS_SGX_BASE_URL: &str = "https://api.trustedservices.intel.com/sgx/certification/v4";

/// The SGX extension of a PCK certificate.
pub const OID_SGX_EXTENSION: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1");
/// The PPID inside the SGX extension.
pub const OID_SGX_PPID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1.1");
/// The TCB inside the SGX extension.
pub const OID_SGX_TCB: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1.2");
/// The PCE identifier inside the SGX extension.
pub const OID_SGX_PCE_ID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1.3");
/// The FMSPC inside the SGX extension.
pub const OID_SGX_FMSPC: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1.4");

/// The number of component SVNs in a TCB.
pub const TCB_COMPONENTS: usize = 16;

/// The URL of the PCK revocation list of a certificate authority
/// (`platform` or `processor`), in DER.
pub fn pck_crl_url(ca: &str) -> String {
    format!("{PCS_SGX_BASE_URL}/pckcrl?ca={ca}&encoding=der")
}

/// The URL of the TDX TCB info for an FMSPC.
pub fn tcb_info_url(fmspc: &str) -> String {
    format!("{PCS_TDX_BASE_URL}/tcb?fmspc={fmspc}")
}

/// The URL of the TDX QE identity.
pub fn qe_identity_url() -> String {
    format!("{PCS_TDX_BASE_URL}/qe/identity")
}

/// A collateral document together with the bytes that Intel signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signed<T> {
    /// The decoded document.
    pub value: T,
    /// The document exactly as it appears in the response body, from the
    /// first to the last byte of the member's value: what the signature
    /// covers.
    pub signed_bytes: Vec<u8>,
    /// The signature: `r` then `s`, 32 bytes each.
    pub signature: [u8; 64],
}

/// The status of a TCB level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcbStatus {
    /// `UpToDate`.
    UpToDate,
    /// `SWHardeningNeeded`.
    SwHardeningNeeded,
    /// `ConfigurationNeeded`.
    ConfigurationNeeded,
    /// `ConfigurationAndSWHardeningNeeded`.
    ConfigurationAndSwHardeningNeeded,
    /// `OutOfDate`.
    OutOfDate,
    /// `OutOfDateConfigurationNeeded`.
    OutOfDateConfigurationNeeded,
    /// `Revoked`.
    Revoked,
}

impl TcbStatus {
    /// The status with the given name, exactly as Intel spells it.
    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "UpToDate" => TcbStatus::UpToDate,
            "SWHardeningNeeded" => TcbStatus::SwHardeningNeeded,
            "ConfigurationNeeded" => TcbStatus::ConfigurationNeeded,
            "ConfigurationAndSWHardeningNeeded" => TcbStatus::ConfigurationAndSwHardeningNeeded,
            "OutOfDate" => TcbStatus::OutOfDate,
            "OutOfDateConfigurationNeeded" => TcbStatus::OutOfDateConfigurationNeeded,
            "Revoked" => TcbStatus::Revoked,
            _ => return None,
        })
    }

    /// The name of the status, as Intel spells it.
    pub fn name(self) -> &'static str {
        match self {
            TcbStatus::UpToDate => "UpToDate",
            TcbStatus::SwHardeningNeeded => "SWHardeningNeeded",
            TcbStatus::ConfigurationNeeded => "ConfigurationNeeded",
            TcbStatus::ConfigurationAndSwHardeningNeeded => "ConfigurationAndSWHardeningNeeded",
            TcbStatus::OutOfDate => "OutOfDate",
            TcbStatus::OutOfDateConfigurationNeeded => "OutOfDateConfigurationNeeded",
            TcbStatus::Revoked => "Revoked",
        }
    }
}

/// One component of a TCB.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcbComponent {
    /// The component's security version number.
    pub svn: u8,
}

/// The security versions of a TCB level.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tcb {
    /// The SGX component SVNs; [`TCB_COMPONENTS`] of them in a level of TCB
    /// info.
    pub sgx_tcb_components: Vec<TcbComponent>,
    /// The PCE SVN; zero when the level does not state one.
    pub pce_svn: u16,
    /// The TDX component SVNs; [`TCB_COMPONENTS`] of them in a level of TCB
    /// info.
    pub tdx_tcb_components: Vec<TcbComponent>,
    /// The ISV SVN of a QE identity or TDX module level; zero when the
    /// level does not state one.
    pub isv_svn: u32,
}

/// One TCB level.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcbLevel {
    /// The security versions that reach this level.
    pub tcb: Tcb,
    /// The status of the level.
    pub status: TcbStatus,
}

/// What TCB info says about the TDX module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TdxModule {
    /// The expected MRSIGNERSEAM.
    pub mr_signer: Vec<u8>,
    /// The expected SEAMATTRIBUTES under the mask.
    pub attributes: Vec<u8>,
    /// The mask applied to SEAMATTRIBUTES.
    pub attributes_mask: Vec<u8>,
}

/// One TDX module identity of TCB info.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TdxModuleIdentity {
    /// The identity's name, such as `TDX_03`.
    pub id: String,
    /// The TCB levels of this module version.
    pub tcb_levels: Vec<TcbLevel>,
}

/// TDX TCB info for one platform family.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcbInfo {
    /// When the document was issued.
    pub issue_date: Instant,
    /// When the document expires.
    pub next_update: Instant,
    /// The FMSPC that the document is for, as written.
    pub fmspc: String,
    /// The PCE identifier that the document is for, as written.
    pub pce_id: String,
    /// The edition of the TCB evaluation that the document reflects, as
    /// written: any 64-bit integer.
    pub tcb_evaluation_data_number: i64,
    /// The TDX module's expected signer and attributes.
    pub tdx_module: TdxModule,
    /// The TDX module identities.
    pub tdx_module_identities: Vec<TdxModuleIdentity>,
    /// The TCB levels, in document order.
    pub tcb_levels: Vec<TcbLevel>,
}

/// The identity of the TDX quoting enclave.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QeIdentity {
    /// When the document was issued.
    pub issue_date: Instant,
    /// When the document expires.
    pub next_update: Instant,
    /// The edition of the TCB evaluation that the document reflects, as
    /// written: any 64-bit integer.
    pub tcb_evaluation_data_number: i64,
    /// The expected MISCSELECT under the mask.
    pub misc_select: Vec<u8>,
    /// The mask applied to MISCSELECT.
    pub misc_select_mask: Vec<u8>,
    /// The expected ATTRIBUTES under the mask.
    pub attributes: Vec<u8>,
    /// The mask applied to ATTRIBUTES.
    pub attributes_mask: Vec<u8>,
    /// The expected MRSIGNER.
    pub mr_signer: Vec<u8>,
    /// The expected ISVPRODID.
    pub isv_prod_id: u16,
    /// The TCB levels, in document order.
    pub tcb_levels: Vec<TcbLevel>,
}

/// The `id` of TDX TCB info.
pub const TCB_INFO_ID: &str = "TDX";
/// The `version` of TDX TCB info.
pub const TCB_INFO_VERSION: u8 = 3;
/// The `id` of the TDX QE identity.
pub const QE_IDENTITY_ID: &str = "TD_QE";
/// The `version` of the TDX QE identity.
pub const QE_IDENTITY_VERSION: u8 = 2;

fn malformed(document: &str, reason: impl std::fmt::Display) -> QuoteError {
    QuoteError::new(format!("{document}: {reason}"))
}

/// A member name reduced to the form in which a reader that ignores letter
/// case would compare it: ASCII letters in lowercase, and the two letters
/// outside ASCII that fold to ASCII letters mapped to them.
fn folded(name: &str) -> String {
    name.chars()
        .map(|character| match character {
            '\u{212a}' => 'k',
            '\u{17f}' => 's',
            other => other.to_ascii_lowercase(),
        })
        .collect()
}

/// The members of one object of a collateral document, read by exact name.
struct Members<'a> {
    object: &'a Object,
    path: &'a str,
}

impl<'a> Members<'a> {
    /// Wraps `value`, which must be an object. `names` lists every member
    /// name that has a meaning at this place. A member whose name is not
    /// one of them but differs from one only in letter case is an error:
    /// readers that match names loosely would take it for the member, so
    /// its meaning is ambiguous. Any other member is ignored.
    fn new(value: &'a Value, path: &'a str, names: &[&str]) -> Result<Self, QuoteError> {
        let object = value.as_object().ok_or_else(|| {
            malformed(path, format!("is a JSON {}, want an object", value.kind()))
        })?;
        for (name, _) in object.iter() {
            if names.contains(&name) {
                continue;
            }
            let reduced = folded(name);
            if names.iter().any(|known| folded(known) == reduced) {
                return Err(malformed(
                    path,
                    format!("member {name:?} differs from a defined member only in spelling"),
                ));
            }
        }
        Ok(Self { object, path })
    }

    fn error(&self, name: &str, reason: impl std::fmt::Display) -> QuoteError {
        malformed(self.path, format!("member {name:?} {reason}"))
    }

    /// A member that must be present and not `null`.
    fn required(&self, name: &str) -> Result<&'a Value, QuoteError> {
        match self.object.get(name) {
            None => Err(self.error(name, "is missing")),
            Some(Value::Null) => Err(self.error(name, "is null")),
            Some(value) => Ok(value),
        }
    }

    /// A member that may be absent or `null`.
    fn optional(&self, name: &str) -> Option<&'a Value> {
        self.object.get(name).filter(|value| !value.is_null())
    }

    fn string(&self, name: &str) -> Result<&'a str, QuoteError> {
        let value = self.required(name)?;
        value
            .as_str()
            .ok_or_else(|| self.error(name, format!("is a JSON {}, want a string", value.kind())))
    }

    /// Hex of either case with an even number of digits.
    fn hex(&self, name: &str) -> Result<Vec<u8>, QuoteError> {
        canonical::decode_hex(self.string(name)?).ok_or_else(|| self.error(name, "is not hex"))
    }

    fn integer<T>(
        &self,
        name: &str,
        value: &Value,
        read: impl Fn(&json::RawNumber) -> Option<T>,
    ) -> Result<T, QuoteError> {
        let number = value.as_number().ok_or_else(|| {
            self.error(name, format!("is a JSON {}, want a number", value.kind()))
        })?;
        read(number).ok_or_else(|| self.error(name, "is not an integer in range"))
    }

    fn u8(&self, name: &str) -> Result<u8, QuoteError> {
        self.integer(name, self.required(name)?, json::RawNumber::to_u8)
    }

    fn u16(&self, name: &str) -> Result<u16, QuoteError> {
        self.integer(name, self.required(name)?, |number| {
            number.to_u64().and_then(|value| u16::try_from(value).ok())
        })
    }

    fn u32(&self, name: &str) -> Result<u32, QuoteError> {
        self.integer(name, self.required(name)?, json::RawNumber::to_u32)
    }

    fn i64(&self, name: &str) -> Result<i64, QuoteError> {
        self.integer(name, self.required(name)?, json::RawNumber::to_i64)
    }

    fn array(&self, name: &str) -> Result<&'a [Value], QuoteError> {
        let value = self.required(name)?;
        value
            .as_array()
            .ok_or_else(|| self.error(name, format!("is a JSON {}, want an array", value.kind())))
    }

    /// A member that verification does not read. When present and not
    /// `null` it must still have its type.
    fn unread(&self, name: &str, kind: Unread) -> Result<(), QuoteError> {
        let Some(value) = self.optional(name) else {
            return Ok(());
        };
        let fits = match kind {
            Unread::String => value.as_str().is_some(),
            Unread::U8 => value.as_number().is_some_and(|n| n.to_u8().is_some()),
            Unread::Strings => value.as_array().is_some_and(|items| {
                items
                    .iter()
                    .all(|item| item.is_null() || item.as_str().is_some())
            }),
        };
        if fits {
            Ok(())
        } else {
            Err(self.error(name, "does not have its type"))
        }
    }

    /// A hex member that verification does not read. When present it must
    /// be hex; `null` is not.
    fn unread_hex(&self, name: &str) -> Result<(), QuoteError> {
        match self.object.get(name) {
            None => Ok(()),
            Some(_) => self.hex(name).map(|_| ()),
        }
    }
}

/// The type of a member that is checked but not read.
#[derive(Clone, Copy)]
enum Unread {
    String,
    U8,
    Strings,
}

/// What a `tcb` object must state.
#[derive(Clone, Copy, PartialEq, Eq)]
enum TcbKind {
    /// A level of TCB info: both component lists and the PCE SVN.
    Platform,
    /// A level of a TDX module identity or of a QE identity: the ISV SVN.
    Enclave,
}

const TCB_MEMBERS: [&str; 4] = ["sgxtcbcomponents", "pcesvn", "tdxtcbcomponents", "isvsvn"];
const TCB_COMPONENT_MEMBERS: [&str; 3] = ["svn", "category", "type"];
const TCB_LEVEL_MEMBERS: [&str; 4] = ["tcb", "tcbDate", "tcbStatus", "advisoryIDs"];

fn decode_components(items: &[Value], path: &str) -> Result<Vec<TcbComponent>, QuoteError> {
    items
        .iter()
        .map(|item| {
            let members = Members::new(item, path, &TCB_COMPONENT_MEMBERS)?;
            members.unread("category", Unread::String)?;
            members.unread("type", Unread::String)?;
            Ok(TcbComponent {
                svn: members.u8("svn")?,
            })
        })
        .collect()
}

fn decode_tcb(value: &Value, path: &str, kind: TcbKind) -> Result<Tcb, QuoteError> {
    let members = Members::new(value, path, &TCB_MEMBERS)?;
    let components = |name: &str| -> Result<Vec<TcbComponent>, QuoteError> {
        let listed = match kind {
            TcbKind::Platform => Some(members.array(name)?),
            TcbKind::Enclave => match members.optional(name) {
                None => None,
                Some(_) => Some(members.array(name)?),
            },
        };
        let components = match listed {
            Some(items) => decode_components(items, path)?,
            None => Vec::new(),
        };
        if kind == TcbKind::Platform && components.len() != TCB_COMPONENTS {
            return Err(members.error(
                name,
                format!("has {} components, want {TCB_COMPONENTS}", components.len()),
            ));
        }
        Ok(components)
    };
    let sgx_tcb_components = components("sgxtcbcomponents")?;
    let tdx_tcb_components = components("tdxtcbcomponents")?;
    let (pce_svn, isv_svn) = match kind {
        TcbKind::Platform => {
            let isv_svn = match members.optional("isvsvn") {
                Some(_) => members.u32("isvsvn")?,
                None => 0,
            };
            (members.u16("pcesvn")?, isv_svn)
        }
        TcbKind::Enclave => {
            let pce_svn = match members.optional("pcesvn") {
                Some(_) => members.u16("pcesvn")?,
                None => 0,
            };
            (pce_svn, members.u32("isvsvn")?)
        }
    };
    Ok(Tcb {
        sgx_tcb_components,
        pce_svn,
        tdx_tcb_components,
        isv_svn,
    })
}

fn decode_levels(items: &[Value], path: &str, kind: TcbKind) -> Result<Vec<TcbLevel>, QuoteError> {
    items
        .iter()
        .map(|item| {
            let members = Members::new(item, path, &TCB_LEVEL_MEMBERS)?;
            members.unread("tcbDate", Unread::String)?;
            members.unread("advisoryIDs", Unread::Strings)?;
            let tcb = decode_tcb(members.required("tcb")?, path, kind)?;
            let name = members.string("tcbStatus")?;
            let status = TcbStatus::from_name(name).ok_or_else(|| {
                members.error("tcbStatus", format!("{name:?} is not a TCB status"))
            })?;
            Ok(TcbLevel { tcb, status })
        })
        .collect()
}

/// The JSON whitespace characters.
fn is_json_whitespace(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\r')
}

/// Walks the encoding of a JSON value that is already known to be well
/// formed, so that members can be taken as the bytes that encode them.
struct RawScanner<'a> {
    data: &'a [u8],
    at: usize,
}

impl<'a> RawScanner<'a> {
    fn peek(&self) -> Option<u8> {
        self.data.get(self.at).copied()
    }

    fn bump(&mut self) -> Option<()> {
        self.at = self.at.checked_add(1)?;
        Some(())
    }

    fn skip_whitespace(&mut self) -> Option<()> {
        while self.peek().is_some_and(is_json_whitespace) {
            self.bump()?;
        }
        Some(())
    }

    fn expect(&mut self, byte: u8) -> Option<()> {
        if self.peek()? != byte {
            return None;
        }
        self.bump()
    }

    /// Passes a string, from its opening to its closing quote.
    fn string(&mut self) -> Option<()> {
        self.expect(b'"')?;
        loop {
            match self.peek()? {
                b'"' => return self.bump(),
                b'\\' => {
                    self.bump()?;
                    self.peek()?;
                    self.bump()?;
                }
                _ => self.bump()?,
            }
        }
    }

    /// Passes one value of any kind and returns its encoding.
    fn value(&mut self) -> Option<&'a [u8]> {
        let start = self.at;
        match self.peek()? {
            b'"' => self.string()?,
            b'{' | b'[' => {
                let mut depth = 0usize;
                loop {
                    match self.peek()? {
                        b'"' => {
                            self.string()?;
                            continue;
                        }
                        b'{' | b'[' => depth = depth.checked_add(1)?,
                        b'}' | b']' => depth = depth.checked_sub(1)?,
                        _ => {}
                    }
                    self.bump()?;
                    if depth == 0 {
                        break;
                    }
                }
            }
            _ => {
                while self.peek().is_some_and(|byte| {
                    !is_json_whitespace(byte) && !matches!(byte, b',' | b'}' | b']')
                }) {
                    self.bump()?;
                }
            }
        }
        if self.at == start {
            return None;
        }
        self.data.get(start..self.at)
    }
}

/// The members of a JSON object, each as its decoded name and the bytes
/// that encode its value, in document order. `object` is the encoding of
/// one well-formed JSON value, with or without whitespace around it;
/// `None` when it is not an object.
fn raw_members(object: &[u8]) -> Option<Vec<(String, &[u8])>> {
    let mut scanner = RawScanner {
        data: object,
        at: 0,
    };
    let mut members = Vec::new();
    scanner.skip_whitespace()?;
    scanner.expect(b'{')?;
    scanner.skip_whitespace()?;
    if scanner.peek()? == b'}' {
        return Some(members);
    }
    loop {
        let start = scanner.at;
        scanner.string()?;
        let literal = object.get(start..scanner.at)?;
        let name = json::parse(literal).ok()?.as_str()?.to_string();
        scanner.skip_whitespace()?;
        scanner.expect(b':')?;
        scanner.skip_whitespace()?;
        members.push((name, scanner.value()?));
        scanner.skip_whitespace()?;
        match scanner.peek()? {
            b',' => {
                scanner.bump()?;
                scanner.skip_whitespace()?;
            }
            b'}' => return Some(members),
            _ => return None,
        }
    }
}

/// The encoding of the member `name` of the object encoded by `object`.
fn raw_member<'a>(object: &'a [u8], name: &str) -> Option<&'a [u8]> {
    raw_members(object)?
        .into_iter()
        .find(|(member, _)| member == name)
        .map(|(_, value)| value)
}

/// A response body: the signed member and the signature.
struct Envelope<'a> {
    /// The decoded signed member.
    document: &'a Value,
    /// The signed member as encoded in the body.
    signed_bytes: &'a [u8],
    signature: [u8; 64],
}

/// Takes a response body apart: `{"<member>": {...}, "signature": "..."}`.
fn envelope<'a>(
    body: &'a [u8],
    parsed: &'a Value,
    member: &'a str,
) -> Result<Envelope<'a>, QuoteError> {
    let members = Members::new(parsed, member, &[member, "signature"])?;
    let document = members.required(member)?;
    let signature: [u8; 64] = members
        .hex("signature")?
        .try_into()
        .map_err(|_| members.error("signature", "is not 64 bytes"))?;
    let signed_bytes = raw_member(body, member)
        .ok_or_else(|| malformed(member, "cannot be located in the response body"))?;
    Ok(Envelope {
        document,
        signed_bytes,
        signature,
    })
}

/// A timestamp member: an RFC 3339 timestamp.
fn timestamp(members: &Members<'_>, name: &str) -> Result<Instant, QuoteError> {
    Instant::parse_rfc3339(members.string(name)?).map_err(|error| members.error(name, error))
}

fn parse_body(body: &[u8], document: &str) -> Result<Value, QuoteError> {
    json::parse(body).map_err(|error| malformed(document, error))
}

/// Decodes a TCB info response body: `{"tcbInfo": {...}, "signature":
/// "..."}`.
///
/// The body is strict JSON: valid UTF-8, no repeated member name at any
/// depth, nothing after the value. The signed bytes are the value of the
/// top-level `tcbInfo` member exactly as it appears in the body; no nested
/// member of the same name and no re-encoding can take its place. The
/// signature is 64 bytes in hex of either case.
///
/// Member names are exact. A member whose name differs from a defined one
/// only in letter case is an error wherever a defined member could stand;
/// other unknown members are ignored.
///
/// Required, each with its type and never `null`:
///
/// - `id` (`TDX`) and `version` (3);
/// - `issueDate` and `nextUpdate`, RFC 3339 timestamps
///   ([`Instant::parse_rfc3339`]);
/// - `fmspc`, `pceId`, and `tcbEvaluationDataNumber`, a 64-bit integer;
/// - `tdxModule` with hex `mrsigner`, `attributes` and `attributesMask`;
/// - `tcbLevels`, at least one.
///
/// `tdxModuleIdentities` may be absent or `null`, as it is in TCB info
/// from before TDX module versions were listed; it then names no module.
/// When present, each identity has `id` and `tcbLevels`.
///
/// A TCB level has `tcb` and a `tcbStatus` that is one of the known
/// statuses; a missing status is an error, never a default. In `tcbLevels`
/// a `tcb` has exactly [`TCB_COMPONENTS`] `sgxtcbcomponents`, exactly as
/// many `tdxtcbcomponents`, each with an `svn` of 0 to 255, and `pcesvn`;
/// in a module identity it has `isvsvn`. Integers are JSON integers in
/// range, without sign, fraction or exponent; only the evaluation data
/// number may be negative.
///
/// Members that verification does not read (`tcbType`, `tcbDate`,
/// `advisoryIDs`, a component's `category` and `type`, a module identity's
/// hex members) may be absent, but when present have their type.
pub fn parse_tcb_info(body: &[u8]) -> Result<Signed<TcbInfo>, QuoteError> {
    const DOCUMENT: &str = "tcbInfo";
    let parsed = parse_body(body, DOCUMENT)?;
    let envelope = envelope(body, &parsed, DOCUMENT)?;
    let members = Members::new(
        envelope.document,
        DOCUMENT,
        &[
            "id",
            "version",
            "issueDate",
            "nextUpdate",
            "fmspc",
            "pceId",
            "tcbType",
            "tcbEvaluationDataNumber",
            "tdxModule",
            "tdxModuleIdentities",
            "tcbLevels",
        ],
    )?;
    let id = members.string("id")?;
    if id != TCB_INFO_ID {
        return Err(members.error("id", format!("is {id:?}, want {TCB_INFO_ID:?}")));
    }
    let version = members.u8("version")?;
    if version != TCB_INFO_VERSION {
        return Err(members.error("version", format!("is {version}, want {TCB_INFO_VERSION}")));
    }
    members.unread("tcbType", Unread::U8)?;

    let module = Members::new(
        members.required("tdxModule")?,
        "tcbInfo.tdxModule",
        &["mrsigner", "attributes", "attributesMask"],
    )?;
    let tdx_module = TdxModule {
        mr_signer: module.hex("mrsigner")?,
        attributes: module.hex("attributes")?,
        attributes_mask: module.hex("attributesMask")?,
    };

    let mut tdx_module_identities = Vec::new();
    let identities = match members.optional("tdxModuleIdentities") {
        Some(_) => members.array("tdxModuleIdentities")?,
        None => &[],
    };
    for item in identities {
        const PATH: &str = "tcbInfo.tdxModuleIdentities";
        let identity = Members::new(
            item,
            PATH,
            &[
                "id",
                "mrsigner",
                "attributes",
                "attributesMask",
                "tcbLevels",
            ],
        )?;
        identity.unread_hex("mrsigner")?;
        identity.unread_hex("attributes")?;
        identity.unread_hex("attributesMask")?;
        tdx_module_identities.push(TdxModuleIdentity {
            id: identity.string("id")?.to_string(),
            tcb_levels: decode_levels(identity.array("tcbLevels")?, PATH, TcbKind::Enclave)?,
        });
    }

    let tcb_levels = decode_levels(
        members.array("tcbLevels")?,
        "tcbInfo.tcbLevels",
        TcbKind::Platform,
    )?;
    if tcb_levels.is_empty() {
        return Err(members.error("tcbLevels", "is empty"));
    }

    let value = TcbInfo {
        issue_date: timestamp(&members, "issueDate")?,
        next_update: timestamp(&members, "nextUpdate")?,
        fmspc: members.string("fmspc")?.to_string(),
        pce_id: members.string("pceId")?.to_string(),
        tcb_evaluation_data_number: members.i64("tcbEvaluationDataNumber")?,
        tdx_module,
        tdx_module_identities,
        tcb_levels,
    };
    Ok(Signed {
        value,
        signed_bytes: envelope.signed_bytes.to_vec(),
        signature: envelope.signature,
    })
}

/// Decodes a QE identity response body: `{"enclaveIdentity": {...},
/// "signature": "..."}`, by the rules of [`parse_tcb_info`].
///
/// Required: `id` (`TD_QE`), `version` (2), `issueDate`, `nextUpdate`,
/// `tcbEvaluationDataNumber`, hex `miscselect`, `miscselectMask`,
/// `attributes`, `attributesMask` and `mrsigner`, `isvprodid`, and
/// `tcbLevels`, at least one, each with a `tcb` that has `isvsvn` and a
/// known `tcbStatus`.
pub fn parse_qe_identity(body: &[u8]) -> Result<Signed<QeIdentity>, QuoteError> {
    const DOCUMENT: &str = "enclaveIdentity";
    let parsed = parse_body(body, DOCUMENT)?;
    let envelope = envelope(body, &parsed, DOCUMENT)?;
    let members = Members::new(
        envelope.document,
        DOCUMENT,
        &[
            "id",
            "version",
            "issueDate",
            "nextUpdate",
            "tcbEvaluationDataNumber",
            "miscselect",
            "miscselectMask",
            "attributes",
            "attributesMask",
            "mrsigner",
            "isvprodid",
            "tcbLevels",
        ],
    )?;
    let id = members.string("id")?;
    if id != QE_IDENTITY_ID {
        return Err(members.error("id", format!("is {id:?}, want {QE_IDENTITY_ID:?}")));
    }
    let version = members.u8("version")?;
    if version != QE_IDENTITY_VERSION {
        return Err(members.error(
            "version",
            format!("is {version}, want {QE_IDENTITY_VERSION}"),
        ));
    }
    let tcb_levels = decode_levels(
        members.array("tcbLevels")?,
        "enclaveIdentity.tcbLevels",
        TcbKind::Enclave,
    )?;
    if tcb_levels.is_empty() {
        return Err(members.error("tcbLevels", "is empty"));
    }
    let value = QeIdentity {
        issue_date: timestamp(&members, "issueDate")?,
        next_update: timestamp(&members, "nextUpdate")?,
        tcb_evaluation_data_number: members.i64("tcbEvaluationDataNumber")?,
        misc_select: members.hex("miscselect")?,
        misc_select_mask: members.hex("miscselectMask")?,
        attributes: members.hex("attributes")?,
        attributes_mask: members.hex("attributesMask")?,
        mr_signer: members.hex("mrsigner")?,
        isv_prod_id: members.u16("isvprodid")?,
        tcb_levels,
    };
    Ok(Signed {
        value,
        signed_bytes: envelope.signed_bytes.to_vec(),
        signature: envelope.signature,
    })
}

/// What a response body says about the edition and the issue time of the
/// document in its member `member`, read on its own, apart from
/// verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Observed {
    /// The body states no `tcbEvaluationDataNumber` that can be read: it
    /// is not strict JSON, the member is missing, or a value has the wrong
    /// type.
    Nothing,
    /// The body states a `tcbEvaluationDataNumber` and, when `issued` is
    /// set, an `issueDate`.
    Edition {
        /// The `tcbEvaluationDataNumber`.
        number: i64,
        /// The `issueDate`, when the body states one.
        issued: Option<Instant>,
    },
    /// The body states a `tcbEvaluationDataNumber` and an `issueDate` that
    /// is not in the accepted timestamp form. Nothing can be concluded
    /// from such a body.
    Unreadable,
}

/// Reads the `tcbEvaluationDataNumber` and `issueDate` of the document in
/// the member `member` of a response body. Only these two members and the
/// strictness of the JSON are looked at.
pub fn observe(body: &[u8], member: &str) -> Observed {
    let Ok(parsed) = json::parse(body) else {
        return Observed::Nothing;
    };
    let Some(document) = parsed
        .as_object()
        .and_then(|object| object.get(member))
        .and_then(Value::as_object)
    else {
        return Observed::Nothing;
    };
    let number = match document.get("tcbEvaluationDataNumber") {
        None | Some(Value::Null) => None,
        Some(Value::Number(number)) => match number.to_i64() {
            Some(number) => Some(number),
            None => return Observed::Nothing,
        },
        Some(_) => return Observed::Nothing,
    };
    let issued = match document.get("issueDate") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) => Instant::parse_rfc3339(text).map(Some),
        Some(_) => return Observed::Nothing,
    };
    match (number, issued) {
        (None, _) => Observed::Nothing,
        (Some(number), Ok(issued)) => Observed::Edition { number, issued },
        (Some(_), Err(_)) => Observed::Unreadable,
    }
}

/// The TCB that a PCK certificate is issued for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PckCertTcb {
    /// The PCE SVN.
    pub pce_svn: u16,
    /// The CPUSVN.
    pub cpu_svn: [u8; TCB_COMPONENTS],
    /// The component SVNs, in order.
    pub cpu_svn_components: [u8; TCB_COMPONENTS],
}

/// The SGX extensions of a PCK certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PckExtensions {
    /// The platform provisioning identifier, lowercase hex.
    pub ppid: String,
    /// The TCB that the certificate is issued for.
    pub tcb: PckCertTcb,
    /// The PCE identifier, lowercase hex.
    pub pce_id: String,
    /// The FMSPC, lowercase hex.
    pub fmspc: String,
}

/// The number of extensions of a PCK certificate.
pub const PCK_CERTIFICATE_EXTENSIONS: usize = 6;
/// The size of a PPID in bytes.
pub const PPID_SIZE: usize = 16;
/// The size of a PCE identifier in bytes.
pub const PCE_ID_SIZE: usize = 2;
/// The size of an FMSPC in bytes.
pub const FMSPC_SIZE: usize = 6;
/// The number of entries of the TCB inside the SGX extension: the
/// component SVNs, the PCE SVN and the CPUSVN.
const TCB_ENTRIES: usize = TCB_COMPONENTS + 2;
/// The tag of a universal ENUMERATED.
const TAG_ENUMERATED: u8 = 0x0a;

fn extension_error(reason: impl std::fmt::Display) -> QuoteError {
    QuoteError::new(format!("PCK certificate SGX extension: {reason}"))
}

/// Reads one `(identifier, value)` pair: a SEQUENCE of exactly an OBJECT
/// IDENTIFIER and one value. The value is a BOOLEAN, an INTEGER of at most
/// eight bytes, an OCTET STRING, an ENUMERATED, a SEQUENCE or a SET; the
/// first two are checked for their canonical form.
fn attribute<'a>(pair: &Element<'a>) -> Result<(ObjectIdentifier, Element<'a>), QuoteError> {
    if pair.tag != TAG_SEQUENCE {
        return Err(extension_error("an entry is not a SEQUENCE"));
    }
    let mut reader = pair.reader();
    let oid = object_identifier(reader.expect(TAG_OID)?.content)?;
    let value = reader.element()?;
    reader.finish()?;
    match value.tag {
        TAG_BOOLEAN => {
            boolean(value.content)?;
        }
        TAG_INTEGER => {
            check_integer(value.content)?;
            if value.content.len() > 8 {
                return Err(extension_error("an INTEGER is wider than 64 bits"));
            }
        }
        TAG_OCTET_STRING | TAG_ENUMERATED | TAG_SEQUENCE | TAG_SET => {}
        other => {
            return Err(extension_error(format!(
                "a value has the unsupported tag {other:#04x}"
            )));
        }
    }
    Ok((oid, value))
}

/// The elements of a SEQUENCE.
fn sequence_elements<'a>(sequence: &Element<'a>) -> Result<Vec<Element<'a>>, QuoteError> {
    if sequence.tag != TAG_SEQUENCE {
        return Err(extension_error("a value is not a SEQUENCE"));
    }
    let mut reader = sequence.reader();
    let mut elements = Vec::new();
    while !reader.is_empty() {
        elements.push(reader.element()?);
    }
    Ok(elements)
}

/// An OCTET STRING value of exactly `size` bytes, or one that holds the
/// encoding of such an OCTET STRING.
fn octets<'a>(value: &Element<'a>, field: &str, size: usize) -> Result<&'a [u8], QuoteError> {
    if value.tag != TAG_OCTET_STRING {
        return Err(extension_error(format!("{field} is not an OCTET STRING")));
    }
    if value.content.len() == size {
        return Ok(value.content);
    }
    let inner = single_element(value.content)?;
    if inner.tag != TAG_OCTET_STRING || inner.content.len() != size {
        return Err(extension_error(format!("{field} is not {size} bytes")));
    }
    Ok(inner.content)
}

/// A non-negative INTEGER value of at most `max`. The value is already
/// known to be in its shortest form.
fn unsigned(value: &Element<'_>, field: &str, max: u16) -> Result<u16, QuoteError> {
    let out_of_range = || extension_error(format!("{field} is not an integer of 0 to {max}"));
    if value.tag != TAG_INTEGER {
        return Err(out_of_range());
    }
    // A set sign bit is a negative number; three bytes hold every value
    // up to 65535 with its sign padding.
    let negative = value.content.first().is_none_or(|first| *first >= 0x80);
    if negative || value.content.len() > 3 {
        return Err(out_of_range());
    }
    let mut number = 0u32;
    for digit in value.content {
        number = (number << 8) | u32::from(*digit);
    }
    u16::try_from(number)
        .ok()
        .filter(|number| *number <= max)
        .ok_or_else(out_of_range)
}

/// Stores a value that must occur once.
fn set_once<T>(slot: &mut Option<T>, value: T, field: &str) -> Result<(), QuoteError> {
    if slot.is_some() {
        return Err(extension_error(format!("{field} occurs twice")));
    }
    *slot = Some(value);
    Ok(())
}

fn tcb_extension(value: &Element<'_>) -> Result<PckCertTcb, QuoteError> {
    let entries = sequence_elements(value)?;
    if entries.len() != TCB_ENTRIES {
        return Err(extension_error(format!(
            "the TCB has {} entries, want {TCB_ENTRIES}",
            entries.len()
        )));
    }
    let prefix: Vec<u32> = OID_SGX_TCB.arcs().collect();
    let mut components: [Option<u8>; TCB_COMPONENTS] = [None; TCB_COMPONENTS];
    let mut pce_svn = None;
    let mut cpu_svn = None;
    for entry in &entries {
        let (oid, value) = attribute(entry)?;
        let arcs: Vec<u32> = oid.arcs().collect();
        let index = match arcs.split_last() {
            Some((last, parent)) if parent == prefix.as_slice() => usize::try_from(*last).ok(),
            _ => None,
        };
        let unknown = || extension_error(format!("the TCB has an unknown entry {oid}"));
        let index = index.ok_or_else(unknown)?;
        if index == TCB_COMPONENTS.saturating_add(1) {
            let number = unsigned(&value, "the PCE SVN", u16::MAX)?;
            set_once(&mut pce_svn, number, "the PCE SVN")?;
        } else if index == TCB_COMPONENTS.saturating_add(2) {
            if value.tag != TAG_OCTET_STRING {
                return Err(extension_error("the CPUSVN is not an OCTET STRING"));
            }
            let bytes: [u8; TCB_COMPONENTS] = value
                .content
                .try_into()
                .map_err(|_| extension_error("the CPUSVN is not 16 bytes"))?;
            set_once(&mut cpu_svn, bytes, "the CPUSVN")?;
        } else {
            let slot = index
                .checked_sub(1)
                .and_then(|index| components.get_mut(index))
                .ok_or_else(unknown)?;
            let number = unsigned(&value, "a TCB component SVN", u16::from(u8::MAX))?;
            let number = u8::try_from(number)
                .map_err(|_| extension_error("a TCB component SVN is not a byte"))?;
            set_once(slot, number, "a TCB component SVN")?;
        }
    }
    let mut cpu_svn_components = [0u8; TCB_COMPONENTS];
    for (out, component) in cpu_svn_components.iter_mut().zip(components) {
        *out = component.ok_or_else(|| extension_error("a TCB component SVN is missing"))?;
    }
    Ok(PckCertTcb {
        pce_svn: pce_svn.ok_or_else(|| extension_error("the PCE SVN is missing"))?,
        cpu_svn: cpu_svn.ok_or_else(|| extension_error("the CPUSVN is missing"))?,
        cpu_svn_components,
    })
}

/// Reads the SGX extensions of a PCK certificate.
///
/// The certificate has exactly [`PCK_CERTIFICATE_EXTENSIONS`] extensions.
/// Its SGX extension is a DER SEQUENCE of at least four `(identifier,
/// value)` pairs with nothing after it. Required, each exactly once: the
/// PPID (16 bytes), the TCB (16 component SVNs of 0 to 255, the PCE SVN
/// and the 16-byte CPUSVN, 18 entries in any order), the PCE identifier (2
/// bytes) and the FMSPC (6 bytes). A byte string may be given directly or
/// wrapped in a second OCTET STRING. Every pair is canonical DER; a
/// missing member is an error, never a zero. Pairs with other identifiers
/// are ignored.
pub fn pck_extensions(certificate: &Certificate) -> Result<PckExtensions, QuoteError> {
    let count = certificate.extensions().count();
    if count != PCK_CERTIFICATE_EXTENSIONS {
        return Err(QuoteError::new(format!(
            "PCK certificate has {count} extensions, want {PCK_CERTIFICATE_EXTENSIONS}"
        )));
    }
    let extension = certificate
        .extension(OID_SGX_EXTENSION)
        .ok_or_else(|| QuoteError::new("PCK certificate has no SGX extension"))?;
    let pairs = sequence_elements(&single_element(extension.value)?)?;
    if pairs.len() < 4 {
        return Err(extension_error(format!(
            "has {} entries, want at least 4",
            pairs.len()
        )));
    }
    let mut ppid = None;
    let mut tcb = None;
    let mut pce_id = None;
    let mut fmspc = None;
    for pair in &pairs {
        let (oid, value) = attribute(pair)?;
        if oid == OID_SGX_PPID {
            let bytes = octets(&value, "the PPID", PPID_SIZE)?;
            set_once(&mut ppid, canonical::encode_lower_hex(bytes), "the PPID")?;
        } else if oid == OID_SGX_TCB {
            set_once(&mut tcb, tcb_extension(&value)?, "the TCB")?;
        } else if oid == OID_SGX_PCE_ID {
            let bytes = octets(&value, "the PCE identifier", PCE_ID_SIZE)?;
            set_once(
                &mut pce_id,
                canonical::encode_lower_hex(bytes),
                "the PCE identifier",
            )?;
        } else if oid == OID_SGX_FMSPC {
            let bytes = octets(&value, "the FMSPC", FMSPC_SIZE)?;
            set_once(&mut fmspc, canonical::encode_lower_hex(bytes), "the FMSPC")?;
        }
    }
    Ok(PckExtensions {
        ppid: ppid.ok_or_else(|| extension_error("the PPID is missing"))?,
        tcb: tcb.ok_or_else(|| extension_error("the TCB is missing"))?,
        pce_id: pce_id.ok_or_else(|| extension_error("the PCE identifier is missing"))?,
        fmspc: fmspc.ok_or_else(|| extension_error("the FMSPC is missing"))?,
    })
}
