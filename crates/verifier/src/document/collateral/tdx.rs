//! Intel TDX endorsement collateral.

use std::collections::BTreeMap;

use super::{CheckedEntry, CollateralError};
use crate::canonical;
use crate::json::Value;
use crate::json::decode::{self, DecodeError};

/// Decoded intel-pcs collateral: Intel PCS responses captured so that a
/// verifier replays them instead of fetching.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IntelPcs {
    /// The captured responses, in document order.
    pub responses: Vec<PcsResponse>,
}

/// One captured Intel PCS response. The headers are kept because Intel
/// delivers issuer chains in response headers.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PcsResponse {
    /// The request URL.
    pub url: String,
    /// The response headers: each name with its values.
    pub headers: BTreeMap<String, Vec<String>>,
    /// The response body.
    pub body: Vec<u8>,
}

/// One captured response as serialized.
#[derive(Default)]
struct RawResponse {
    url: String,
    headers: BTreeMap<String, Vec<String>>,
    body_base64: String,
}

pub(super) fn decode(entry: CheckedEntry) -> Result<IntelPcs, CollateralError> {
    let id = entry.id;
    let parsing = |error: DecodeError| CollateralError::parsing("intel-pcs", &id, &error);
    let mut raw = Vec::new();
    for (name, value) in entry.data.into_members() {
        match name.as_str() {
            "responses" => {
                let responses = decode::array(value, &name).map_err(parsing)?;
                for response in responses.unwrap_or_default() {
                    raw.push(decode_response(response).map_err(parsing)?);
                }
            }
            _ => return Err(parsing(decode::unknown_member("data", &name))),
        }
    }
    let mut pcs = IntelPcs::default();
    for (index, response) in raw.into_iter().enumerate() {
        let body =
            canonical::decode_base64("body_base64", &response.body_base64).map_err(|error| {
                CollateralError::invalid(format!(
                    "intel-pcs collateral entry {id:?} response {index}: {error}"
                ))
            })?;
        pcs.responses.push(PcsResponse {
            url: response.url,
            headers: response.headers,
            body,
        });
    }
    Ok(pcs)
}

fn decode_response(value: Value) -> Result<RawResponse, DecodeError> {
    let mut raw = RawResponse::default();
    let Some(object) = decode::object(value, "responses")? else {
        return Ok(raw);
    };
    for (name, value) in object.into_members() {
        match name.as_str() {
            "url" => raw.url = decode::string(value, "url")?,
            "headers" => {
                let headers = decode::object(value, "headers")?.unwrap_or_default();
                for (header, values) in headers.into_members() {
                    let values = decode::strings(values, "headers")?.unwrap_or_default();
                    raw.headers.insert(header, values);
                }
            }
            "body_base64" => raw.body_base64 = decode::string(value, "body_base64")?,
            _ => return Err(decode::unknown_member("responses", &name)),
        }
    }
    Ok(raw)
}
