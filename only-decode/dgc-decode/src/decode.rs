use std::collections::BTreeMap;
use serde_cbor::Value;

const HCERT_KEY: i128 = -260;
const HCERT_V1: i128 = 1;


pub fn get_meta(raw_payload: &[u8]) -> Result<MetaInfo, Box<dyn std::error::Error>> {
    let value: serde_cbor::Value = serde_cbor::from_reader(raw_payload)?;
    let value = match value {
        Value::Array(inner) => inner,
        _ => return Err("not an array".into()),
    };
    let protected_headers = match &value[0] {
        Value::Bytes(b) => b,
        _ => return Err("No protected headers".into()),
    };

    let message = match &value[2] {
        Value::Bytes(b) => b,
        _ => return Err("no message".into()),
    };

    let protected_headers: serde_cbor::Value = serde_cbor::from_reader(&protected_headers[..])?;

    let unprotected_headers = match &value[1] {
        Value::Map(m) => m,
        _ => return Err("No unprotected headers".into()),
    };

    let message: BTreeMap<Value, Value> = serde_cbor::from_reader(&message[..])?;

    let (alg, key_id) = match protected_headers {
        Value::Map(m) => {
            let alg = m.get(&Value::Integer(1)).ok_or("Not found")?;
            let alg = match alg {
                Value::Integer(i) => {
                    match i {
                        -7 => "EC".to_string(),
                        -37 => "RSA".to_string(),
                        _ => i.to_string()
                    }
                },
                _ => return Err("Should be integer".into()),
            };
            let key_id = m
                .get(&Value::Integer(4))
                .or_else(|| unprotected_headers.get(&Value::Integer(4))).ok_or("KeyId not found")?;
            let key_id = match key_id {
                Value::Bytes(b) => {
                    base64::encode(b)
                }
                _ => {
                    return Err("keyId should be a bytearray".into());
                }
            };
            
            (alg, key_id)
        }
        _ => return Err("Protected headers is not a map".into()),
    };
    let exp = message.get(&Value::Integer(4)).map(|f|{
        match f {
            Value::Integer(i) => {
                *i
            }
            _ => 0
        }
    }).unwrap_or(0);
    let iat = message.get(&Value::Integer(6)).map(|f|{
        match f {
            Value::Integer(i) => {
                *i
            }
            _ => 0
        }
    }).unwrap_or(0);

    let iss = message.get(&Value::Integer(1)).map(|f|{
        match f {
            Value::Text(i) => {
                i.to_owned()
            }
            _ => String::new()
        }
    }).unwrap_or_default();

    Ok(MetaInfo {
        alg,
        key_id,
        exp: exp as u64,
        iat: iat as u64,
        iss
    })
}

/// Get the CWT payload, which according to [RFC-8392 Section-7](https://tools.ietf.org/html/rfc8392#section-7)
/// is just the `Cose_Sign1` Struct from [RFC-8152 Section-4.2](https://tools.ietf.org/html/rfc8152#section-4.2)
/// This means we have a CBOR-Array like this, where the `Headers` defines the Algorithm used and `payload` contains
/// CWT's claims. In our case the `hcert` will be one of those claims.
/// ## COSE Sign struct
/// ```
/// COSE_Sign = [
///       Headers,
///       payload : bstr / nil,
///       signatures : [+ COSE_Signature]
///   ]
///```
/// ## COSE Protected Headers and Unprotected Headers
/// ```
/// Headers = (
///       protected : empty_or_serialized_map,
///       unprotected : header_map
///   )

///   header_map = {
///       Generic_Headers,
///       * label => values
///   }
///
///   empty_or_serialized_map = bstr .cbor header_map / bstr .size 0
/// ```

pub fn get_payload(raw_payload: &[u8]) -> Result<CwtParsed, Box<dyn std::error::Error>> {
    let value: serde_cbor::Value = serde_cbor::from_reader(raw_payload)?;
    println!("{:?}", value);
    let value = match value {
        Value::Array(inner) => inner,
        _ => return Err("not an array".into()),
    };
    let protected_headers = match &value[0] {
        Value::Bytes(b) => b,
        _ => return Err("No protected headers".into()),
    };
    let unprotected_headers = match &value[1] {
        Value::Map(m) => m,
        _ => return Err("No unprotected headers".into()),
    };
    let message = match &value[2] {
        Value::Bytes(b) => b,
        _ => return Err("no message".into()),
    };

    let signature = match &value[3] {
        Value::Bytes(a) => a,
        _ => return Err("no signature".into()),
    };
    let protected_headers: BTreeMap<Value, Value>  = serde_cbor::from_reader(&protected_headers[..])?;

    let message: BTreeMap<Value, Value> = serde_cbor::from_reader(&message[..])?;

    Ok(CwtParsed {
        protected_headers,
        protected_headers_original: value[0].clone(),
        unprotected_headers: unprotected_headers.clone(),
        message,
        original: value[2].clone(),
        signature: signature.clone(),
    })
}

#[macro_export]
/// Simple macro to produce a Vec<u8> from a byte string.
macro_rules! from_byte_string {
    ($s:expr) => {
        $s.as_bytes()
            .windows(2)
            .step_by(2)
            .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap_or(0))
            .collect::<Vec<_>>()
    };
}

#[macro_export]
/// Simple macro to produce a byte string from a Vec<u8>
macro_rules! to_byte_string {
    ($s:expr) => {
        $s.iter()
            .map(|b| format!("{:0>2x}", b))
            .collect::<Vec<_>>()
            .join("")
    };
}
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct MetaInfo {
    alg: String,
    key_id: String,
    iss: String,
    exp: u64,
    iat: u64,
}
#[derive(Debug, serde::Serialize, serde::Deserialize)]
/// The parsed CWT struct
pub struct CwtParsed {
    /// According to [RFC-8152 Section-3](https://tools.ietf.org/html/rfc8152#section-3)
    /// since the protected headers are cryptographically signed, we want to prevent accidental
    /// changes, so they are included as a serialized CBOR Map.
    pub protected_headers: BTreeMap<Value,Value>,
    pub protected_headers_original: serde_cbor::Value,
    /// Unprotected headers do not need such protection and as such are just presented as a CBOR Map
    pub unprotected_headers: BTreeMap<Value, Value>,
    /// Since we later on want to get the `hcert` we deserialized the CBOR Byte-String. For the message
    /// the same argumen as for the `protected_headers` is made, as the signature includes the message
    /// payload
    pub message: BTreeMap<Value, Value>,
    original: serde_cbor::Value,
    /// The signature as a byte string. In the case of `ECDSA` this is just `r || s`
    pub signature: Vec<u8>,
}

impl CwtParsed {

    /// The `hcert` is part of the claims in the CWT. The `hcert` itself is a container for multiple different certificates (c.f [Section 2.6.4](https://ec.europa.eu/health/sites/health/files/ehealth/docs/digital-green-certificates_v3_en.pdf)). For the Version 1 of the `DGC` the claim key `1` is used (c.f. [Section 3.3.1](https://ec.europa.eu/health/sites/health/files/ehealth/docs/digital-green-certificates_v1_en.pdf))
    pub fn get_hcert(&self) -> Option<BTreeMap<Value, Value>> {
        match self.message.get(&Value::Integer(HCERT_KEY)) {
            std::option::Option::Some(Value::Map(hcert)) => {
                match hcert.get(&Value::Integer(HCERT_V1)) {
                    Some(Value::Bytes(hcert)) => serde_cbor::from_reader(&hcert[..]).ok(),
                    Some(Value::Map(m)) => Some(m.to_owned()),
                    _ => None,
                }
            }
            _ => None,
        }
    }
}

