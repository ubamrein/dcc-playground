use rust_dgc::*;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn parse_cwt_from_bytestring(cbor_cwt: String) -> String {
    let cbor_bytes = from_byte_string!(cbor_cwt);
    if let Ok(cwt) = get_payload(&cbor_bytes) {
        return serde_json::to_string_pretty(&cwt).unwrap_or("{}".to_string());
    } else {
        return "{}".to_string();
    }
}
#[wasm_bindgen]
pub fn get_hcert_from_cwt(cbor_cwt: String) -> String {
    let cbor_bytes = from_byte_string!(cbor_cwt);
    if let Ok(cwt) = get_payload(&cbor_bytes) {
        return serde_json::to_string_pretty(&cwt.get_hcert()).unwrap_or("{}".to_string());
    } else {
        return "{}".to_string();
    }
}

#[wasm_bindgen]
pub fn verify_cwt_ec(cbor_cwt: String, x: String, y: String) -> bool {
    let cbor_bytes = from_byte_string!(cbor_cwt);
    let cwt = if let Ok(cwt) = get_payload(&cbor_bytes) {
        cwt
    } else {
        return false;
    };

    let key = VerificationKey::Es256 { x, y };
    match cwt.verify(&key) {
        Ok(_) => true,
        _ => false,
    }
}

#[wasm_bindgen]
pub fn verify_cwt_rsa(cbor_cwt: String, pem: String) -> bool {
    let cbor_bytes = from_byte_string!(cbor_cwt);
    let cwt = if let Ok(cwt) = get_payload(&cbor_bytes) {
        cwt
    } else {
        return false;
    };
    let mut payload = String::from("");
    for line in pem.lines() {
        if line.starts_with("-") {
            continue;
        }
        payload += line;
    }
    let bytes = base64::decode(payload).unwrap_or(vec![]);
    let key = VerificationKey::Rsa {
        key: to_byte_string!(bytes),
    };
    match cwt.verify(&key) {
        Ok(_) => true,
        _ => false,
    }
}
