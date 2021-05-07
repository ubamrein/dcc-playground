use std::io::Cursor;

use rust_dgc::{VerificationKey, base45, from_byte_string, get_payload, to_byte_string};
use wasm_bindgen::prelude::*;
use std::io::Read;

#[wasm_bindgen]
pub fn parse_cwt_from_bytestring(cbor_cwt: String) -> String {
    let cbor_cwt = if cbor_cwt.starts_with("HC1:") {
        let mut decoded = Cursor::new( base45::decode(&cbor_cwt.replace("HC1:", "")).unwrap_or(vec![]));
        let mut decompressor = flate2::read::ZlibDecoder::new(&mut decoded);
        let mut decompressed = vec![];
        match decompressor.read_to_end(&mut decompressed) {
            Ok(_) => to_byte_string!(decompressed),
            Err(r) => "".to_string()
        }
    } else {
        cbor_cwt.replace(" ", "").replace("\n", "")
    };
   
    let cbor_bytes = from_byte_string!(cbor_cwt);
    if let Ok(cwt) = get_payload(&cbor_bytes) {
        return serde_json::to_string_pretty(&cwt).unwrap_or("{}".to_string());
    } else {
        return "{}".to_string();
    }
}
#[wasm_bindgen]
pub fn get_hcert_from_cwt(cbor_cwt: String) -> String {
     let cbor_cwt = if cbor_cwt.starts_with("HC1:") {
        let mut decoded = Cursor::new( base45::decode(&cbor_cwt.replace("HC1:", "")).unwrap_or(vec![]));
        let mut decompressor = flate2::read::ZlibDecoder::new(&mut decoded);
        let mut decompressed = vec![];
        match decompressor.read_to_end(&mut decompressed) {
            Ok(_) => to_byte_string!(decompressed),
            Err(r) => "".to_string()
        }
    } else {
        cbor_cwt.replace(" ", "").replace("\n", "")
    };
    let cbor_bytes = from_byte_string!(cbor_cwt);
    if let Ok(cwt) = get_payload(&cbor_bytes) {
        return serde_json::to_string_pretty(&cwt.get_hcert()).unwrap_or("{}".to_string());
    } else {
        return "{}".to_string();
    }
}

#[wasm_bindgen]
pub fn verify_cwt_ec(cbor_cwt: String, x: String, y: String, encoding: String) -> bool {
    let cbor_cwt = if cbor_cwt.starts_with("HC1:") {
        let mut decoded = Cursor::new( base45::decode(&cbor_cwt.replace("HC1:", "")).unwrap_or(vec![]));
        let mut decompressor = flate2::read::ZlibDecoder::new(&mut decoded);
        let mut decompressed = vec![];
        match decompressor.read_to_end(&mut decompressed) {
            Ok(_) => to_byte_string!(decompressed),
            Err(r) => "".to_string()
        }
    } else {
        cbor_cwt.replace(" ", "").replace("\n", "")
    };
    let cbor_bytes = from_byte_string!(cbor_cwt);

    let cwt = if let Ok(cwt) = get_payload(&cbor_bytes) {
        cwt
    } else {
        return false;
    };
    let x = if encoding.to_lowercase() == "base64" {
        to_byte_string!(base64::decode_config(x, base64::STANDARD_NO_PAD).unwrap_or(vec![]))
    } else {x};
    let y = if encoding.to_lowercase() == "base64" {
        to_byte_string!(base64::decode_config(y, base64::STANDARD_NO_PAD).unwrap_or(vec![]))
    } else {y};
    println!("{}", x);
println!("{}", y);
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
