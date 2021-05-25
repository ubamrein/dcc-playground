use std::io::Cursor;

use rust_dgc::{base45, from_byte_string, get_payload,get_meta, to_byte_string, VerificationKey};
use std::io::Read;
use wasm_bindgen::prelude::*;

const DEV_KEY : [&str;2] = ["AOLmTuP+7Z3md1w+TgIk8qADTqIUGQvg82eGAtAKC5xDvmdz3E4mpQrkSktcx37ozTyNBhhtPQ0VVV3b/rXCjVxQ7f50VNc5VgxhX+P+t5eUSI5FhQ9yRSqkfCJXCY62GMbLbmbNzGst0hkCfpGWnh+RhWTEbxNMGh6jMW38GpL43/KsgVwq2dVrCvlyX+4mGyUtnTtWuR53oMT7kQO2c/IpDu0Ec5kqJ4KjpZHoxGiJBY8e4Cxk1LDqwT2GubHWaopw8Jp47Soudhy1mqzF7PrdTDeHrSKexhO/82q4wTcZNRH4osJfkXXMCdrlcH64M8X79/03pGRfCFMpFdhnrt0=", "AQAB"];

const DEV_KEY_ID: &str = "";

const ABN_KEY : [&str;2] = [
    "ANG1XnHVRFARGgelLvFbV67VZzdBWvfoQHDtF3Iy4C1QwfPWOPobhjveGPd02ON8fXl0UVnDZXmnAUdDncw6QFDn3VG768NpzUm+ToYShvph27gWiJliqb4pmtAXitBondNSBvLvN0igTmm1N+FlJ+Zt+5j49GKJ6hTso58ghNcK52nhveZYdGQuVglAdgajSOGWUF8AwgguUk5Gt5dNmTQCBzKBy5oKgKlm110ua+NZbbpm0UWlRruO6UlEac8/8AmXqeh55oTbzhP0+ZTc5aJcYHJbSnO1WbXKGZyvSRZE+7ZOBkdh+JpwNZcQBzpCTmhJGcU+ja5ua/DrwNMm7jE=",
    "AQAB"
];
const ABN_KEY_ID: &str = "";

#[wasm_bindgen]
pub fn get_qr_code_data(image: String) -> String {
    if let Ok(data) = base64::decode(&image) {
        return rust_dgc::decode_qr(&data).unwrap_or(String::from(""))
    }
    return String::from("")
}

#[wasm_bindgen]
pub fn parse_cwt_from_bytestring(cbor_cwt: String) -> String {
    let cbor_cwt = if cbor_cwt.starts_with("HC1:") {
        let mut decoded =
            Cursor::new(base45::decode(&cbor_cwt.replace("HC1:", "")).unwrap_or(vec![]));
        let mut decompressor = flate2::read::ZlibDecoder::new(&mut decoded);
        let mut decompressed = vec![];
        match decompressor.read_to_end(&mut decompressed) {
            Ok(_) => to_byte_string!(decompressed),
            Err(r) => "".to_string(),
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
pub fn get_cwt_info(cbor_cwt: String) -> String {
     let cbor_cwt = if cbor_cwt.starts_with("HC1:") {
        let mut decoded =
            Cursor::new(base45::decode(&cbor_cwt.replace("HC1:", "")).unwrap_or(vec![]));
        let mut decompressor = flate2::read::ZlibDecoder::new(&mut decoded);
        let mut decompressed = vec![];
        match decompressor.read_to_end(&mut decompressed) {
            Ok(_) => to_byte_string!(decompressed),
            Err(r) => "".to_string(),
        }
    } else {
        cbor_cwt.replace(" ", "").replace("\n", "")
    };

    let cbor_bytes = from_byte_string!(cbor_cwt);
    if let Ok(cwt) = get_meta(&cbor_bytes) {
        return serde_json::to_string_pretty(&cwt).unwrap_or("{}".to_string());
    } else {
        return "{}".to_string();
    }
}

#[wasm_bindgen]
pub fn get_hcert_from_cwt(cbor_cwt: String) -> String {
    let cbor_cwt = if cbor_cwt.starts_with("HC1:") {
        let mut decoded =
            Cursor::new(base45::decode(&cbor_cwt.replace("HC1:", "")).unwrap_or(vec![]));
        let mut decompressor = flate2::read::ZlibDecoder::new(&mut decoded);
        let mut decompressed = vec![];
        match decompressor.read_to_end(&mut decompressed) {
            Ok(_) => to_byte_string!(decompressed),
            Err(r) => "".to_string(),
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
        let mut decoded =
            Cursor::new(base45::decode(&cbor_cwt.replace("HC1:", "")).unwrap_or(vec![]));
        let mut decompressor = flate2::read::ZlibDecoder::new(&mut decoded);
        let mut decompressed = vec![];
        match decompressor.read_to_end(&mut decompressed) {
            Ok(_) => to_byte_string!(decompressed),
            Err(r) => "".to_string(),
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
    } else {
        x
    };
    let y = if encoding.to_lowercase() == "base64" {
        to_byte_string!(base64::decode_config(y, base64::STANDARD_NO_PAD).unwrap_or(vec![]))
    } else {
        y
    };
    println!("{}", x);
    println!("{}", y);
    let key = VerificationKey::Es256 { x, y };
    match cwt.verify(&key) {
        Ok(_) => true,
        _ => false,
    }
}

#[wasm_bindgen]
pub fn verify_cwt_rsa_with_environment(cbor_cwt: String, env: String) -> bool {
    let key = match env.to_lowercase().as_str() {
        "abn" => VerificationKey::rsa_from_n_and_e(ABN_KEY[0], ABN_KEY[1]),
        "dev" => VerificationKey::rsa_from_n_and_e(DEV_KEY[0], DEV_KEY[1]),
        _ => return false,
    };
    if let Ok(key) = key {
        let cbor_cwt = if cbor_cwt.starts_with("HC1:") {
            let mut decoded =
                Cursor::new(base45::decode(&cbor_cwt.replace("HC1:", "")).unwrap_or(vec![]));
            let mut decompressor = flate2::read::ZlibDecoder::new(&mut decoded);
            let mut decompressed = vec![];
            match decompressor.read_to_end(&mut decompressed) {
                Ok(_) => to_byte_string!(decompressed),
                Err(r) => "".to_string(),
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
        cwt.verify(&key).is_ok()
    } else {
        return false;
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
