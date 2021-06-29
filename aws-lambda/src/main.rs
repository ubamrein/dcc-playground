use std::{
    collections::BTreeMap,
    io::{Cursor, Read},
    time::Duration,
};

use flate2::Compression;
use image::{DynamicImage, ImageOutputFormat, Luma, Rgb};
use lambda_runtime::{handler_fn, Context, Error};
use rand::rngs::OsRng;
use rust_dgc::{base45, from_byte_string, to_byte_string, CwtParsed, SigningKey};
use serde_json::{json, Value};
const PRIVATE_KEY: &str = "48483aca9813ef5eb42f0b6b1d4f583efef07aa6eb12922fc60d8d453ab81e3e";
const PUBLIC_KEY: (&str, &str) = (
    "ceBrQgj3RwWzoxkv8/vApqkB7yJGfpBC9TjeIiXUR0U=",
    "g9ufnhfjFLVIiQYeQWmQATN/CMiVbfAgFp/08+Qqv2s=",
);

#[tokio::main]
async fn main() -> Result<(), Error> {
    let func = handler_fn(func);
    lambda_runtime::run(func).await?;
    Ok(())
}

fn parse_cwt(cbor_cwt: &str) -> Result<CwtParsed, Error> {
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
        "".to_string()
    };
    Ok(rust_dgc::get_payload(&from_byte_string!(cbor_cwt)).map_err(|_| "Bytestring invalid")?)
}

async fn func(event: Value, _: Context) -> Result<Value, Error> {
    if event["getPublicKeys"].as_str().is_some() {
        return Ok(json!({
            "x": PUBLIC_KEY.0,
            "y": PUBLIC_KEY.1
        }));
    }
    let cwt_string = event["hcert"].as_str().unwrap_or("");
    let mut cwt = parse_cwt(cwt_string)?;
    let sig_key = SigningKey::Es256 {
        d: PRIVATE_KEY.to_string(),
    };

    cwt.protected_headers.insert(
        serde_cbor::Value::Integer(4),
        serde_cbor::Value::Bytes(vec![0, 0, 1, 1, 2, 2, 3, 3]),
    );
    {
        let entry = cwt
            .protected_headers
            .get_mut(&serde_cbor::Value::Integer(1))
            .unwrap();
        *entry = serde_cbor::Value::Integer(-7);
    }
    {
        let hcert = cwt.get_hcert().unwrap();
        let (gn, name, fnt, gnt, dob, cert_id) = if let (Some(name), Some(dob)) = (
            hcert.get(&serde_cbor::Value::Text("nam".to_string())),
            hcert.get(&serde_cbor::Value::Text("dob".to_string())),
        ) {
            let (gn, name, fnt, gnt) = match name {
                serde_cbor::Value::Map(m) => (
                    m.get(&serde_cbor::Value::Text("gn".to_string())).unwrap(),
                    m.get(&serde_cbor::Value::Text("fn".to_string())).unwrap(),
                     m.get(&serde_cbor::Value::Text("fnt".to_string())).unwrap(),
                    m.get(&serde_cbor::Value::Text("gnt".to_string())).unwrap(),
                ),
                _ => return Err("Name is not a map".into()),
            };
            let cert_id = hcert
                .get(&serde_cbor::Value::Text("v".to_string()))
                .or_else(|| hcert.get(&serde_cbor::Value::Text("r".to_string())))
                .or_else(|| hcert.get(&serde_cbor::Value::Text("t".to_string())))
                .and_then(|v| match v {
                    serde_cbor::Value::Array(m) => {
                        let first = &m[0];
                        match first {
                            serde_cbor::Value::Map(m) => {
                                m.get(&serde_cbor::Value::Text("ci".to_string()))
                            },
                            _ => None
                        }
                    }
                    _ => None,
                })
                .ok_or("No valid entry")?;
            match (gn, name,fnt,gnt, dob, cert_id) {
                (
                    serde_cbor::Value::Text(gn),
                    serde_cbor::Value::Text(name),
                    serde_cbor::Value::Text(fnt),
                    serde_cbor::Value::Text(gnt),
                    serde_cbor::Value::Text(dob),
                    serde_cbor::Value::Text(cert_id),
                ) => (gn, name,fnt,gnt, dob, cert_id),
                _ => return Err("No valid cert".into()),
            }
        } else {
            return Err("no valid cert".into());
        };
        let mut light_cert: BTreeMap<serde_cbor::Value, serde_cbor::Value> = BTreeMap::new();
        light_cert.insert(
            serde_cbor::Value::Text("fn".to_string()),
            serde_cbor::Value::Text(name.to_owned()),
        );
        light_cert.insert(
            serde_cbor::Value::Text("gn".to_string()),
            serde_cbor::Value::Text(gn.to_owned()),
        );
          light_cert.insert(
            serde_cbor::Value::Text("fnt".to_string()),
            serde_cbor::Value::Text(fnt.to_owned()),
        );
        light_cert.insert(
            serde_cbor::Value::Text("gnt".to_string()),
            serde_cbor::Value::Text(gnt.to_owned()),
        );
        light_cert.insert(
            serde_cbor::Value::Text("dob".to_string()),
            serde_cbor::Value::Text(dob.to_owned()),
        );
        light_cert.insert(
            serde_cbor::Value::Text("ci".to_string()),
            serde_cbor::Value::Text(cert_id.to_owned()),
        );

        let mut new_map: BTreeMap<serde_cbor::Value, serde_cbor::Value> = BTreeMap::new();
        new_map.insert(
            serde_cbor::Value::Integer(1),
            cwt.message
                .get(&serde_cbor::Value::Integer(1))
                .unwrap()
                .to_owned(),
        );
        let iat = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let exp = (std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap()
            + Duration::from_millis(48 * 3600 * 1000))
        .as_secs();

        new_map.insert(
            serde_cbor::Value::Integer(4),
            serde_cbor::Value::Integer(exp as i128),
        );
        new_map.insert(
            serde_cbor::Value::Integer(6),
            serde_cbor::Value::Integer(iat as i128),
        );
        new_map.insert(
            serde_cbor::Value::Integer(-250),
            serde_cbor::Value::Map(light_cert),
        );
        cwt.message = new_map;
    }

    cwt.sign(&sig_key).unwrap();
    let bytes = cwt.to_cbor().map_err(|_| "Cannot encode to cbor")?;
    let mut b = vec![];
    let mut compression = flate2::write::ZlibEncoder::new(&mut b, Compression::default());
    use std::io::Write;
    compression.write_all(&bytes).unwrap();
    let _ = compression.finish()?;
    let base45_string = rust_dgc::base45::encode(&b);
    let cert = format!("BAG:{}", base45_string);
    let qrcode = qrcode::QrCode::new(cert.as_bytes())?;
    let the_qr_code = qrcode.render::<Rgb<u8>>().dark_color([0x27,0x32,0x77].into()).build();
    let dyn_image = DynamicImage::ImageRgb8(the_qr_code);
    let mut png_bytes = vec![];
    dyn_image.write_to(&mut png_bytes, ImageOutputFormat::Png)?;

    Ok(json!({
       "qrcode" : base64::encode(&png_bytes),
       "payload" : cert
    }))
}
