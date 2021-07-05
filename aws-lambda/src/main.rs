use std::{
    collections::BTreeMap,
    io::{Cursor, Read},
    time::Duration,
};

use flate2::Compression;
use image::{DynamicImage, ImageOutputFormat, Rgb};
use lambda_runtime::{handler_fn, Context, Error};
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
            Err(r) => format!("{:?}", r),
        }
    } else {
        "".to_string()
    };
    Ok(rust_dgc::get_payload(&from_byte_string!(cbor_cwt)).map_err(|_| "Bytestring invalid")?)
}

fn generate_light_cert(mut cwt: CwtParsed, without_exp: bool) -> Result<Value, Error> {
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
        let (gn, name, fnt, gnt, dob) = if let (Some(name), Some(dob)) = (
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
            // let cert_id = hcert
            //     .get(&serde_cbor::Value::Text("v".to_string()))
            //     .or_else(|| hcert.get(&serde_cbor::Value::Text("r".to_string())))
            //     .or_else(|| hcert.get(&serde_cbor::Value::Text("t".to_string())))
            //     .and_then(|v| match v {
            //         serde_cbor::Value::Array(m) => {
            //             let first = &m[0];
            //             match first {
            //                 serde_cbor::Value::Map(m) => {
            //                     m.get(&serde_cbor::Value::Text("ci".to_string()))
            //                 },
            //                 _ => None
            //             }
            //         }
            //         _ => None,
            //     })
            //     .ok_or("No valid entry")?;
            match (gn, name,fnt,gnt, dob) {
                (
                    serde_cbor::Value::Text(gn),
                    serde_cbor::Value::Text(name),
                    serde_cbor::Value::Text(fnt),
                    serde_cbor::Value::Text(gnt),
                    serde_cbor::Value::Text(dob)
                ) => (gn, name,fnt,gnt, dob),
                _ => return Err("No valid cert".into()),
            }
        } else {
            return Err("no valid cert".into());
        };
        let mut light_cert: BTreeMap<serde_cbor::Value, serde_cbor::Value> = BTreeMap::new();
        let mut name_map : BTreeMap<serde_cbor::Value, serde_cbor::Value> = BTreeMap::new();
        name_map.insert(
            serde_cbor::Value::Text("fn".to_string()),
            serde_cbor::Value::Text(name.to_owned()),
        );
        name_map.insert(
            serde_cbor::Value::Text("gn".to_string()),
            serde_cbor::Value::Text(gn.to_owned()),
        );
          name_map.insert(
            serde_cbor::Value::Text("fnt".to_string()),
            serde_cbor::Value::Text(fnt.to_owned()),
        );
        name_map.insert(
            serde_cbor::Value::Text("gnt".to_string()),
            serde_cbor::Value::Text(gnt.to_owned()),
        );
        light_cert.insert(
        serde_cbor::Value::Text("ver".to_string()),
            serde_cbor::Value::Text("1.0.0".to_string()),
        );
         light_cert.insert(
            serde_cbor::Value::Text("nam".to_string()),
            serde_cbor::Value::Map(name_map),
        );
        light_cert.insert(
            serde_cbor::Value::Text("dob".to_string()),
            serde_cbor::Value::Text(dob.to_owned()),
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

        if !without_exp {
            new_map.insert(
                serde_cbor::Value::Integer(4),
                serde_cbor::Value::Integer(exp as i128),
            );
        }
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
    let cert = format!("LT1:{}", base45_string);
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

async fn func(event: Value, _: Context) -> Result<Value, Error> {
    if event["getPublicKeys"].as_str().is_some() {
        return Ok(json!({
            "x": PUBLIC_KEY.0,
            "y": PUBLIC_KEY.1
        }));
    }
    let cwt_string = event["hcert"].as_str().unwrap_or("");
    let cwt = parse_cwt(cwt_string)?;
    generate_light_cert(cwt, false)
}
#[cfg(test)]
mod tests {
    use image::Rgb;
    use super::*;

    #[test]
    fn test_custom_qr() {
        let hcert = r#"HC1:NCFJ60EG0/3WUWGSLKH47GO0KNJ9DSWQIIWT9CK+500XKY-CE59-G80:84F3ZKG%QU2F30GK JEY50.FK6ZK7:EDOLOPCF8F746KG7+59.Q6+A80:6JM8SX8RM8.A8TL6IA7-Q6.Q6JM8WJCT3EYM8XJC +DXJCCWENF6OF63W5$Q69L6%JC+QE$.32%E6VCHQEU$DE44NXOBJE719$QE0/D+8D-ED.24-G8$:8.JCBECB1A-:8$96646AL60A60S6Q$D.UDRYA 96NF6L/5QW6307KQEPD09WEQDD+Q6TW6FA7C466KCN9E%961A6DL6FA7D46JPCT3E5JDJA76L68463W5/A6..DX%DZJC3/DH$9- NTVDWKEI3DK2D4XOXVD1/DLPCG/DU2D4ZA2T9GY8MPCG/DY-CAY81C9XY8O/EZKEZ96446256V50G7AZQ4CUBCD9-FV-.6+OJROVHIBEI3KMU/TLRYPM0FA9DCTID.GQ$NYE3NPBP90/9IQH24YL7WMO0CNV1 SDB1AHX7:O26872.NV/LC+VJ75L%NGF7PT134ERGJ.I0 /49BB6JA7WKY:AL19PB120CUQ37XL1P9505-YEFJHVETB3CB-KE8EN9BPQIMPRTEW*DU+X2STCJ6O6S4XXVJ$UQNJW6IIO0X20D4S3AWSTHTA5FF7I/J9:8ALF/VP 4K1+8QGI:N0H 91QBHPJLSMNSJC BFZC5YSD.9-9E5R8-.IXUB-OG1RRQR7JEH/5T852EA3T7P6 VPFADBFUN0ZD93MQY07/4OH1FKHL9P95LIG841 BM7EXDR/PLCUUE88+-IX:Q"#;
        let cwt = parse_cwt(hcert).unwrap();
        let light = generate_light_cert(cwt, true).unwrap();
        println!("{}", serde_json::to_string_pretty(&light).unwrap());
    }
}