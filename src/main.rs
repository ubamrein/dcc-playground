use std::io::Cursor;

use flate2::Compression;
use image::{ImageBuffer, Luma, RgbImage, Rgba};
use p256::ecdsa::VerifyingKey;
use rand::{rngs::OsRng, thread_rng};
use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair};
use rust_dgc::{SigningKey, VerificationKey, from_byte_string, get_payload, to_byte_string};
use serde_cbor::Value;

const RFC_TEST : &str = "d28443a10126a104524173796d6d657472696345434453413235365850a70175636f61703a2f2f61732e6578616d706c652e636f6d02656572696b77037818636f61703a2f2f6c696768742e6578616d706c652e636f6d041a5612aeb0051a5610d9f0061a5610d9f007420b7158405427c1ff28d23fbad1f29c4c7c6a555e601d6fa29f9179bc3d7438bacaca5acd08c8d4d4f96131680c429a01f85951ecee743a52b9b63632c57209120e1c9e30";

const HCERT : &str = "d2844da204489a024e6b59bf42ce0126a0590220a4041a625eef58061a607dbbd801624154390103a101590207bf63737562bf62676e684761627269656c6562666e6a4d75737465726672617563646f626a313939382d30322d32366367656e6666656d616c656269649fbf61746350504e61696c31323334354142432d333231ffffff637661639fbf6364697369383430353339303036637661706a31313139333035303035636d65706c45552f312f32302f31353238636175746d4f52472d313030303330323135637365710163746f7402636c6f746d4332322d38363246462d303031636461746a323032312d30322d31386361646d781c56616363696e6174696f6e2063656e747265205669656e6e6120323363636f75624154ffbf6364697369383430353339303036637661706a31313139333035303035636d65706c45552f312f32302f31353238636175746d4f52472d313030303330323135637365710263746f7402636c6f746d4332322d48363246462d303130636461746a323032312d30332d31326361646d781c56616363696e6174696f6e2063656e747265205669656e6e6120323363636f75624154ffff6463657274bf626973781b4d696e6973747279206f66204865616c74682c204175737472696162696478273031415434323139363536303237353233303432373430323437303235363532303235303034326276666a323032312d30342d30346276756a323032312d31302d303462636f6241546276726476312e30ffff5840cea198d7da5cb609f9b1d0622d3d2824d5a05b0a8cbd0f112ec8be8860be3944ab9f0a4614521328db093570bd64bc2c1d88decdd597578a329b2aa96fbfe906";

const JWK: &str = "MIIDQjCCAiqgAwIBAgIGATz/FuLiMA0GCSqGSIb3DQEBBQUAMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDAeFw0xMzAyMjEyMzI5MTVaFw0xODA4MTQyMjI5MTVaMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL64zn8/QnHYMeZ0LncoXaEde1fiLm1jHjmQsF/449IYALM9if6amFtPDy2yvz3YlRij66s5gyLCyO7ANuVRJx1NbgizcAblIgjtdf/u3WG7K+IiZhtELto/A7Fck9Ws6SQvzRvOE8uSirYbgmj6He4iO8NCyvaK0jIQRMMGQwsU1quGmFgHIXPLfnpnfajr1rVTAwtgV5LEZ4Iel+W1GC8ugMhyr4/p1MtcIM42EA8BzE6ZQqC7VPqPvEjZ2dbZkaBhPbiZAS3YeYBRDWm1p1OZtWamT3cEvqqPpnjL1XyW+oyVVkaZdklLQp2Btgt9qr21m42f4wTw+Xrp6rCKNb0CAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAh8zGlfSlcI0o3rYDPBB07aXNswb4ECNIKG0CETTUxmXl9KUL+9gGlqCz5iWLOgWsnrcKcY0vXPG9J1r9AqBNTqNgHq2G03X09266X5CpOe1zFo+Owb1zxtp3PehFdfQJ610CDLEaS9V9Rqp17hCyybEpOGVwe8fnk+fbEL2Bo3UPGrpsHzUoaGpDftmWssZkhpBJKVMJyf/RuP2SmmaIzmnw9JiSlYhzo4tpzd5rFXhjRbg4zW9C+2qok+2+qDM1iJ684gPHMIY8aLWrdgQTxkumGmTqgawR+N5MDtdPTEQ0XfIBc2cJEUyMTY5MPvACWpkA6SdS4xSvdXK3IVfOWA==";
const SE_HCERT: &str = "d28450a3012603183d0448ab374d001ccc4a33a059013fa4061a6082927c041a6263c5fc01625858390103a101a46376657265312e302e30636e616da462666e756427417273c3b86e73202d2076616e2048616c656e62676e6e4672616ec3a76f69732d4a6f616e63666e7471444152534f4e533c56414e3c48414c454e63676e746d4652414e434f49533c4a4f414e63646f626a323030392d30322d3238617681aa627467693834303533393030366276706a31313139333439303037626d706c45552f312f32302f31353238626d616d4f52472d31303030333032313562646e02627364026264746a323032312d30342d323162636f624e4c626973782c4d696e6973747279206f66205075626c6963204865616c74682c2057656c6661726520616e642053706f7274626369782575726e3a757663693a30313a4e4c3a506c413855575336305a34525a5856414c6c3647415a5840084660e5f9454f2cfddc3d5e4c6e0a4968e9791df7ac823b837d620eed8d5ddbc39ce9cba44bd430a4b5339eb85306b66a76effecd56c36513165ca5435128e8";

const PRIVATE_PART: &str = "MIIEowIBAAKCAQEAzFbQTlvm+IRJ/HwvIIW6xzye64rUMTBxaCUxD6EIzjDr6WkwzaLYpV5pgPPKsr5trTbN/NnaFSj9xeU8JM7AJRIvajvoJ7lRPWd7jIeQ9czGzTjwuo72mu3QzIu85y4tCDiopAVvApyzFUyuuU+JDdVIXHRBQKnMUndA6kVs9oJ5fuisZIrV4OCBsN94NNiomMaMeCD82g7Vo/O5P1KAfM2IHhTD6e7PrSCDERlHpnw8C1NIo0sWuHzA99go6vvkpJVm3zR3cJSX06r354g4w3JrPrnZOt+ikwYXpNXORQYn59VMezKjtKihKgaFy656Ezh8Zw+249ksPX3vhXjMMwIDAQABAoIBAAT+skTYFkNI6I4Vcwl2e2RXZQMY96rkJkGHdzWMmCyCIaIpAhpkuqsALdALJY9M/F1Zk5t0r9IImHt36Qp1S1kcorAUGs6txwCbQPfkcHSxtsJZe/jzea+71HjLiaiVBmDHEchAocAMmIwSvcql2RHPft9TsCymeeoiJCIV5F36M1Hw9RA19pEvzqy2XFtEftDETclWVKoYBLnzMJopptmuklZhEO7zxSH2IVvgdZ4Iax9G5S5VcrP2+eGYBZ5fWkojQYzeVKWikCkms0szoP3TTDoUvXHR7K/Ec7Yc38sxKZ2LLrQ1qltDDMpvJb649KnbR9Omkagu6PyFLpgB9hECgYEA7JVrjCmybdwjbJRCta3sTb+/xQZ1QZo4d87VnsQIKqdXKvg2CjT0tX7o1NC4saIXjg7HBB84D2madX2HvhcO9+M9s+Co3bUFfuccFS7GRSbB+Df5c4qmwgOAunXtm6G+ZVD5o5CG9xWMoRHrekE+GhrNbGbKnEmmUkr9VKFifl0CgYEA3Rvw+vg0U7MuPkHXE3IDWlOS/srSFU8RrmB6D2Yn+eU3FHJZj9YaXkxgsrmI778IxQvizmMOEaESlEFw0qKNQiuFxYLhAuL+/Xvr0XqbkZT4/YM9waTRPuRaTRzqcy/AcKig0FMe9alucunGALH1G3Ix55Uj+eIEpFhtkhJXK88CgYEAlJ/Nv3DWceOwsV52hhHr+G/0dj73XK4YuVNLqgC2rK0RuqHRuRnJfVdrx34T+Su+JnUsG2/NVQlfil3A7+8mbR3pvl3tV9KH0FA5uSj4T6roghoP8MDyv8FZlknNak7zAE0ddt6tmv2DqhBK4TOpYtbhpC7zK7ms7dfES+1SpdUCgYBiHRj0tJi7n2HgvGSMu2XjefxbVXKdhAWLhEIFfUY17FFhoFA/tDjlKS0rgYrTH8jrbxfIj0nZ5siQwu0men0GJLvqZeYk2sddgdSlkqtfkWRfUhJgUBuNtdSgLTmXvVO+agVaC9hMGE/ra/KxskXaVPTyF0rsgi+fIaIVVFAcHwKBgFmjrzI8fY3dol1U8NTf1rqiyTRnYJxKyBWOVZ+ozN8BFID0i+dpnrDatyC+PIhlbD+6nIwD51QVvBBNvlNDHMZZgC6gEeca8JRX/hiK1JfJampeAk/FylOujAjbUOlvaFKHLQEcmWkrU+kOJOuOsWbyh9DcxRGWWKwDi3fFH9GD";

const PUBLIC_PART: &str = "MIIBCgKCAQEAzFbQTlvm+IRJ/HwvIIW6xzye64rUMTBxaCUxD6EIzjDr6WkwzaLYpV5pgPPKsr5trTbN/NnaFSj9xeU8JM7AJRIvajvoJ7lRPWd7jIeQ9czGzTjwuo72mu3QzIu85y4tCDiopAVvApyzFUyuuU+JDdVIXHRBQKnMUndA6kVs9oJ5fuisZIrV4OCBsN94NNiomMaMeCD82g7Vo/O5P1KAfM2IHhTD6e7PrSCDERlHpnw8C1NIo0sWuHzA99go6vvkpJVm3zR3cJSX06r354g4w3JrPrnZOt+ikwYXpNXORQYn59VMezKjtKihKgaFy656Ezh8Zw+249ksPX3vhXjMMwIDAQAB";


 const ehnVaccinationCert: &str = "NCFD:MFY7N/Q.53VEEWRH7ATC3NY5F*DKNBV04E/IE/ZGM:MS1FA7RR4RA/4VDTTJPJ848DRR*S*:2GG90P2PL7THV$ZMDB8Q7EESNKT5X97G090R8 2DO$BK-R0245.VW.1D-J5OSCCU+ZNXSP42O% 4W*L28KKQ1WIPTDSE%FX:2J6O/LCW7V96DN%FTWD6.5BH5I+I2I9R+IPHK6 8FTCFXB$22CSOEPM:$VF M784PMB71OIWMMPALHBPCCYI5B.PK-P$CBXF5%S2WG6:3K.NJL$4P Q/YEEC7V24DQ3U 2TBA9XEB1D+JAP%5LOCLIAY 4HBD-UN3 PHXUEES:XJG/KHK67TM3H0ZK1MEERYA*B7F4MCLJK$9TMQPIA4%68DH GP+FGN%3KO8H5BH941MEN*9/OJHQG:K6S30B98Y63P P8OHOZKK$7IAS$Q8Z.8X0WCE6$J1UFJ56GBS8P-TUD9VN0SR2UPLLN9E469F0J.NNO4QT3240Q57F8C:TP1 M3DGRMSIWK7MRF9WC1S5RJ4 FT TGLV3WMK5I6MF+RGZ:NNQU9ARK2G7D7%+8I8S$2U7%INWK8RFW5ELQRMKTD6763D 1G-HOL$V*7HTN752E%O7:CFU.2WM365";
  const public_part_se: &str = "MIIBIzCByqADAgECAgQbc6tlMAoGCCqGSM49BAMCMBAxDjAMBgNVBAMMBUVDLU1lMB4XDTIxMDQyMDA3Mjg1MVoXDTIxMDUyMDA3Mjg1MVowEDEOMAwGA1UEAwwFRUMtTWUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASAnF9trnoiLJxV8zkWDCv4jM9/ls3bC5vVt/+oXkgHCOndb7e/7stg1OP64Gh3l/k64MlTBdR448bQA1IPXgOcoxIwEDAOBgNVHQ8BAf8EBAMCBaAwCgYIKoZIzj0EAwIDSAAwRQIgcRqHvybuL5WlAlNusu++a+cR1onTcj9VeH9ymNsFnQUCIQDfs95vijEGiXZEz2D8LF2umf1zBHvTo2s9u8EW92NypA==";

const BIT_CWT: &str = "d28444a1013824a1044843415554494f4e21590177a401624348041b00701cd2fa9578ff061a60940bb2390103a10179015a7b226e616d223a5b7b22666e223a224dc3bc6c6c6572222c22676e223a2243c3a96c696e65227d5d2c22646f62223a22313934332d30322d3031222c226973223a2242756e646573616d742066c3bc7220476573756e6468656974222c226369223a2230313a43483a3239453445463942353541323441463938433532384438454232323844363941222c2276223a5b7b227467223a7b22636f6465223a22383430353339303036222c2273797374656d223a22322e31362e3834302e312e3131333838332e362e3936227d2c227670223a7b22636f6465223a2231313139333439303037227d2c226d70223a7b22636f6465223a223638323637227d2c226d61223a7b22636f6465223a224d6f6465726e6120537769747a65726c616e6420476d62482c20426173656c227d2c22646e223a312c227364223a322c226474223a22323032312d30342d3330222c22636f223a224348227d5d7d581d43415554494f4e212054686973206973206a75737420612066616b6521";
const BIT_NEW: &str = 
"d28444a1013824a1044843415554494f4e21590117a401624348041b00701cd2fa9578ff061a6094d9a9390103a101a4617681aa626369782630313a43483a324137413633363544444644343433454138303430413236413245303442413462636f62434862646e016264746a323032312d30342d3237626973781942756e646573616d742066c3bc7220476573756e6468656974626d61781f4d6f6465726e6120537769747a65726c616e6420476d62482c20426173656c626d7065363832363762736402627467693834303533393030366276706a3131313933343930303763646f626a313934332d30322d3031636e616da462666e674dc3bc6c6c657262676e6743c3a96c696e6563666e74674d75656c6c657263676e746643656c696e656376657265312e302e30581d43415554494f4e212054686973206973206a75737420612066616b6521";

const HCERT_LI: &str = "HC1:NCFOXN%TSMAHN-HOPCB1PZ5H$SD8+JM52WEL1WG+MP RIXF5K3E$E08WA6AVO91:ZH6I1$4JM:IN1MPK9V L*H1VUU8C1VTE5ZM3763WUH*MLAVPEH.9VS+1M3N8*UFB6SH932QZJD+G9EPL.Q6846A$QY76QW6:C1:667C07ZD$J4VIJGDB7LKUTIPOJ2EA1NJSVBMOJ06J.ZJUIIQHS3DJQMIWVB*IBA2K0OAKOJ62K7UJ$JCI8CHOJL7J/922JB.NI7DJ/MJQZJ%WC*B4DJP-NT0 2$$0X4PCY0+-C1W4/GJI+C7*4M:KK54%KIO4KPK6PK6F$BG+SB.V Q5-L9TL2.WQTU1KNIL4T.B9GYPWRUXT0B0L:/6J/5R95926$17VE4+Y5ET42:6.77/Z6YCRT8QSA7G6MCORN96HC3+ ONM8NM8JPGN6HN8NB4JQK4CPHEBSM+O*+Q.*BPTMKNE9*M.NUW-MMWU/O90.FB5S9CF%R2IAFSCEIX0/XBB 7HKSFCS*+F%8OAGWVCVJ2AARB%SL000XJO+MH";

use std::io::{Seek,Read};
use x509_parser::prelude::*;

#[derive(serde::Serialize, serde::Deserialize, Default)]
struct Jwk {
    pub kid: String,
    pub kty: String,
    pub alg: String,
    pub x : Option<String>,
    pub y : Option<String>,
    pub n: Option<String>,
    pub e: Option<String>,
    pub r#use: String,
    pub crv : Option<String>
}
fn main() -> Result<(), Box<dyn std::error::Error>> {

    // let key_list = include_bytes!("list");
    // let cwt = get_payload(key_list).unwrap();
    // let keys = cwt.message.get(&serde_cbor::Value::Text("c".to_string())).unwrap();

    // match keys { 
    //     serde_cbor::Value::Array(arr) => {
    //         let jwks = arr.iter().filter_map(|key_entry| {
    //             match key_entry {
    //                 serde_cbor::Value::Map(m) => Some(m),
    //                 _ => None
    //             }
    //         }).filter_map(|key| {
    //             let kid = if let Some(serde_cbor::Value::Bytes(i))= key.get(&serde_cbor::Value::Text("i".to_string())) { base64::encode_config(i, base64::STANDARD)} else { return None};
    //             match key.get(&serde_cbor::Value::Text("k".to_string())) {
    //                 Some(serde_cbor::Value::Text(t)) if t == "e" => {
    //                     let key = if let Some(serde_cbor::Value::Bytes(b)) = key.get(&serde_cbor::Value::Text("p".to_string())) {b.to_owned()} else { return None};
    //                     let x = base64::encode_config(&key[1..33],base64::STANDARD_NO_PAD);
    //                     let y = base64::encode_config(&key[33..],base64::STANDARD_NO_PAD);
    //                     Some(
    //                         Jwk {
    //                             kid,
    //                             x: Some(x),
    //                             y: Some(y),
    //                             crv: Some(String::from("P-256")),
    //                             kty: "EC".to_string(),
    //                             alg: "ES256".to_string(),
    //                             r#use: "sig".to_string(),
    //                             ..Default::default()
    //                         }
    //                     )
    //                 },
    //                 Some(serde_cbor::Value::Text(t) ) if t == "r" =>{
    //                     let key = if let Some(serde_cbor::Value::Bytes(b)) = key.get(&serde_cbor::Value::Text("p".to_string())) {b.to_owned()} else { return None};
    //                     let asn_codes = simple_asn1::from_der(&key).unwrap();
    //                     match &asn_codes[0] {
    //                         simple_asn1::ASN1Block::Sequence(seq,a) => {
    //                             let n = if let simple_asn1::ASN1Block::Integer(_, bi) = &a[0] { base64::encode_config(bi.to_signed_bytes_be(), base64::STANDARD_NO_PAD)} else {return None};
    //                             let e = if let simple_asn1::ASN1Block::Integer(_, bi) = &a[1] {  base64::encode_config(bi.to_signed_bytes_be(), base64::STANDARD_NO_PAD)} else {return None};
    //                             return Some(
    //                                 Jwk {
    //                                     kid,
    //                                     n: Some(n),
    //                                     e: Some(e),
    //                                     kty: "RSA".to_string(),
    //                                     alg: "RS256".to_string(),
    //                                     r#use: "sig".to_string(),
    //                                     ..Default::default()
    //                                 }
    //                             )
                                
    //                         },
    //                         _ => return None
    //                     }
    //                 },
    //                 _ => return None
    //             }
    //         }).collect::<Vec<Jwk>>();
    //         println!("{:}", serde_json::to_string(&jwks).unwrap());
    //     }
    //     _ => panic!()
    // }
    // println!("{:?}",cwt.message);
    // return Ok(());
    
    let mut cwt_bit = get_payload(&from_byte_string!(BIT_NEW)).unwrap();
    // println!("{}", serde_json::to_string_pretty(&cwt_bit.get_hcert().unwrap()).unwrap());
    // return Ok(());

    // println!("Verify swedish CWT");
    // let mut test_se =Cursor::new( base45::decode(&ehnVaccinationCert));
    // let mut za = flate2::read::ZlibDecoder::new(&mut test_se);
    // let mut new_bytes = vec![];
    // za.read_to_end(&mut new_bytes).unwrap();
    // let cwt = get_payload(&new_bytes).unwrap();
    // println!("{:x?}",serde_json::to_string_pretty(&cwt.get_hcert().unwrap()));

    // let data_bytes = base64::decode(public_part_se)?;
    // let (_,cert) = parse_x509_certificate(&data_bytes)?;
    
    // let key = cert.tbs_certificate.subject_pki.subject_public_key.data;
    // let x = to_byte_string!(&key[1..33]);
    // let y = to_byte_string!(&key[33..]);
   

    // println!("x: {}", base64::encode(&key[1..33]));
    // println!("y: {}", base64::encode(&key[33..]));
    // let key = VerificationKey::Es256 {
    //     x,
    //     y
    // };
    // println!("{:?}", cwt.verify(&key));
    // return Ok(());

    // let bytes: Vec<u8> = from_byte_string!(RFC_TEST);

    // let key = VerificationKey::Es256 {
    //     x: "143329cce7868e416927599cf65a34f3ce2ffda55a7eca69ed8919a394d42f0f".to_string(),
    //     y: "60f7f1a780d8a783bfb7a2dd6b2796e8128dbbcef9d3d168db9529971a36e7b9".to_string(),
    // };

    // println!("Verify CWT taken from RFC");
    // let cwt = get_payload(&bytes)?;
    // println!("Signature was {:?}",cwt.verify(&key));


    // println!("Verify swedish CWT");
    // let mut test_se =Cursor::new( base45::decode(&ehnVaccinationCert));
    // let mut za = flate2::read::ZlibDecoder::new(&mut test_se);
    // let mut new_bytes = vec![];
    // za.read_to_end(&mut new_bytes).unwrap();
    // println!("{:x?}", new_bytes);
    
    // let cwt = get_payload(&new_bytes)?;
    // let data_bytes = base64::decode(public_part_se)?;
    // let (_,cert) = parse_x509_certificate(&data_bytes)?;
    
    // println!("{:x?}", cert);
    // let key = cert.tbs_certificate.subject_pki.subject_public_key.data;
    // println!("{}", to_byte_string!(key));
    // let y = to_byte_string!(&key[33..]);
    // let x = to_byte_string!(&key[1..33]);
    // println!("{}", x);
    // println!("{}", y);
    // let key = VerificationKey::Es256 {
    //     x,
    //     y
    // };
    // println!("{:x?}", cwt);
    // println!("Signature was {:?}", cwt.verify(&key));

    // let bytes: Vec<u8> = from_byte_string!(HCERT);
    // let mut cwt_hcert = get_payload(&bytes)?;
    // println!(
    //     "{}",
    //     serde_json::to_string_pretty(&cwt_hcert.get_hcert()).unwrap()
    // );
    // let cert_bytes = base64::decode(&JWK)?;
    // let (_, cert) = parse_x509_certificate(&cert_bytes)?;

    // let key = SigningKey::RsaDer {
    //     der: base64::decode(PRIVATE_PART)?,
    // };
    // // we need to check signing the content with our own keypair since we don't support SHA1
    // println!("Sign key now with our own keypair");
    // cwt_hcert.sign(&key)?;
    // println!("Signed, now verify again");

    // let verification_key = VerificationKey::Rsa{key: to_byte_string!(base64::decode(PUBLIC_PART).unwrap())};

    // println!("Signature {:?}", cwt_hcert.verify(&verification_key));
    
    let key = p256::ecdsa::SigningKey::random(&mut OsRng);
    let sig_key = key.to_bytes().to_vec();
    let sig_key = SigningKey::Es256 { d: to_byte_string!(sig_key) };
    
    let pk = p256::ecdsa::VerifyingKey::from(&key);
    cwt_bit.protected_headers.insert(serde_cbor::Value::Integer(4), serde_cbor::Value::Bytes(vec![0,0,1,1,2,2,3,3]));
    let entry = cwt_bit.protected_headers.get_mut(&serde_cbor::Value::Integer(1)).unwrap();
    *entry = Value::Integer(-7);
    
    cwt_bit.message.remove(&serde_cbor::Value::Integer(6));
    cwt_bit.message.remove(&serde_cbor::Value::Integer(4));

    // cwt_bit.message.entry(serde_cbor::Value::Integer(6)).and_modify(|e| {
    //     *e = serde_cbor::Value::Text("dreiundzwanzigster fünfter zweitausendundzwanzig".to_string())
    // }).or_insert(serde_cbor::Value::Text("dreiundzwanzigster fünfter zweitausendundzwanzig".to_string()));

    //  cwt_bit.message.entry(serde_cbor::Value::Integer(4)).and_modify(|e| {
    //     *e = serde_cbor::Value::Bool(true)
    // }).or_insert(serde_cbor::Value::Bool(true));

    cwt_bit.sign(&sig_key).unwrap();
    let bytes = cwt_bit.to_cbor()?;
    let mut b = vec![];
    let mut compression = flate2::write::ZlibEncoder::new(&mut b, Compression::default());
    use std::io::Write;
    compression.write_all(&bytes).unwrap();
    let _ = compression.finish()?;
    let encoded_point_struct = pk.to_encoded_point(false);
    let encoded_point = encoded_point_struct.as_bytes();
    println!("X {}",base64::encode(&encoded_point[1..33]));
    println!("Y {}",base64::encode(&encoded_point[33..]));

    let vk = VerificationKey::Es256 { x: to_byte_string!(&encoded_point[1..33]), y: to_byte_string!(&encoded_point[33..]) };
    println!("{:?}", cwt_bit.verify(&vk));
    let base45_string = rust_dgc::base45::encode(&b);
    let cert = format!("HC1:{}", base45_string);
    println!("HC1:{}", base45_string);
    println!("{}", base64::encode(vec![0,0,1,1,2,2,3,3]));

    let qrcode = qrcode::QrCode::new(cert.as_bytes())?;
    let the_qr_code = qrcode.render::<Luma<u8>>().build();
    the_qr_code.save("test_untagged.png")?;
    Ok(())
}
