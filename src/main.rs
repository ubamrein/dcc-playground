use std::collections::BTreeMap;

use digital_green_certificates::{
    from_byte_string, get_payload, to_byte_string, SigningKey, VerificationKey,
};
use serde_cbor::Value;

const RFC_TEST : &str = "d28443a10126a104524173796d6d657472696345434453413235365850a70175636f61703a2f2f61732e6578616d706c652e636f6d02656572696b77037818636f61703a2f2f6c696768742e6578616d706c652e636f6d041a5612aeb0051a5610d9f0061a5610d9f007420b7158405427c1ff28d23fbad1f29c4c7c6a555e601d6fa29f9179bc3d7438bacaca5acd08c8d4d4f96131680c429a01f85951ecee743a52b9b63632c57209120e1c9e30";

const HCERT : &str = "d2844da204489a024e6b59bf42ce0126a0590220a4041a625eef58061a607dbbd801624154390103a101590207bf63737562bf62676e684761627269656c6562666e6a4d75737465726672617563646f626a313939382d30322d32366367656e6666656d616c656269649fbf61746350504e61696c31323334354142432d333231ffffff637661639fbf6364697369383430353339303036637661706a31313139333035303035636d65706c45552f312f32302f31353238636175746d4f52472d313030303330323135637365710163746f7402636c6f746d4332322d38363246462d303031636461746a323032312d30322d31386361646d781c56616363696e6174696f6e2063656e747265205669656e6e6120323363636f75624154ffbf6364697369383430353339303036637661706a31313139333035303035636d65706c45552f312f32302f31353238636175746d4f52472d313030303330323135637365710263746f7402636c6f746d4332322d48363246462d303130636461746a323032312d30332d31326361646d781c56616363696e6174696f6e2063656e747265205669656e6e6120323363636f75624154ffff6463657274bf626973781b4d696e6973747279206f66204865616c74682c204175737472696162696478273031415434323139363536303237353233303432373430323437303235363532303235303034326276666a323032312d30342d30346276756a323032312d31302d303462636f6241546276726476312e30ffff5840cea198d7da5cb609f9b1d0622d3d2824d5a05b0a8cbd0f112ec8be8860be3944ab9f0a4614521328db093570bd64bc2c1d88decdd597578a329b2aa96fbfe906";

const JWK: &str = "MIIDQjCCAiqgAwIBAgIGATz/FuLiMA0GCSqGSIb3DQEBBQUAMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDAeFw0xMzAyMjEyMzI5MTVaFw0xODA4MTQyMjI5MTVaMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL64zn8/QnHYMeZ0LncoXaEde1fiLm1jHjmQsF/449IYALM9if6amFtPDy2yvz3YlRij66s5gyLCyO7ANuVRJx1NbgizcAblIgjtdf/u3WG7K+IiZhtELto/A7Fck9Ws6SQvzRvOE8uSirYbgmj6He4iO8NCyvaK0jIQRMMGQwsU1quGmFgHIXPLfnpnfajr1rVTAwtgV5LEZ4Iel+W1GC8ugMhyr4/p1MtcIM42EA8BzE6ZQqC7VPqPvEjZ2dbZkaBhPbiZAS3YeYBRDWm1p1OZtWamT3cEvqqPpnjL1XyW+oyVVkaZdklLQp2Btgt9qr21m42f4wTw+Xrp6rCKNb0CAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAh8zGlfSlcI0o3rYDPBB07aXNswb4ECNIKG0CETTUxmXl9KUL+9gGlqCz5iWLOgWsnrcKcY0vXPG9J1r9AqBNTqNgHq2G03X09266X5CpOe1zFo+Owb1zxtp3PehFdfQJ610CDLEaS9V9Rqp17hCyybEpOGVwe8fnk+fbEL2Bo3UPGrpsHzUoaGpDftmWssZkhpBJKVMJyf/RuP2SmmaIzmnw9JiSlYhzo4tpzd5rFXhjRbg4zW9C+2qok+2+qDM1iJ684gPHMIY8aLWrdgQTxkumGmTqgawR+N5MDtdPTEQ0XfIBc2cJEUyMTY5MPvACWpkA6SdS4xSvdXK3IVfOWA==";


const PRIVATE_PART: &str = "MIIEowIBAAKCAQEAzFbQTlvm+IRJ/HwvIIW6xzye64rUMTBxaCUxD6EIzjDr6WkwzaLYpV5pgPPKsr5trTbN/NnaFSj9xeU8JM7AJRIvajvoJ7lRPWd7jIeQ9czGzTjwuo72mu3QzIu85y4tCDiopAVvApyzFUyuuU+JDdVIXHRBQKnMUndA6kVs9oJ5fuisZIrV4OCBsN94NNiomMaMeCD82g7Vo/O5P1KAfM2IHhTD6e7PrSCDERlHpnw8C1NIo0sWuHzA99go6vvkpJVm3zR3cJSX06r354g4w3JrPrnZOt+ikwYXpNXORQYn59VMezKjtKihKgaFy656Ezh8Zw+249ksPX3vhXjMMwIDAQABAoIBAAT+skTYFkNI6I4Vcwl2e2RXZQMY96rkJkGHdzWMmCyCIaIpAhpkuqsALdALJY9M/F1Zk5t0r9IImHt36Qp1S1kcorAUGs6txwCbQPfkcHSxtsJZe/jzea+71HjLiaiVBmDHEchAocAMmIwSvcql2RHPft9TsCymeeoiJCIV5F36M1Hw9RA19pEvzqy2XFtEftDETclWVKoYBLnzMJopptmuklZhEO7zxSH2IVvgdZ4Iax9G5S5VcrP2+eGYBZ5fWkojQYzeVKWikCkms0szoP3TTDoUvXHR7K/Ec7Yc38sxKZ2LLrQ1qltDDMpvJb649KnbR9Omkagu6PyFLpgB9hECgYEA7JVrjCmybdwjbJRCta3sTb+/xQZ1QZo4d87VnsQIKqdXKvg2CjT0tX7o1NC4saIXjg7HBB84D2madX2HvhcO9+M9s+Co3bUFfuccFS7GRSbB+Df5c4qmwgOAunXtm6G+ZVD5o5CG9xWMoRHrekE+GhrNbGbKnEmmUkr9VKFifl0CgYEA3Rvw+vg0U7MuPkHXE3IDWlOS/srSFU8RrmB6D2Yn+eU3FHJZj9YaXkxgsrmI778IxQvizmMOEaESlEFw0qKNQiuFxYLhAuL+/Xvr0XqbkZT4/YM9waTRPuRaTRzqcy/AcKig0FMe9alucunGALH1G3Ix55Uj+eIEpFhtkhJXK88CgYEAlJ/Nv3DWceOwsV52hhHr+G/0dj73XK4YuVNLqgC2rK0RuqHRuRnJfVdrx34T+Su+JnUsG2/NVQlfil3A7+8mbR3pvl3tV9KH0FA5uSj4T6roghoP8MDyv8FZlknNak7zAE0ddt6tmv2DqhBK4TOpYtbhpC7zK7ms7dfES+1SpdUCgYBiHRj0tJi7n2HgvGSMu2XjefxbVXKdhAWLhEIFfUY17FFhoFA/tDjlKS0rgYrTH8jrbxfIj0nZ5siQwu0men0GJLvqZeYk2sddgdSlkqtfkWRfUhJgUBuNtdSgLTmXvVO+agVaC9hMGE/ra/KxskXaVPTyF0rsgi+fIaIVVFAcHwKBgFmjrzI8fY3dol1U8NTf1rqiyTRnYJxKyBWOVZ+ozN8BFID0i+dpnrDatyC+PIhlbD+6nIwD51QVvBBNvlNDHMZZgC6gEeca8JRX/hiK1JfJampeAk/FylOujAjbUOlvaFKHLQEcmWkrU+kOJOuOsWbyh9DcxRGWWKwDi3fFH9GD";

const PUBLIC_PART: &str = "MIIBCgKCAQEAzFbQTlvm+IRJ/HwvIIW6xzye64rUMTBxaCUxD6EIzjDr6WkwzaLYpV5pgPPKsr5trTbN/NnaFSj9xeU8JM7AJRIvajvoJ7lRPWd7jIeQ9czGzTjwuo72mu3QzIu85y4tCDiopAVvApyzFUyuuU+JDdVIXHRBQKnMUndA6kVs9oJ5fuisZIrV4OCBsN94NNiomMaMeCD82g7Vo/O5P1KAfM2IHhTD6e7PrSCDERlHpnw8C1NIo0sWuHzA99go6vvkpJVm3zR3cJSX06r354g4w3JrPrnZOt+ikwYXpNXORQYn59VMezKjtKihKgaFy656Ezh8Zw+249ksPX3vhXjMMwIDAQAB";
use x509_parser::prelude::*;
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bytes: Vec<u8> = from_byte_string!(RFC_TEST);

    let key = VerificationKey::Es256 {
        x: "143329cce7868e416927599cf65a34f3ce2ffda55a7eca69ed8919a394d42f0f".to_string(),
        y: "60f7f1a780d8a783bfb7a2dd6b2796e8128dbbcef9d3d168db9529971a36e7b9".to_string(),
    };

    println!("Verify CWT taken from RFC");
    let cwt = get_payload(&bytes)?;
    println!("Signature was {:?}",cwt.verify(&key));


    let bytes: Vec<u8> = from_byte_string!(HCERT);
    let mut cwt_hcert = get_payload(&bytes)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&cwt_hcert.get_hcert()).unwrap()
    );
    let cert_bytes = base64::decode(&JWK)?;
    let (_, cert) = parse_x509_certificate(&cert_bytes)?;

    let key = SigningKey::RsaDer {
        der: base64::decode(PRIVATE_PART)?,
    };
    // we need to check signing the content with our own keypair since we don't support SHA1
    println!("Sign key now with our own keypair");
    cwt_hcert.sign(&key)?;
    println!("Signed, now verify again");

    let verification_key = VerificationKey::Rsa{key: to_byte_string!(base64::decode(PUBLIC_PART).unwrap())};

    println!("Signature {:?}", cwt_hcert.verify(&verification_key));

    Ok(())
}
