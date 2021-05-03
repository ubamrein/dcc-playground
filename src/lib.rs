use std::collections::BTreeMap;

use serde_cbor::Value;

const HCERT_KEY: i128 = -260;
const HCERT_V1: i128 = 1;

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
    let value: serde_cbor::Value = serde_cbor::from_reader(&raw_payload[..]).unwrap();
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
    let protected_headers: serde_cbor::Value = serde_cbor::from_reader(&protected_headers[..])?;

    let message: BTreeMap<Value, Value> = serde_cbor::from_reader(&message[..])?;

    Ok(CwtParsed {
        protected_headers: protected_headers.clone(),
        unprotected_headers: unprotected_headers.clone(),
        message: message.clone(),
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
            .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
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

#[derive(Debug)]
/// The parsed CWT struct
pub struct CwtParsed {
    /// According to [RFC-8152 Section-3](https://tools.ietf.org/html/rfc8152#section-3) 
    /// since the protected headers are cryptographically signed, we want to prevent accidental
    /// changes, so they are included as a serialized CBOR Map.
    pub protected_headers: serde_cbor::Value,
    /// Unprotected headers do not need such protection and as such are just presented as a CBOR Map
    pub unprotected_headers: BTreeMap<Value, Value>,
    /// Since we later on want to get the `hcert` we deserialized the CBOR Byte-String. For the message
    /// the same argumen as for the `protected_headers` is made, as the signature includes the message
    /// payload
    pub message: BTreeMap<Value, Value>,
    /// The signature as a byte string. In the case of `ECDSA` this is just `r || s`
    pub signature: Vec<u8>,
}


impl CwtParsed {
    /// Verify the signature present in the CWT with the given [VerificationKey]
    pub fn verify(&self, key: &VerificationKey) -> Result<(), Box<dyn std::error::Error>> {
        let message = match self.get_verification_bytes() {
            Ok(v) => v,
            _ => return Err("Could not decode".into()),
        };
        match key {
            VerificationKey::Es256 { x, y } => {
                let mut pk = Vec::with_capacity(65);
                pk.push(0x04u8);
                pk.extend(from_byte_string!(x));
                pk.extend(from_byte_string!(y));
                let pk = ring::signature::UnparsedPublicKey::new(
                    &ring::signature::ECDSA_P256_SHA256_FIXED,
                    &pk,
                );
                pk.verify(&message, &self.signature)
            }
            VerificationKey::Rsa { key } => {
                let key = from_byte_string!(key);
               
                let pk = ring::signature::UnparsedPublicKey::new(
                    &ring::signature::RSA_PKCS1_2048_8192_SHA256,
                    &key,
                );
                pk.verify(&message, &self.signature)
            }
        }.map_err(|_| "Could not verify")?;
        Ok(())
    }

    /// Sign the CWT with the given [SigningKey]. Overwrites the `siganture` field of `self`.
    pub fn sign(&mut self, key: &SigningKey) -> Result<(), Box<dyn std::error::Error>> {
        match key {
            SigningKey::Es256 { d, x, y } => {
                let mut pk = Vec::with_capacity(65);
                pk.push(0x04u8);
                pk.extend(from_byte_string!(x));
                pk.extend(from_byte_string!(y));
                let key_pair = ring::signature::EcdsaKeyPair::from_private_key_and_public_key(
                    &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
                    &from_byte_string!(d),
                    &pk,
                )
                .map_err(|e| format!("KeyRejected {:?}", e))?;
                let bytes_to_sign = self.get_verification_bytes()?;
                let rng = ring::rand::SystemRandom::new();
                let signature = key_pair
                    .sign(&rng, &bytes_to_sign)
                    .map_err(|_| format!("Could not sign"))?;
                self.signature = signature.as_ref().to_vec();
            }
            SigningKey::RsaPkcs8 { pkcs8 } => {
                let rsa_keypair = ring::signature::RsaKeyPair::from_pkcs8(&pkcs8)
                    .map_err(|e| format!("KeyRejected {:?}", e))?;
                let bytes_to_sign = self.get_verification_bytes()?;
                let rng = ring::rand::SystemRandom::new();
                 let mut signature = vec![0; rsa_keypair.public_modulus_len()];

                rsa_keypair
                    .sign(
                        &ring::signature::RSA_PKCS1_SHA256,
                        &rng,
                        &bytes_to_sign,
                        &mut signature,
                    )
                    .map_err(|_| format!("Could not sign"))?;
                self.signature = signature;
            }
            SigningKey::RsaDer { der } => {
                  let rsa_keypair = ring::signature::RsaKeyPair::from_der(&der)
                    .map_err(|e| format!("KeyRejected {:?}", e))?;
                let bytes_to_sign = self.get_verification_bytes()?;
                let rng = ring::rand::SystemRandom::new();
                let mut signature = vec![0; rsa_keypair.public_modulus_len()];

                rsa_keypair
                    .sign(
                        &ring::signature::RSA_PKCS1_SHA256,
                        &rng,
                        &bytes_to_sign,
                        &mut signature,
                    )
                    .map_err(|_| format!("Could not sign"))?;
                self.signature = signature;
            },
        }
        Ok(())
    }
    /// Get the CBOR canoncial form for the bytes to sign according to [RFC-8152# Section-4.4](https://tools.ietf.org/html/rfc8152#section-4.4)
    fn get_verification_bytes(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut verification = vec![];
        verification.push(Value::Text("Signature1".to_string()));
        verification.push(Value::Bytes(serde_cbor::to_vec(&self.protected_headers)?));
        verification.push(Value::Bytes(vec![]));
        verification.push(Value::Bytes(serde_cbor::to_vec(&self.message)?));

        Ok(serde_cbor::to_vec(&verification)?)
    }

    /// The `hcert` is part of the claims in the CWT. The `hcert` itself is a container for multiple different certificates (c.f [Section 2.6.4](https://ec.europa.eu/health/sites/health/files/ehealth/docs/digital-green-certificates_v3_en.pdf)). For the Version 1 of the `DGC` the claim key `1` is used (c.f. [Section 3.3.1](https://ec.europa.eu/health/sites/health/files/ehealth/docs/digital-green-certificates_v1_en.pdf))
    pub fn get_hcert(&self) -> Option<BTreeMap<Value, Value>> {
        match self.message.get(&Value::Integer(HCERT_KEY)) {
            std::option::Option::Some(Value::Map(hcert)) => match hcert.get(&Value::Integer(HCERT_V1)) {
                Some(Value::Bytes(hcert)) => serde_cbor::from_reader(&hcert[..]).ok(),
                _ => None,
            },
            _ => None,
        }
    }
}

/// Possible verification keys. Either `RSA` or `EC` 
pub enum VerificationKey {
    /// The elliptic curve key, where `x` and `y` are byte strings of the respective curve point
    Es256 { x: String, y: String },
    /// RSA key in the `ASN.1` encoding as described in [RFC-3447 Appendix A 1.1](https://tools.ietf.org/html/rfc3447#appendix-A.1.1).
    /// Note that OpenSSL usually encodes keys as a [SubjectPublicKeyInfo](https://tools.ietf.org/html/rfc5280#section-4.1).
    /// Visit the [ring Documentation](https://briansmith.org/rustdoc/ring/signature/index.html#signing-and-verifying-with-rsa-pkcs1-15-padding) for more information on extracting the correct form.
    Rsa { key: String },
}

/// Possible SigningKeys. We allow `RSA` or `EC`.
pub enum SigningKey {
    /// The `EC` private key
    Es256 { d: String, x: String, y: String },
    /// The RSA-Private key in the der format in a PKCS8 container.
    RsaPkcs8 { pkcs8: Vec<u8> },
    /// The RSA-Private key in the der format without a ccontainer.
    RsaDer { der: Vec<u8> },
}
