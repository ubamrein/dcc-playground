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
    /// According to [RFC-8152 Section-3] (https://tools.ietf.org/html/rfc8152#section-3) 
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
    fn get_verification_bytes(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut verification = vec![];
        verification.push(Value::Text("Signature1".to_string()));
        verification.push(Value::Bytes(serde_cbor::to_vec(&self.protected_headers)?));
        verification.push(Value::Bytes(vec![]));
        verification.push(Value::Bytes(serde_cbor::to_vec(&self.message)?));

        Ok(serde_cbor::to_vec(&verification)?)
    }

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

pub enum VerificationKey {
    Es256 { x: String, y: String },
    Rsa { key: String },
}
pub enum SigningKey {
    Es256 { d: String, x: String, y: String },
    RsaPkcs8 { pkcs8: Vec<u8> },
    RsaDer { der: Vec<u8> },
}
