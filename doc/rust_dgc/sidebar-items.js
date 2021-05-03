initSidebarItems({"enum":[["SigningKey","Possible SigningKeys. We allow `RSA` or `EC`."],["VerificationKey","Possible verification keys. Either `RSA` or `EC` "]],"fn":[["get_payload","Get the CWT payload, which according to RFC-8392 Section-7 is just the `Cose_Sign1` Struct from RFC-8152 Section-4.2 This means we have a CBOR-Array like this, where the `Headers` defines the Algorithm used and `payload` contains CWT’s claims. In our case the `hcert` will be one of those claims."]],"macro":[["from_byte_string","Simple macro to produce a Vec from a byte string."],["to_byte_string","Simple macro to produce a byte string from a Vec"]],"struct":[["CwtParsed","The parsed CWT struct"]]});