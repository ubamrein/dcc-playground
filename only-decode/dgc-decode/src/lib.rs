use std::io::{Cursor, Read};

use wasm_bindgen::prelude::*;

mod base45;
mod decode;

#[wasm_bindgen]
pub fn get_cert(payload: String) -> Result<JsValue, JsValue> {
    let payload = payload.replace("HC1:", "");
    let decompressed = decompress(&payload)?;
    get_cert_internal(&decompressed)
        .map(|e| e.into())
        .map_err(|e| e.into())
}

fn decompress(payload: &str) -> Result<Vec<u8>, String> {
    let mut decoded = Cursor::new(base45::decode(payload).map_err(|e| format!("{:?}", e))?);
    let mut decompressor = flate2::read::ZlibDecoder::new(&mut decoded);
    let mut decompressed = vec![];
    match decompressor.read_to_end(&mut decompressed) {
        Ok(_) => {}
        Err(r) => return Err(format!("{:?}", r)),
    };
    Ok(decompressed)
}

fn get_cert_internal(decoded_bytes: &[u8]) -> Result<String, String> {
    let cwt = decode::get_payload(decoded_bytes).map_err(|e| format!("{:?}", e))?;
    let hcert = cwt
        .get_hcert()
        .ok_or_else(|| "no hcert found".to_string())?;
    serde_json::to_string(&hcert).map_err(|e| format!("{:?}", e))
}

#[wasm_bindgen]
pub fn get_meta(payload: String) -> Result<JsValue, JsValue> {
    get_meta_internal(&decompress(&payload)?)
        .map(|e| e.into())
        .map_err(|e| e.into())
}

fn get_meta_internal(payload: &[u8]) -> Result<String, String> {
    let meta = decode::get_meta(payload).map_err(|e| format!("{:?}", e))?;

    serde_json::to_string(&meta).map_err(|e| format!("{:?}", e))
}

#[cfg(test)]
mod tests {
    use crate::decompress;

    #[test]
    fn test() {
        let cert = "NCFI60FG0/3WUWGSLKH47GO0$WV:/F2-3MFH9CK*500XK0JCV497F3JXMUZP3F3%NU  PY50.FK6ZKZWERILOPCO8F6%E3.DA%EOPC1G72A6YM89G7MA7A46/G8HL6-R8EL6+Q6W47TL6UW6SM80S6UPC0JCZ69+EDG8F3I80/D6$CBECSUER:C2$NS346$C2%E9VC- CSUE145GB8JA5B$D:TC0R6307JQE1VE846KF67465W53*6:961G78:66468JB5WEWEE6$CEWE0EC634QF6L%6 470R64KCD3DX47B46IL6646H*6KWEKDDC%6GL69L67464KCCWE6T9OF6:/6NA76W5JPCT3E6JD846Y96%964W5Z57..DX%DZJC..D0S6I3DYUCZED1ECW.C3WE1S6I3D6WEMTA8+9$PC5$CUZC$$5Y$5FBB/20+Y3/OMK0KYUNP+4-3GH6D/DP9CUP8GIAHKVG/58$WE0+E 060 8M:58-TR%SW5U3T6:-8P+SL:0RYRC*T2VDEZQ3PR6DI55A7TR7XP6PO.BO:KG$6W 4C+FC.0P*6AK787B6530Q0A2+E9NSX3LFF3O9QBO2TUE$BUG4SMV0C-SL7EV2SC25IAT -VR-0E8H:HA-QIRYE+%7H9K952-$80.A*-M61TYVGJRL$I0*O8+KTYQLQRD6W71 TJ%E2GIZLASRP:L9.9MUM5VJF2AVPQEP4S*-F/8SAL96RD4GV:UF25L4Z04*VC66IU7L.OZHBERF273TRACUEQP6/GL99GE68O*CGA7WNL1AQ3.5%+D2:S7YM JNOKDSPNQJ06 E64WQ3";

        super::get_cert_internal(&decompress(cert).unwrap()).unwrap();
    }
}
