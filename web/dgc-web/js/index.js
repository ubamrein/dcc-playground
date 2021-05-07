import("../pkg/index.js").then(m => {
    window.parse_cwt = m.parse_cwt_from_bytestring;
    window.verify_cwt = (cwt, key, encoding) => {
        if (key.x !== undefined) {
            return m.verify_cwt_ec(cwt, key.x, key.y, encoding);
        } else {
            return m.verify_cwt_rsa(cwt, key, encoding);
        }
    };
    window.get_hcert = m.get_hcert_from_cwt;
}).catch(console.error);
