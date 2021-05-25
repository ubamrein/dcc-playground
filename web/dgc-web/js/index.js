import("../pkg/index.js").then(m => {
    window.parse_cwt = m.parse_cwt_from_bytestring;
    window.verify_cwt = (cwt, key, encoding) => {
        if (key.x !== undefined) {
            return m.verify_cwt_ec(cwt, key.x, key.y, encoding);
        } else {
            return m.verify_cwt_rsa(cwt, key, encoding);
        }
    };
    window.verify_cwt_with_env = (cwt, environment) => {
        return m.verify_cwt_rsa_with_environment(cwt, environment)
    };
    window.get_cwt_info = (cwt) => {
        return m.get_cwt_info(cwt)
    };
    window.get_qr_code_payload = (image) => {
        var data = image.split(",")[1].trim();
        return m.get_qr_code_data(data)
    }
    window.get_hcert = m.get_hcert_from_cwt;
}).catch(console.error);
