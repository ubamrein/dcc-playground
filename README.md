# Digital Green Certificates

This repo contains code to study CWTs. We use `serde_cbor` for deserializing and follow the [CWT](https://tools.ietf.org/html/rfc8392#page-5) specification.

We check our implementation with the samples from the RFC and also parse the example data found [here](https://github.com/eu-digital-green-certificates/dgc-testdata). Sadly, currently the COSE uses a SHA1 algorithm, which we wont support and should not be supported according to the (Digital Green Certificates outline)[https://ec.europa.eu/health/sites/health/files/ehealth/docs/digital-green-certificates_v1_en.pdf] in Section 3.3.2.