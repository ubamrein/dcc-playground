# Digital Green Certificates

This repo contains code to study CWTs. We use `serde_cbor` for deserializing and follow the [CWT](https://tools.ietf.org/html/rfc8392#page-5) specification.

We use this implementation for an online hcert viewer and signature verifier for debugging purposes. Further, we use this to generate custom weird and broken hcerts to verify that decoding issues are caught.
