# Aws Lambda

Um das Lambda zu builden, braucht es einen MUSL Cross-Compiler.

## MacOSX

1) Installiere Musl-Cross:
```shell
brew install FiloSottile/musl-cross/musl-cross
```

2) Builde mit:
```shell
TARGET_CC="x86_64-linux-musl-gcc" cargo build --release --target x86_64-unknown-linux-musl
```

3) Rename File in `target/x86_64-unknown-linux-musl/release` von `aws-labmda` zu `bootstrap`.

4) `Compress` `bootstrap` Executable und Lade `ZIP` zu AWS hoch

## Curl Requests

Zusammen mit dem Lambda wurde eine REST-API deployed, welche das Lambda triggered. Folgende cURLs können benutzt werden:

### Get Public Key

```shell
curl -X 'POST' --data '{"getPublicKeys": ""}' <lambda endpoint>
```

### Get Light Cert

```shell
curl -X 'POST' --data '{"hcert" : "HC1:..."}' <labmda endpoint>
```