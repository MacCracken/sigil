# Authenticode test fixtures

Throwaway keys and certificates for `tests/tcyr/authenticode.tcyr`. **None of
these has ever signed anything real**, and none should be. They are committed
so the fixtures in that test are reproducible rather than being opaque hex
blobs nobody can regenerate.

| File | What |
|---|---|
| `ac_key.hex` | DER PKCS#1 RSA-2048 private key (the "db" signer) |
| `ac_cert.hex` | its self-signed X.509 cert, `CN=Sigil Authenticode Test db` |
| `gen_signedattrs_fixture.py` | regenerates the `ATTRS_HEX` third-party-shape fixture |

The RSA pair was generated with:

```
openssl genrsa -out ac.key 2048
openssl req -new -x509 -key ac.key -sha256 -days 7300 \
  -subj "/CN=Sigil Authenticode Test db" \
  -addext basicConstraints=critical,CA:FALSE \
  -addext keyUsage=critical,digitalSignature -out ac.crt
openssl rsa  -in ac.key  -outform DER | xxd -p -c100000   # -> ac_key.hex
openssl x509 -in ac.crt  -outform DER | xxd -p -c100000   # -> ac_cert.hex
```

The tcyr also carries a P-256 pair, and a CA + leaf pair for chain-mode
verification, generated the same way (`openssl ecparam -name prime256v1
-genkey`, and `openssl x509 -req -CA ca.crt -CAkey ca.key` respectively). Those
live only as literals in the test — only the RSA pair is needed here, because
only the signedAttrs fixture has an external generator.

## Why `gen_signedattrs_fixture.py` exists

sigil's own signer never emits CMS `signedAttrs`, so signing-then-verifying
cannot exercise the branch of `authenticode_pe_verify` that handles
third-party binaries. The script builds one with an **independent**
implementation (its own DER writer + `cryptography`'s RSA signer), computing
the Authenticode image hash straight from the specification. Run it from a
directory holding `ac_key.hex` and `ac_cert.hex`:

```
python3 gen_signedattrs_fixture.py     # writes attrs_signed.hex
```

then paste the result into the `ATTRS_HEX` literal in
`tests/tcyr/authenticode.tcyr`, updating the `hex_decode` length argument to
match.
