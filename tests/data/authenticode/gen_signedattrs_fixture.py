#!/usr/bin/env python3
"""Regenerate the third-party-shape Authenticode fixture in tests/tcyr/authenticode.tcyr.

WHY THIS EXISTS
---------------
sigil's own Authenticode signer emits NO CMS signedAttrs and a bare
`rsaEncryption` AlgId. Microsoft's signer and osslsigncode do the opposite,
and `authenticode_pe_verify` has to accept both. A sign-then-verify test
cannot reach that branch at all, because sigil never produces it.

So this script builds a signed PE with an INDEPENDENT implementation -- a
hand-rolled DER writer plus `cryptography`'s RSA signer -- using the
third-party shape throughout:

  * signedAttrs present, so per RFC 5652 5.4 the signature covers
    DER(SET OF Attribute): the [0] IMPLICIT span with tag 0xA0 re-encoded
    as 0x31, length bytes untouched;
  * contentType + messageDigest attributes present and bound to the content;
  * digestEncryptionAlgorithm is sha256WithRSAEncryption, not rsaEncryption.

It also computes the Authenticode image hash from the specification directly,
rather than calling sigil -- so the test checks sigil against an outside
opinion, not against itself.

USAGE
-----
Needs `ac_key.hex` / `ac_cert.hex` (the DER RSA key + self-signed cert used by
tests/tcyr/authenticode.tcyr, generated with the openssl commands recorded in
that file's fixture comment) in the working directory. Emits
`attrs_signed.hex`; paste it into the `ATTRS_HEX` literal in the tcyr, and
update the length argument to `hex_decode`.

These are THROWAWAY test keys. Never used to sign anything real.
"""

import hashlib, struct
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

# ---- minimal DER writer (independent of sigil) ----
def L(n):
    if n < 128: return bytes([n])
    b = n.to_bytes((n.bit_length()+7)//8, 'big')
    return bytes([0x80|len(b)]) + b
def T(tag, content): return bytes([tag]) + L(len(content)) + content
def SEQ(*xs): return T(0x30, b''.join(xs))
def SET(*xs): return T(0x31, b''.join(xs))
def OID(dotted):
    p=[int(x) for x in dotted.split('.')]
    out=bytes([p[0]*40+p[1]])
    for v in p[2:]:
        if v==0: out+=b'\x00'; continue
        s=[]
        while v: s.append(v&0x7f); v>>=7
        s.reverse()
        out+=bytes([x|0x80 for x in s[:-1]]+[s[-1]])
    return T(0x06, out)
def OCT(b): return T(0x04, b)
def INT(n):
    b=n.to_bytes(max(1,(n.bit_length()+8)//8),'big')
    return T(0x02, b)
def NULL(): return T(0x05, b'')
def CTX(n, content, constructed=True):
    return bytes([(0xA0 if constructed else 0x80)|n]) + L(len(content)) + content

OID_SIGNED_DATA   = '1.2.840.113549.1.7.2'
OID_SPC_INDIRECT  = '1.3.6.1.4.1.311.2.1.4'
OID_SPC_PE_IMAGE  = '1.3.6.1.4.1.311.2.1.15'
OID_SHA256        = '2.16.840.1.101.3.4.2.1'
OID_RSA_SHA256    = '1.2.840.113549.1.1.11'   # sha256WithRSAEncryption (NOT bare rsaEncryption)
OID_CONTENTTYPE   = '1.2.840.113549.1.9.3'
OID_MSGDIGEST     = '1.2.840.113549.1.9.4'

# ---- the same synthetic PE the tcyr builds ----
pe = bytearray(bytes(range(256)))
pe[0x3c:0x40] = struct.pack('<I', 0x40)
pe[0x40:0x44] = b'PE\0\0'
pe[0x58:0x5a] = struct.pack('<H', 0x20b)
pe[0xE8:0xF0] = b'\0'*8

# ---- Authenticode image hash, computed independently per spec ----
opt = 0x40 + 24            # 0x58
checksum_off = opt + 64    # 0x98
ddir = opt + 112           # 0xC8
secdir = ddir + 4*8        # 0xE8
cert_start = (len(pe) + 7) & ~7      # 256, already aligned
h = hashlib.sha256()
h.update(bytes(pe[:checksum_off]))
h.update(bytes(pe[checksum_off+4:secdir]))
h.update(bytes(pe[secdir+8:cert_start]))
pe_hash = h.digest()

# ---- SpcIndirectDataContent (matches the Authenticode schema) ----
obsolete = ''.join('\x00'+c for c in '<<<Obsolete>>>').encode('latin-1')
spc_link = CTX(2, CTX(0, obsolete, constructed=False))
spc_pe_image_data = SEQ(spc_link)
data = SEQ(OID(OID_SPC_PE_IMAGE), spc_pe_image_data)
msgdigest = SEQ(SEQ(OID(OID_SHA256), NULL()), OCT(pe_hash))
spc = SEQ(data, msgdigest)

# ---- signedAttrs: the third-party shape sigil's own signer never emits ----
attr_ct = SEQ(OID(OID_CONTENTTYPE), SET(OID(OID_SPC_INDIRECT)))
attr_md = SEQ(OID(OID_MSGDIGEST),   SET(OCT(hashlib.sha256(spc).digest())))
# RFC 5652 5.4: signature is over DER(SET OF Attribute) -- explicit 0x31 tag.
signed_attrs_set = SET(attr_ct, attr_md)
# [0] IMPLICIT is the SAME length bytes + content with tag 0xA0 instead of
# 0x31. That equivalence is the whole point of the test: the verifier has to
# hash the 0x31 form while the file stores the 0xA0 form.
signed_attrs_implicit = bytes([0xA0]) + signed_attrs_set[1:]

key  = serialization.load_der_private_key(bytes.fromhex(open('ac_key.hex').read().strip()), password=None)
cert = bytes.fromhex(open('ac_cert.hex').read().strip())
sig = key.sign(signed_attrs_set, padding.PKCS1v15(), hashes.SHA256())

# ---- issuerAndSerialNumber, copied verbatim out of the cert ----
from cryptography import x509 as X
c = X.load_der_x509_certificate(cert)
ias = SEQ(c.issuer.public_bytes(), INT(c.serial_number))

signer_info = SEQ(
    INT(1), ias,
    SEQ(OID(OID_SHA256), NULL()),
    signed_attrs_implicit,
    SEQ(OID(OID_RSA_SHA256), NULL()),
    OCT(sig),
)
signed_data = SEQ(
    INT(1),
    SET(SEQ(OID(OID_SHA256), NULL())),
    SEQ(OID(OID_SPC_INDIRECT), CTX(0, spc)),
    CTX(0, cert),
    SET(signer_info),
)
p7 = SEQ(OID(OID_SIGNED_DATA), CTX(0, signed_data))

dwlen = 8 + len(p7)
entry = (dwlen + 7) & ~7
out = bytearray(pe[:cert_start])
out += struct.pack('<IHH', dwlen, 0x0200, 0x0002) + p7 + b'\0'*(entry-dwlen)
out[secdir:secdir+8] = struct.pack('<II', cert_start, entry)

open('attrs_signed.hex','w').write(out.hex())
print("signed PE bytes:", len(out), " p7:", len(p7))
print("uses sha256WithRSAEncryption + signedAttrs (NOT sigil's own shape)")
