"""WebAuthn ceremonies from first principles: a software authenticator and a relying party (attestation 'none', ES256)."""
import hashlib, json, os, struct
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

RP_ID, ORIGIN = "orders.test", "https://orders.test"


# --- tiny CBOR: only what a COSE EC2 key needs (ints, bytes, small map) ---
def _head(major, n):
    return bytes([major << 5 | n]) if n < 24 else bytes([major << 5 | 24, n]) if n < 256 else bytes([major << 5 | 25]) + struct.pack(">H", n)


def cbor(o):
    if isinstance(o, int):
        return _head(0, o) if o >= 0 else _head(1, -1 - o)
    if isinstance(o, bytes):
        return _head(2, len(o)) + o
    return _head(5, len(o)) + b"".join(cbor(k) + cbor(v) for k, v in o.items())


def uncbor(b, i=0):
    major, n, i = b[i] >> 5, b[i] & 31, i + 1
    if n == 24:
        n, i = b[i], i + 1
    elif n == 25:
        n, i = struct.unpack(">H", b[i:i + 2])[0], i + 2
    if major == 0:
        return n, i
    if major == 1:
        return -1 - n, i
    if major == 2:
        return b[i:i + n], i + n
    out = {}
    for _ in range(n):
        k, i = uncbor(b, i)
        out[k], i = uncbor(b, i)
    return out, i


class Authenticator:
    """Holds the private key; it never leaves. Signs only for the rpId it registered with."""

    def __init__(self):
        self.keys, self.counter = {}, 0

    def _auth_data(self, flags, cred=None):
        d = hashlib.sha256(RP_ID.encode()).digest() + bytes([flags]) + struct.pack(">I", self.counter)
        return d + cred if cred else d

    def make_credential(self, challenge):
        key, cid = ec.generate_private_key(ec.SECP256R1()), os.urandom(16)
        self.keys[cid] = key
        n = key.public_key().public_numbers()
        cose = cbor({1: 2, 3: -7, -1: 1, -2: n.x.to_bytes(32, "big"), -3: n.y.to_bytes(32, "big")})
        attested = bytes(16) + struct.pack(">H", len(cid)) + cid + cose
        cdj = json.dumps({"type": "webauthn.create", "challenge": challenge.hex(), "origin": ORIGIN}).encode()
        return cid, self._auth_data(0x45, attested), cdj  # UP | UV | AT

    def get_assertion(self, cid, challenge, origin=ORIGIN):
        self.counter += 1
        cdj = json.dumps({"type": "webauthn.get", "challenge": challenge.hex(), "origin": origin}).encode()
        ad = self._auth_data(0x05)  # UP | UV
        return ad, cdj, self.keys[cid].sign(ad + hashlib.sha256(cdj).digest(), ec.ECDSA(hashes.SHA256()))


class RelyingParty:
    def __init__(self):
        self.creds, self.pending = {}, None

    def challenge(self):
        self.pending = os.urandom(32)
        return self.pending

    def _check(self, cdj, typ, ad):
        c = json.loads(cdj)
        assert c["type"] == typ and c["origin"] == ORIGIN, "bad origin/type"
        assert bytes.fromhex(c["challenge"]) == self.pending, "bad challenge"
        self.pending = None  # single use
        assert ad[:32] == hashlib.sha256(RP_ID.encode()).digest(), "bad rpIdHash"
        assert ad[32] & 0x01 and ad[32] & 0x04, "user presence/verification missing"

    def register(self, cid, ad, cdj):
        self._check(cdj, "webauthn.create", ad)
        cose, _ = uncbor(ad[55 + len(cid):])
        pub = ec.EllipticCurvePublicNumbers(int.from_bytes(cose[-2], "big"), int.from_bytes(cose[-3], "big"), ec.SECP256R1())
        self.creds[cid] = {"pub": pub.public_key(), "count": 0}

    def login(self, cid, ad, cdj, sig):
        self._check(cdj, "webauthn.get", ad)
        cred = self.creds[cid]
        cred["pub"].verify(sig, ad + hashlib.sha256(cdj).digest(), ec.ECDSA(hashes.SHA256()))  # raises if invalid
        count = struct.unpack(">I", ad[33:37])[0]
        assert count > cred["count"], "signCount did not increase: cloned authenticator?"
        cred["count"] = count


def expect_fail(fn):
    try:
        fn()
    except Exception as e:
        return type(e).__name__
    raise SystemExit("expected failure did not happen")


if __name__ == "__main__":
    rp, dev = RelyingParty(), Authenticator()
    cid, ad, cdj = dev.make_credential(rp.challenge())
    rp.register(cid, ad, cdj)
    print("registered passkey", cid.hex())

    ad, cdj, sig = dev.get_assertion(cid, rp.challenge())
    rp.login(cid, ad, cdj, sig)
    print("login ok, signCount =", rp.creds[cid]["count"])

    # replay: same signed assertion again after the challenge was consumed
    print("replayed assertion  :", expect_fail(lambda: rp.login(cid, ad, cdj, sig)))
    ad2, cdj2, sig2 = dev.get_assertion(cid, rp.challenge(), origin="https://evil.test")
    print("phishing origin     :", expect_fail(lambda: rp.login(cid, ad2, cdj2, sig2)))
    ad3, cdj3, sig3 = dev.get_assertion(cid, rp.challenge())
    print("tampered signature  :", expect_fail(lambda: rp.login(cid, ad3, cdj3, sig3[:-1] + bytes([sig3[-1] ^ 1]))))
    print("OK")
