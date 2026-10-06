# passkeys-webauthn

`webauthn_demo.py`: a software authenticator and a relying party that perform WebAuthn registration and login (ES256, attestation `none`), with a tiny CBOR encoder for the COSE key.

## Goal

Show what happens in the WebAuthn ceremonies at the byte level and why passkeys resist replay and phishing.

## Run it

```bash
pip install -r requirements.txt   # cryptography==3.4.8
python3 webauthn_demo.py
```

Expected output (the credential id is random):

```
registered passkey aa8d34b76724dd2fb535c084ebb6e6eb
login ok, signCount = 1
replayed assertion  : AssertionError
phishing origin     : AssertionError
tampered signature  : InvalidSignature
OK
```

## What it proves

- Registration: `Authenticator.make_credential` creates a P-256 key and returns authenticator data with the COSE public key; `RelyingParty.register` checks the challenge, origin and rpId hash and stores the key.
- Login: the authenticator signs authenticator data plus the hash of the client data; the relying party verifies the signature and requires `signCount` to increase.
- Three attacks fail: replaying an assertion (the challenge is single use), an assertion for `https://evil.test`, and a signature with one bit flipped.

## Trade-offs

- There is no browser, no real authenticator and no attestation verification; the "device" is Python code, so it demonstrates the protocol but not hardware security.
- The CBOR code handles only the integers, byte strings and small maps this key needs.
- Client data is JSON with a hex challenge, simplified from the real base64url format, so it is not interoperable with browsers.

## When not to use it

- For a real deployment, use a maintained WebAuthn library such as `py_webauthn` or `webauthn4j`.
- To test browser or hardware key behaviour; use a real authenticator and browser.
