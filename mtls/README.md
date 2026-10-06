# mtls

`Mtls.java` (server and client in one process) and `run.sh`, which creates a throwaway CA, server and client keystores with `keytool`.

## Goal

Show two services authenticating each other with certificates: the server demands a client certificate and reports the caller by its subject name.

## Run it

```bash
bash run.sh
```

Needs Java 21 with `keytool` on the PATH. Expected output:

```
with client cert   : hello CN=client
without client cert: rejected (SSLHandshakeException)
OK
```

Not run end to end: this output is what the code asserts and prints, but the script was not executed while writing this README, so the exception class name is not confirmed.

## What it proves

- `run.sh` builds an EC (secp256r1) CA, signs `server` and `client` certificates with it, and discards everything on exit (temporary directory, password `changeit`).
- `Mtls.java` starts an `HttpsServer` on `localhost:8443` with `setNeedClientAuth(true)` over TLS 1.3, and `/whoami` returns the peer principal, which must contain `CN=client`.
- A client with a trust store but no key store fails the handshake with an `IOException`, and the program throws if that call succeeds.

## Trade-offs

- Certificates are created per run and valid for 2 days; real systems need issuance, rotation and revocation.
- Trust is a single CA, and identity is only the subject string; there is no authorization beyond "has a certificate from this CA".
- Server and client run in one JVM on one port (8443), which fails if the port is busy.

## When not to use it

- When a service mesh or ingress already terminates mTLS for you.
- Where clients cannot hold private keys safely, such as browsers on unmanaged devices; use tokens there.
