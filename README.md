# sec-identity-federation

Five small, runnable demos of identity federation and strong authentication (SAML, SCIM, mutual TLS, device flow, passkeys), so you can see how each protocol is wired without a large framework around it. The examples use the shared Orders domain (`orders.test`, `ada@orders.test`).

## What is inside

| Folder | What it shows | Run |
| --- | --- | --- |
| [`saml-federation`](./saml-federation) | Keycloak as a SAML 2.0 identity provider with a declarative `orders` realm and a pinned service-provider client | `python3 saml-federation/check.py` |
| [`scim`](./scim) | A SCIM 2.0 `/Users` server and a client that provisions, deactivates and deletes a user | `python3 scim/scim_demo.py` |
| [`mtls`](./mtls) | Two Java services over mutual TLS with throwaway certificates; the server identifies the caller by certificate subject | `bash mtls/run.sh` |
| [`device-flow`](./device-flow) | OAuth 2.0 device authorization grant (RFC 8628) with a mock server and a polling client | `python3 device-flow/device_flow.py` |
| [`passkeys-webauthn`](./passkeys-webauthn) | WebAuthn registration and login with a software authenticator and a relying party | `pip install -r passkeys-webauthn/requirements.txt && python3 passkeys-webauthn/webauthn_demo.py` |

## Prerequisites

- Python 3.8 or newer (standard library only, except `cryptography==3.4.8` for `passkeys-webauthn`)
- Java 21 with `keytool` (for `mtls`; the source file is run directly with `java Mtls.java`)
- Docker with Compose (only for the live part of `saml-federation`; Keycloak 26.0.7)

## How to read it

Start with `device-flow` or `scim`: each is one Python file that starts its own server and asserts the result. `saml-federation` is the only folder that needs a container, and its offline check works without one.
