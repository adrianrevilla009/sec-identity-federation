# saml-federation

Keycloak 26.0.7 compose file, an importable `orders` realm (`orders-realm.json`) and `check.py`, which validates the config and can fetch the IdP metadata.

## Goal

Show Keycloak acting as a SAML 2.0 identity provider whose realm, user and service-provider client are all declared in version control. The SP client has a single allowed assertion-consumer URL and signed assertions.

## Run it

```bash
python3 check.py                 # offline: validates realm JSON and the pinned image
docker compose up -d             # Keycloak on :8080, realm imported (admin/admin, lab only)
python3 check.py --live          # fetches /realms/orders/protocol/saml/descriptor
docker compose down -v           # destroy
```

Expected offline output:

```
config ok: SP http://localhost:8081/saml/metadata -> ACS http://localhost:8081/saml/acs
OK
```

Not run end to end: the Keycloak container was not started here, so `--live` and the metadata fetch are untested. Only the offline check was run. There is no service provider in this folder; point any SAML SP at the descriptor URL with ACS `http://localhost:8081/saml/acs`, so a browser login was never exercised.

## What it proves

- `orders-realm.json` defines the realm `orders`, user `ada` and a SAML client `orders-sp` that Keycloak imports at startup via `compose.yaml`.
- `check.py` asserts that the ACS URL is the only redirect URI, that `saml.assertion.signature` is `true`, and that the Keycloak image tag is pinned.
- With the stack up, `--live` asserts the IdP descriptor contains a `SingleSignOnService` endpoint.

## Trade-offs

- `start-dev` runs over plain HTTP with a development database and the admin password is `admin`; fine for a lab, not for a real IdP.
- The checks are static or metadata-only; they do not show that a browser SSO round trip succeeds.
- `saml.client.signature` is `false`, so the IdP does not verify signed requests from the SP.

## When not to use it

- When the application can speak OIDC: SAML is XML-heavy and is worth it mainly for enterprise SPs that require it.
- As a production IdP setup; use a hardened Keycloak deployment with TLS and a real database.
