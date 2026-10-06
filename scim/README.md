# scim

`scim_demo.py`: a minimal SCIM 2.0 `/scim/v2/Users` server on a random local port plus an IdP-style client that drives it.

## Goal

Show the provisioning lifecycle an identity provider runs against an application: create a user, find it, deactivate it when the person leaves, and delete it.

## Run it

```bash
python3 scim_demo.py
```

Expected output (the id differs per run):

```
provisioned ada@orders.test c582d08d-13e2-471c-8a1e-77fc381f676e
deactivated (leaver flow)
OK
```

## What it proves

- `POST /Users` returns 201 with a generated `id`; creating the same `userName` again returns 409 with `scimType: uniqueness`.
- `GET /Users?filter=userName eq "..."` returns a `ListResponse` with `totalResults` 1, and a `PATCH` with a `replace` operation sets `active` to `false`.
- A wrong bearer token gets 401; `DELETE` returns 204 and a following `GET` returns 404.

## Trade-offs

- State lives in an in-memory dict and the server speaks plain HTTP with one hard-coded demo token.
- Only a slice of RFC 7644 is implemented: the `userName eq` filter, `replace` on top-level attributes, no groups, no paging, no `/Schemas` or `/ServiceProviderConfig`.
- The server is single-purpose test code; it does not validate request schemas.

## When not to use it

- For a real integration, use your IdP's SCIM client against a SCIM library or the application's own SCIM endpoint.
- To test full SCIM compliance; this covers only the happy path of the leaver flow.
