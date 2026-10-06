# device-flow

`device_flow.py`: a mock OAuth 2.0 authorization server and a TV-style client that polls for a token (RFC 8628).

## Goal

Show how an input-constrained device gets an access token: it receives a user code, the user approves on a second device, and the first device polls until approval.

## Run it

```bash
python3 device_flow.py
```

Expected output (the user code is random):

```
On your phone open http://localhost/activate and enter BF4DEBE8
polled: authorization_pending, authorization_pending -> got access token
OK
```

## What it proves

- `/device_authorization` returns a `device_code`, a `user_code`, `interval` 1 and a 30 s expiry; the client sleeps one interval between `/token` calls.
- Until the simulated phone posts to `/activate` (after about 2.5 s), `/token` answers `authorization_pending`; afterwards it returns a Bearer token.
- Polling faster than the interval gets `slow_down`, and the client adds 5 s to its interval when it sees that error.

## Trade-offs

- The server keeps state in a module-level dict and does not authenticate the client or check `client_id`.
- `/activate` is a bare POST with the user code; a real server shows a login and consent page.
- The final `slow_down` assertion is loose (`code == 200 or slow_down`), so it does not strictly test rate limiting.

## When not to use it

- When the device has a browser or can receive a redirect; use the authorization code flow with PKCE.
- For a real device flow, use your identity provider's implementation, such as Keycloak's, rather than this mock.
