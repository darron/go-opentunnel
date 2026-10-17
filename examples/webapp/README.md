# Small Go web app

This app demonstrates HTTP, streaming, WebSockets and graceful shutdown. It can
also act as a backend that verifies otgo's signed GitHub identity on every route.

## Run behind GitHub authentication

The browser signs in at otgo. The app checks the signed assertion before serving
anything, including `/request`, `/stream`, `/ws` and unknown paths. Direct requests
without a valid assertion return `401`.

1. Set up a profile for this backend, then enable GitHub login:

   ```sh
   otgo auth init --profile verified-webapp --upstream http://127.0.0.1:8080
   otgo auth github --profile verified-webapp --allow-user YOUR-GITHUB-LOGIN
   ```

   Replace `YOUR-GITHUB-LOGIN` with your account. If you already have a GitHub
   profile pointing at this backend, reuse it and skip setup. These commands
   contact OpenTunnel and GitHub; certificate issuance can take several minutes.

2. Export its public key and display the expected origins:

   ```sh
   otgo auth public-key --profile verified-webapp > otgo-webapp.pub
   otgo auth public-key --profile verified-webapp --json
   ```

   Use the JSON's `Issuer` and `Audience` values below. Keep the public-key file
   under your control: its integrity matters even though it is not secret. Never
   accept a key or expected origin from an incoming request.

3. From the repository root, start the backend in one terminal:

   ```sh
   go run ./examples/webapp --local-only \
     --identity-public-key ./otgo-webapp.pub \
     --identity-issuer https://YOUR-HOST.opentunnel.xyz \
     --identity-audience http://127.0.0.1:8080
   ```

   Replace `YOUR-HOST` with the profile's hostname. All three identity flags are
   required together; a bad key or incomplete configuration prevents startup.
   `--local-only` means the app listens locally while otgo owns the tunnel and
   authentication. For another port, set `--addr`, the profile's upstream and the
   audience to the same backend address. The default listener is plain HTTP on
   loopback; use an HTTP audience for it.

4. In another terminal, start the proxy:

   ```sh
   otgo proxy --profile verified-webapp
   ```

5. Open `https://YOUR-HOST.opentunnel.xyz/` and sign in. Then visit `/whoami` on
   that same site. The app returns the verified user, for example:

   ```json
   {"login":"darron","id":"5176"}
   ```

   A direct request should fail even with a forged username:

   ```sh
   curl -i -H 'X-GitHub-User: darron' -H 'X-GitHub-ID: 5176' \
     http://127.0.0.1:8080/whoami
   ```

## Reuse the verification in your app

See [auth.go](auth.go): it loads a pinned public key once, calls
`identity.VerifyRequest` before routing, and passes the verified identity through
the request context. `/whoami` reads that value, rather than trusting raw headers.
The wrapper preserves streaming and WebSocket upgrades.

`VerifyRequest` checks the signature, expiry, issuer, backend origin, HTTP method,
exact escaped path/query and companion GitHub headers. It rejects expired
assertions; `InspectRequest` and `otgo auth verify` are diagnostic tools and are
not appropriate for backend access control.

The profile's GitHub allowlist controls who can enter. Your app can make further
authorization decisions using the verified numeric `ID`, which survives account
renames. Password and machine-token requests carry no GitHub identity and are
rejected by this example's verified mode.

Keep the backend hop on loopback or HTTPS. Assertions do not sign request bodies
or prevent replay before expiry. Streams and WebSockets are verified at admission,
not on each message. See the [identity security model](../../docs/AUTH_PROXY.md#signed-backend-identity).
After reinitializing the profile or rotating its key, export the trusted key again
and restart the app with the current issuer and audience.

## Run the original tunnel example

Without identity flags, the example is an **unauthenticated** demonstration:

```sh
go run ./examples/webapp              # serve directly through a tunnel listener
go run ./examples/webapp --forward    # forward a tunnel to the loopback listener
go run ./examples/webapp --local-only # serve only on loopback
```

Verified-identity mode requires `--local-only` and a separate `otgo proxy`.
The embedded tunnel client alone does not perform GitHub login or issue assertions.
