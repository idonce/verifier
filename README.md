# idonce Verifier

OpenID4VP credential verifier for the idonce human verification system. Verifies eIDAS 2.0 compatible SD-JWT-VC presentations from any wallet.

## What it does

- Creates **OpenID4VP sessions** for credential verification
- Receives and verifies **SD-JWT-VC presentations** with Key Binding JWT
- Resolves **external issuer keys** via did:web / JWKS (any issuer, not just idonce)
- Provides a **demo page** with QR code for live testing
- Supports **DCQL queries** for requesting specific credential types and claims

## Endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/vp/sessions` | Create VP session (verifier initiates) |
| `GET` | `/vp/request/{id}` | Fetch authorization request (wallet) |
| `POST` | `/vp/response` | Submit VP token via direct_post (wallet) |
| `GET` | `/vp/sessions/{id}` | Poll session status (verifier) |
| `GET` | `/demo` | Interactive demo page |
| `GET` | `/health` | Health check |

## Run

```bash
go run .
# Listening on :9090
# Open http://localhost:9090/demo

BASE_URL=https://www.idonce.com PORT=9090 go run .
```

## Integration

```bash
# 1. Create VP session
curl -X POST http://localhost:9090/vp/sessions \
  -H 'Content-Type: application/json' \
  -d '{"client_id":"my-platform"}'

# 2. Show QR code from response.qr_data to user

# 3. Poll for result
curl http://localhost:9090/vp/sessions/{session_id}
# -> {"status":"presented","disclosed_claims":{"biometricConfirmed":true,...}}
```

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `PORT` | `9090` | Server port |
| `BASE_URL` | `http://localhost:9090` | Public URL |
| `ALLOWED_ORIGIN` | `*` | CORS origin |

## Test

```bash
go test ./... -v
go vet ./...
staticcheck ./...
```

## Deploy

```bash
docker build -t verifier .
docker run -p 9090:9090 verifier
```

## Tech

- Go 1.22, zero external dependencies
- Verifies SD-JWT-VC from any issuer (resolves JWKS via did:web or HTTPS)
- Validates Key Binding JWT (aud, nonce, iat freshness, sd_hash)
- ES256 (ECDSA P-256) signature verification
- QR code generation inlined (no external JS dependencies)
