# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in idonce, please report it responsibly.

**Email:** security@idonce.com

Please include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact

We will acknowledge receipt within 48 hours and aim to provide a fix within 7 days for critical issues.

## Scope

This policy covers:
- The idonce verifier (`verifier`)
- SD-JWT-VC verification logic
- OpenID4VP session management
- Key Binding JWT validation
- JWKS resolution and issuer key fetching

## Out of Scope

- Denial of service via rate limiting (already mitigated)
- Issues in third-party dependencies (we have zero Go dependencies)
- Social engineering

## Security Notes

- JWKS resolution uses HTTPS for all non-localhost issuers
- HTTP is allowed only for `localhost` and `127.0.0.1` (development)
- The default CORS origin is `*` — configure `ALLOWED_ORIGIN` in production
- Session nonces are cryptographically random (32 bytes)

## Disclosure

We follow coordinated disclosure. Please do not open public issues for security vulnerabilities.
