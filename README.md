# Aegis-RASP-Engine

An advanced Runtime Application Self-Protection (RASP) agent for Node.js. Features AST-based SQLi interception, zero-day RCE prevention via core monkey-patching, and a real-time egress exfiltration firewall.

## Features

| Module | What it does |
|---|---|
| **SQL Injection Interceptor** | Tokenises SQL into a lightweight AST and detects structural anomalies — UNION injection, stacked queries, tautologies, time-based blind payloads, comment truncation, and schema enumeration. |
| **RCE Prevention** | Monkey-patches `child_process.exec` / `execSync` to block dangerous commands (rm, sudo, nc, …) and shell-injection patterns (backticks, `$()`, pipe-to-shell, curl\|bash). |
| **Egress Exfiltration Firewall** | Intercepts outbound `http.request` / `https.request` and blocks connections to hosts not in an explicit allowlist, preventing data exfiltration. |
| **Strict CORS** | Never uses `Access-Control-Allow-Origin: *`. Reflects origin only when it appears in a configured allowlist. Adds security headers (HSTS, X-Frame-Options, CSP hints). |
| **Token-based Auth** | Bearer-token authentication with constant-time comparison for the admin dashboard. |
| **Rate Limiter** | In-memory sliding-window rate limiter to protect endpoints from brute-force. |
| **Input Validation** | Type-safe validators for strings, integers, enums, and hostnames — with a sanitiser for stripping dangerous characters. |

## Security design

- **Zero hardcoded secrets** — every credential is loaded from environment variables at startup; the app refuses to start if `AEGIS_ADMIN_TOKEN` is missing.
- **No debug endpoints** — the dashboard only exposes `/api/health`, `/api/config` (redacted), and `/api/check/sql`. All routes require Bearer authentication.
- **Strict CORS** — origins must be explicitly allowlisted; wildcards are never used.
- **Constant-time token comparison** — prevents timing-based brute-force of the admin token.
- **Egress-deny-by-default** — outbound HTTP/HTTPS to unlisted hosts is blocked.
- **No `eval`, no `new Function`** — ESLint rules enforced project-wide.

## Quick start

```bash
# Install dependencies
npm install

# Copy the example env and fill in real values
cp .env.example .env

# Run tests
npm test

# Build
npm run build

# Start the dashboard (requires AEGIS_ADMIN_TOKEN in env)
npm start
```

## Environment variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `AEGIS_ADMIN_TOKEN` | yes | — | Bearer token for dashboard auth |
| `AEGIS_LOG_LEVEL` | no | `info` | `debug` \| `info` \| `warn` \| `error` |
| `AEGIS_ALLOWED_EGRESS_HOSTS` | no | *(empty)* | Comma-separated hosts for egress allowlist |
| `AEGIS_CORS_ALLOWED_ORIGINS` | no | *(empty)* | Comma-separated origins for CORS |
| `AEGIS_ENABLE_SQLI_PROTECTION` | no | `true` | Enable/disable SQLi module |
| `AEGIS_ENABLE_RCE_PROTECTION` | no | `true` | Enable/disable RCE module |
| `AEGIS_ENABLE_EGRESS_FIREWALL` | no | `true` | Enable/disable egress firewall |

## Usage as a library

```ts
import { createEngine } from 'aegis-rasp-engine';

// All protection modules activate automatically based on env config
const engine = createEngine();

// Check a SQL query
const result = engine.checkSql("SELECT * FROM users WHERE id = 1 UNION SELECT password FROM admins");
if (result.isMalicious) {
  console.log('Blocked:', result.reasons);
}

// Shut down (restores monkey-patched modules)
engine.shutdown();
```

## Project structure

```
src/
  config.ts                  — env-driven configuration loader
  engine.ts                  — core orchestrator
  dashboard.ts               — authenticated admin HTTP server
  index.ts                   — public API surface
  interceptors/
    sqli-interceptor.ts      — AST-based SQL injection detection
    rce-interceptor.ts       — child_process monkey-patching
    egress-firewall.ts       — outbound request filtering
  middleware/
    auth.ts                  — Bearer token auth (constant-time)
    cors.ts                  — strict CORS with security headers
    rate-limiter.ts          — sliding-window rate limiter
  utils/
    input-validator.ts       — type-safe input validation
    logger.ts                — structured logging
tests/
  *.test.ts                  — Jest test suites (64 tests)
```

## License

MIT
