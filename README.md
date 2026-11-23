# authenticated-ports

Self-hosted web portal that opens and closes **firewall port forwards on
demand, only for an authenticated user**, by driving a UPnP IGD on the
local network. Users toggle entries from a server-defined allowlist; the
web client can't name arbitrary internal hosts.

**Status:** Phase 1 (UPnP probe) + Phase 2 (Flask web app, docker-compose)
complete.

Verified against a Ubiquiti Dream Machine (MiniUPnPd/2.3.8): discovery,
external IP, same-host TCP, different-host TCP (no secure_mode), UDP, and
lease-honoring all PASS.

---

## Architecture

```
                                 ┌────────────────────────────┐
  Browser ──HTTPS──▶  Flask app ─┤  server-side SessionStore  │
   (mobile-first                 │  MappingManager (owns map  │
    Tailwind)                    │   -per-session, persists)  │
                                 │  AuthService (argon2id,    │
                                 │   lockout, credentials.json│
                                 │  AuditLog (JSONL)          │
                                 └──────────────┬─────────────┘
                                                │
                                ForwardingBackend interface
                                                │
                            ┌───────────────────┴────────────────────┐
                            │                                        │
                       UpnpBackend                         (future) FirewallBackend
                     (miniupnpc lib or                      nft / iptables / router API,
                      `upnpc` CLI)                          can scope by source IP
                            │
                            ▼
                     UPnP IGD on LAN
                 (UDM / miniupnpd / etc.)
```

Lifecycle contract:

- login → server-side session created, random id in `Secure; HttpOnly;
  SameSite=Strict` cookie.
- activate → `backend.add_mapping`; the record is tagged
  `authenticated-ports:<sid8>:<mapping_id>` and owned by the session.
- deactivate / logout / idle timeout / server shutdown / signal →
  **every mapping owned by that session gets `remove_mapping`'d**.
- startup → read `state/active_mappings.json`, delete each record from the
  gateway, clear the file. (This is the crash-recovery path. A UPnP lease
  is always set as a backstop so a double crash still auto-expires.)

---

## Quick start

### Option A — Docker Compose (recommended)

```bash
git clone https://github.com/jgruber/authenticated-ports.git
cd authenticated-ports
mkdir -p data/state data/certs
cp mappings.example.json      data/mappings.json      # edit for your LAN
cp config.example.json        data/config.json
# TLS: either drop server.crt / server.key into data/certs/,
# or unset AP_TLS_CERT / AP_TLS_KEY in docker-compose.yml and
# run behind a reverse proxy that terminates HTTPS.

# Create a user (writes data/credentials.json):
docker compose run --rm authenticated-ports useradd alice

docker compose up -d
docker compose logs -f
```

Open `https://<LAN-host>:8443/`.

> **Why `network_mode: host` in compose:** UPnP IGD discovery is SSDP
> multicast on `239.255.255.250:1900`. Docker's default bridge network
> doesn't pass multicast through to the LAN, so a bridge-networked
> container never finds the gateway. Host networking is the simple fix.
> Side effect: the `ports:` block is ignored — the app binds on every
> host interface at `AP_LISTEN_PORT`. Pin `AP_LISTEN_HOST` to a specific
> LAN interface if you want to narrow that.

### Option B — Direct install

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[web,upnp]"

cp mappings.example.json ./mappings.json
cp config.example.json   ./config.json   # edit paths
authenticated-ports useradd alice
authenticated-ports serve \
    --config ./config.json \
    --cert certs/server.crt --key certs/server.key
```

### TLS

The app serves HTTPS directly when you give it a cert and key
(`--cert`/`--key`, or `AP_TLS_CERT`/`AP_TLS_KEY`, or the `tls_cert` /
`tls_key` fields in `config.json`). Without them, you'll see a startup
warning and the app serves plain HTTP — fine only behind a reverse proxy
that terminates HTTPS. In that case set `behind_proxy: true` (or
`AP_BEHIND_PROXY=1`) so audit logs record the real client IP.

---

## Config files

### `mappings.json` (checked-in example in `mappings.example.json`)

```json
{
  "mappings": [
    {
      "id": "home-rdp",
      "name": "Home desktop RDP",
      "protocol": "tcp",
      "external_port": 53389,
      "internal_host": "192.168.1.50",
      "internal_port": 3389,
      "lease_seconds": 3600,
      "description": "RDP to home desktop"
    }
  ]
}
```

- `id` is alphanumeric with `-`/`_`, 1..64 chars, unique in the file.
- `protocol` is `tcp` or `udp`.
- Ports are validated 1..65535.
- `(external_port, protocol)` must be unique across all entries.
- `lease_seconds` is clamped to 30..86400 (default 3600).

### `credentials.json` (gitignored; managed by `useradd`)

Written automatically by `authenticated-ports useradd <user>`:

```json
{
  "users": [
    { "username": "alice",
      "password_hash": "$argon2id$v=19$m=65536,t=3,p=4$...",
      "role": "user" }
  ]
}
```

- Argon2id is used for new hashes.
- Existing bcrypt (`$2b$...`) hashes verify if the `bcrypt` package is
  installed.
- The file is written atomically at mode 0600.

### `config.json` (optional; `config.example.json` is a template)

All keys are optional and have sensible defaults. Common env-var
overrides: `AP_LISTEN_HOST`, `AP_LISTEN_PORT`, `AP_CREDENTIALS`,
`AP_MAPPINGS`, `AP_TLS_CERT`, `AP_TLS_KEY`, `AP_BEHIND_PROXY`,
`AP_LOG_LEVEL`.

---

## CLI

```
authenticated-ports useradd <username> [--role {user,admin}]
                          [--credentials PATH] [--password-stdin]
authenticated-ports deluser <username> [--credentials PATH]
authenticated-ports serve   [--config PATH] [--credentials PATH]
                          [--mappings PATH] [--host IP] [--port N]
                          [--cert PATH --key PATH] [--behind-proxy]
                          [--backend-prefer {auto,library,cli}]
```

---

## Security model (implemented, not just documented)

- **Password hashing:** Argon2id via `argon2-cffi`. The `useradd` CLI
  enforces `len(password) >= 8`.
- **Lockout:** per-user failed-login counter; after
  `lockout_threshold` failures inside `lockout_window_seconds`, the
  account is locked until the window elapses. Correct logins clear the
  count. (In-process state — fine for a single-worker deployment.)
- **Sessions:** fully server-side. The cookie carries only a random
  32-byte id. Flags: `HttpOnly; Secure; SameSite=Strict`.
- **CSRF:** every state-changing request requires a per-session token;
  login POST has a separate one-shot cookie-bound token. Checked with
  `hmac.compare_digest`.
- **Allowlist enforcement:** the web client sends `mapping_id`; the
  server resolves it against `mappings.json`. There is no way for a
  logged-in user to specify an arbitrary `internal_host:port`.
- **Audit log:** JSONL at `state/audit.log`. Events logged:
  `startup`, `shutdown`, `login_success`, `login_failure`,
  `logout`, `mapping_activate`, `mapping_deactivate`,
  `mapping_activate_failed`, `mapping_deactivate_failed`,
  `reconcile_removed`, `session_expired`. User + short session id,
  remote address, and event-specific fields are recorded. **Passwords
  and session cookies are never logged.**
- **Startup reconciliation + lease backstop:** `state/active_mappings.json`
  is an atomic file; on boot, the manager deletes every record it finds
  from the gateway. Every live mapping also carries a UPnP lease so that
  a crashed-out-twice server still auto-expires.
- **Idle session reaper:** background thread sweeps `SessionStore` on a
  cadence of `idle_timeout_seconds / 4` and triggers the same cleanup
  path as logout.

### Threat model note on UPnP

UPnP does not let you restrict a mapping by source IP. From the moment
you activate a mapping until the lease expires or you deactivate it,
the chosen external port is reachable from the **entire public
internet**. Mitigate with:

- **Short leases + short sessions** (defaults: 30 min idle, mapping
  lease per entry; your `mappings.json` can set shorter).
- **Non-standard external ports.**
- **Hardening on the target host** (strong auth, fail2ban, NLA for RDP,
  key-only SSH, etc.).
- When your threat model doesn't tolerate that, implement a
  `FirewallBackend` (nft / iptables / router API) with the same
  interface — the web layer never touches UPnP directly.

### miniupnpd secure mode

Some firmware ships `miniupnpd` in secure mode, which refuses mappings
to anywhere but the requesting host. The probe (`probe/upnp_probe.py`,
Phase 1) tests for this explicitly. On a secure-mode gateway, run
authenticated-ports on the box you want to expose, or switch to a
firewall backend.

---

## Phase 1 — UPnP probe

Still runnable standalone:

```bash
python3 probe/upnp_probe.py \
    --external-port 61820 \
    --internal-host 192.168.0.100 \
    --internal-port 51820 \
    --protocol tcp --lease 120
```

Flags and interpretation documented inline in `probe/upnp_probe.py` and
in the original Phase 1 output. Use `--cleanup` to remove any mappings
tagged `authenticated-ports-probe` from an interrupted run.

---

## Tests

```bash
pytest -q
```

The suite (currently 44 tests) covers:

- `test_backend_mock.py` — ForwardingBackend contract against MockIGD
  (including secure_mode behavior).
- `test_probe_shape.py` — probe CLI surface + lease-honor judgment.
- `test_auth.py` — argon2id hashing round-trip, unknown-user, lockout,
  clear-on-success, whitespace/empty rejection, unsupported-hash error.
- `test_config.py` — mapping / app config validation, duplicates,
  out-of-range values, missing fields, unknown keys.
- `test_session_lifecycle.py` — activate, deactivate, double-activate,
  cross-session ownership, logout-closes-all, shutdown-closes-all,
  state-file reconcile across restart, idle sweep, backend-failure
  surfaces.
- `test_web_flow.py` — Flask test client: login/redirect, bad password,
  lockout via HTTP, activate-deactivate roundtrip, unknown mapping id,
  CSRF-required, logout-closes-all, auth-required redirect,
  `/healthz`.

The live UPnP probe (Phase 1) is a separate manual step — run it as
shown above.

---

## Layout

```
authenticated-ports/
├── README.md
├── LICENSE
├── .gitignore .dockerignore
├── pyproject.toml requirements.txt
├── Dockerfile docker-compose.yml
├── credentials.json.example
├── mappings.example.json
├── config.example.json
├── authenticated_ports/
│   ├── __init__.py app.py audit.py auth.py cli.py
│   ├── config.py manager.py session.py state.py
│   ├── backends/   base.py upnp.py
│   └── templates/  base.html login.html dashboard.html
├── probe/           upnp_probe.py
└── tests/           mock_backend.py test_*.py
```

---

## Known limitations

- UPnP cannot restrict mappings by source IP (see Security model above).
- miniupnpd secure mode may restrict mappings to the requesting host
  only (use the Phase 1 probe to detect; UDM at `192.168.0.1` in testing
  was permissive).
- Single-process server. The in-memory session + lockout state is lost
  on restart (open mappings are not lost — they're reconciled). If you
  need multi-worker, you'd need to externalize that state.
- Tailwind is loaded from the public CDN (`https://cdn.tailwindcss.com`)
  to keep the app zero-build. Browsers on the LAN need internet access
  to that CDN to render styled correctly. Swap for a bundled build if
  that's unacceptable in your environment.

---

## License

MIT. See [LICENSE](LICENSE).
