# authenticated-ports

Self-hosted web portal that opens and closes **firewall port forwards on
demand, only for an authenticated user**, by driving a UPnP IGD on the local
network. Mapping targets (host/port/protocol) are defined server-side; users
can only toggle them, never create arbitrary forwards.

**Status:** Phase 1 (UPnP probe + pluggable backend) complete. Phase 2 (web
app) will follow once the probe confirms the gateway behaves as expected.

---

## Architecture

```
                                 ┌────────────────────────────┐
  Browser ──HTTPS──▶  Flask web ─┤  session + audit log       │
                     app         │  mappings.json (allowlist) │
                                 │  credentials.json (argon2) │
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

The web layer never talks to UPnP directly — it goes through
`ForwardingBackend`, which keeps a firewall-based backend a drop-in
replacement.

---

## Phase 1 — UPnP probe

The probe answers the questions that decide whether / how the main app can
run on this network:

1. Does the gateway advertise UPnP IGD?
2. What's the WAN IP?
3. Can we add + list + delete a mapping pointing back at **this host** (TCP)?
4. Can we add + list + delete a mapping pointing at a **different internal
   host** (TCP)? — this is the miniupnpd *secure_mode* test.
5. Does UDP work?
6. Does the gateway honor the lease duration we asked for?

Every test mapping is tagged with description `authenticated-ports-probe`
and torn down at the end (plus a `--cleanup` mode that only removes
leftovers from an aborted run).

### Install

```bash
cd authenticated-ports
python3 -m venv .venv
. .venv/bin/activate
pip install miniupnpc pytest
# If pip can't build miniupnpc on your box, install the OS package:
#   Debian/Ubuntu:  sudo apt install miniupnpc
#   macOS (brew):   brew install miniupnpc
# The probe will fall back to the `upnpc` CLI automatically.
```

### Run against your gateway

From a host on the **same LAN** as your Dream Machine:

```bash
python3 probe/upnp_probe.py \
    --external-port 51820 \
    --internal-host 192.168.1.50 \
    --internal-port 51820 \
    --protocol tcp \
    --lease 120
```

Replace `--internal-host` with the LAN IP of **some other** box on your
network (it does not need any service listening — the probe only creates
and immediately removes the mapping). That's what reveals whether the UDM
is running miniupnpd in secure mode.

Useful flags:

| flag | purpose |
| --- | --- |
| `--external-port N` | base external port (also uses `N+1`, `N+2`) |
| `--internal-host IP` | LAN IP for the secure_mode check |
| `--internal-port N` | internal port used by all tests |
| `--lease SECS` | requested lease duration (default 120) |
| `--cleanup` | remove any leftover probe mappings and exit |
| `--prefer {auto,library,cli}` | force miniupnpc impl |
| `--json` | also emit a machine-readable summary |

Exit code is non-zero if discovery, external-IP, or the same-host TCP test
fails.

### Reading the output

The final `Interpretation` block tells you what the results mean for the
main app:

* **secure_mode detected** → you must either run the main app on the host
  you want to expose, or switch to a firewall backend later.
* **both same-host and different-host pass** → the web app can run on any
  LAN host and forward to any other internal host declared in
  `mappings.json`.
* **lease not honored** → forwards still work, but the device will time
  them out on its own schedule instead of the one you requested.

### Clean up only

If a run was interrupted:

```bash
python3 probe/upnp_probe.py --cleanup
```

---

## Phase 2 — web app (planned)

Once Phase 1 confirms the gateway behavior, this is what gets built on top
of the backend interface:

* **Auth** — local users in `credentials.json` (argon2id hashes), CLI
  helper `authenticated-ports useradd <name>`, bcrypt accepted as a
  fallback.
* **Port mappings** — admin-defined allowlist in `mappings.json`; users
  can only toggle entries that exist in the file.
* **Session lifecycle** — on activate, the backend creates the forward and
  the session takes ownership; on deactivate / logout / idle timeout /
  shutdown, every forward owned by that session is removed. A UPnP lease
  is always set as a backstop so a crashed server doesn't leak forwards
  forever. A small state file lets the app reconcile on restart.
* **Web UI** — login page, dashboard listing each allowed mapping with its
  current state and an activate/deactivate toggle, display of
  `externalIP:external_port → internal_host:internal_port (proto)` for
  active mappings, logout button.
* **Security** — HTTPS (cert/key in config, or run behind a reverse
  proxy), CSRF tokens on state-changing routes, `Secure` /
  `HttpOnly` / `SameSite=Strict` session cookies, login rate limit /
  lockout, audit log of logins, activations, deactivations, logouts.

### Config formats (preview)

`credentials.json` (gitignored):

```json
{
  "users": [
    { "username": "alice",
      "password_hash": "$argon2id$...",
      "role": "user" }
  ]
}
```

`mappings.json` — see [`mappings.example.json`](mappings.example.json).
Each entry carries `id`, `name`, `protocol` (`tcp` or `udp`),
`external_port`, `internal_host`, `internal_port`, `lease_seconds`, and
`description`.

---

## Known limitations

* **UPnP cannot restrict mappings by source IP.** Once a mapping is up,
  the port is reachable from the entire public internet until the lease
  expires or it is deleted. Mitigate by keeping leases short, using
  non-standard external ports, and hardening whatever listens on the
  internal host. The `FirewallBackend` slot exists specifically so a
  source-IP-scoping backend (nft / iptables / router API) can replace
  UPnP later.
* **miniupnpd secure mode** may restrict mappings to the requesting
  host only. Use the probe to confirm, and either run the app on the
  target host or switch to a firewall backend.
* **No multi-user coordination over the same port.** If two users both
  have mappings for the same external port in the config, activations
  are last-writer-wins at the gateway — avoid in your config.

---

## Layout

```
authenticated-ports/
├── README.md
├── LICENSE
├── .gitignore
├── pyproject.toml
├── requirements.txt
├── credentials.json.example
├── mappings.example.json
├── authenticated_ports/
│   ├── __init__.py
│   └── backends/
│       ├── __init__.py
│       ├── base.py          # ForwardingBackend, Mapping, exceptions
│       └── upnp.py          # UpnpBackend: library-preferred, CLI fallback
├── probe/
│   ├── __init__.py
│   └── upnp_probe.py        # standalone probe CLI
└── tests/
    ├── mock_backend.py      # in-memory ForwardingBackend
    ├── test_backend_mock.py # contract tests, no real gateway needed
    └── test_probe_shape.py
```

Run the mock tests:

```bash
pytest -q
```

The **live probe is a separate, manual step** (it requires a real UPnP
IGD on the LAN) and is run exactly as shown above.

---

## License

MIT. See [LICENSE](LICENSE).
