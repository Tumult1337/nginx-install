# nginx-gen

Generates and installs nginx config: per-vhost server blocks (proxy or static),
the global `nginx.conf`, OS-level tuning (sysctl + systemd `LimitNOFILE`), and
the nginx install itself — including building [ngx_brotli](https://github.com/google/ngx_brotli)
from source when the distro packages are ABI-incompatible.

Validates with `nginx -t` before reload and rolls back on validation failure.
Stdlib-only, single static binary.

## Quickstart

**One-shot fresh-host bootstrap** (Debian / Ubuntu, root required):

```bash
# Build locally
git clone https://github.com/tumult1337/nginx-install.git && cd nginx-install
make                              # → ./nginx-gen

# Ship to the server
scp nginx-gen root@server:/usr/local/bin/nginx-gen

# On the server (one command — installs nginx.org mainline, compiles brotli,
# renders managed nginx.conf, applies sysctl tuning):
ssh root@server '/usr/local/bin/nginx-gen --bootstrap --brotli=on'

# Then deploy vhosts:
nginx-gen --allow=cf --cert-dir=/etc/ssl/cf api.example.com 127.0.0.1:8080
nginx-gen --allow=cf --cert-dir=/etc/ssl/cf static.example.com /var/www/static
```

`--bootstrap` is idempotent — rerun any time to repair drift, re-render
nginx.conf, or pick up new template changes.

## Install the binary on a server

The tool is a single static Go binary; no runtime deps. Three install methods:

**1. Build locally and copy.**

```bash
make                                      # produces ./nginx-gen
scp nginx-gen root@server:/usr/local/bin/
ssh root@server chmod +x /usr/local/bin/nginx-gen
```

**2. Build on the server directly** (needs Go ≥ 1.22):

```bash
ssh root@server
apt-get install -y golang-go git
git clone https://github.com/tumult1337/nginx-install.git
cd nginx-install && sudo make install     # → /usr/local/bin/nginx-gen
```

**3. Use a release artifact** if the project publishes them
(see `.goreleaser.yaml`):

```bash
curl -fsSL https://github.com/tumult1337/nginx-install/releases/latest/download/nginx-gen_Linux_x86_64.tar.gz \
    | sudo tar -xz -C /usr/local/bin nginx-gen
sudo chmod +x /usr/local/bin/nginx-gen
```

All subsequent invocations need root (writes under `/etc/nginx`, locks `/run`,
reloads via systemd).

## Commands

```
# ---- lifecycle ----
nginx-gen --bootstrap     [--channel=mainline|stable] [--brotli=auto|on|off]
                          [--force] [--dry-run] [--no-reload]
    First-time host setup: --install + --sysctl in one shot.

nginx-gen --install       [--channel=mainline|stable] [--brotli=auto|on|off]
                          [--force] [--dry-run]
    Add nginx.org apt repo, install nginx, render managed nginx.conf,
    optionally build brotli. Skips --sysctl.

nginx-gen --upgrade       [--force] [--dry-run] [--no-reload]
    apt-upgrade the nginx package, auto-rebuild brotli if version drifted,
    re-render nginx.conf, restart. Idempotent: no-op when nothing changed.
    NOTE: this upgrades nginx, not the nginx-gen tool itself — see --self-update.

nginx-gen --convert       [--channel=mainline|stable] [--brotli=auto|on|off]
                          [--dry-run] [--no-reload]
    Best-effort migration of an existing nginx install (e.g. Debian's
    apt nginx) into nginx-gen's managed setup. Snapshots /etc/nginx + writes
    an executable rollback.sh BEFORE touching anything, then runs --install
    + --sysctl. On any failure, prints the rollback command prominently.

nginx-gen --abi-check
    Print nginx + brotli ABI sync status. Exit 0 if in sync, 1 on drift.
    Suitable for cron / monit / Nagios.

nginx-gen --self-update   [--force] [--dry-run]
    Replace this nginx-gen binary with the latest GitHub release
    (verified by sha256 against the release's checksums.txt). Downloads
    the raw binary for the current GOOS/GOARCH, atomically swaps it in
    over the currently-running executable's path. Does NOT touch nginx.

nginx-gen --version
    Print nginx-gen tool version and exit.

nginx-gen --brotli-build  [--force] [--dry-run]
    Compile ngx_brotli dynamic modules against the installed nginx and
    install to /etc/nginx/modules/. For nginx.org hosts where the Debian
    brotli packages are ABI-incompatible.

nginx-gen --sysctl        [--force] [--dry-run] [--no-reload]
    Network stack tuning + systemd LimitNOFILE override.

nginx-gen --main          [--brotli=auto|on|off] [--force] [--dry-run] [--no-reload]
    Render only /etc/nginx/nginx.conf.

# ---- per-vhost ----
nginx-gen [--ssl] [--proxy-ssl-verify] [--allow=cf|cidrs] [--cert-dir=...]
          [--hsts=off|on|subdomains|preload]
          [--force] [--dry-run] [--no-reload] <host> <target>
    target = [http://|https://]ip[:port]   → proxy mode
           = [http://|https://]host[:port] → proxy mode
           = /absolute/path/to/htmldir     → static mode (path must exist)

    A leading https:// makes nginx speak TLS to the backend
    (proxy_pass https://). Default port follows the scheme: 80 for
    http, 443 for https. With no scheme, the upstream is plain http.

nginx-gen --remove <host>
nginx-gen --list
nginx-gen --domains
    Print `domain -> backend` for every managed vhost (proxy → host:port,
    static → served root dir).
```

### Common flags

| Flag                | Default              | Notes |
|---                  |---                   |---    |
| `--ssl`             | `true`               | Adds 443 listener, HTTP→HTTPS redirect. Cert auto-resolved. |
| `--proxy-ssl-verify`| `false`              | Verify the backend cert (only for `https://` upstreams). Off = encrypt but don't authenticate; needed for IP/self-signed backends. |
| `--allow`           | unset                | `cf` → Cloudflare IPs. Or comma-separated CIDRs/IPs. |
| `--hsts`            | `off`                | `on` → this host only. `subdomains`, `preload` → see [HSTS](#--hsts) before using. Requires `--ssl`. |
| `--rate-limit`      | `off`                | Opt-in per-vhost rate limiting. Bare `--rate-limit` = `50r/s`, burst 100. `--rate-limit=rate:burst` (e.g. `50r/s:100`) sets both. Ignored with `--allow=cf`. See [Rate limiting](#rate-limiting). |
| `--cert-dir`        | `/etc/letsencrypt/live` | Cert lookup base. Also `$NGINX_CERT_DIR`. |
| `--brotli`          | `auto`               | `auto` = best-effort. `on` = require/build. `off` = skip entirely. |
| `--channel`         | `mainline`           | nginx.org repo channel (only for `--install` / `--bootstrap`). |
| `--dry-run`         | `false`              | Print plan to stdout, no FS changes. |
| `--no-reload`       | `false`              | Skip `nginx -t` and reload/restart. |
| `--force`           | `false`              | Overwrite unmanaged files / rebuild even if not needed. |

## Brotli

`--main` emits `brotli on; brotli_static on; brotli_types ...` alongside
`gzip` only when the dynamic module is loaded
(`/etc/nginx/modules-enabled/*brotli*.conf`).

There are three sources of the module:

1. **Debian's `libnginx-mod-http-brotli-{filter,static}` packages** — work
   only with Debian's nginx (`nginx-abi-1.26.3-1`). `--main --brotli=auto`
   tries `apt-get install` for these first.
2. **nginx.org's repo** does **not** ship a brotli package.
3. **Compile from source** via `--brotli-build`: downloads matching nginx
   sources from `nginx.org/download/`, clones `ngx_brotli`, builds the
   bundled brotli C library with cmake, compiles the modules
   `--with-compat`, installs `.so` files to `/etc/nginx/modules/`, and
   writes a `modules-enabled/50-mod-http-brotli.conf` tagged with the
   nginx version it was built against.

**`--brotli` flag values:**

| Value  | Behavior |
|---     |---       |
| `auto` | Use brotli if module already loaded; try `apt-get install` (Debian packages) once; fall through to no-brotli render if install fails. ABI mismatch is detected up-front via `apt-cache depends` + `dpkg-query` and skips the apt attempt entirely. |
| `on`   | Require brotli. In `--install`/`--bootstrap`: chains `--brotli-build` on hosts where apt won't satisfy the dep. In `--main`: errors if module can't be installed. |
| `off`  | Render without brotli. Don't touch apt. |

**ABI drift after nginx upgrade.** The compiled `.so` is pinned to the exact
nginx version it was built against (nginx checks at startup). After
`apt upgrade nginx`, `nginx -t` will error with *"module … not binary
compatible"* until brotli is rebuilt. Use `--upgrade` (handles both) or
`--brotli-build --force` (brotli only). `--abi-check` reports drift
without doing anything; exit 1 = needs rebuild.

## Custom snippets (`conf.d/`)

The rendered `nginx.conf` includes both:

```nginx
include /etc/nginx/conf.d/*.conf;        # operator-managed (nginx-gen never writes here)
include /etc/nginx/sites-enabled/*.conf; # nginx-gen-managed vhosts
```

Drop http-scope snippets (`map`, custom `log_format`, `geo`, additional
`upstream` blocks, etc.) into `/etc/nginx/conf.d/<sortable-name>.conf` and
they survive every `--main` / `--upgrade` re-render.

Example — language routing map:

```nginx
# /etc/nginx/conf.d/00-lang-maps.conf
map $http_accept_language $client_lang {
    default  en;
    "~*^de"  de;
    "~*^en"  en;
}
```

Then `nginx -s reload`. nginx-gen will not touch it.

## HTTP/2 version detection

`nginx-gen` runs `nginx -v` at write time and emits the correct directive:

- **nginx ≥ 1.25.1**: standalone `http2 on;`
- **nginx < 1.25.1**: inline `listen 443 ssl http2;`

`--dry-run` skips detection and defaults to the modern syntax.

## Wildcard certs (auto-detect)

`--ssl=true` resolves the cert dir by walking up the host's domain labels:
`a.b.example.com` → tries `<cert-dir>/a.b.example.com`, then `b.example.com`,
then `example.com`. First directory containing `fullchain.pem` wins.

Default base is `/etc/letsencrypt/live` (override via `--cert-dir` or
`$NGINX_CERT_DIR`). For Cloudflare Origin certs: `--cert-dir=/etc/ssl/cf`.

## `--hsts`

Off by default. HSTS is the one header here whose blast radius outlives the
config that produced it: browsers cache the directive for its full `max-age`
and enforce it against a store you cannot reach. Deleting the vhost, reverting
the commit, or reinstalling the server does not retract it.

| Value        | Emitted header                                            |
|---           |---                                                        |
| `off`        | *(nothing)*                                               |
| `on`         | `max-age=63072000`                                        |
| `subdomains` | `max-age=63072000; includeSubDomains`                     |
| `preload`    | `max-age=63072000; includeSubDomains; preload`            |

`max-age` is fixed at two years, which satisfies the preload list's one-year
minimum. There is no flag to tune it.

**`subdomains` asserts policy over hosts this vhost knows nothing about.**
Setting it on `app.example.com` tells browsers that *every* name under
`example.com` must be HTTPS — including siblings that serve plain HTTP, an
internal tool on port 80, or a subdomain that does not exist yet. Those break
for anyone who visited `app.example.com` first, and stay broken for up to two
years. Use it only when you control every current and future subdomain and all
of them serve TLS.

**`preload` is effectively permanent.** The token alone does nothing; you must
submit the domain at <https://hstspreload.org> separately. Once accepted, the
rule ships hardcoded inside browser binaries, so removal requires a delisting
request plus a full browser release cycle — months, and older installs never
update. Do not use it on a domain you might repurpose.

### Behind Cloudflare

Cloudflare terminates TLS at the edge, so the browser sees CF's response, not
the origin's — but CF passes the origin's HSTS header through by default, so
`--hsts` here still reaches real browsers. Pick one owner for the header:
either set it at CF (SSL/TLS → Edge Certificates → HSTS) and leave `--hsts=off`
here, or manage it here and leave CF's setting disabled. Two sources means the
one you forget about is the one that bites.

### Undoing a mistake

`--hsts=off` stops *sending* the header; it does not retract what browsers
already cached. Genuinely unwinding a bad policy means serving `max-age=0` over
HTTPS from the affected host until clients revisit, which this tool does not
generate — hand-edit the vhost for that. Prevention is much cheaper than the
cure, which is why `subdomains` and `preload` are opt-in.

## Rate limiting

Rate limiting is **opt-in per vhost** via `--rate-limit`. Without the flag a
vhost carries no `limit_req`/`limit_conn` directives.

| Form | Result |
|---|---|
| (flag absent) | Off. No rate-limit directives. |
| `--rate-limit` | On with defaults: `50r/s`, burst 100, 100 connections per IP. |
| `--rate-limit=rate:burst` | On with the given rate and burst, e.g. `--rate-limit=50r/s:100`. |
| `--rate-limit=rate` | On with the given rate and the default burst. |

`rate` is an nginx rate token: `<n>r/s` or `<n>r/m`. The value is validated and
rebuilt before it is written, so a malformed or injected value is rejected
rather than emitted. The connection cap stays at 100 per IP and is not
configurable through this flag.

Each opted-in vhost gets its own `limit_req_zone` and `limit_conn_zone`, keyed
on `$binary_remote_addr`. The zone name is the host with a short hash appended
(the hash keeps two hosts that differ only by `.` vs `-` from colliding on one
zone name, which nginx would reject). Each zone is sized `10m` (about 160k
client IPs per zone). The zones live in the vhost file itself, at `http` scope.

`--rate-limit` is ignored with `--allow=cf` (see [`--allow=cf`](#--allowcf)):
the key would be the Cloudflare edge IP, so the limit would throttle every
client behind one edge together.

### Upgrading from a build that rate-limited by default

Earlier builds defined shared `perip`/`reqip` zones in `nginx.conf` and applied
them to every non-CF vhost. This build removes the shared zones and makes rate
limiting opt-in. A vhost file written by an older build still references
`reqip`/`perip`, so **re-render each vhost before you re-render `nginx.conf`**
(`nginx-gen --main`). The tool runs `nginx -t` before every reload, so a stale
reference fails closed — the reload is refused and the running config keeps
serving — but the update is blocked until the vhost is re-rendered.
`nginx-gen --list` shows `ratelimit=?` for a vhost that predates the flag.

## `--allow=cf`

Fetches Cloudflare IP ranges from `cloudflare.com/ips-{v4,v6}` and writes
`/etc/nginx/snippets/cf-allow.conf` (refreshed once per 24 h). On fetch
failure, falls back to `/var/lib/nginx-gen/cf-allow.conf` (last good copy)
if < 7 days old.

CF vhosts restrict ingress to Cloudflare edge IPs via `allow`/`deny`. Rate
limiting is never applied to a CF vhost, even with `--rate-limit`: the key would
be the Cloudflare edge IP, so nginx would 503 legitimate traffic once one edge
crossed the limit. Rate-limit at the edge instead.

### Why no `set_real_ip_from`

The snippet contains only `allow`/`deny`. nginx's `realip` module runs in
`POST_READ`, *before* the `ACCESS` phase. If `set_real_ip_from` were
configured, `$remote_addr` would already be the end-user's IP by the time
`allow` runs — the CF-prefix allow list would never match, so all CF traffic
would be 403'd. Read `$http_cf_connecting_ip` directly in your upstream app
if you need the real client IP.

## `--sysctl`

Writes OS-level tuning needed to actually achieve nginx's configured limits:

- `/etc/sysctl.d/99-nginx.conf` — `somaxconn=65535`, BBR, `tcp_tw_reuse`,
  buffer autotuning, `fs.file-max=2097152`, etc.
- `/etc/systemd/system/nginx.service.d/override.conf` — `LimitNOFILE=1048576`
  matching `worker_rlimit_nofile`.

Applies via `sysctl --system`, `systemctl daemon-reload`,
`systemctl restart nginx` (restart required for `LimitNOFILE`; reload is not
enough). `modprobe tcp_bbr` if not already loaded.

## Maintenance

**Check ABI drift weekly via cron:**

```cron
# /etc/cron.d/nginx-gen-check
0 6 * * 1 root /usr/local/bin/nginx-gen --abi-check > /var/log/nginx-gen-check.log 2>&1 || \
  mail -s "nginx-gen drift" root < /var/log/nginx-gen-check.log
```

**Patch nginx (CVE response):**

```bash
sudo nginx-gen --upgrade
```

That's it. Apt-upgrades nginx, rebuilds brotli if version drifted, re-renders,
runs `nginx -t`, restarts.

**Update the nginx-gen tool itself:**

```bash
sudo nginx-gen --self-update
```

Downloads the latest release binary from GitHub, verifies its sha256, and
atomically replaces the running executable. Does not touch nginx.

**Prune old backups:**

```bash
find /var/backups/nginx-gen -mtime +30 -delete
```

## Migrating a host already running nginx (Debian apt or other)

```bash
nginx-gen --convert --brotli=on        # one command, safe by construction
```

What this does:

1. **Snapshots** `/etc/nginx` (full `cp -a`) plus current `nginx -T` output
   and the installed nginx package version to
   `/var/backups/nginx-gen/convert/<timestamp>/`.
2. **Writes an executable `rollback.sh`** next to the snapshot. Runs `cp -a`
   the snapshot back, removes nginx.org's apt source + pin, and reinstalls
   the previously-pinned nginx via apt (using `--allow-downgrades` since
   nginx.org's version is typically newer).
3. **Inventories** which files in `sites-enabled/`, `conf.d/`, `snippets/`
   are operator-owned (no nginx-gen marker) so you know what was preserved
   untouched vs. what was overwritten.
4. **Runs `--install`** (adds nginx.org repo, apt-upgrades nginx to upstream,
   renders managed `nginx.conf` with `--force`, builds brotli if `--brotli=on`)
   then **`--sysctl`**.
5. **Final `nginx -t` + restart** before declaring success.

If any step fails, the rollback command is printed prominently. You can also
just stop the world and run the rollback script:

```bash
sudo bash /var/backups/nginx-gen/convert/<ts>/rollback.sh
```

**What's preserved automatically:**
- All vhost files in `sites-available/` and `sites-enabled/` (untouched —
  they keep working as-is). You can optionally re-render them later with
  `nginx-gen <host> <target>` to put the managed marker on them.
- Everything in `conf.d/` (the new template includes this dir).
- Everything in `snippets/`.
- Cert dirs under `/etc/letsencrypt`, `/etc/ssl/cf`, etc.

**What's NOT preserved automatically:**
- Custom http-scope directives (`map`, `geo`, `log_format`, `upstream`) that
  were inside your hand-written `nginx.conf` — the managed template replaces
  the file entirely. After conversion, `less` the snapshotted
  `<backup>/etc-nginx/nginx.conf` and move anything you need into
  `/etc/nginx/conf.d/00-custom.conf` (auto-loaded, survives `--main`).

**Preview before committing** — `--dry-run` prints the full plan without
touching anything:

```bash
sudo nginx-gen --convert --brotli=on --dry-run
```

## Examples

```bash
# Lifecycle
sudo nginx-gen --bootstrap --brotli=on              # fresh host
sudo nginx-gen --upgrade                       # patch nginx + rebuild brotli
sudo nginx-gen --self-update                         # patch the nginx-gen tool
sudo nginx-gen --abi-check                           # cron-friendly status

# Per-vhost (proxy)
sudo nginx-gen api.example.com 10.0.0.5:8080
sudo nginx-gen --allow=cf --cert-dir=/etc/ssl/cf api.tumult.dev 127.0.0.1:8080
sudo nginx-gen manager.skybyte.cloud https://5.231.234.5:8443             # TLS to backend (unverified)
sudo nginx-gen --proxy-ssl-verify app.example.com https://backend.internal:8443  # + verify backend cert

# Per-vhost (static)
sudo nginx-gen blog.example.com /var/www/blog
sudo nginx-gen --ssl=false health.example.com 127.0.0.1:9090

# Custom CIDRs
sudo nginx-gen --allow=10.0.0.0/8,192.168.1.0/24 internal.example.com 10.0.0.7

# HSTS (off by default — read the --hsts section before using subdomains/preload)
sudo nginx-gen --hsts=on app.example.com 10.0.0.5:8080          # this host only
sudo nginx-gen --hsts=subdomains example.com /var/www/site      # all subdomains must be TLS

# Management
sudo nginx-gen --list
sudo nginx-gen --remove old.example.com
```

## Filesystem layout

| Path                                                | Purpose |
|---                                                  |---      |
| `/etc/nginx/nginx.conf`                             | Global config (`--main`) |
| `/etc/nginx/sites-available/<host>.conf`            | Per-vhost config file |
| `/etc/nginx/sites-enabled/<host>.conf`              | Symlink → sites-available |
| `/etc/nginx/conf.d/*.conf`                          | Operator-managed snippets (untouched) |
| `/etc/nginx/modules/*.so`                           | Compiled dynamic modules (`--brotli-build`) |
| `/etc/nginx/modules-enabled/50-mod-http-brotli.conf`| `load_module` directives, version-tagged |
| `/etc/nginx/snippets/cf-allow.conf`                 | Cloudflare allow-list (24 h refresh) |
| `/var/lib/nginx-gen/cf-allow.conf`                  | Last-good CF cache for offline fallback |
| `/var/backups/nginx-gen/`                           | Timestamped backups before any overwrite |
| `/run/nginx-gen.lock`                               | flock — serializes concurrent invocations |
| `/etc/sysctl.d/99-nginx.conf`                       | Network stack tuning (`--sysctl`) |
| `/etc/systemd/system/nginx.service.d/override.conf` | `LimitNOFILE=1048576` (`--sysctl`) |
| `/usr/share/keyrings/nginx-archive-keyring.gpg`     | nginx.org signing key (`--install`) |
| `/etc/apt/sources.list.d/nginx.list`                | nginx.org apt source (`--install`) |
| `/etc/apt/preferences.d/99nginx`                    | Pin priority 900 (`--install`) |

Override via environment variables:

```
NGINX_SITES_AVAILABLE       NGINX_SITES_ENABLED        NGINX_CONF_PATH
NGINX_BACKUP_DIR            NGINX_LOCK_PATH            NGINX_CF_SNIPPET
NGINX_CF_CACHE              NGINX_CERT_DIR             NGINX_SYSCTL_PATH
NGINX_SYSTEMD_OVERRIDE_DIR  NGINX_MODULES_DIR          NGINX_MODULES_ENABLED_DIR
```

## Managed-by marker

Every file the tool writes starts with:

```
# Managed by nginx-gen. Do not edit by hand.
# kind=vhost host=... mode=... ssl=... allow=... hsts=... ts=...
```

Files without the marker are treated as user-managed; the tool refuses to
overwrite or remove them unless you pass `--force`.

Sysctl, systemd override, and brotli load-module files use a simpler
`# Managed by nginx-gen` prefix for the same guard.

## Rollback semantics

For every write:

1. Take an exclusive flock on `/run/nginx-gen.lock`.
2. Back up the current file (if any) to `/var/backups/nginx-gen/`.
3. Atomic-write the new contents (tmp + fsync + rename).
4. Run `nginx -t`. **On failure: restore the backup (or remove if first deploy)
   and unlink any new symlink.** Exit 3.
5. Run `systemctl reload nginx` (or `restart` after `--sysctl`/`--upgrade`).
   **Reload/restart failures do NOT roll back** — the config is valid;
   runtime failure is a separate concern.

`--bootstrap`/`--install`/`--upgrade` add a final `nginx -t` before
`systemctl restart`, so a broken assembled state surfaces as exit 3 with
the old nginx still running, not as a failed restart with nginx down.

## Exit codes

| Code | Meaning |
|---   |---      |
| 0    | OK |
| 1    | User error (bad input, refused, `--abi-check` drift) |
| 2    | System error (FS, exec, network) |
| 3    | `nginx -t` failed; rolled back |

## Migration from the legacy tool

If you previously deployed vhosts that include `/etc/nginx/conf.d/cf.conf`
(very old) or `/etc/nginx/cf.conf` (interim), the first time `nginx-gen` runs
a write op it neutralizes those files in place — replacing them with a
`# MIGRATED-PLACEHOLDER` stub so old `include` lines still resolve at
`nginx -t`. Affected vhosts lose their CF allow-list until you re-deploy them
with `--allow=cf`. The tool prints the affected paths to stderr.
