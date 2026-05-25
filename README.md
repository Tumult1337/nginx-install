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
    apt-upgrade nginx, auto-rebuild brotli if version drifted, re-render
    nginx.conf, restart. Idempotent: no-op when nothing changed.

nginx-gen --version-check
    Print nginx + brotli ABI sync status. Exit 0 if in sync, 1 on drift.
    Suitable for cron / monit / Nagios.

nginx-gen --brotli-build  [--force] [--dry-run]
    Compile ngx_brotli dynamic modules against the installed nginx and
    install to /etc/nginx/modules/. For nginx.org hosts where the Debian
    brotli packages are ABI-incompatible.

nginx-gen --sysctl        [--force] [--dry-run] [--no-reload]
    Network stack tuning + systemd LimitNOFILE override.

nginx-gen --main          [--brotli=auto|on|off] [--force] [--dry-run] [--no-reload]
    Render only /etc/nginx/nginx.conf.

# ---- per-vhost ----
nginx-gen [--ssl] [--allow=cf|cidrs] [--cert-dir=...] [--force]
          [--dry-run] [--no-reload] <host> <target>
    target = ip[:port] | host[:port]   → proxy mode
           = /absolute/path/to/htmldir → static mode (path must exist)

nginx-gen --remove <host>
nginx-gen --list
```

### Common flags

| Flag                | Default              | Notes |
|---                  |---                   |---    |
| `--ssl`             | `true`               | Adds 443 listener, HSTS, HTTP→HTTPS redirect. Cert auto-resolved. |
| `--allow`           | unset                | `cf` → Cloudflare IPs. Or comma-separated CIDRs/IPs. |
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
`--brotli-build --force` (brotli only). `--version-check` reports drift
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

## `--allow=cf`

Fetches Cloudflare IP ranges from `cloudflare.com/ips-{v4,v6}` and writes
`/etc/nginx/snippets/cf-allow.conf` (refreshed once per 24 h). On fetch
failure, falls back to `/var/lib/nginx-gen/cf-allow.conf` (last good copy)
if < 7 days old.

CF vhosts restrict ingress to Cloudflare edge IPs via `allow`/`deny`. Rate
limiting is intentionally **not** applied — CF handles that at the edge, and
nginx rate limits keyed on CF edge IPs would 503 legitimate traffic.

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
0 6 * * 1 root /usr/local/bin/nginx-gen --version-check > /var/log/nginx-gen-check.log 2>&1 || \
  mail -s "nginx-gen drift" root < /var/log/nginx-gen-check.log
```

**Patch nginx (CVE response):**

```bash
nginx-gen --upgrade
```

That's it. Apt-upgrades nginx, rebuilds brotli if version drifted, re-renders,
runs `nginx -t`, restarts.

**Prune old backups:**

```bash
find /var/backups/nginx-gen -mtime +30 -delete
```

## Examples

```bash
# Lifecycle
sudo nginx-gen --bootstrap --brotli=on              # fresh host
sudo nginx-gen --upgrade                             # patch nginx + rebuild brotli
sudo nginx-gen --version-check                       # cron-friendly status

# Per-vhost (proxy)
sudo nginx-gen api.example.com 10.0.0.5:8080
sudo nginx-gen --allow=cf --cert-dir=/etc/ssl/cf api.tumult.dev 127.0.0.1:8080

# Per-vhost (static)
sudo nginx-gen blog.example.com /var/www/blog
sudo nginx-gen --ssl=false health.example.com 127.0.0.1:9090

# Custom CIDRs
sudo nginx-gen --allow=10.0.0.0/8,192.168.1.0/24 internal.example.com 10.0.0.7

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
# kind=vhost host=... mode=... ssl=... allow=... ts=...
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
| 1    | User error (bad input, refused, `--version-check` drift) |
| 2    | System error (FS, exec, network) |
| 3    | `nginx -t` failed; rolled back |

## Migration from the legacy tool

If you previously deployed vhosts that include `/etc/nginx/conf.d/cf.conf`
(very old) or `/etc/nginx/cf.conf` (interim), the first time `nginx-gen` runs
a write op it neutralizes those files in place — replacing them with a
`# MIGRATED-PLACEHOLDER` stub so old `include` lines still resolve at
`nginx -t`. Affected vhosts lose their CF allow-list until you re-deploy them
with `--allow=cf`. The tool prints the affected paths to stderr.
