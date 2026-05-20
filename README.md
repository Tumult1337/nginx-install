# nginx-gen

Generates and installs nginx config: per-vhost server blocks (proxy or static),
the global `nginx.conf`, and OS-level tuning (sysctl + systemd `LimitNOFILE`).
Validates with `nginx -t` before reload and rolls back on validation failure.
Stdlib-only, single static binary.

## Build

```
make
sudo make install        # /usr/local/bin/nginx-gen
```

Run as root (writes under `/etc/nginx`, locks `/run`, reloads via systemd).

## Usage

```
# Proxy vhost (target = ip[:port] or host[:port])
nginx-gen [--ssl] [--allow=cf|cidrs] [--force] [--dry-run] [--no-reload] <host> <ip[:port]>

# Static vhost (target = absolute path; must already exist)
nginx-gen [--ssl] [--allow=cf|cidrs] [--force] [--dry-run] [--no-reload] <host> </path/to/htmldir>

# Global nginx.conf
nginx-gen --main [--force] [--dry-run] [--no-reload]

# OS-level tuning: sysctl + systemd LimitNOFILE override
nginx-gen --sysctl [--force] [--dry-run] [--no-reload]

# Remove a managed vhost (symlink only; sites-available file kept for audit)
nginx-gen --remove <host>

# List managed vhosts
nginx-gen --list
```

### Flags

| Flag          | Default | Notes |
|---            |---      |---    |
| `--ssl`       | `true`  | Adds 443 listener, HSTS, HTTP→HTTPS redirect. Cert is auto-resolved (see below). |
| `--allow`     | unset   | `cf` → restrict to Cloudflare IP ranges. Or comma-separated CIDRs / bare IPs. |
| `--dry-run`   | `false` | Render to stdout, no FS changes. |
| `--no-reload` | `false` | Skip `nginx -t` and reload/restart. |
| `--force`     | `false` | Overwrite files lacking the managed marker. |
| `--cert-dir`  | `/etc/letsencrypt/live` | Override cert lookup base (e.g. `--cert-dir=/etc/ssl/cf` for Cloudflare Origin certs). Also `$NGINX_CERT_DIR`. |

### HTTP/2 version detection

`nginx-gen` runs `nginx -v` at write time to detect the installed version and
emits the correct HTTP/2 directive automatically:

- **nginx ≥ 1.25.1**: `http2 on;` as a standalone block directive (new syntax)
- **nginx < 1.25.1**: `listen 443 ssl http2;` inline parameter (old syntax)

`--dry-run` skips detection and defaults to the modern syntax.

### Wildcard certs (auto-detect)

`--ssl=true` resolves the cert dir by walking up the host's domain labels:

- `a.b.example.com` → tries `<cert-dir>/a.b.example.com`, then `b.example.com`, then `example.com`.
- First directory containing `fullchain.pem` wins.

Default cert base is `/etc/letsencrypt/live` (override via `NGINX_CERT_DIR`).
A wildcard cert at `/etc/letsencrypt/live/example.com/` automatically covers
all subdomains; no extra flag needed.

### `--allow=cf`

Fetches Cloudflare IP ranges from `cloudflare.com/ips-{v4,v6}` and writes
`/etc/nginx/snippets/cf-allow.conf`. Refreshed automatically once per 24h.
On fetch failure, falls back to `/var/lib/nginx-gen/cf-allow.conf` (last good
copy) if it's < 7 days old.

CF vhosts restrict ingress to Cloudflare edge IPs via `allow`/`deny`. Rate
limiting is intentionally **not** applied to CF vhosts — Cloudflare handles
rate limiting at the CDN edge, and applying nginx rate limits keyed on CF edge
IPs would 503 legitimate traffic.

#### CF and real IP — why no `set_real_ip_from`

The snippet contains only `allow`/`deny` — not `set_real_ip_from`. nginx's
`realip` module runs in `POST_READ` phase, *before* the `ACCESS` phase that
evaluates `allow`/`deny`. If `set_real_ip_from` were configured, `$remote_addr`
would already be the end-user's IP by the time `allow` runs — the CF-prefix
allow list would never match, so all CF traffic would be 403'd. Keeping
`realip` out of the snippet means `$remote_addr` stays as the actual TCP peer
(Cloudflare), which is what the allow check needs.

To log or forward the real end-user IP, read `$http_cf_connecting_ip` directly
in your upstream app or via a custom `proxy_set_header`.

### `--sysctl`

Writes OS-level tuning needed to actually achieve nginx's configured limits:

- `/etc/sysctl.d/99-nginx.conf` — network stack tuning: `somaxconn=65535`,
  BBR congestion control, `tcp_tw_reuse`, buffer autotuning, `fs.file-max=2097152`
- `/etc/systemd/system/nginx.service.d/override.conf` — `LimitNOFILE=1048576`,
  matching `worker_rlimit_nofile` in `nginx.conf`

Then runs `sysctl --system`, `systemctl daemon-reload`, and
`systemctl restart nginx` (restart is required to pick up the new `LimitNOFILE`;
a reload is not enough).

BBR is loaded via `modprobe tcp_bbr` if not already available; a warning is
printed if it can't be loaded (the rest of the tuning still applies).

Both files are backed up before overwriting. Existing files without the
managed marker are refused unless `--force` is passed.

```
sudo nginx-gen --sysctl             # apply
sudo nginx-gen --sysctl --dry-run   # preview both files
sudo nginx-gen --sysctl --no-reload # write files only, don't apply
```

### Examples

```bash
sudo nginx-gen api.example.com 10.0.0.5:8080
sudo nginx-gen --allow=cf shop.example.com 10.0.0.6:3000
sudo nginx-gen --ssl=false health.example.com 127.0.0.1:9090
sudo nginx-gen blog.example.com /var/www/blog
sudo nginx-gen --allow=10.0.0.0/8,192.168.1.0/24 internal.example.com 10.0.0.7
sudo nginx-gen --remove old.example.com
sudo nginx-gen --list
sudo nginx-gen --main
sudo nginx-gen --sysctl
```

## Filesystem layout

| Path | Purpose |
|--- |--- |
| `/etc/nginx/nginx.conf` | Global config (`--main`) |
| `/etc/nginx/sites-available/<host>.conf` | Per-vhost config file |
| `/etc/nginx/sites-enabled/<host>.conf` | Symlink → above |
| `/etc/nginx/snippets/cf-allow.conf` | Cloudflare allow-list (refreshed daily) |
| `/var/lib/nginx-gen/cf-allow.conf` | Last-good CF cache for offline fallback |
| `/var/backups/nginx-gen/` | Timestamped backups before any overwrite |
| `/run/nginx-gen.lock` | flock — serializes concurrent invocations |
| `/etc/sysctl.d/99-nginx.conf` | Network stack tuning (`--sysctl`) |
| `/etc/systemd/system/nginx.service.d/override.conf` | `LimitNOFILE=1048576` (`--sysctl`) |

Override paths via environment variables:

```
NGINX_SITES_AVAILABLE      NGINX_SITES_ENABLED        NGINX_CONF_PATH
NGINX_BACKUP_DIR           NGINX_LOCK_PATH             NGINX_CF_SNIPPET
NGINX_CF_CACHE             NGINX_CERT_DIR              NGINX_SYSCTL_PATH
NGINX_SYSTEMD_OVERRIDE_DIR
```

## Managed-by marker

Every file the tool writes starts with:

```
# Managed by nginx-gen. Do not edit by hand.
# kind=vhost host=... mode=... ssl=... allow=... ts=...
```

Files **without** the marker are treated as user-managed; the tool refuses to
overwrite or remove them unless you pass `--force`.

Sysctl and systemd override files use a simpler `# Managed by nginx-gen` prefix
for the same guard.

## Rollback semantics

For every write:

1. Take an exclusive flock on `/run/nginx-gen.lock`.
2. Back up the current file (if any) to `/var/backups/nginx-gen/`.
3. Atomic-write the new contents (tmp + fsync + rename).
4. Run `nginx -t`. **On failure: restore the backup (or remove if first deploy)
   and unlink any new symlink.** Exit 3.
5. Run `systemctl reload nginx`. **Reload failures do NOT roll back** — the
   config is valid; reload failure is a runtime issue.

`--sysctl` follows the same backup/restore pattern. On `sysctl --system`
failure, both files are restored. `systemctl restart` failure is not rolled
back (same policy as reload).

## Exit codes

| Code | Meaning |
|--- |--- |
| 0 | OK |
| 1 | User error (bad input, refused) |
| 2 | System error (FS, exec, network) |
| 3 | `nginx -t` failed; rolled back |

## Maintenance

Backups accumulate forever by design. Prune periodically:

```
find /var/backups/nginx-gen -mtime +30 -delete
```

## Migration from the legacy tool

If you previously deployed vhosts that include `/etc/nginx/conf.d/cf.conf`
(very old) or `/etc/nginx/cf.conf` (interim), the first time `nginx-gen` runs
a write op it neutralizes those files in place — replacing them with a
`# MIGRATED-PLACEHOLDER` stub so old `include` lines still resolve at
`nginx -t`. Affected vhosts lose their CF allow-list until you re-deploy them
with `--allow=cf`. The tool prints the affected paths to stderr.
