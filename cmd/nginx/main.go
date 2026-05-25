// nginx-gen — generate and install nginx config files (vhosts and global).
// Validates with `nginx -t` before reload; rolls back on validation failure.
package main

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"nginx-gen/internal/cert"
	"nginx-gen/internal/cf"
	"nginx-gen/internal/cli"
	"nginx-gen/internal/fsop"
	"nginx-gen/internal/marker"
	"nginx-gen/internal/nginx"
	"nginx-gen/internal/render"
)

type Layout struct {
	SitesAvailable   string
	SitesEnabled     string
	MainConfPath     string
	BackupDir        string
	LockPath         string
	SnippetPath      string
	CachePath        string
	CertDir          string
	SysctlPath       string
	SystemdOverrideDir string
	ModulesDir         string // where compiled .so files live (load_module path)
	ModulesEnabledDir  string // where load_module *.conf snippets live
}

func DefaultLayout() Layout {
	get := func(env, def string) string {
		if v := os.Getenv(env); v != "" {
			return v
		}
		return def
	}
	return Layout{
		SitesAvailable:    get("NGINX_SITES_AVAILABLE", "/etc/nginx/sites-available"),
		SitesEnabled:      get("NGINX_SITES_ENABLED", "/etc/nginx/sites-enabled"),
		MainConfPath:      get("NGINX_CONF_PATH", "/etc/nginx/nginx.conf"),
		BackupDir:         get("NGINX_BACKUP_DIR", "/var/backups/nginx-gen"),
		LockPath:          get("NGINX_LOCK_PATH", "/run/nginx-gen.lock"),
		SnippetPath:       get("NGINX_CF_SNIPPET", cf.DefaultSnippet),
		CachePath:         get("NGINX_CF_CACHE", cf.DefaultCache),
		CertDir:           get("NGINX_CERT_DIR", "/etc/letsencrypt/live"),
		SysctlPath:        get("NGINX_SYSCTL_PATH", "/etc/sysctl.d/99-nginx.conf"),
		SystemdOverrideDir: get("NGINX_SYSTEMD_OVERRIDE_DIR", "/etc/systemd/system/nginx.service.d"),
		ModulesDir:         get("NGINX_MODULES_DIR", "/etc/nginx/modules"),
		ModulesEnabledDir:  get("NGINX_MODULES_ENABLED_DIR", "/etc/nginx/modules-enabled"),
	}
}

type Deps struct {
	Layout       Layout
	Exec         nginx.Execer
	HTTP         cf.HTTPGetter
	ReleaseHTTP  httpGetter // for --self-update; longer timeout, GitHub-friendly headers
	Now          func() time.Time
	Stdout       io.Writer
	Stderr       io.Writer
	NginxVersion func() (nginx.VersionInfo, error)
}

func DefaultDeps() Deps {
	exec := nginx.RealExecer{}
	return Deps{
		Layout:      DefaultLayout(),
		Exec:        exec,
		HTTP:        cf.DefaultConfig().HTTP,
		ReleaseHTTP: releaseHTTP{},
		Now:         time.Now,
		Stdout:      os.Stdout,
		Stderr:      os.Stderr,
		NginxVersion: sync.OnceValues(func() (nginx.VersionInfo, error) {
			return nginx.Version(exec)
		}),
	}
}

func main() {
	os.Exit(Run(os.Args[1:], DefaultDeps()))
}

const (
	exitOK         = 0
	exitUserError  = 1
	exitSystemErr  = 2
	exitValidation = 3
)

func Run(args []string, d Deps) int {
	fs := flag.NewFlagSet("nginx-gen", flag.ContinueOnError)
	fs.SetOutput(d.Stderr)

	useMain  := fs.Bool("main", false, "write the global /etc/nginx/nginx.conf")
	doRemove := fs.Bool("remove", false, "remove a managed vhost: --remove <host>")
	doList   := fs.Bool("list", false, "list managed vhosts")
	doSysctl := fs.Bool("sysctl", false, "install sysctl tuning and systemd LimitNOFILE override")
	doBrotliBuild := fs.Bool("brotli-build", false, "compile ngx_brotli dynamic modules against the installed nginx (for hosts where the Debian brotli packages are ABI-incompatible)")
	doInstall := fs.Bool("install", false, "bootstrap a fresh nginx install: add nginx.org repo, apt-get install nginx, render managed nginx.conf, optionally build brotli")
	doBootstrap := fs.Bool("bootstrap", false, "first-time host setup: --install + --sysctl in one shot (idempotent, safe to rerun)")
	doNginxUpgrade := fs.Bool("nginx-upgrade", false, "apt-upgrade the nginx package, rebuild brotli if version drifted, re-render nginx.conf, restart. (Does NOT touch the nginx-gen tool — use --self-update for that.)")
	doABICheck := fs.Bool("abi-check", false, "print nginx + brotli ABI sync status; exit 1 on drift (suitable for cron/nagios)")
	doConvert := fs.Bool("convert", false, "best-effort migration of an existing (Debian/other) nginx install into nginx-gen's managed setup; snapshots /etc/nginx + writes a rollback script before touching anything")
	doSelfUpdate := fs.Bool("self-update", false, "replace this nginx-gen binary with the latest GitHub release (verified by sha256). Does NOT touch nginx itself — use --nginx-upgrade for that.")
	doVersion := fs.Bool("version", false, "print nginx-gen tool version and exit")
	channel  := fs.String("channel", "mainline", "nginx.org channel: mainline | stable (only used with --install / --bootstrap)")
	useSSL   := fs.Bool("ssl", true, "enable SSL listener (HTTP→HTTPS redirect + 443)")
	allowFlag := fs.String("allow", "", "cf | comma-separated CIDRs (or bare IPs)")
	dryRun   := fs.Bool("dry-run", false, "print rendered config to stdout, no FS changes")
	noReload := fs.Bool("no-reload", false, "skip nginx -t and systemctl reload")
	force    := fs.Bool("force", false, "overwrite files lacking the managed marker")
	certDir  := fs.String("cert-dir", "", "override cert lookup base (default: $NGINX_CERT_DIR or /etc/letsencrypt/live)")
	brotli   := fs.String("brotli", "auto", "auto: try to install brotli, fall back if unavailable | on: require brotli (error if unavailable) | off: render without brotli, skip apt entirely")

	if err := fs.Parse(args); err != nil {
		return exitUserError
	}
	pos := fs.Args()

	if *certDir != "" {
		d.Layout.CertDir = *certDir
	}

	// Mode dispatch
	switch {
	case *doList:
		return runList(d)
	case *doRemove:
		if len(pos) != 1 {
			fmt.Fprintln(d.Stderr, "usage: nginx-gen --remove <host>")
			return exitUserError
		}
		return runRemove(d, pos[0], *force, *noReload)
	case *useMain:
		if len(pos) != 0 {
			fmt.Fprintln(d.Stderr, "usage: nginx-gen --main  (no positional args)")
			return exitUserError
		}
		mode, err := parseBrotliMode(*brotli)
		if err != nil {
			fmt.Fprintln(d.Stderr, err)
			return exitUserError
		}
		return runMain(d, *force, *dryRun, *noReload, mode)
	case *doSysctl:
		if len(pos) != 0 {
			fmt.Fprintln(d.Stderr, "usage: nginx-gen --sysctl  (no positional args)")
			return exitUserError
		}
		return runSysctl(d, *force, *dryRun, *noReload)
	case *doBrotliBuild:
		if len(pos) != 0 {
			fmt.Fprintln(d.Stderr, "usage: nginx-gen --brotli-build  (no positional args)")
			return exitUserError
		}
		return runBrotliBuild(d, *force, *dryRun)
	case *doInstall:
		if len(pos) != 0 {
			fmt.Fprintln(d.Stderr, "usage: nginx-gen --install  (no positional args)")
			return exitUserError
		}
		mode, err := parseBrotliMode(*brotli)
		if err != nil {
			fmt.Fprintln(d.Stderr, err)
			return exitUserError
		}
		return runInstall(d, *channel, mode, *dryRun, *force)
	case *doBootstrap:
		if len(pos) != 0 {
			fmt.Fprintln(d.Stderr, "usage: nginx-gen --bootstrap  (no positional args)")
			return exitUserError
		}
		mode, err := parseBrotliMode(*brotli)
		if err != nil {
			fmt.Fprintln(d.Stderr, err)
			return exitUserError
		}
		return runBootstrap(d, *channel, mode, *dryRun, *force, *noReload)
	case *doNginxUpgrade:
		if len(pos) != 0 {
			fmt.Fprintln(d.Stderr, "usage: nginx-gen --nginx-upgrade  (no positional args)")
			return exitUserError
		}
		return runNginxUpgrade(d, *dryRun, *force, *noReload)
	case *doABICheck:
		if len(pos) != 0 {
			fmt.Fprintln(d.Stderr, "usage: nginx-gen --abi-check  (no positional args)")
			return exitUserError
		}
		return runABICheck(d)
	case *doConvert:
		if len(pos) != 0 {
			fmt.Fprintln(d.Stderr, "usage: nginx-gen --convert  (no positional args)")
			return exitUserError
		}
		mode, err := parseBrotliMode(*brotli)
		if err != nil {
			fmt.Fprintln(d.Stderr, err)
			return exitUserError
		}
		return runConvert(d, *channel, mode, *dryRun, *noReload)
	case *doSelfUpdate:
		if len(pos) != 0 {
			fmt.Fprintln(d.Stderr, "usage: nginx-gen --self-update  [--force] [--dry-run]")
			return exitUserError
		}
		return runSelfUpdate(d, *dryRun, *force)
	case *doVersion:
		if len(pos) != 0 {
			fmt.Fprintln(d.Stderr, "usage: nginx-gen --version  (no positional args)")
			return exitUserError
		}
		return runVersion(d)
	}

	// Vhost mode
	if len(pos) != 2 {
		printUsage(d.Stderr)
		return exitUserError
	}
	return runVhost(d, pos[0], pos[1], *useSSL, *allowFlag, *force, *dryRun, *noReload)
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  nginx-gen [--ssl=true|false] [--allow=cf|cidrs] [--force] [--dry-run] [--no-reload] <host> <target>")
	fmt.Fprintln(w, "    target = ip[:port] | host[:port]   (proxy mode)")
	fmt.Fprintln(w, "           = /absolute/path/to/htmldir (static mode, must exist)")
	fmt.Fprintln(w, "  nginx-gen --main [--brotli=auto|on|off] [--force] [--dry-run] [--no-reload]")
	fmt.Fprintln(w, "  nginx-gen --remove <host>")
	fmt.Fprintln(w, "  nginx-gen --list")
	fmt.Fprintln(w, "  nginx-gen --sysctl  [--force] [--dry-run] [--no-reload]")
	fmt.Fprintln(w, "  nginx-gen --brotli-build  [--force] [--dry-run]")
	fmt.Fprintln(w, "  nginx-gen --install    [--channel=mainline|stable] [--brotli=auto|on|off] [--force] [--dry-run]")
	fmt.Fprintln(w, "  nginx-gen --bootstrap  [--channel=mainline|stable] [--brotli=auto|on|off] [--force] [--dry-run] [--no-reload]")
	fmt.Fprintln(w, "  nginx-gen --nginx-upgrade  [--force] [--dry-run] [--no-reload]")
	fmt.Fprintln(w, "  nginx-gen --abi-check       (exit 0 if nginx+brotli ABIs match; 1 on drift)")
	fmt.Fprintln(w, "  nginx-gen --convert    [--channel=mainline|stable] [--brotli=auto|on|off] [--dry-run] [--no-reload]")
	fmt.Fprintln(w, "  nginx-gen --self-update  [--force] [--dry-run]")
	fmt.Fprintln(w, "  nginx-gen --version")
}

// ---- vhost ----

func runVhost(d Deps, host, target string, ssl bool, allowSpec string, force, dryRun, noReload bool) int {
	if !cli.ValidHost(host) {
		fmt.Fprintln(d.Stderr, "invalid host:", host)
		return exitUserError
	}

	migrateLegacyAllowConf(d.Stderr)

	tk, tval, err := cli.ParseTarget(target)
	if err != nil {
		fmt.Fprintln(d.Stderr, "target:", err)
		return exitUserError
	}

	allowKind, allowCIDRs, err := cli.ParseAllow(allowSpec)
	if err != nil {
		fmt.Fprintln(d.Stderr, "allow:", err)
		return exitUserError
	}

	// Detect nginx version for http2 directive syntax. Skip in dry-run (nginx
	// may not be installed in the calling environment). On detection failure,
	// vi stays zero-value: HTTP2Inline() = false → modern `http2 on;` syntax.
	var vi nginx.VersionInfo
	if !dryRun {
		if d.NginxVersion != nil {
			vi, _ = d.NginxVersion()
		} else {
			vi, _ = nginx.Version(d.Exec)
		}
	}

	cfg := render.VhostCfg{
		Host:        host,
		SSL:         ssl,
		AllowCIDRs:  allowCIDRs,
		Now:         d.Now(),
		HTTP2Inline: vi.HTTP2Inline(),
	}
	switch tk {
	case cli.TargetProxy:
		cfg.Mode = render.ModeProxy
		cfg.Upstream = tval
		cfg.UpstreamName = cli.UpstreamName(host)
	case cli.TargetStatic:
		cfg.Mode = render.ModeStatic
		abs, err := filepath.Abs(tval)
		if err != nil {
			fmt.Fprintln(d.Stderr, "abs path:", err)
			return exitSystemErr
		}
		cfg.Root = abs
	}
	switch allowKind {
	case cli.AllowCF:
		cfg.Allow = render.AllowCF
	case cli.AllowList:
		cfg.Allow = render.AllowList
	}

	if ssl {
		certDir, err := cert.Resolve(host, d.Layout.CertDir)
		if err != nil {
			fmt.Fprintln(d.Stderr, "cert:", err)
			return exitUserError
		}
		cfg.CertDir = certDir
	}

	rendered, err := render.Vhost(cfg)
	if err != nil {
		fmt.Fprintln(d.Stderr, "render:", err)
		return exitSystemErr
	}

	if dryRun {
		_, _ = d.Stdout.Write(rendered)
		return exitOK
	}

	targetAvail := filepath.Join(d.Layout.SitesAvailable, host+".conf")
	targetLink  := filepath.Join(d.Layout.SitesEnabled, host+".conf")

	release, err := fsop.Flock(d.Layout.LockPath)
	if err != nil {
		fmt.Fprintln(d.Stderr, "lock:", err)
		return exitSystemErr
	}
	defer release()

	// CF snippet is shared state — keep it inside the lock so concurrent
	// --allow=cf invocations don't fetch and write redundantly.
	if cfg.Allow == render.AllowCF {
		cfCfg := cf.Config{
			SnippetPath: d.Layout.SnippetPath,
			CachePath:   d.Layout.CachePath,
			URLv4:       cf.URLv4,
			URLv6:       cf.URLv6,
			HTTP:        d.HTTP,
			Now:         d.Now,
		}
		if err := cf.Ensure(cfCfg); err != nil {
			fmt.Fprintln(d.Stderr, "cf:", err)
			return exitSystemErr
		}
	}

	// Marker check on sites-available
	chk, _, err := marker.RequireOurs(targetAvail)
	if err != nil {
		fmt.Fprintln(d.Stderr, "marker check:", err)
		return exitSystemErr
	}
	if chk == marker.CheckNotOurs && !force {
		fmt.Fprintln(d.Stderr, "refusing to overwrite unmanaged file:", targetAvail, "(use --force)")
		return exitUserError
	}

	backupPath, err := fsop.Backup(targetAvail, d.Layout.BackupDir)
	if err != nil {
		fmt.Fprintln(d.Stderr, "backup:", err)
		return exitSystemErr
	}

	if err := os.MkdirAll(d.Layout.SitesAvailable, 0755); err != nil {
		fmt.Fprintln(d.Stderr, "mkdir sites-available:", err)
		return exitSystemErr
	}
	if err := fsop.AtomicWrite(targetAvail, rendered, 0644); err != nil {
		fmt.Fprintln(d.Stderr, "write:", err)
		return exitSystemErr
	}

	if err := os.MkdirAll(d.Layout.SitesEnabled, 0755); err != nil {
		fmt.Fprintln(d.Stderr, "mkdir sites-enabled:", err)
		return exitSystemErr
	}
	createdLink, err := fsop.IdempotentSymlink(targetAvail, targetLink)
	if err != nil {
		fmt.Fprintln(d.Stderr, "symlink:", err)
		// Roll back the file write.
		rollback(d, targetAvail, backupPath)
		return exitSystemErr
	}

	if !noReload {
		if err := nginx.Test(d.Exec); err != nil {
			fmt.Fprintln(d.Stderr, err)
			rollback(d, targetAvail, backupPath)
			if createdLink {
				_ = os.Remove(targetLink)
			}
			return exitValidation
		}
		if err := nginx.Reload(d.Exec); err != nil {
			fmt.Fprintln(d.Stderr, err)
			// Don't roll back — config is valid; reload failure is a runtime issue.
			return exitSystemErr
		}
	}

	logEvent(d.Stderr, d.Now(), "vhost-write", host, map[string]any{
		"mode": cfg.Mode.String(), "ssl": ssl, "allow": cfg.Allow.String(),
		"backup": backupPath, "result": "ok",
	})
	return exitOK
}

func rollback(d Deps, target, backup string) {
	if backup == "" {
		// First deploy — remove what we wrote.
		if err := os.Remove(target); err != nil {
			fmt.Fprintln(d.Stderr, "CRITICAL: rollback (remove) failed:", err)
		} else {
			fmt.Fprintln(d.Stderr, "rolled back: removed new file")
		}
		return
	}
	if err := fsop.Restore(backup, target); err != nil {
		fmt.Fprintln(d.Stderr, "CRITICAL: rollback (restore) failed:", err)
		return
	}
	fmt.Fprintln(d.Stderr, "rolled back: restored previous file from", backup)
}

// ---- main ----

func runMain(d Deps, force, dryRun, noReload bool, brotliMode BrotliMode) int {
	migrateLegacyAllowConf(d.Stderr)
	brotli, hardErr := resolveBrotli(d, brotliMode, dryRun)
	if hardErr {
		return exitUserError
	}
	rendered, err := render.Main(render.MainCfg{Now: d.Now(), Brotli: brotli})
	if err != nil {
		fmt.Fprintln(d.Stderr, "render main:", err)
		return exitSystemErr
	}
	if dryRun {
		_, _ = d.Stdout.Write(rendered)
		return exitOK
	}

	release, err := fsop.Flock(d.Layout.LockPath)
	if err != nil {
		fmt.Fprintln(d.Stderr, "lock:", err)
		return exitSystemErr
	}
	defer release()

	chk, _, err := marker.RequireOurs(d.Layout.MainConfPath)
	if err != nil {
		fmt.Fprintln(d.Stderr, "marker check:", err)
		return exitSystemErr
	}
	if chk == marker.CheckNotOurs && !force {
		fmt.Fprintln(d.Stderr, "refusing to overwrite unmanaged file:", d.Layout.MainConfPath, "(use --force)")
		return exitUserError
	}

	backupPath, err := fsop.Backup(d.Layout.MainConfPath, d.Layout.BackupDir)
	if err != nil {
		fmt.Fprintln(d.Stderr, "backup:", err)
		return exitSystemErr
	}
	if err := fsop.AtomicWrite(d.Layout.MainConfPath, rendered, 0644); err != nil {
		fmt.Fprintln(d.Stderr, "write:", err)
		return exitSystemErr
	}

	if !noReload {
		if err := nginx.Test(d.Exec); err != nil {
			fmt.Fprintln(d.Stderr, err)
			rollback(d, d.Layout.MainConfPath, backupPath)
			return exitValidation
		}
		if err := nginx.Reload(d.Exec); err != nil {
			fmt.Fprintln(d.Stderr, err)
			return exitSystemErr
		}
	}

	logEvent(d.Stderr, d.Now(), "main-write", "", map[string]any{
		"backup": backupPath, "result": "ok",
	})
	return exitOK
}

// ---- remove ----

func runRemove(d Deps, host string, force, noReload bool) int {
	if !cli.ValidHost(host) {
		fmt.Fprintln(d.Stderr, "invalid host:", host)
		return exitUserError
	}
	migrateLegacyAllowConf(d.Stderr)
	targetAvail := filepath.Join(d.Layout.SitesAvailable, host+".conf")
	targetLink  := filepath.Join(d.Layout.SitesEnabled, host+".conf")

	release, err := fsop.Flock(d.Layout.LockPath)
	if err != nil {
		fmt.Fprintln(d.Stderr, "lock:", err)
		return exitSystemErr
	}
	defer release()

	chk, _, err := marker.RequireOurs(targetAvail)
	if err != nil {
		fmt.Fprintln(d.Stderr, "marker check:", err)
		return exitSystemErr
	}
	switch chk {
	case marker.CheckMissing:
		fmt.Fprintln(d.Stderr, "no such managed vhost:", host)
		return exitUserError
	case marker.CheckNotOurs:
		if !force {
			fmt.Fprintln(d.Stderr, "refusing to remove unmanaged file:", targetAvail, "(use --force)")
			return exitUserError
		}
	}

	if err := os.Remove(targetLink); err != nil && !errors.Is(err, fs.ErrNotExist) {
		fmt.Fprintln(d.Stderr, "remove symlink:", err)
		return exitSystemErr
	}
	// sites-available file retained for audit.

	if !noReload {
		if err := nginx.Test(d.Exec); err != nil {
			fmt.Fprintln(d.Stderr, err)
			return exitValidation
		}
		if err := nginx.Reload(d.Exec); err != nil {
			fmt.Fprintln(d.Stderr, err)
			return exitSystemErr
		}
	}
	logEvent(d.Stderr, d.Now(), "remove", host, map[string]any{"result": "ok"})
	return exitOK
}

// ---- list ----

func runList(d Deps) int {
	entries, err := os.ReadDir(d.Layout.SitesAvailable)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return exitOK // empty
		}
		fmt.Fprintln(d.Stderr, "list:", err)
		return exitSystemErr
	}
	type row struct {
		host, mode, allow, ts, enabled string
		ssl                            bool
	}
	var rows []row
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".conf") {
			continue
		}
		path := filepath.Join(d.Layout.SitesAvailable, e.Name())
		_, h, err := marker.RequireOurs(path)
		if err != nil || h.Kind != marker.KindVhost {
			continue
		}
		linkPath := filepath.Join(d.Layout.SitesEnabled, e.Name())
		enabled := "no"
		if _, err := os.Lstat(linkPath); err == nil {
			enabled = "yes"
		}
		rows = append(rows, row{
			host: h.Host, mode: h.Mode, ssl: h.SSL, allow: h.Allow,
			ts: h.TS.Format(time.RFC3339), enabled: enabled,
		})
	}
	slices.SortFunc(rows, func(a, b row) int { return cmp.Compare(a.host, b.host) })
	for _, r := range rows {
		fmt.Fprintf(d.Stdout, "%-40s mode=%-6s ssl=%-5t allow=%-10s enabled=%s ts=%s\n",
			r.host, r.mode, r.ssl, r.allow, r.enabled, r.ts)
	}
	return exitOK
}

// ---- sysctl ----

const sysctlManagedPrefix = "# Managed by nginx-gen\n"

func sysctlContent() string {
	return `# Managed by nginx-gen
# Network stack tuning for high-throughput nginx (TLS termination + reverse proxy)

# Listen / accept queues
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 16384
net.ipv4.tcp_max_syn_backlog = 65535

# Ephemeral ports (large outbound fan-out to upstreams)
net.ipv4.ip_local_port_range = 1024 65535

# TIME_WAIT recycling for high connection churn
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15

# SYN flood resilience
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_max_tw_buckets = 1440000

# Buffers (autotuned ranges)
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 262144
net.core.wmem_default = 262144
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216

# Congestion control / pacing
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# Misc
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_mtu_probing = 1

# File descriptors (system-wide ceiling)
fs.file-max = 2097152
fs.nr_open = 2097152
`
}

func systemdOverrideContent() string {
	return `# Managed by nginx-gen
[Service]
LimitNOFILE=1048576
LimitNPROC=65535
`
}

func runSysctl(d Deps, force, dryRun, noReload bool) int {
	sysctl  := sysctlContent()
	override := systemdOverrideContent()
	overridePath := filepath.Join(d.Layout.SystemdOverrideDir, "override.conf")

	if dryRun {
		fmt.Fprintf(d.Stdout, "# --- %s ---\n%s\n# --- %s ---\n%s\n",
			d.Layout.SysctlPath, sysctl, overridePath, override)
		return exitOK
	}

	release, err := fsop.Flock(d.Layout.LockPath)
	if err != nil {
		fmt.Fprintln(d.Stderr, "lock:", err)
		return exitSystemErr
	}
	defer release()

	// Managed-file guard: refuse to overwrite files we didn't create.
	if existing, err := os.ReadFile(d.Layout.SysctlPath); err == nil {
		if !bytes.HasPrefix(existing, []byte(sysctlManagedPrefix)) && !force {
			fmt.Fprintln(d.Stderr, "refusing to overwrite unmanaged file:", d.Layout.SysctlPath, "(use --force)")
			return exitUserError
		}
	}
	if existing, err := os.ReadFile(overridePath); err == nil {
		if !bytes.HasPrefix(existing, []byte(sysctlManagedPrefix)) && !force {
			fmt.Fprintln(d.Stderr, "refusing to overwrite unmanaged file:", overridePath, "(use --force)")
			return exitUserError
		}
	}

	backupSysctl, err := fsop.Backup(d.Layout.SysctlPath, d.Layout.BackupDir)
	if err != nil {
		fmt.Fprintln(d.Stderr, "backup sysctl:", err)
		return exitSystemErr
	}
	backupOverride, err := fsop.Backup(overridePath, d.Layout.BackupDir)
	if err != nil {
		fmt.Fprintln(d.Stderr, "backup systemd override:", err)
		return exitSystemErr
	}

	if err := fsop.AtomicWrite(d.Layout.SysctlPath, []byte(sysctl), 0644); err != nil {
		fmt.Fprintln(d.Stderr, "write sysctl:", err)
		return exitSystemErr
	}
	if err := os.MkdirAll(d.Layout.SystemdOverrideDir, 0755); err != nil {
		fmt.Fprintln(d.Stderr, "mkdir systemd override dir:", err)
		return exitSystemErr
	}
	if err := fsop.AtomicWrite(overridePath, []byte(override), 0644); err != nil {
		fmt.Fprintln(d.Stderr, "write systemd override:", err)
		return exitSystemErr
	}

	if !noReload {
		// Load BBR module if not yet available.
		avail, _ := os.ReadFile("/proc/sys/net/ipv4/tcp_available_congestion_control")
		if !bytes.Contains(avail, []byte("bbr")) {
			if _, err := d.Exec.Run("modprobe", "tcp_bbr"); err != nil {
				fmt.Fprintln(d.Stderr, "warning: tcp_bbr unavailable — BBR sysctl line will be ignored by the kernel")
			}
		}

		if out, err := d.Exec.Run("sysctl", "--system"); err != nil {
			fmt.Fprintln(d.Stderr, "sysctl --system failed:", string(out))
			rollback(d, d.Layout.SysctlPath, backupSysctl)
			rollback(d, overridePath, backupOverride)
			return exitSystemErr
		}
		if out, err := d.Exec.Run("systemctl", "daemon-reload"); err != nil {
			fmt.Fprintln(d.Stderr, "systemctl daemon-reload failed:", string(out))
			rollback(d, overridePath, backupOverride)
			return exitSystemErr
		}
		// Restart (not reload) required to pick up new LimitNOFILE.
		if out, err := d.Exec.Run("systemctl", "restart", "nginx"); err != nil {
			fmt.Fprintln(d.Stderr, "systemctl restart nginx failed:", string(out))
			// Don't roll back — config is valid; restart failure is a runtime issue.
			return exitSystemErr
		}
	}

	logEvent(d.Stderr, d.Now(), "sysctl-write", "", map[string]any{
		"sysctl_backup":   backupSysctl,
		"override_backup": backupOverride,
		"result":          "ok",
	})
	return exitOK
}

// ---- brotli build ----

// brotliBuildDeps: minimal apt set to compile a dynamic nginx module from
// nginx.org sources. libpcre2-dev tracks current nginx (PCRE1 is dropped in
// 1.27+). cmake is pulled in via ngx_brotli's brotli submodule build.
var brotliBuildDeps = []string{
	"build-essential", "libpcre2-dev", "zlib1g-dev",
	"libssl-dev", "cmake", "git", "curl",
}

const (
	brotliRepoURL  = "https://github.com/google/ngx_brotli.git"
	brotliLoadConf = "50-mod-http-brotli.conf"
)

// runBrotliBuild fetches matching nginx sources, clones ngx_brotli, compiles
// the two filter/static dynamic modules `--with-compat`, installs them under
// /etc/nginx/modules/, and writes a load_module conf. Idempotent: if the
// module is already loaded, exits OK unless --force is given.
func runBrotliBuild(d Deps, force, dryRun bool) int {
	if d.NginxVersion == nil {
		fmt.Fprintln(d.Stderr, "internal: NginxVersion probe unavailable")
		return exitSystemErr
	}
	vi, err := d.NginxVersion()
	if err != nil {
		fmt.Fprintln(d.Stderr, "nginx version probe:", err)
		return exitSystemErr
	}
	version := fmt.Sprintf("%d.%d.%d", vi.Major, vi.Minor, vi.Patch)

	loadConfPath := filepath.Join(d.Layout.ModulesEnabledDir, brotliLoadConf)
	if !force && brotliModuleLoaded(d.Layout.ModulesEnabledDir) {
		fmt.Fprintln(d.Stderr, "brotli module already loaded; pass --force to rebuild (current nginx:", version+")")
		return exitOK
	}

	if dryRun {
		fmt.Fprintf(d.Stdout, "# would build ngx_brotli against nginx %s\n", version)
		fmt.Fprintf(d.Stdout, "apt-get install -y %s\n", strings.Join(brotliBuildDeps, " "))
		fmt.Fprintf(d.Stdout, "curl -fsSL -o nginx.tar.gz https://nginx.org/download/nginx-%s.tar.gz\n", version)
		fmt.Fprintf(d.Stdout, "tar -xzf nginx.tar.gz\n")
		fmt.Fprintf(d.Stdout, "git clone --recurse-submodules --depth=1 %s\n", brotliRepoURL)
		fmt.Fprintf(d.Stdout, "(cd ngx_brotli/deps/brotli && mkdir -p out && cd out && cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF .. && cmake --build . --config Release --target brotlienc -j$(nproc))\n")
		fmt.Fprintf(d.Stdout, "(cd nginx-%s && ./configure --with-compat --add-dynamic-module=../ngx_brotli && make -j$(nproc) modules)\n", version)
		fmt.Fprintf(d.Stdout, "install objs/ngx_http_brotli_{filter,static}_module.so → %s/\n", d.Layout.ModulesDir)
		fmt.Fprintf(d.Stdout, "write %s\n", loadConfPath)
		return exitOK
	}

	release, err := fsop.Flock(d.Layout.LockPath)
	if err != nil {
		fmt.Fprintln(d.Stderr, "lock:", err)
		return exitSystemErr
	}
	defer release()

	fmt.Fprintln(d.Stderr, "installing build dependencies via apt-get...")
	if out, err := d.Exec.RunEnv("apt-get",
		[]string{"DEBIAN_FRONTEND=noninteractive"},
		append([]string{"install", "-y"}, brotliBuildDeps...)...); err != nil {
		fmt.Fprintln(d.Stderr, "apt-get install failed:", err)
		fmt.Fprintln(d.Stderr, strings.TrimSpace(string(out)))
		return exitSystemErr
	}

	tmpDir, err := os.MkdirTemp("", "nginx-brotli-")
	if err != nil {
		fmt.Fprintln(d.Stderr, "mktemp:", err)
		return exitSystemErr
	}
	defer os.RemoveAll(tmpDir)

	tarPath := filepath.Join(tmpDir, "nginx.tar.gz")
	tarURL := fmt.Sprintf("https://nginx.org/download/nginx-%s.tar.gz", version)
	fmt.Fprintln(d.Stderr, "downloading", tarURL)
	if out, err := d.Exec.Run("curl", "-fsSL", "-o", tarPath, tarURL); err != nil {
		fmt.Fprintln(d.Stderr, "download failed:", err)
		fmt.Fprintln(d.Stderr, strings.TrimSpace(string(out)))
		return exitSystemErr
	}
	if out, err := d.Exec.Run("tar", "-xzf", tarPath, "-C", tmpDir); err != nil {
		fmt.Fprintln(d.Stderr, "tar:", err)
		fmt.Fprintln(d.Stderr, strings.TrimSpace(string(out)))
		return exitSystemErr
	}

	brotliSrc := filepath.Join(tmpDir, "ngx_brotli")
	fmt.Fprintln(d.Stderr, "cloning ngx_brotli...")
	if out, err := d.Exec.Run("git", "clone", "--recurse-submodules", "--depth=1", brotliRepoURL, brotliSrc); err != nil {
		fmt.Fprintln(d.Stderr, "git clone failed:", err)
		fmt.Fprintln(d.Stderr, strings.TrimSpace(string(out)))
		return exitSystemErr
	}

	// Build the bundled brotli C library — ngx_brotli's config script
	// hardcodes -L$addon/deps/brotli/c/../out, so the static libs must
	// exist at that path before nginx configure/make.
	brotliBuildDir := filepath.Join(brotliSrc, "deps", "brotli", "out")
	if err := os.MkdirAll(brotliBuildDir, 0755); err != nil {
		fmt.Fprintln(d.Stderr, "mkdir brotli build:", err)
		return exitSystemErr
	}
	fmt.Fprintln(d.Stderr, "building bundled brotli library...")
	if out, err := d.Exec.RunDir(brotliBuildDir, "cmake",
		"-DCMAKE_BUILD_TYPE=Release",
		"-DBUILD_SHARED_LIBS=OFF",
		".."); err != nil {
		fmt.Fprintln(d.Stderr, "cmake configure failed:", err)
		fmt.Fprintln(d.Stderr, strings.TrimSpace(string(out)))
		return exitSystemErr
	}
	if out, err := d.Exec.RunDir(brotliBuildDir, "cmake",
		"--build", ".", "--config", "Release",
		"--target", "brotlienc",
		"-j", strconv.Itoa(runtime.NumCPU())); err != nil {
		fmt.Fprintln(d.Stderr, "cmake build brotli failed:", err)
		fmt.Fprintln(d.Stderr, strings.TrimSpace(string(out)))
		return exitSystemErr
	}

	nginxSrc := filepath.Join(tmpDir, "nginx-"+version)
	fmt.Fprintln(d.Stderr, "configuring nginx build...")
	if out, err := d.Exec.RunDir(nginxSrc, "./configure", "--with-compat", "--add-dynamic-module="+brotliSrc); err != nil {
		fmt.Fprintln(d.Stderr, "configure failed:", err)
		fmt.Fprintln(d.Stderr, strings.TrimSpace(string(out)))
		return exitSystemErr
	}
	fmt.Fprintln(d.Stderr, "compiling modules (this can take a minute)...")
	if out, err := d.Exec.RunDir(nginxSrc, "make", "-j"+strconv.Itoa(runtime.NumCPU()), "modules"); err != nil {
		fmt.Fprintln(d.Stderr, "make modules failed:", err)
		fmt.Fprintln(d.Stderr, strings.TrimSpace(string(out)))
		return exitSystemErr
	}

	if err := os.MkdirAll(d.Layout.ModulesDir, 0755); err != nil {
		fmt.Fprintln(d.Stderr, "mkdir modules:", err)
		return exitSystemErr
	}
	objs := filepath.Join(nginxSrc, "objs")
	for _, m := range []string{"ngx_http_brotli_filter_module.so", "ngx_http_brotli_static_module.so"} {
		data, err := os.ReadFile(filepath.Join(objs, m))
		if err != nil {
			fmt.Fprintln(d.Stderr, "read built module:", err)
			return exitSystemErr
		}
		if err := fsop.AtomicWrite(filepath.Join(d.Layout.ModulesDir, m), data, 0644); err != nil {
			fmt.Fprintln(d.Stderr, "install module:", err)
			return exitSystemErr
		}
	}

	if err := os.MkdirAll(d.Layout.ModulesEnabledDir, 0755); err != nil {
		fmt.Fprintln(d.Stderr, "mkdir modules-enabled:", err)
		return exitSystemErr
	}
	// Absolute paths — nginx resolves bare `modules/...` against its compiled
	// prefix (typically /etc/nginx/), which silently breaks if ModulesDir was
	// overridden via NGINX_MODULES_DIR.
	loadConf := fmt.Sprintf(
		"# Managed by nginx-gen; built against nginx %s\nload_module %s/ngx_http_brotli_filter_module.so;\nload_module %s/ngx_http_brotli_static_module.so;\n",
		version, d.Layout.ModulesDir, d.Layout.ModulesDir,
	)
	if err := fsop.AtomicWrite(loadConfPath, []byte(loadConf), 0644); err != nil {
		fmt.Fprintln(d.Stderr, "write load conf:", err)
		return exitSystemErr
	}

	if err := nginx.Test(d.Exec); err != nil {
		fmt.Fprintln(d.Stderr, err)
		return exitValidation
	}

	logEvent(d.Stderr, d.Now(), "brotli-build", "", map[string]any{
		"nginx_version": version,
		"result":        "ok",
	})
	// load_module is parsed at startup only — `systemctl reload nginx` won't
	// pick it up. Tell the operator explicitly rather than auto-restart so
	// they can choose when to drop connections.
	fmt.Fprintln(d.Stderr, "module installed. Run 'systemctl restart nginx' to load it (reload is not enough — load_module is parsed only at startup).")
	return exitOK
}

// ---- upgrade ----

// brotliBuildVersion returns the nginx version the loaded brotli module
// was compiled against, parsed from our managed load_module conf header.
// Returns "" if the conf is missing, hand-written, or unparseable.
var brotliBuiltAgainstRE = regexp.MustCompile(`built against nginx (\S+)`)

func brotliBuildVersion(modulesEnabledDir string) string {
	data, err := os.ReadFile(filepath.Join(modulesEnabledDir, brotliLoadConf))
	if err != nil {
		return ""
	}
	m := brotliBuiltAgainstRE.FindSubmatch(data)
	if m == nil {
		return ""
	}
	return string(m[1])
}

// runNginxUpgrade applies apt upgrades to nginx, rebuilds brotli if the new
// nginx version differs from what brotli was compiled against, re-renders
// nginx.conf (in case the template was updated alongside the binary), and
// restarts. Idempotent: a no-op apt + matching brotli version + already-
// managed conf exits in ~2 s with nothing changed.
func runNginxUpgrade(d Deps, dryRun, force, noReload bool) int {
	if dryRun {
		printNginxUpgradeRecipe(d.Stdout)
		return exitOK
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(d.Stderr, "--nginx-upgrade requires root (apt-get + writes to /etc)")
		return exitUserError
	}

	preVI, err := nginx.Version(d.Exec)
	if err != nil {
		fmt.Fprintln(d.Stderr, "pre-upgrade nginx version probe:", err)
		return exitSystemErr
	}
	preVer := fmt.Sprintf("%d.%d.%d", preVI.Major, preVI.Minor, preVI.Patch)

	fmt.Fprintln(d.Stderr, "updating apt index...")
	if out, err := d.Exec.RunEnv("apt-get",
		[]string{"DEBIAN_FRONTEND=noninteractive"}, "update"); err != nil {
		fmt.Fprintln(d.Stderr, "apt-get update failed:", err)
		fmt.Fprintln(d.Stderr, strings.TrimSpace(string(out)))
		return exitSystemErr
	}
	fmt.Fprintln(d.Stderr, "upgrading nginx (if newer available)...")
	if out, err := d.Exec.RunEnv("apt-get",
		[]string{"DEBIAN_FRONTEND=noninteractive"},
		"install", "--only-upgrade", "-y", "nginx"); err != nil {
		fmt.Fprintln(d.Stderr, "apt-get install --only-upgrade nginx failed:", err)
		fmt.Fprintln(d.Stderr, strings.TrimSpace(string(out)))
		return exitSystemErr
	}

	// Fresh probe — d.NginxVersion's sync.OnceValues cache would return
	// the pre-upgrade value. Downstream calls (runBrotliBuild) also use
	// d.NginxVersion, so replace it with a non-cached probe.
	d.NginxVersion = func() (nginx.VersionInfo, error) { return nginx.Version(d.Exec) }
	postVI, err := d.NginxVersion()
	if err != nil {
		fmt.Fprintln(d.Stderr, "post-upgrade nginx version probe:", err)
		return exitSystemErr
	}
	postVer := fmt.Sprintf("%d.%d.%d", postVI.Major, postVI.Minor, postVI.Patch)
	if preVer == postVer {
		fmt.Fprintln(d.Stderr, "nginx already at latest:", postVer)
	} else {
		fmt.Fprintf(d.Stderr, "nginx upgraded: %s → %s\n", preVer, postVer)
	}

	brotliWasInstalled := brotliModuleLoaded(d.Layout.ModulesEnabledDir)
	builtVer := brotliBuildVersion(d.Layout.ModulesEnabledDir)
	needRebuild := brotliWasInstalled && (force || builtVer != postVer)
	if needRebuild {
		fmt.Fprintf(d.Stderr, "rebuilding brotli (was built against %s, nginx is %s)...\n",
			cmpOrFallback(builtVer, "unknown"), postVer)
		if code := runBrotliBuild(d, true, false); code != exitOK {
			return code
		}
	}

	// Re-render with brotli iff it's installed (preserves prior state).
	renderMode := BrotliOff
	if brotliWasInstalled {
		renderMode = BrotliOn
	}
	if code := runMain(d, true, false, true, renderMode); code != exitOK {
		return code
	}

	if err := nginx.Test(d.Exec); err != nil {
		fmt.Fprintln(d.Stderr, "post-upgrade config validation failed:", err)
		return exitValidation
	}

	if !noReload {
		// Restart, not reload: if brotli was rebuilt the load_module
		// directive needs to be re-parsed at startup. Restart is safe
		// even when only a minor upgrade happened.
		if out, err := d.Exec.Run("systemctl", "restart", "nginx"); err != nil {
			fmt.Fprintln(d.Stderr, "systemctl restart nginx failed:", err)
			fmt.Fprintln(d.Stderr, strings.TrimSpace(string(out)))
			return exitSystemErr
		}
	}

	logEvent(d.Stderr, d.Now(), "nginx-upgrade", "", map[string]any{
		"nginx_from":     preVer,
		"nginx_to":       postVer,
		"brotli_rebuilt": needRebuild,
		"result":         "ok",
	})
	return exitOK
}

func cmpOrFallback(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

func printNginxUpgradeRecipe(w io.Writer) {
	fmt.Fprintln(w, "# would upgrade nginx + rebuild brotli if version drifted")
	fmt.Fprintln(w, "apt-get update")
	fmt.Fprintln(w, "apt-get install --only-upgrade -y nginx")
	fmt.Fprintln(w, "[probe new nginx -v]")
	fmt.Fprintln(w, "if brotli previously installed AND new nginx version != built-against:")
	fmt.Fprintln(w, "    rerun --brotli-build --force against the new nginx")
	fmt.Fprintln(w, "render /etc/nginx/nginx.conf via --main (brotli preserved from prior state)")
	fmt.Fprintln(w, "nginx -t")
	fmt.Fprintln(w, "systemctl restart nginx")
}

// runABICheck reports nginx ↔ brotli ABI sync status. Exit 0 if no
// drift; exit 1 if a rebuild is needed. Designed for cron/monit/Nagios.
func runABICheck(d Deps) int {
	vi, err := nginx.Version(d.Exec)
	if err != nil {
		fmt.Fprintln(d.Stderr, "nginx version probe:", err)
		return exitSystemErr
	}
	nginxVer := fmt.Sprintf("%d.%d.%d", vi.Major, vi.Minor, vi.Patch)
	fmt.Fprintln(d.Stdout, "nginx:", nginxVer)

	if !brotliModuleLoaded(d.Layout.ModulesEnabledDir) {
		fmt.Fprintln(d.Stdout, "brotli: not installed")
		return exitOK
	}
	builtVer := brotliBuildVersion(d.Layout.ModulesEnabledDir)
	if builtVer == "" {
		fmt.Fprintln(d.Stdout, "brotli: loaded (hand-managed; nginx-gen cannot verify ABI)")
		return exitOK
	}
	if builtVer == nginxVer {
		fmt.Fprintln(d.Stdout, "brotli built against:", builtVer, "(in sync)")
		return exitOK
	}
	fmt.Fprintf(d.Stdout,
		"brotli built against: %s  DRIFT — nginx is %s. Run `nginx-gen --nginx-upgrade` (or `--brotli-build --force`).\n",
		builtVer, nginxVer)
	return exitUserError
}

// ---- convert ----

const convertBackupRoot = "/var/backups/nginx-gen/convert"

// runConvert migrates an existing (Debian or other) nginx install into
// nginx-gen's managed setup, in the safest way possible:
//
//   1. Snapshot /etc/nginx (cp -a) + nginx -T + dpkg state to a timestamped
//      backup dir.
//   2. Write an executable rollback.sh next to the snapshot.
//   3. Run --install (which itself rewrites nginx.conf with --force, deletes
//      the upstream stub, optionally builds brotli) then --sysctl.
//
// Vhost files in sites-enabled/ are NOT rewritten — the caller can re-render
// them with `nginx-gen <host> <target>` afterwards to put the managed
// marker on them, but they keep working as-is. Custom http-scope directives
// (map, geo, log_format, upstream) that were in the operator's hand-written
// nginx.conf are *not* automatically extracted — they're preserved only as
// the snapshotted nginx.conf, and the operator should grep through it and
// move anything they need into /etc/nginx/conf.d/<name>.conf.
//
// On --install failure, the rollback script path is printed prominently.
func runConvert(d Deps, channelStr string, brotliMode BrotliMode, dryRun, noReload bool) int {
	if _, err := parseChannel(channelStr); err != nil {
		fmt.Fprintln(d.Stderr, err)
		return exitUserError
	}

	if dryRun {
		printConvertRecipe(d.Stdout, channelStr, brotliMode)
		return exitOK
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(d.Stderr, "--convert requires root (snapshots /etc/nginx + apt-get + writes to /etc)")
		return exitUserError
	}

	if _, err := os.Stat("/etc/nginx"); errors.Is(err, fs.ErrNotExist) {
		fmt.Fprintln(d.Stderr, "no /etc/nginx found — nothing to convert. Use --bootstrap for a clean install.")
		return exitUserError
	}

	// Already-managed guard. If our marker is on nginx.conf, the host is
	// already in our setup; --convert would do nothing useful. Suggest the
	// correct command instead.
	if data, err := os.ReadFile(d.Layout.MainConfPath); err == nil {
		if bytes.HasPrefix(data, []byte(marker.FirstLine)) {
			fmt.Fprintln(d.Stderr, "nginx.conf already managed by nginx-gen — nothing to convert.")
			fmt.Fprintln(d.Stderr, "       use --nginx-upgrade to refresh, or --main to re-render.")
			return exitOK
		}
	}

	ts := d.Now().UTC().Format("20060102T150405Z")
	backupDir := filepath.Join(convertBackupRoot, ts)
	if err := os.MkdirAll(backupDir, 0700); err != nil {
		fmt.Fprintln(d.Stderr, "create backup dir:", err)
		return exitSystemErr
	}
	fmt.Fprintf(d.Stderr, "snapshotting /etc/nginx → %s/etc-nginx/ ...\n", backupDir)
	if out, err := d.Exec.Run("cp", "-a", "/etc/nginx", filepath.Join(backupDir, "etc-nginx")); err != nil {
		fmt.Fprintln(d.Stderr, "snapshot failed:", err)
		fmt.Fprintln(d.Stderr, strings.TrimSpace(string(out)))
		return exitSystemErr
	}

	// Capture nginx -T (best-effort — config may be broken already, in
	// which case nginx -T errors but we still proceed).
	if out, err := d.Exec.Run("nginx", "-T"); err == nil && len(out) > 0 {
		_ = os.WriteFile(filepath.Join(backupDir, "nginx-T.before.txt"), out, 0644)
	}

	// Capture installed nginx version for the rollback pin.
	var prevPkgVer string
	if out, err := d.Exec.Run("dpkg-query", "-W", "-f=${Version}", "nginx"); err == nil {
		prevPkgVer = strings.TrimSpace(string(out))
		if prevPkgVer != "" {
			_ = os.WriteFile(filepath.Join(backupDir, "nginx-pkg-version.before.txt"),
				[]byte(prevPkgVer+"\n"), 0644)
		}
	}

	// Inventory unmanaged files that will keep working untouched. Helpful
	// for the operator to know what's been preserved vs replaced.
	inventory := writeConvertInventory(backupDir)
	if inventory != "" {
		fmt.Fprintln(d.Stderr, "preserved unmanaged files inventoried at:", inventory)
	}

	rollbackPath := filepath.Join(backupDir, "rollback.sh")
	if err := writeRollbackScript(rollbackPath, backupDir, prevPkgVer); err != nil {
		fmt.Fprintln(d.Stderr, "write rollback script:", err)
		return exitSystemErr
	}
	fmt.Fprintf(d.Stderr, "rollback ready: sudo bash %s\n", rollbackPath)

	fmt.Fprintln(d.Stderr, "==> step 1/2: install")
	if code := runInstall(d, channelStr, brotliMode, false, true); code != exitOK {
		fmt.Fprintln(d.Stderr, "")
		fmt.Fprintln(d.Stderr, "==> CONVERSION FAILED at --install. To revert to pre-conversion state:")
		fmt.Fprintf(d.Stderr, "       sudo bash %s\n", rollbackPath)
		return code
	}

	fmt.Fprintln(d.Stderr, "==> step 2/2: sysctl")
	if code := runSysctl(d, true, false, noReload); code != exitOK {
		fmt.Fprintln(d.Stderr, "")
		fmt.Fprintln(d.Stderr, "==> sysctl step failed — install completed but tuning not applied.")
		fmt.Fprintf(d.Stderr, "       to revert everything: sudo bash %s\n", rollbackPath)
		fmt.Fprintln(d.Stderr, "       to retry just sysctl: sudo nginx-gen --sysctl --force")
		return code
	}

	fmt.Fprintln(d.Stderr, "")
	fmt.Fprintln(d.Stderr, "==> conversion complete.")
	fmt.Fprintln(d.Stderr, "")
	fmt.Fprintln(d.Stderr, "  Custom http-scope directives (map/geo/log_format/upstream) you had")
	fmt.Fprintln(d.Stderr, "  in /etc/nginx/nginx.conf are NOT carried over automatically. Recover")
	fmt.Fprintln(d.Stderr, "  them from the snapshot and drop into /etc/nginx/conf.d/*.conf:")
	fmt.Fprintf(d.Stderr, "       less %s/etc-nginx/nginx.conf\n", backupDir)
	fmt.Fprintln(d.Stderr, "")
	fmt.Fprintln(d.Stderr, "  Diff against pre-conversion view:")
	fmt.Fprintf(d.Stderr, "       diff %s/nginx-T.before.txt <(nginx -T 2>/dev/null)\n", backupDir)
	fmt.Fprintln(d.Stderr, "")
	fmt.Fprintf(d.Stderr, "  Rollback (if anything is broken): sudo bash %s\n", rollbackPath)

	logEvent(d.Stderr, d.Now(), "convert", "", map[string]any{
		"backup":     backupDir,
		"rollback":   rollbackPath,
		"channel":    channelStr,
		"brotli":     brotliMode.String(),
		"prev_nginx": prevPkgVer,
		"result":     "ok",
	})
	return exitOK
}

// writeConvertInventory walks sites-available/, conf.d/, snippets/ and
// records which files lack our marker (i.e. operator-owned, will keep
// working). Returns the inventory file path or "" on failure.
func writeConvertInventory(backupDir string) string {
	var b bytes.Buffer
	for _, dir := range []string{
		"/etc/nginx/sites-available", "/etc/nginx/sites-enabled",
		"/etc/nginx/conf.d", "/etc/nginx/snippets",
	} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			path := filepath.Join(dir, e.Name())
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			tag := "unmanaged"
			if bytes.HasPrefix(data, []byte(marker.FirstLine)) {
				tag = "managed"
			}
			fmt.Fprintf(&b, "%-9s %s\n", tag, path)
		}
	}
	if b.Len() == 0 {
		return ""
	}
	out := filepath.Join(backupDir, "files-inventory.txt")
	if err := os.WriteFile(out, b.Bytes(), 0644); err != nil {
		return ""
	}
	return out
}

// writeRollbackScript emits an executable script that restores /etc/nginx
// from the snapshot, removes the nginx.org apt repo files, and reinstalls
// the previously-pinned nginx version (if known). Idempotent.
func writeRollbackScript(path, backupDir, prevPkgVer string) error {
	pinClause := ""
	if prevPkgVer != "" {
		pinClause = fmt.Sprintf("=%s", prevPkgVer)
	}
	content := fmt.Sprintf(`#!/usr/bin/env bash
# Generated by nginx-gen --convert.
# Restores /etc/nginx and the previously-installed nginx package.
# Idempotent: safe to rerun.

set -euo pipefail

BACKUP=%q
PREV_PKG=%q

if [[ ! -d "$BACKUP/etc-nginx" ]]; then
    echo "ERROR: snapshot not found at $BACKUP/etc-nginx" >&2
    exit 1
fi

echo "==> stopping nginx (if running)"
systemctl stop nginx 2>/dev/null || true

echo "==> removing nginx.org apt source + pin"
rm -f /etc/apt/sources.list.d/nginx.list
rm -f /etc/apt/preferences.d/99nginx
# Keyring left in place — harmless and reusable.

echo "==> restoring /etc/nginx from snapshot"
# Move (not delete) current state aside as a second-level safety net.
if [[ -d /etc/nginx ]]; then
    mv /etc/nginx "/etc/nginx.rolled-back.$(date +%%s)"
fi
cp -a "$BACKUP/etc-nginx" /etc/nginx

echo "==> apt update + reinstalling nginx${PREV_PKG:+ ($PREV_PKG)}"
apt-get update
# --allow-downgrades because the nginx.org version installed by --convert
# is likely newer than the Debian package we're restoring.
if [[ -n "$PREV_PKG" ]]; then
    apt-get install -y --allow-downgrades --reinstall "nginx=$PREV_PKG"
else
    apt-get install -y --reinstall nginx
fi

echo "==> validating restored config"
nginx -t

echo "==> starting nginx"
systemctl start nginx

echo "rollback complete. Pre-conversion state restored."
`, backupDir, pinClause)
	return os.WriteFile(path, []byte(content), 0755)
}

func printConvertRecipe(w io.Writer, channelStr string, mode BrotliMode) {
	fmt.Fprintln(w, "# would migrate an existing nginx install to nginx-gen's managed setup")
	fmt.Fprintln(w, "mkdir -p "+convertBackupRoot+"/<TS>")
	fmt.Fprintln(w, "cp -a /etc/nginx          → <backup>/etc-nginx/")
	fmt.Fprintln(w, "nginx -T                  → <backup>/nginx-T.before.txt")
	fmt.Fprintln(w, "dpkg-query nginx version  → <backup>/nginx-pkg-version.before.txt")
	fmt.Fprintln(w, "[managed/unmanaged file inventory] → <backup>/files-inventory.txt")
	fmt.Fprintln(w, "write executable rollback script   → <backup>/rollback.sh")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "==> step 1/2: --install (channel="+channelStr+", brotli="+mode.String()+")")
	fmt.Fprintln(w, "==> step 2/2: --sysctl --force")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "on any step failure: prints `sudo bash <backup>/rollback.sh` prominently")
	fmt.Fprintln(w, "vhost files in sites-enabled/ are NOT rewritten; they keep working as-is")
}

// ---- bootstrap ----

// runBootstrap is the first-time-host setup: --install then --sysctl,
// sharing the same channel/brotli/dry-run/force flags. Each step takes its
// own flock; sequencing is fine because they're not nested.
func runBootstrap(d Deps, channelStr string, brotliMode BrotliMode, dryRun, force, noReload bool) int {
	fmt.Fprintln(d.Stderr, "==> step 1/2: install (nginx, managed nginx.conf, brotli="+brotliMode.String()+")")
	if code := runInstall(d, channelStr, brotliMode, dryRun, force); code != exitOK {
		return code
	}
	fmt.Fprintln(d.Stderr, "==> step 2/2: sysctl tuning + systemd LimitNOFILE override")
	if code := runSysctl(d, force, dryRun, noReload); code != exitOK {
		return code
	}
	logEvent(d.Stderr, d.Now(), "bootstrap", "", map[string]any{
		"channel": channelStr,
		"brotli":  brotliMode.String(),
		"result":  "ok",
	})
	return exitOK
}

// ---- install ----

const (
	nginxOrgKeyURL      = "https://nginx.org/keys/nginx_signing.key"
	nginxOrgKeyring     = "/usr/share/keyrings/nginx-archive-keyring.gpg"
	nginxOrgSourcesList = "/etc/apt/sources.list.d/nginx.list"
	nginxOrgPrefs       = "/etc/apt/preferences.d/99nginx"
	upstreamStubConf    = "/etc/nginx/conf.d/default.conf"
)

type nginxChannel string

const (
	channelMainline nginxChannel = "mainline"
	channelStable   nginxChannel = "stable"
)

func parseChannel(s string) (nginxChannel, error) {
	switch strings.ToLower(s) {
	case "", "mainline":
		return channelMainline, nil
	case "stable":
		return channelStable, nil
	}
	return "", fmt.Errorf("invalid --channel %q (want mainline|stable)", s)
}

// nginxOrgAptURL returns the apt repo base URL for the given channel.
// Mainline lives under /packages/mainline/debian; stable under /packages/debian.
func (c nginxChannel) aptURL() string {
	if c == channelStable {
		return "https://nginx.org/packages/debian"
	}
	return "https://nginx.org/packages/mainline/debian"
}

// runInstall bootstraps a fresh nginx host. Idempotent: rerunning is safe
// (apt skips already-current packages, writes are content-stable, dirs
// already exist). On hosts where nginx is from Debian's apt, switching to
// nginx.org via --install will trigger an apt upgrade — that is the user's
// explicit intent when they invoke this with --channel=mainline.
func runInstall(d Deps, channelStr string, brotliMode BrotliMode, dryRun, userForce bool) int {
	channel, err := parseChannel(channelStr)
	if err != nil {
		fmt.Fprintln(d.Stderr, err)
		return exitUserError
	}

	if dryRun {
		printInstallRecipe(d.Stdout, channel, brotliMode)
		return exitOK
	}

	if os.Geteuid() != 0 {
		fmt.Fprintln(d.Stderr, "--install requires root (apt-get + writes to /etc)")
		return exitUserError
	}

	fmt.Fprintln(d.Stderr, "configuring nginx.org apt repo (channel="+string(channel)+")...")
	if err := ensureNginxOrgRepo(d, channel, userForce); err != nil {
		fmt.Fprintln(d.Stderr, "repo setup:", err)
		return exitSystemErr
	}

	fmt.Fprintln(d.Stderr, "updating apt index...")
	if out, err := d.Exec.RunEnv("apt-get",
		[]string{"DEBIAN_FRONTEND=noninteractive"}, "update"); err != nil {
		fmt.Fprintln(d.Stderr, "apt-get update failed:", err)
		fmt.Fprintln(d.Stderr, strings.TrimSpace(string(out)))
		return exitSystemErr
	}

	fmt.Fprintln(d.Stderr, "installing nginx...")
	if out, err := d.Exec.RunEnv("apt-get",
		[]string{"DEBIAN_FRONTEND=noninteractive"},
		"install", "-y", "nginx"); err != nil {
		fmt.Fprintln(d.Stderr, "apt-get install nginx failed:", err)
		fmt.Fprintln(d.Stderr, strings.TrimSpace(string(out)))
		return exitSystemErr
	}

	// Upstream ships a stub server in conf.d/default.conf that listens on :80
	// with server_name localhost. Our managed nginx.conf doesn't include
	// conf.d/, so the stub is silently ignored — but leaving it on disk
	// confuses future operators. Remove it.
	if err := os.Remove(upstreamStubConf); err == nil {
		fmt.Fprintln(d.Stderr, "removed upstream stub:", upstreamStubConf)
	} else if !errors.Is(err, fs.ErrNotExist) {
		fmt.Fprintln(d.Stderr, "warning: could not remove", upstreamStubConf, ":", err)
	}

	for _, dir := range []string{
		d.Layout.SitesAvailable, d.Layout.SitesEnabled,
		d.Layout.ModulesDir, d.Layout.ModulesEnabledDir,
	} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			fmt.Fprintln(d.Stderr, "mkdir", dir, ":", err)
			return exitSystemErr
		}
	}

	// First render: skip brotli unconditionally when the user passed
	// --brotli=on, because the module isn't built yet and passing BrotliOn
	// into runMain would trigger an apt brotli install (guaranteed to fail
	// on nginx.org due to ABI mismatch). We re-render with BrotliOn AFTER
	// --brotli-build completes below.
	// force=true: the file we are overwriting was just placed there by apt
	// and lacks our marker. noReload=true: we restart ourselves at the end.
	firstPassMode := brotliMode
	if brotliMode == BrotliOn {
		firstPassMode = BrotliOff
	}
	if code := runMain(d, true, false, true, firstPassMode); code != exitOK {
		return code
	}

	// --brotli=on: ensure the module is present (build from source if not —
	// the only path that works on nginx.org, where Debian's pre-built brotli
	// packages are ABI-incompatible), then re-render so the brotli
	// directives actually appear in nginx.conf. The re-render runs
	// unconditionally on rerun even if the module is already loaded —
	// otherwise the first-pass BrotliOff render would be the final state
	// and the loaded module would sit there inert.
	if brotliMode == BrotliOn {
		if !brotliModuleLoaded(d.Layout.ModulesEnabledDir) {
			fmt.Fprintln(d.Stderr, "compiling brotli module against the just-installed nginx...")
			if code := runBrotliBuild(d, userForce, false); code != exitOK {
				return code
			}
		}
		if code := runMain(d, true, false, true, BrotliOn); code != exitOK {
			return code
		}
	}

	// Validate the assembled config before we drop service via restart.
	// All embedded runMain calls above used noReload=true to avoid a
	// premature reload (load_module changes require restart, not reload),
	// so this is the first `nginx -t` against the final on-disk state.
	// Without this, a broken combination would only surface as a failed
	// restart with nginx already down.
	if err := nginx.Test(d.Exec); err != nil {
		fmt.Fprintln(d.Stderr, "config validation failed before restart:", err)
		return exitValidation
	}

	if out, err := d.Exec.Run("systemctl", "enable", "--now", "nginx"); err != nil {
		fmt.Fprintln(d.Stderr, "systemctl enable --now nginx failed:", err)
		fmt.Fprintln(d.Stderr, strings.TrimSpace(string(out)))
		return exitSystemErr
	}
	if out, err := d.Exec.Run("systemctl", "restart", "nginx"); err != nil {
		fmt.Fprintln(d.Stderr, "systemctl restart nginx failed:", err)
		fmt.Fprintln(d.Stderr, strings.TrimSpace(string(out)))
		return exitSystemErr
	}

	logEvent(d.Stderr, d.Now(), "install", "", map[string]any{
		"channel": string(channel),
		"brotli":  brotliMode.String(),
		"result":  "ok",
	})
	return exitOK
}

// ensureNginxOrgRepo writes the apt key, sources list, and pin preference
// for the nginx.org repo. File writes are content-stable so reruns are no-ops
// (apt-get update won't re-fetch identical InRelease).
func ensureNginxOrgRepo(d Deps, channel nginxChannel, force bool) error {
	// gnupg + curl + ca-certificates are required for key handling on a
	// minimal Debian. apt-get install is fast/idempotent.
	if out, err := d.Exec.RunEnv("apt-get",
		[]string{"DEBIAN_FRONTEND=noninteractive"},
		"install", "-y", "curl", "ca-certificates", "gnupg"); err != nil {
		return fmt.Errorf("install repo prereqs: %w\n%s", err, strings.TrimSpace(string(out)))
	}

	if _, err := os.Stat(nginxOrgKeyring); err != nil || force {
		// curl | gpg --dearmor → one pipeline. sh -c is intentional here:
		// avoids buffering the ASCII-armored key through Go.
		// --yes: gpg refuses overwrites by default; without it `--force`
		// reruns blockingly prompt "Overwrite? (y/N)" on a non-TTY.
		cmd := fmt.Sprintf("curl -fsSL %q | gpg --dearmor --yes -o %q",
			nginxOrgKeyURL, nginxOrgKeyring)
		if out, err := d.Exec.Run("sh", "-c", cmd); err != nil {
			return fmt.Errorf("fetch nginx signing key: %w\n%s", err, strings.TrimSpace(string(out)))
		}
	}

	codename, err := debianCodename(d.Exec)
	if err != nil {
		return fmt.Errorf("detect distro codename: %w", err)
	}

	sourcesContent := fmt.Sprintf("deb [signed-by=%s] %s %s nginx\n",
		nginxOrgKeyring, channel.aptURL(), codename)
	if err := os.WriteFile(nginxOrgSourcesList, []byte(sourcesContent), 0644); err != nil {
		return fmt.Errorf("write %s: %w", nginxOrgSourcesList, err)
	}

	// Pin priority 900 → prefers nginx.org over Debian's nginx when both
	// repos provide the package. Without this, apt may stick on Debian's
	// older version after the user adds the nginx.org repo.
	prefsContent := "Package: *\nPin: origin nginx.org\nPin-Priority: 900\n"
	if err := os.WriteFile(nginxOrgPrefs, []byte(prefsContent), 0644); err != nil {
		return fmt.Errorf("write %s: %w", nginxOrgPrefs, err)
	}
	return nil
}

// debianCodename returns the distro codename (e.g. "trixie", "bookworm").
// lsb_release is not always installed; fall back to /etc/os-release.
func debianCodename(exec nginx.Execer) (string, error) {
	if out, err := exec.Run("lsb_release", "-cs"); err == nil {
		if c := strings.TrimSpace(string(out)); c != "" {
			return c, nil
		}
	}
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return "", err
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		if v, ok := strings.CutPrefix(line, "VERSION_CODENAME="); ok {
			return strings.Trim(v, `"`), nil
		}
	}
	return "", fmt.Errorf("VERSION_CODENAME not in /etc/os-release")
}

func printInstallRecipe(w io.Writer, channel nginxChannel, mode BrotliMode) {
	fmt.Fprintln(w, "# would install nginx from nginx.org channel="+string(channel))
	fmt.Fprintln(w, "apt-get install -y curl ca-certificates gnupg")
	fmt.Fprintf(w, "curl -fsSL %s | gpg --dearmor -o %s\n", nginxOrgKeyURL, nginxOrgKeyring)
	fmt.Fprintf(w, "write %s   # deb [signed-by=...] %s <codename> nginx\n", nginxOrgSourcesList, channel.aptURL())
	fmt.Fprintf(w, "write %s   # pin: origin nginx.org priority 900\n", nginxOrgPrefs)
	fmt.Fprintln(w, "apt-get update")
	fmt.Fprintln(w, "apt-get install -y nginx")
	fmt.Fprintf(w, "rm %s   # remove upstream stub server\n", upstreamStubConf)
	fmt.Fprintln(w, "mkdir -p /etc/nginx/{sites-available,sites-enabled,modules,modules-enabled}")
	fmt.Fprintln(w, "render /etc/nginx/nginx.conf via --main (brotli="+mode.String()+")")
	if mode == BrotliOn {
		fmt.Fprintln(w, "[--brotli=on] would also chain --brotli-build if module is absent")
	}
	fmt.Fprintln(w, "systemctl enable --now nginx && systemctl restart nginx")
}

// ---- brotli module ----

// BrotliMode controls whether the rendered main config emits brotli
// directives and whether nginx-gen will attempt to install them.
type BrotliMode int

const (
	BrotliAuto BrotliMode = iota // try to install; render with brotli iff available
	BrotliOn                     // require brotli; abort if it cannot be made available
	BrotliOff                    // render without brotli; never touch apt
)

func (m BrotliMode) String() string {
	switch m {
	case BrotliAuto:
		return "auto"
	case BrotliOn:
		return "on"
	case BrotliOff:
		return "off"
	}
	return "unknown"
}

func parseBrotliMode(s string) (BrotliMode, error) {
	switch strings.ToLower(s) {
	case "", "auto":
		return BrotliAuto, nil
	case "on", "true", "1", "yes":
		return BrotliOn, nil
	case "off", "false", "0", "no":
		return BrotliOff, nil
	}
	return 0, fmt.Errorf("invalid --brotli value %q (want auto|on|off)", s)
}

// brotliPackages: Debian/Ubuntu split packages. A wrapper metapackage
// (libnginx-mod-brotli) exists on some distros but isn't universal —
// installing the two split packages directly works everywhere apt does.
var brotliPackages = []string{
	"libnginx-mod-http-brotli-filter",
	"libnginx-mod-http-brotli-static",
}

// brotliModuleLoaded reports whether nginx will load the brotli module on
// startup — detected by a load_module conf in the modules-enabled dir.
// Custom builds that compile brotli in statically aren't detected here;
// those operators can edit the template directly.
func brotliModuleLoaded(modulesEnabledDir string) bool {
	matches, _ := filepath.Glob(filepath.Join(modulesEnabledDir, "*brotli*.conf"))
	return len(matches) > 0
}

// resolveBrotli decides whether to render brotli directives. The second
// return is true when the caller should abort (e.g. --brotli=on but install
// is impossible). For --brotli=auto, dry-run reflects the current host —
// rendering brotli the real apply wouldn't install would mislead the
// operator (e.g. on non-apt distros).
func resolveBrotli(d Deps, mode BrotliMode, dryRun bool) (enabled, hardErr bool) {
	switch mode {
	case BrotliOff:
		return false, false
	case BrotliOn:
		if brotliModuleLoaded(d.Layout.ModulesEnabledDir) {
			return true, false
		}
		if dryRun {
			fmt.Fprintln(d.Stderr, "note: --brotli=on with --dry-run; rendering with brotli (install would run on a real apply).")
			return true, false
		}
		if ensureBrotli(d) {
			return true, false
		}
		fmt.Fprintln(d.Stderr, "error: --brotli=on but the brotli module could not be installed. Use --brotli=auto to fall back, or --brotli=off to skip.")
		return false, true
	default: // BrotliAuto
		if brotliModuleLoaded(d.Layout.ModulesEnabledDir) {
			return true, false
		}
		if dryRun {
			return false, false
		}
		return ensureBrotli(d), false
	}
}

// brotliABIRequired extracts the `nginx-abi-X.Y.Z-N` virtual-package
// dependency the brotli filter package declares. Empty string means we
// couldn't determine it (apt-cache missing, package not in index, etc).
var brotliABIRE = regexp.MustCompile(`(?m)Depends:\s+(nginx-abi-\S+)`)

func brotliABIRequired(exec nginx.Execer) string {
	out, err := exec.Run("apt-cache", "depends", brotliPackages[0])
	if err != nil {
		return ""
	}
	m := brotliABIRE.FindSubmatch(out)
	if m == nil {
		return ""
	}
	return string(m[1])
}

// nginxProvidesABI returns the set of virtual packages provided by the
// installed nginx (the `Provides:` field, e.g. "nginx-abi-1.26.3-1, httpd").
// Returns (nil, false) only if dpkg-query itself errored (nginx not installed
// via dpkg, or dpkg-query missing). An empty `Provides:` field — common for
// the nginx.org package, which doesn't declare any virtuals — is conclusive
// evidence the package provides nothing, NOT inconclusive; that maps to
// (emptySet, true) so the caller treats it as "no ABI match".
// Set membership rather than substring-matching avoids `nginx-abi-1.26.3-1`
// false-positiving against `nginx-abi-1.26.3-10`.
func nginxProvidesABI(exec nginx.Execer) (map[string]struct{}, bool) {
	out, err := exec.Run("dpkg-query", "-W", "-f=${Provides}", "nginx")
	if err != nil {
		return nil, false
	}
	set := make(map[string]struct{})
	for p := range strings.SplitSeq(string(out), ",") {
		if p = strings.TrimSpace(p); p != "" {
			set[p] = struct{}{}
		}
	}
	return set, true
}

// ensureBrotli returns true if the brotli dynamic module is loaded after a
// best-effort apt-get install. On non-apt hosts or install failure, returns
// false and emits a warning — runMain then renders without brotli so
// `nginx -t` still passes.
//
// Before invoking apt-get we probe the ABI compatibility between the
// Debian-packaged brotli modules and the installed nginx. The Debian
// packages hard-pin to a specific `nginx-abi-X.Y.Z-N` virtual package; the
// upstream nginx.org packages don't provide that virtual, so the solver
// cannot satisfy the dependency. Detecting this up-front skips a slow,
// always-failing apt-get run and produces a clearer message.
//
// DEBIAN_FRONTEND=noninteractive prevents apt from blocking on debconf
// prompts (which -y does NOT suppress) when invoked from systemd units,
// CI, or other non-TTY contexts.
func ensureBrotli(d Deps) bool {
	if brotliModuleLoaded(d.Layout.ModulesEnabledDir) {
		return true
	}
	if required := brotliABIRequired(d.Exec); required != "" {
		if provides, ok := nginxProvidesABI(d.Exec); ok {
			if _, has := provides[required]; !has {
				have := make([]string, 0, len(provides))
				for p := range provides {
					have = append(have, p)
				}
				slices.Sort(have)
				fmt.Fprintf(d.Stderr, "warning: brotli unavailable: Debian brotli packages require %s but installed nginx provides %v\n", required, have)
				fmt.Fprintln(d.Stderr, "       this commonly means nginx was installed from nginx.org instead of Debian.")
				fmt.Fprintln(d.Stderr, "       rendering nginx.conf without brotli; pass --brotli=off to silence this.")
				return false
			}
		}
	}
	args := append([]string{"install", "-y"}, brotliPackages...)
	fmt.Fprintln(d.Stderr, "installing brotli packages via apt-get (this may take a moment)...")
	out, err := d.Exec.RunEnv("apt-get", []string{"DEBIAN_FRONTEND=noninteractive"}, args...)
	if err != nil {
		fmt.Fprintln(d.Stderr, "warning: brotli auto-install failed; rendering nginx.conf without brotli")
		fmt.Fprintln(d.Stderr, "       hint: if packages can't be located, run 'apt-get update' first")
		fmt.Fprintln(d.Stderr, "apt-get output:", strings.TrimSpace(string(out)))
		return false
	}
	if !brotliModuleLoaded(d.Layout.ModulesEnabledDir) {
		fmt.Fprintln(d.Stderr, "warning: brotli module not present after install; rendering nginx.conf without brotli")
		return false
	}
	return true
}

// ---- legacy migration ----

// TODO: drop after all known hosts have been re-deployed with a post-migration
// binary. Delete migrateLegacyAllowConf, neutralizeLegacy, legacyMarker, and
// the bytes import (bytes.HasPrefix is used only here).

const legacyMarker = "# MIGRATED-PLACEHOLDER:"

func migrateLegacyAllowConf(stderr io.Writer) {
	for _, p := range []string{
		"/etc/nginx/conf.d/cf.conf", // pre-fix; auto-included → denies globally
		"/etc/nginx/cf.conf",        // interim path between bug-fix pass and rewrite
	} {
		neutralizeLegacy(p, stderr)
	}
}

func neutralizeLegacy(path string, stderr io.Writer) {
	b, err := os.ReadFile(path)
	if err != nil {
		return // missing; nothing to do
	}
	if bytes.HasPrefix(b, []byte(legacyMarker)) {
		return // already migrated; stay quiet
	}
	placeholder := []byte(legacyMarker + " cf.conf moved to " + cf.DefaultSnippet + ".\n" +
		"# Re-deploy any vhost that still includes this path to restore its allow-list.\n")
	if err := os.WriteFile(path, placeholder, 0644); err != nil {
		fmt.Fprintln(stderr, "warning: could not neutralize legacy", path, ":", err)
		return
	}
	fmt.Fprintln(stderr, "NOTE: legacy", path, "neutralized; re-deploy any vhost that included it.")
}

// ---- log ----

func logEvent(w io.Writer, t time.Time, action, host string, extra map[string]any) {
	rec := map[string]any{
		"ts":     t.UTC().Format(time.RFC3339),
		"action": action,
	}
	if host != "" {
		rec["host"] = host
	}
	maps.Copy(rec, extra)
	if b, err := json.Marshal(rec); err == nil {
		fmt.Fprintln(w, string(b))
	}
}
