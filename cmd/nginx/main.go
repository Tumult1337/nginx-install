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
	"slices"
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
	}
}

type Deps struct {
	Layout       Layout
	Exec         nginx.Execer
	HTTP         cf.HTTPGetter
	Now          func() time.Time
	Stdout       io.Writer
	Stderr       io.Writer
	NginxVersion func() (nginx.VersionInfo, error)
}

func DefaultDeps() Deps {
	exec := nginx.RealExecer{}
	return Deps{
		Layout: DefaultLayout(),
		Exec:   exec,
		HTTP:   cf.DefaultConfig().HTTP,
		Now:    time.Now,
		Stdout: os.Stdout,
		Stderr: os.Stderr,
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
	useSSL   := fs.Bool("ssl", true, "enable SSL listener (HTTP→HTTPS redirect + 443)")
	allowFlag := fs.String("allow", "", "cf | comma-separated CIDRs (or bare IPs)")
	dryRun   := fs.Bool("dry-run", false, "print rendered config to stdout, no FS changes")
	noReload := fs.Bool("no-reload", false, "skip nginx -t and systemctl reload")
	force    := fs.Bool("force", false, "overwrite files lacking the managed marker")
	certDir  := fs.String("cert-dir", "", "override cert lookup base (default: $NGINX_CERT_DIR or /etc/letsencrypt/live)")

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
		return runMain(d, *force, *dryRun, *noReload)
	case *doSysctl:
		if len(pos) != 0 {
			fmt.Fprintln(d.Stderr, "usage: nginx-gen --sysctl  (no positional args)")
			return exitUserError
		}
		return runSysctl(d, *force, *dryRun, *noReload)
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
	fmt.Fprintln(w, "  nginx-gen --main")
	fmt.Fprintln(w, "  nginx-gen --remove <host>")
	fmt.Fprintln(w, "  nginx-gen --list")
	fmt.Fprintln(w, "  nginx-gen --sysctl  [--force] [--dry-run] [--no-reload]")
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

func runMain(d Deps, force, dryRun, noReload bool) int {
	migrateLegacyAllowConf(d.Stderr)
	rendered, err := render.Main(d.Now())
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
