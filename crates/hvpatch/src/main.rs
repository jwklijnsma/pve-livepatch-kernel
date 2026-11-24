use std::path::PathBuf;
use std::process::{Command, ExitCode};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use hvpatch::agent::{Agent, ApplyOpts, Outcome};
use hvpatch::check::{self, Checker, Level};
use hvpatch::config::{Config, DEFAULT_CONFIG};
use hvpatch::linux::LinuxKernel;
use hvpatch::lock::Lock;
use hvpatch::{repo, report};
use klp_core::sig::TrustStore;

#[derive(Parser)]
#[command(name = "hvpatch", version, about = "Verify and load kernel livepatches on Proxmox VE hosts")]
struct Cli {
    /// Configuration file.
    #[arg(long, global = true, env = "HVPATCH_CONFIG", default_value = DEFAULT_CONFIG)]
    config: PathBuf,
    /// Only print errors.
    #[arg(short, long, global = true)]
    quiet: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Configure repository, ring and trusted key, then run `check`.
    Setup {
        /// Release repository, e.g. https://klp.example.org or /srv/klp.
        /// Required the first time; kept when omitted later.
        #[arg(long)]
        repository: Option<String>,
        /// Release ring of this node (canary, early, stable). Kept when
        /// omitted; `stable` on first setup.
        #[arg(long, value_parser = ["canary", "early", "stable"])]
        ring: Option<String>,
        /// Manifest signing key: a minisign public key file, or an https URL.
        #[arg(long)]
        key: Option<String>,
        /// Name under which the key is stored in trusted.d.
        #[arg(long, default_value = "repository")]
        key_name: String,
    },
    /// Check prerequisites: kernel config, Secure Boot / MOK, keys, repository.
    Check {
        #[arg(long)]
        json: bool,
    },
    /// Show running kernel, active livepatch, covered and uncovered CVEs.
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Fetch, verify and load the livepatch for the running kernel.
    Apply {
        /// Only apply if the repository offers exactly this level.
        #[arg(long)]
        level: Option<u32>,
        /// Also replace livepatches that were not built by this project.
        #[arg(long)]
        replace_foreign: bool,
        /// Run from the timer: respects a hold set by `revert`.
        #[arg(long, hide = true)]
        timer: bool,
    },
    /// Reload the previously active livepatch from cache (boot unit).
    Boot,
    /// Disable and unload the active livepatch and put the node on hold.
    Revert,
    /// Enable or disable the timer that applies new levels automatically.
    Auto {
        #[arg(value_parser = ["enable", "disable"])]
        action: String,
    },
    /// Enroll the module signing certificate as Machine Owner Key.
    Mok {
        #[arg(value_parser = ["enroll"])]
        action: String,
    },
    /// Print a shell completion script (used by the package build).
    #[command(hide = true)]
    Completions { shell: clap_complete::Shell },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => ExitCode::from(code as u8),
        Err(e) => {
            eprintln!("hvpatch: error: {e:#}");
            ExitCode::from(1)
        }
    }
}

/// Root of /proc, /sys and /boot. Read-only commands (status, check)
/// honour `HVPATCH_SYSROOT` so they can be tested against a prepared tree;
/// commands that load or unload modules always use the real system.
fn sysroot(read_only: bool) -> std::path::PathBuf {
    match std::env::var_os("HVPATCH_SYSROOT") {
        Some(r) if read_only && !r.is_empty() => r.into(),
        _ => "/".into(),
    }
}

fn build_agent(cfg: Config, quiet: bool) -> Result<Agent<LinuxKernel>> {
    build_agent_at(cfg, quiet, sysroot(false))
}

fn build_agent_at(cfg: Config, quiet: bool, root: std::path::PathBuf) -> Result<Agent<LinuxKernel>> {
    let (trust, warnings) = TrustStore::load_dir_lenient(&cfg.trusted_keys_dir)?;
    for w in warnings {
        eprintln!("hvpatch: warning: {w}");
    }
    let repo = if cfg.repository.trim().is_empty() { None } else { Some(repo::open(&cfg)?) };
    let mut agent = Agent::new(cfg, LinuxKernel::with_root(root), repo, trust);
    agent.echo = !quiet;
    Ok(agent)
}

fn write_textfile(agent: &Agent<LinuxKernel>) {
    if let Some(dir) = &agent.cfg.textfile_dir
        && let Err(e) = report::collect(agent).and_then(|r| r.write_textfile(dir))
    {
        eprintln!("hvpatch: warning: textfile: {e:#}");
    }
}

fn run(cli: Cli) -> Result<i32> {
    if let Cmd::Completions { shell } = cli.cmd {
        use clap::CommandFactory;
        clap_complete::generate(shell, &mut Cli::command(), "hvpatch", &mut std::io::stdout());
        return Ok(0);
    }
    if let Cmd::Setup { repository, ring, key, key_name } = &cli.cmd {
        return setup(&cli.config, repository.as_deref(), ring.as_deref(), key.as_deref(), key_name);
    }
    let cfg = Config::load(&cli.config)?;
    match cli.cmd {
        Cmd::Setup { .. } | Cmd::Completions { .. } => unreachable!("handled above"),
        Cmd::Check { json } => {
            let agent = build_agent_at(cfg, true, sysroot(true))?;
            let items = Checker { agent: &agent, root: sysroot(true) }.run();
            if json {
                println!("{}", serde_json::to_string_pretty(&items)?);
            } else {
                for i in &items {
                    let tag = match i.level {
                        Level::Ok => "  ok ",
                        Level::Info => " info",
                        Level::Warn => " WARN",
                        Level::Fail => " FAIL",
                    };
                    println!("{tag}  {:<18} {}", i.check, i.detail);
                }
            }
            Ok(match check::worst(&items) {
                Level::Fail => 2,
                Level::Warn => 1,
                _ => 0,
            })
        }
        Cmd::Status { json } => {
            let agent = build_agent_at(cfg, true, sysroot(true))?;
            let r = report::collect(&agent)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&r)?);
            } else {
                print!("{}", r.to_text());
            }
            if let Some(dir) = &agent.cfg.textfile_dir {
                let _ = r.write_textfile(dir);
            }
            Ok(r.exit_code())
        }
        Cmd::Apply { level, replace_foreign, timer } => {
            let _lock = Lock::acquire(&cfg.lock_file())?;
            let agent = build_agent(cfg, cli.quiet)?;
            let res = agent.apply(&ApplyOpts { level, replace_foreign, explicit: !timer });
            write_textfile(&agent);
            finish(res)
        }
        Cmd::Boot => {
            // The timer may be running: wait for it instead of giving up.
            let _lock = Lock::acquire_wait(&cfg.lock_file(), std::time::Duration::from_secs(cfg.boot_lock_wait))?;
            let agent = build_agent(cfg, cli.quiet)?;
            let res = agent.boot();
            write_textfile(&agent);
            finish(res)
        }
        Cmd::Revert => {
            let _lock = Lock::acquire(&cfg.lock_file())?;
            let agent = build_agent(cfg, cli.quiet)?;
            let res = agent.revert();
            write_textfile(&agent);
            finish(res)
        }
        Cmd::Auto { action } => {
            let verb = if action == "enable" { "enable" } else { "disable" };
            let st = Command::new("systemctl")
                .args([verb, "--now", "hvpatch-auto.timer"])
                .status()
                .context("running systemctl")?;
            if !st.success() {
                bail!("systemctl {verb} failed");
            }
            println!("automatic apply {verb}d (ring {})", cfg.ring);
            Ok(0)
        }
        Cmd::Mok { .. } => {
            let cert = cfg.module_cert.clone().context("no module_cert configured")?;
            if !cert.exists() {
                bail!("{} not found", cert.display());
            }
            match check::mok_state(&cert) {
                Some(check::MokState::Enrolled) => {
                    println!("{} is already enrolled", cert.display());
                    return Ok(0);
                }
                Some(check::MokState::Pending) => {
                    println!(
                        "{} is already imported: confirm the enrollment in MokManager on the next boot \
                         (console or BMC)",
                        cert.display()
                    );
                    return Ok(0);
                }
                _ => {}
            }
            println!(
                "Importing {} as Machine Owner Key. mokutil asks for a one-time password.\n\
                 On the next reboot, MokManager appears on the console (use BMC/IPMI or local access):\n\
                 choose \"Enroll MOK\", confirm and enter that password. Without this step the kernel\n\
                 keeps rejecting the livepatch modules while Secure Boot is on.",
                cert.display()
            );
            let st = Command::new("mokutil").arg("--import").arg(&cert).status().context("running mokutil")?;
            Ok(if st.success() { 0 } else { 1 })
        }
    }
}

fn setup(
    config: &std::path::Path,
    repository: Option<&str>,
    ring: Option<&str>,
    key: Option<&str>,
    key_name: &str,
) -> Result<i32> {
    use hvpatch::setup;
    let changes = setup::write_config(config, repository, ring)?;
    println!("{}:", config.display());
    for c in &changes {
        if c.changed() {
            let old = if c.old.is_empty() { "(unset)" } else { c.old.as_str() };
            println!("  {:<11} {} -> {}", c.key, old, c.new);
        } else {
            println!("  {:<11} {} (unchanged)", c.key, c.new);
        }
    }
    let cfg = Config::load(config)?;
    if let Some(k) = key {
        let text = if k.starts_with("https://") {
            fetch_text(k)?
        } else {
            std::fs::read_to_string(k).with_context(|| format!("reading {k}"))?
        };
        let id = setup::install_key(&cfg.trusted_keys_dir, key_name, &text)?;
        println!("installed manifest key {id} as {}/{key_name}.pub", cfg.trusted_keys_dir.display());
        println!("  compare this key id with the one published by the repository owner");
    }
    println!();
    let agent = build_agent(cfg, true)?;
    let items = Checker { agent: &agent, root: "/".into() }.run();
    let mut problems = 0;
    for i in items.iter().filter(|i| i.level >= Level::Warn) {
        problems += 1;
        println!("{}  {:<18} {}", if i.level == Level::Fail { " FAIL" } else { " WARN" }, i.check, i.detail);
    }
    if problems == 0 {
        println!("all checks passed.");
    }
    println!(
        "\nnext steps:\n  hvpatch apply          load the livepatch for this kernel now\n  \
         hvpatch status         see what is fixed and what still needs a reboot\n  \
         hvpatch auto enable    apply new levels automatically (hourly)"
    );
    Ok(if items.iter().any(|i| i.level == Level::Fail) { 2 } else { 0 })
}

#[cfg(feature = "http")]
fn fetch_text(url: &str) -> Result<String> {
    // https only, also across redirects: this fetches a trust anchor.
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .https_only(true)
        .timeout_global(Some(std::time::Duration::from_secs(60)))
        .build()
        .into();
    let mut resp = agent.get(url).call().with_context(|| format!("GET {url}"))?;
    Ok(resp.body_mut().with_config().limit(64 << 10).read_to_string()?)
}

#[cfg(not(feature = "http"))]
fn fetch_text(url: &str) -> Result<String> {
    bail!("built without https support; download {url} and pass the file instead")
}

fn finish(res: Result<Outcome, hvpatch::agent::ApplyError>) -> Result<i32> {
    match res {
        Ok(o) => {
            let msg = match o {
                Outcome::Applied { level, .. } => format!("level {level} applied"),
                Outcome::AlreadyActive { level } => format!("level {level} already active"),
                Outcome::Skipped(why) => format!("skipped: {why}"),
                Outcome::NothingPublished => "no livepatch published for this kernel".into(),
                Outcome::NothingToLoad => "nothing to reload".into(),
                Outcome::Reverted { levels } => format!("reverted level(s) {levels:?}; on hold until `hvpatch apply`"),
                Outcome::NothingActive => "no livepatch active; on hold until `hvpatch apply`".into(),
            };
            println!("{msg}");
            Ok(0)
        }
        Err(e) => {
            eprintln!("hvpatch: {e}");
            Ok(e.exit_code())
        }
    }
}
