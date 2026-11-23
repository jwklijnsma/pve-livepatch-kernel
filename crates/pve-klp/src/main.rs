use std::path::PathBuf;
use std::process::{Command, ExitCode};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use klp_core::sig::TrustStore;
use pve_klp::agent::{Agent, ApplyOpts, Outcome};
use pve_klp::check::{self, Checker, Level};
use pve_klp::config::{Config, DEFAULT_CONFIG};
use pve_klp::linux::LinuxKernel;
use pve_klp::lock::Lock;
use pve_klp::{repo, report};

#[derive(Parser)]
#[command(name = "pve-klp", version, about = "Verify and load kernel livepatches on Proxmox VE hosts")]
struct Cli {
    /// Configuration file.
    #[arg(long, global = true, env = "PVE_KLP_CONFIG", default_value = DEFAULT_CONFIG)]
    config: PathBuf,
    /// Only print errors.
    #[arg(short, long, global = true)]
    quiet: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
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
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => ExitCode::from(code as u8),
        Err(e) => {
            eprintln!("pve-klp: error: {e:#}");
            ExitCode::from(1)
        }
    }
}

fn build_agent(cfg: Config, quiet: bool) -> Result<Agent<LinuxKernel>> {
    let trust = TrustStore::load_dir(&cfg.trusted_keys_dir)?;
    let repo = if cfg.repository.trim().is_empty() { None } else { Some(repo::open(&cfg)?) };
    let mut agent = Agent::new(cfg, LinuxKernel::default(), repo, trust);
    agent.echo = !quiet;
    Ok(agent)
}

fn write_textfile(agent: &Agent<LinuxKernel>) {
    if let Some(dir) = &agent.cfg.textfile_dir
        && let Err(e) = report::collect(agent).and_then(|r| r.write_textfile(dir))
    {
        eprintln!("pve-klp: warning: textfile: {e:#}");
    }
}

fn run(cli: Cli) -> Result<i32> {
    let cfg = Config::load(&cli.config)?;
    match cli.cmd {
        Cmd::Check { json } => {
            let agent = build_agent(cfg, true)?;
            let items = Checker { agent: &agent, root: "/".into() }.run();
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
            let agent = build_agent(cfg, true)?;
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
            let _lock = Lock::acquire(&cfg.lock_file())?;
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
                .args([verb, "--now", "pve-klp-auto.timer"])
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
            if check::mok_enrolled(&cert) == Some(true) {
                println!("{} is already enrolled", cert.display());
                return Ok(0);
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

fn finish(res: Result<Outcome, pve_klp::agent::ApplyError>) -> Result<i32> {
    match res {
        Ok(o) => {
            let msg = match o {
                Outcome::Applied { level, .. } => format!("level {level} applied"),
                Outcome::AlreadyActive { level } => format!("level {level} already active"),
                Outcome::Skipped(why) => format!("skipped: {why}"),
                Outcome::NothingPublished => "no livepatch published for this kernel".into(),
                Outcome::NothingToLoad => "nothing to reload".into(),
                Outcome::Reverted { levels } => format!("reverted level(s) {levels:?}; on hold until `pve-klp apply`"),
                Outcome::NothingActive => "no livepatch active; on hold until `pve-klp apply`".into(),
            };
            println!("{msg}");
            Ok(0)
        }
        Err(e) => {
            eprintln!("pve-klp: {e}");
            Ok(e.exit_code())
        }
    }
}
