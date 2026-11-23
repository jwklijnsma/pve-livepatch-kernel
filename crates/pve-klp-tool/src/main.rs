//! Build-side tooling. Used by the pipeline scripts in `builder/`.

mod catalog;
mod gate;
mod kconfig;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use chrono::{Duration, Utc};
use clap::{Parser, Subcommand};
use klp_core::manifest::{FORMAT_VERSION, Manifest, RINGS};
use klp_core::naming;
use klp_core::sig::{SecretKey, TrustStore};
use sha2::{Digest, Sha256};

#[derive(Parser)]
#[command(name = "pve-klp-tool", version, about = "Build-side tooling for pve-klp")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate a manifest signing key (minisign-compatible public key).
    Keygen {
        #[arg(long)]
        secret: PathBuf,
        #[arg(long)]
        public: PathBuf,
    },
    /// Sign a file; writes <file>.minisig.
    Sign {
        #[arg(long)]
        key: PathBuf,
        #[arg(long, default_value = "")]
        trusted_comment: String,
        file: PathBuf,
    },
    /// Verify <file>.minisig against one or more public keys.
    Verify {
        #[arg(long = "pubkey", required = true)]
        pubkeys: Vec<PathBuf>,
        file: PathBuf,
    },
    /// Print the module name for a kernel release and level.
    ModuleName {
        #[arg(long)]
        kernel: String,
        #[arg(long)]
        level: u32,
    },
    /// Compare the build tree's .config with the shipped /boot/config-<kver>.
    ConfigCheck {
        #[arg(long)]
        built: PathBuf,
        #[arg(long)]
        shipped: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Lint catalog entries (stage 0), optionally comparing patch-ids with upstream.
    Lint {
        #[arg(long, default_value = "catalog")]
        catalog: PathBuf,
        /// Upstream kernel git checkout for the patch-id comparison.
        #[arg(long)]
        upstream: Option<PathBuf>,
    },
    /// Resolve the catalog for one kernel: which patches go into the module.
    Resolve {
        #[arg(long, default_value = "catalog")]
        catalog: PathBuf,
        #[arg(long)]
        kernel: String,
        /// Patched kernel source tree to test-apply patches against.
        #[arg(long)]
        tree: Option<PathBuf>,
        /// Report non-applying patches as "not covered" instead of failing.
        #[arg(long)]
        allow_conflicts: bool,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Gate A: check a built module against the shipped kernel's artifacts.
    GateA {
        #[arg(long)]
        module: PathBuf,
        #[arg(long)]
        kernel: String,
        #[arg(long)]
        expected_name: Option<String>,
        #[arg(long)]
        system_map: PathBuf,
        #[arg(long)]
        symvers: PathBuf,
        #[arg(long)]
        modules_dir: Option<PathBuf>,
        /// Patched functions from `objtool klp diff` (object:function per line).
        #[arg(long)]
        functions: Option<PathBuf>,
        /// Resolved catalog; requires the patched functions to equal the
        /// reviewed `functions` of its entries.
        #[arg(long)]
        resolved: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Create a manifest for a built and signed module.
    Manifest {
        #[arg(long)]
        resolved: PathBuf,
        #[arg(long)]
        module: PathBuf,
        #[arg(long)]
        level: u32,
        #[arg(long)]
        ring: String,
        /// GNU build-id of the shipped vmlinux (from /sys/kernel/notes of a booted test VM).
        #[arg(long)]
        build_id: Option<String>,
        /// Patched functions from `objtool klp diff` (object:function per line).
        #[arg(long)]
        functions: PathBuf,
        #[arg(long, default_value_t = 30)]
        valid_days: i64,
        #[arg(long)]
        superseded_by: Option<String>,
        #[arg(long)]
        builder_image: Option<String>,
        #[arg(long)]
        catalog_commit: Option<String>,
        #[arg(long)]
        out: PathBuf,
    },
    /// Re-issue a manifest for another ring (promotion), same module and level.
    Promote {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        ring: String,
        #[arg(long)]
        out: PathBuf,
    },
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(e) => {
            eprintln!("pve-klp-tool: error: {e:#}");
            ExitCode::from(2)
        }
    }
}

fn read(p: &Path) -> Result<Vec<u8>> {
    std::fs::read(p).with_context(|| format!("reading {}", p.display()))
}

fn write(p: &Path, data: &[u8]) -> Result<()> {
    std::fs::write(p, data).with_context(|| format!("writing {}", p.display()))
}

fn sig_path(file: &Path) -> PathBuf {
    let mut s = file.as_os_str().to_owned();
    s.push(".minisig");
    s.into()
}

fn run(cli: Cli) -> Result<bool> {
    match cli.cmd {
        Cmd::Keygen { secret, public } => {
            if secret.exists() {
                bail!("{} exists; refusing to overwrite a key", secret.display());
            }
            let k = SecretKey::generate()?;
            {
                use std::io::Write;
                use std::os::unix::fs::OpenOptionsExt;
                let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&secret)?;
                f.write_all(k.to_file_string().as_bytes())?;
            }
            write(&public, k.public_key_file().as_bytes())?;
            println!("key id {}: secret {} (mode 0600), public {}", k.key_id(), secret.display(), public.display());
            Ok(true)
        }
        Cmd::Sign { key, trusted_comment, file } => {
            let k = SecretKey::from_file_string(&String::from_utf8(read(&key)?)?)?;
            let data = read(&file)?;
            let tc = if trusted_comment.is_empty() {
                format!(
                    "timestamp:{}\tfile:{}",
                    Utc::now().timestamp(),
                    file.file_name().unwrap_or_default().to_string_lossy()
                )
            } else {
                trusted_comment
            };
            write(&sig_path(&file), k.sign(&data, &tc)?.as_bytes())?;
            Ok(true)
        }
        Cmd::Verify { pubkeys, file } => {
            let mut store = TrustStore::default();
            for p in &pubkeys {
                store.add(&p.display().to_string(), &String::from_utf8(read(p)?)?)?;
            }
            let sig = String::from_utf8(read(&sig_path(&file))?)?;
            let k = store.verify(&read(&file)?, &sig)?;
            println!("good signature by {} ({})", k.name, k.key_id);
            Ok(true)
        }
        Cmd::ModuleName { kernel, level } => {
            println!("{}", naming::module_name(&kernel, level));
            Ok(true)
        }
        Cmd::ConfigCheck { built, shipped, json } => {
            let b = kconfig::parse(&String::from_utf8_lossy(&read(&built)?));
            let s = kconfig::parse(&String::from_utf8_lossy(&read(&shipped)?));
            let r = kconfig::compare(&b, &s);
            if json {
                println!("{}", serde_json::to_string_pretty(&r)?);
            } else {
                for p in &r.problems {
                    println!("PROBLEM {p}");
                }
                for d in &r.diffs {
                    println!(
                        "{} {}: built={} shipped={}",
                        if d.toolchain { "TOOLCHAIN" } else { "CONFIG   " },
                        d.key,
                        d.built.as_deref().unwrap_or("(unset)"),
                        d.shipped.as_deref().unwrap_or("(unset)")
                    );
                }
                println!("{}", if r.ok { "config and toolchain match" } else { "MISMATCH: do not build" });
            }
            Ok(r.ok)
        }
        Cmd::Lint { catalog: dir, upstream } => {
            let entries = catalog::load(&dir)?;
            let mut ok = true;
            for l in &entries {
                let mut problems = catalog::lint(l);
                if let Some(up) = &upstream
                    && let Some(p) = catalog::check_patch_id(l, up)?
                {
                    if l.entry.reason.trim().is_empty() {
                        problems.push(p);
                    } else {
                        println!("{}: note: {p}", l.entry.id);
                    }
                }
                for p in &problems {
                    println!("{}: {p}", l.entry.id);
                }
                ok &= problems.is_empty();
            }
            println!("{} entries, {}", entries.len(), if ok { "ok" } else { "problems found" });
            Ok(ok)
        }
        Cmd::Resolve { catalog: dir, kernel, tree, allow_conflicts, out } => {
            let entries = catalog::load(&dir)?;
            let r = catalog::resolve(&entries, &kernel, tree.as_deref(), allow_conflicts)?;
            let json = serde_json::to_string_pretty(&r)? + "\n";
            match out {
                Some(p) => write(&p, json.as_bytes())?,
                None => print!("{json}"),
            }
            Ok(true)
        }
        Cmd::GateA { module, kernel, expected_name, system_map, symvers, modules_dir, functions, resolved, json } => {
            let r = gate::run(&gate::Inputs {
                module: &module,
                kernel_release: &kernel,
                expected_name: expected_name.as_deref(),
                system_map: &system_map,
                symvers: &symvers,
                modules_dir: modules_dir.as_deref(),
                functions: functions.as_deref(),
                resolved: resolved.as_deref(),
            })?;
            if json {
                println!("{}", serde_json::to_string_pretty(&r)?);
            } else {
                for e in &r.errors {
                    println!("ERROR   {e}");
                }
                for w in &r.warnings {
                    println!("warning {w}");
                }
                println!(
                    "gate A {}: {} modversions, {} klp symbols, {} functions checked{}",
                    if r.ok { "passed" } else { "FAILED" },
                    r.checked_versions,
                    r.checked_klp_symbols,
                    r.checked_functions,
                    if r.compared_with_catalog { ", equal to the reviewed catalog" } else { "" }
                );
            }
            Ok(r.ok)
        }
        Cmd::Manifest {
            resolved,
            module,
            level,
            ring,
            build_id,
            functions,
            valid_days,
            superseded_by,
            builder_image,
            catalog_commit,
            out,
        } => {
            let r: catalog::Resolved = serde_json::from_slice(&read(&resolved)?).context("parsing resolved catalog")?;
            if r.fixes.is_empty() {
                bail!("the resolved catalog contains no fixes; nothing to publish");
            }
            let bytes = read(&module)?;
            if !klp_core::elf::has_module_signature(&bytes) {
                bail!("{} is not signed (scripts/sign-file); sign before creating the manifest", module.display());
            }
            let info = klp_core::elf::parse_modinfo(&bytes)?;
            let module_name = info.name().context("module has no name")?.to_owned();
            if module_name != naming::module_name(&r.kernel, level) {
                bail!(
                    "module name {module_name} does not match level {level} (expected {})",
                    naming::module_name(&r.kernel, level)
                );
            }
            let fixes = r.fixes.clone();
            let diff = gate::read_function_list(&functions)?;
            let reviewed: Vec<String> = fixes.iter().flat_map(|f| f.functions.iter().cloned()).collect();
            let errs = gate::compare_function_sets(&diff, &reviewed);
            if !errs.is_empty() {
                bail!("module and catalog disagree:\n  {}", errs.join("\n  "));
            }
            let built = Utc::now();
            let m = Manifest {
                format: FORMAT_VERSION,
                kernel: r.kernel.clone(),
                kernel_build_id: build_id.map(|b| b.to_lowercase()),
                level,
                ring,
                module: module.file_name().context("module path")?.to_string_lossy().into_owned(),
                module_name,
                sha256: hex::encode(Sha256::digest(&bytes)),
                built,
                expires: built + Duration::days(valid_days),
                fixes,
                not_covered: r.not_covered.clone(),
                superseded_by_kernel: superseded_by,
                builder_image,
                catalog_commit,
            };
            m.validate()?;
            write(&out, m.to_json_pretty().as_bytes())?;
            Ok(true)
        }
        Cmd::Promote { manifest, ring, out } => {
            if !RINGS.contains(&ring.as_str()) {
                bail!("unknown ring {ring}");
            }
            let mut m = Manifest::from_json(&read(&manifest)?)?;
            let from = RINGS.iter().position(|r| *r == m.ring).unwrap();
            let to = RINGS.iter().position(|r| *r == ring).unwrap();
            if to <= from {
                bail!("promotion goes canary -> early -> stable; {} -> {ring} is not a promotion", m.ring);
            }
            m.ring = ring;
            write(&out, m.to_json_pretty().as_bytes())?;
            Ok(true)
        }
    }
}
