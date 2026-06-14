//! `sysupgrade` — flash a new firmware image and reboot into it.
//!
//! OpenWrt's sysupgrade is a long shell script; the essential job is small:
//! sanity-check the image, optionally stash the config, sync the disks, write
//! the image onto the boot partition, and reboot. We lean on the `mtd` applet
//! for the actual erase-then-write so there is exactly one flash code path.
//!
//! Usage:
//!   sysupgrade [-n] [-T] [-p <part>] <image>
//!     -n           do not keep configuration (skip the backup copy)
//!     -T           test only: validate the image, change nothing
//!     -p <part>    target partition (default: "firmware")
//!
//! Config model: LWRT keeps its entire writable config in a single INI file at
//! `/etc/lwrt/config`. Unless `-n` is given we copy it to `BACKUP` before
//! flashing so a freshly booted image can restore it; this only survives the
//! upgrade if `/etc/lwrt` lives on a separate overlay partition (the common
//! layout), which is why it is a copy and not a no-op.

use std::path::Path;

const DEFAULT_PART: &str = "firmware";
const CONFIG: &str = "/etc/lwrt/config";
const BACKUP: &str = "/etc/lwrt/config.bak";

struct Opts {
    keep_config: bool,
    test_only: bool,
    part: String,
    image: Option<String>,
}

fn parse(args: &[String]) -> Result<Opts, String> {
    let mut o = Opts {
        keep_config: true,
        test_only: false,
        part: DEFAULT_PART.to_string(),
        image: None,
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-n" => o.keep_config = false,
            "-T" | "--test" => o.test_only = true,
            "-p" => {
                i += 1;
                o.part = args.get(i).ok_or("-p needs a partition name")?.clone();
            }
            other if other.starts_with('-') => {
                return Err(format!("unknown option '{other}'"));
            }
            img => o.image = Some(img.to_string()),
        }
        i += 1;
    }
    Ok(o)
}

/// Pre-flight: the image must exist, be non-empty, and the target partition
/// must resolve. Returns the image size on success.
fn validate(o: &Opts) -> Result<u64, String> {
    let img = o.image.as_deref().ok_or("no image given")?;
    let meta = std::fs::metadata(img).map_err(|e| format!("{img}: {e}"))?;
    if !meta.is_file() {
        return Err(format!("{img} is not a regular file"));
    }
    if meta.len() == 0 {
        return Err(format!("{img} is empty"));
    }
    let dev = crate::mtd::resolve(&o.part).map_err(|e| format!("partition {}: {e}", o.part))?;
    eprintln!(
        "sysupgrade: image {img} ({} bytes) -> {} ({dev})",
        meta.len(),
        o.part
    );
    Ok(meta.len())
}

fn backup_config() {
    if Path::new(CONFIG).exists() {
        match std::fs::copy(CONFIG, BACKUP) {
            Ok(_) => eprintln!("sysupgrade: saved config to {BACKUP}"),
            Err(e) => eprintln!("sysupgrade: WARNING could not back up config: {e}"),
        }
    }
}

/// Flush page cache to flash. Best-effort: there is no portable errno here.
fn sync_disks() {
    unsafe { libc::sync() };
}

pub fn run(args: &[String]) -> i32 {
    let opts = match parse(args) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("sysupgrade: {e}");
            eprintln!("usage: sysupgrade [-n] [-T] [-p <part>] <image>");
            return 2;
        }
    };

    if let Err(e) = validate(&opts) {
        eprintln!("sysupgrade: {e}");
        return 1;
    }

    if opts.test_only {
        println!("sysupgrade: image valid (test mode, nothing written)");
        return 0;
    }

    if opts.keep_config {
        backup_config();
    }

    eprintln!("sysupgrade: syncing and flashing — do not power off");
    sync_disks();

    let img = opts.image.as_deref().unwrap(); // validated above
    let rc = crate::mtd::write_image(img, &opts.part);
    if rc != 0 {
        eprintln!("sysupgrade: flash failed (rc={rc}); NOT rebooting");
        return rc;
    }

    sync_disks();
    eprintln!("sysupgrade: upgrade complete, rebooting");
    let _ = crate::sys::reboot(libc::LINUX_REBOOT_CMD_RESTART);
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parse_defaults_keep_config_and_firmware_part() {
        let o = parse(&args(&["fw.bin"])).unwrap();
        assert!(o.keep_config);
        assert!(!o.test_only);
        assert_eq!(o.part, "firmware");
        assert_eq!(o.image.as_deref(), Some("fw.bin"));
    }

    #[test]
    fn parse_flags_and_partition_override() {
        let o = parse(&args(&["-n", "-T", "-p", "kernel", "img"])).unwrap();
        assert!(!o.keep_config);
        assert!(o.test_only);
        assert_eq!(o.part, "kernel");
        assert_eq!(o.image.as_deref(), Some("img"));
    }

    #[test]
    fn parse_rejects_unknown_flag_and_missing_p_arg() {
        assert!(parse(&args(&["-z", "img"])).is_err());
        assert!(parse(&args(&["-p"])).is_err());
    }

    #[test]
    fn validate_rejects_missing_image() {
        let o = Opts {
            keep_config: true,
            test_only: true,
            part: "firmware".into(),
            image: Some("/nonexistent/firmware.bin".into()),
        };
        assert!(validate(&o).is_err());
    }
}
