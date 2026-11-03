# ============================================================
# canary_check/canary_check.rs
# Detect a canary file and clear it. Standard library only.
#
# Contract (stable; safe to script against):
#   0   no canary present
#   10  canary present and removed
#   11  canary present, removal failed
#   1   usage or environment error
#
# Target resolution: argv[1] > $CANARY_PATH > $HOME/$USERPROFILE/$HOMEDRIVE+$HOMEPATH/attacker.txt
# ============================================================

#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

const DEFAULT_NAME: &str = "attacker.txt";

const EXIT_ABSENT: u8 = 0;
const EXIT_REMOVED: u8 = 10;
const EXIT_FAILED: u8 = 11;
const EXIT_ERROR: u8 = 1;

fn main() -> ExitCode {
    ExitCode::from(run())
}

fn run() -> u8 {
    let mut dry_run = false;
    let mut positional: Vec<String> = Vec::new();

    for arg in env::args().skip(1) {
        match arg.as_str() {
            "-h" | "--help" => {
                usage();
                return EXIT_ABSENT;
            }
            "-n" | "--dry-run" => dry_run = true,
            a if a.starts_with('-') && a != "-" => {
                eprintln!("error: unknown option {a}");
                usage();
                return EXIT_ERROR;
            }
            _ => positional.push(arg),
        }
    }

    if positional.len() > 1 {
        eprintln!("error: expected at most one path argument");
        usage();
        return EXIT_ERROR;
    }

    let target = match positional.pop() {
        Some(p) if !p.is_empty() => PathBuf::from(p),
        Some(_) => {
            eprintln!("error: empty path");
            return EXIT_ERROR;
        }
        None => match default_path() {
            Ok(p) => p,
            Err(e) => {
                eprintln!("error: {e}");
                return EXIT_ERROR;
            }
        },
    };

    if target == Path::new("/") {
        eprintln!("error: refusing to operate on /");
        return EXIT_ERROR;
    }

    let meta = match fs::symlink_metadata(&target) {
        Ok(m) => m,
        Err(e) if e.kind() == ErrorKind::NotFound => {
            log(&format!("absent  {}", target.display()));
            return EXIT_ABSENT;
        }
        Err(e) => {
            eprintln!("error: stat {}: {e}", target.display());
            return EXIT_ERROR;
        }
    };

    let kind = if meta.file_type().is_symlink() {
        "symlink"
    } else if meta.is_dir() {
        "dir"
    } else {
        "file"
    };

    log(&format!(
        "present kind={kind} size={} mtime={} {}",
        meta.len(),
        fmt_time(meta.modified().ok()),
        target.display()
    ));

    if dry_run {
        log("dry-run: not deleting");
        return EXIT_REMOVED;
    }

    let result = if meta.is_dir() {
        fs::remove_dir(&target)
    } else {
        fs::remove_file(&target)
    };

    match result {
        Ok(()) => {
            log(&format!("removed {}", target.display()));
            EXIT_REMOVED
        }
        Err(e) if e.kind() == ErrorKind::NotFound => {
            log("vanished between stat and remove; treating as removed");
            EXIT_REMOVED
        }
        Err(e) => {
            eprintln!("error: remove {}: {e}", target.display());
            EXIT_FAILED
        }
    }
}

fn default_path() -> Result<PathBuf, String> {
    if let Some(p) = env::var_os("CANARY_PATH") {
        if !p.is_empty() {
            return Ok(PathBuf::from(p));
        }
    }

    let home = env::var_os("HOME")
        .filter(|v| !v.is_empty())
        .or_else(|| env::var_os("USERPROFILE").filter(|v| !v.is_empty()))
        .or_else(|| {
            let drive = env::var_os("HOMEDRIVE").filter(|v| !v.is_empty())?;
            let path = env::var_os("HOMEPATH").filter(|v| !v.is_empty())?;
            let mut buf = drive;
            buf.push(path);
            Some(buf)
        })
        .ok_or("cannot determine home directory; pass a path or set CANARY_PATH")?;

    Ok(PathBuf::from(home).join(DEFAULT_NAME))
}

fn log(msg: &str) {
    eprintln!("[{}] {msg}", fmt_time(Some(SystemTime::now())));
}

fn fmt_time(t: Option<SystemTime>) -> String {
    let Some(t) = t else {
        return "-".to_string();
    };
    let secs = t
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let (days, rem) = ((secs / 86_400) as i64, secs % 86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Howard Hinnant's days-to-civil conversion. No dependency needed.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn usage() {
    eprintln!(
        "\
canary_check — detect a canary file and remove it. No dependencies, no network.

USAGE:
    canary_check [OPTIONS] [PATH]

    PATH defaults to $CANARY_PATH, else <home>/{DEFAULT_NAME}.

OPTIONS:
    -n, --dry-run   report without deleting
    -h, --help      show this help

EXIT CODES:
     0  no canary present
    10  canary present and removed (or would be, with --dry-run)
    11  canary present, removal failed
     1  usage or environment error"
    );
}

# ============================================================
# canary_check/canary_check.go
# Detect a canary file and clear it. Standard library only.
#
# Contract (stable; safe to script against):
#    0  no canary present
#   10  canary present and removed
#   11  canary present, removal failed
#    1  usage or environment error
#
# Target resolution: argv[1] > $CANARY_PATH > $HOME/$USERPROFILE/$HOMEDRIVE+$HOMEPATH/attacker.txt
# ============================================================

package main

import (
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

const defaultName = "attacker.txt"

const (
	exitAbsent  = 0
	exitRemoved = 10
	exitFailed  = 11
	exitError   = 1
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(argv []string) int {
	flags := flag.NewFlagSet("canary_check", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	dryRun := flags.Bool("n", false, "report without deleting")
	flags.BoolVar(dryRun, "dry-run", false, "report without deleting")
	flags.Usage = usage

	if err := flags.Parse(argv); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitAbsent
		}
		return exitError
	}

	if flags.NArg() > 1 {
		fmt.Fprintln(os.Stderr, "error: expected at most one path argument")
		usage()
		return exitError
	}

	target := flags.Arg(0)
	if target == "" {
		var err error
		if target, err = defaultPath(); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return exitError
		}
	}

	if abs, err := filepath.Abs(target); err == nil && abs == string(filepath.Separator) {
		fmt.Fprintln(os.Stderr, "error: refusing to operate on /")
		return exitError
	}

	// Lstat, not Stat: a dangling canary symlink must still register as present.
	info, err := os.Lstat(target)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			logf("absent  %s", target)
			return exitAbsent
		}
		fmt.Fprintf(os.Stderr, "error: stat %s: %v\n", target, err)
		return exitError
	}

	kind := "file"
	switch {
	case info.Mode()&os.ModeSymlink != 0:
		kind = "symlink"
	case info.IsDir():
		kind = "dir"
	}
	logf("present kind=%s size=%d mtime=%s %s",
		kind, info.Size(), info.ModTime().UTC().Format(time.RFC3339), target)

	if *dryRun {
		logf("dry-run: not deleting")
		return exitRemoved
	}

	if err := os.Remove(target); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			logf("vanished between stat and remove; treating as removed")
			return exitRemoved
		}
		fmt.Fprintf(os.Stderr, "error: remove %s: %v\n", target, err)
		return exitFailed
	}

	logf("removed %s", target)
	return exitRemoved
}

func defaultPath() (string, error) {
	if p := os.Getenv("CANARY_PATH"); p != "" {
		return p, nil
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "", errors.New("cannot determine home directory; pass a path or set CANARY_PATH")
	}
	return filepath.Join(home, defaultName), nil
}

func logf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[%s] %s\n",
		time.Now().UTC().Format(time.RFC3339), fmt.Sprintf(format, args...))
}

func usage() {
	fmt.Fprintf(os.Stderr, `canary_check — detect a canary file and remove it. No dependencies, no network.

USAGE:
    canary_check [OPTIONS] [PATH]

    PATH defaults to $CANARY_PATH, else <home>/%s.

OPTIONS:
    -n, --dry-run   report without deleting
    -h, --help      show this help

EXIT CODES:
     0  no canary present
    10  canary present and removed (or would be, with --dry-run)
    11  canary present, removal failed
     1  usage or environment error
`, defaultName)
}

# ============================================================
# canary_check/CanaryCheck.java
# Detect a canary file and clear it. Standard library only.
#
# Contract (stable; safe to script against):
#    0  no canary present
#   10  canary present and removed
#   11  canary present, removal failed
#    1  usage or environment error
#
# Target resolution: argv[0] > $CANARY_PATH > user.home/attacker.txt
#
# Run directly: java CanaryCheck.java
# ============================================================

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.BasicFileAttributes;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

public final class CanaryCheck {

    private static final String DEFAULT_NAME = "attacker.txt";
    private static final DateTimeFormatter TS =
            DateTimeFormatter.ofPattern("uuuu-MM-dd'T'HH:mm:ss'Z'").withZone(ZoneOffset.UTC);

    static final int EXIT_ABSENT = 0;
    static final int EXIT_REMOVED = 10;
    static final int EXIT_FAILED = 11;
    static final int EXIT_ERROR = 1;

    private CanaryCheck() {
    }

    public static void main(String[] argv) {
        System.exit(run(argv));
    }

    static int run(String[] argv) {
        boolean dryRun = false;
        List<String> positional = new ArrayList<>();

        for (String arg : argv) {
            switch (arg) {
                case "-h", "--help" -> {
                    usage();
                    return EXIT_ABSENT;
                }
                case "-n", "--dry-run" -> dryRun = true;
                default -> {
                    if (arg.startsWith("-") && !arg.equals("-")) {
                        System.err.println("error: unknown option " + arg);
                        usage();
                        return EXIT_ERROR;
                    }
                    positional.add(arg);
                }
            }
        }

        if (positional.size() > 1) {
            System.err.println("error: expected at most one path argument");
            usage();
            return EXIT_ERROR;
        }

        Path target;
        try {
            if (!positional.isEmpty()) {
                if (positional.get(0).isEmpty()) {
                    System.err.println("error: empty path");
                    return EXIT_ERROR;
                }
                target = Paths.get(positional.get(0));
            } else {
                target = defaultPath();
            }
        } catch (IOException e) {
            System.err.println("error: " + e.getMessage());
            return EXIT_ERROR;
        }

        if (target.toAbsolutePath().getParent() == null) {
            System.err.println("error: refusing to operate on /");
            return EXIT_ERROR;
        }

        // NOFOLLOW_LINKS: a dangling canary symlink must still register as present.
        BasicFileAttributes attrs;
        try {
            attrs = Files.readAttributes(target, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        } catch (NoSuchFileException e) {
            log("absent  " + target);
            return EXIT_ABSENT;
        } catch (IOException e) {
            System.err.println("error: stat " + target + ": " + e.getMessage());
            return EXIT_ERROR;
        }

        String kind = attrs.isSymbolicLink() ? "symlink" : attrs.isDirectory() ? "dir" : "file";
        log("present kind=" + kind + " size=" + attrs.size()
                + " mtime=" + TS.format(Instant.ofEpochMilli(attrs.lastModifiedTime().toMillis()))
                + " " + target);

        if (dryRun) {
            log("dry-run: not deleting");
            return EXIT_REMOVED;
        }

        try {
            Files.delete(target);
            log("removed " + target);
            return EXIT_REMOVED;
        } catch (NoSuchFileException e) {
            log("vanished between stat and remove; treating as removed");
            return EXIT_REMOVED;
        } catch (IOException e) {
            System.err.println("error: remove " + target + ": " + e.getMessage());
            return EXIT_FAILED;
        }
    }

    private static Path defaultPath() throws IOException {
        String fromEnv = System.getenv("CANARY_PATH");
        if (fromEnv != null && !fromEnv.isEmpty()) {
            return Paths.get(fromEnv);
        }
        String home = System.getProperty("user.home");
        if (home == null || home.isEmpty()) {
            throw new IOException("cannot determine home directory; pass a path or set CANARY_PATH");
        }
        return Paths.get(home, DEFAULT_NAME);
    }

    private static void log(String message) {
        System.err.println("[" + TS.format(Instant.now()) + "] " + message);
    }

    private static void usage() {
        System.err.printf("""
                canary_check — detect a canary file and remove it. No dependencies, no network.

                USAGE:
                    java CanaryCheck.java [OPTIONS] [PATH