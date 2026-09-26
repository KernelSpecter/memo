//! Command-line parsing for memo. Hand-rolled to avoid heavy dependencies.

#[derive(Debug, Clone, Default)]
pub struct Flags {
    pub cache_failures: bool,
    pub allow_network: bool,
    pub no_color_env: bool,
    pub no_read: bool,
    pub quiet: bool,
    pub verbose: bool,
}

#[derive(Debug, Clone)]
pub enum Command {
    /// Run (and possibly replay) a command.
    Run { argv: Vec<String>, flags: Flags },
    /// Explain why the last run of a command missed / would miss.
    Explain { argv: Vec<String> },
    Stats,
    Gc { max_bytes: Option<u64> },
    Clear,
    Help,
}

fn parse_size(s: &str) -> Option<u64> {
    let s = s.trim();
    let (num, mult): (&str, u64) = if let Some(x) = s.strip_suffix(['G', 'g']) {
        (x, 1024 * 1024 * 1024)
    } else if let Some(x) = s.strip_suffix(['M', 'm']) {
        (x, 1024 * 1024)
    } else if let Some(x) = s.strip_suffix(['K', 'k']) {
        (x, 1024)
    } else {
        (s, 1)
    };
    num.trim().parse::<f64>().ok().map(|v| (v * mult as f64) as u64)
}

/// Parse argv (excluding argv[0]).
pub fn parse(args: &[String]) -> Command {
    if args.is_empty() {
        return Command::Help;
    }

    // Leading flags for run mode; also detect subcommands / `--`.
    let mut flags = Flags::default();
    let mut i = 0;
    let mut forced_run = false;

    // Peek for subcommands only when they appear before any `--` and before a
    // program name.
    while i < args.len() {
        let a = &args[i];
        match a.as_str() {
            "--" => {
                forced_run = true;
                i += 1;
                break;
            }
            "--cache-failures" => flags.cache_failures = true,
            "--allow-network" => flags.allow_network = true,
            "--no-color-env" => flags.no_color_env = true,
            "--no-read" => flags.no_read = true,
            "-q" | "--quiet" => flags.quiet = true,
            "-v" | "--verbose" => flags.verbose = true,
            "-h" | "--help" => return Command::Help,
            _ => break, // first non-flag token
        }
        i += 1;
    }

    let rest = &args[i..];
    if rest.is_empty() {
        return Command::Help;
    }

    if !forced_run {
        match rest[0].as_str() {
            "explain" => {
                return Command::Explain {
                    argv: rest[1..].to_vec(),
                };
            }
            "stats" => return Command::Stats,
            "clear" => return Command::Clear,
            "gc" => {
                let mut max_bytes = None;
                let mut j = 1;
                while j < rest.len() {
                    if rest[j] == "--max-size" && j + 1 < rest.len() {
                        max_bytes = parse_size(&rest[j + 1]);
                        j += 2;
                    } else {
                        j += 1;
                    }
                }
                return Command::Gc { max_bytes };
            }
            _ => {}
        }
    }

    Command::Run {
        argv: rest.to_vec(),
        flags,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_run() {
        let c = parse(&["npm".into(), "test".into()]);
        match c {
            Command::Run { argv, .. } => assert_eq!(argv, vec!["npm", "test"]),
            _ => panic!("expected run"),
        }
    }

    #[test]
    fn flags_before_command() {
        let c = parse(&["--allow-network".into(), "-v".into(), "node".into(), "x.js".into()]);
        match c {
            Command::Run { argv, flags } => {
                assert_eq!(argv, vec!["node", "x.js"]);
                assert!(flags.allow_network);
                assert!(flags.verbose);
            }
            _ => panic!("expected run"),
        }
    }

    #[test]
    fn stats_subcommand() {
        assert!(matches!(parse(&["stats".into()]), Command::Stats));
    }

    #[test]
    fn dash_dash_forces_run_of_subcommand_name() {
        let c = parse(&["--".into(), "stats".into()]);
        match c {
            Command::Run { argv, .. } => assert_eq!(argv, vec!["stats"]),
            _ => panic!("expected run of a program called stats"),
        }
    }

    #[test]
    fn gc_with_size() {
        match parse(&["gc".into(), "--max-size".into(), "2G".into()]) {
            Command::Gc { max_bytes } => assert_eq!(max_bytes, Some(2 * 1024 * 1024 * 1024)),
            _ => panic!("expected gc"),
        }
    }

    #[test]
    fn explain_carries_argv() {
        match parse(&["explain".into(), "npm".into(), "test".into()]) {
            Command::Explain { argv } => assert_eq!(argv, vec!["npm", "test"]),
            _ => panic!("expected explain"),
        }
    }
}
