mod inspect;
#[cfg(all(target_os = "linux", feature = "live-capture"))]
mod live_cli;

use std::{env, ffi::OsString, io, path::Path, process::ExitCode};

const HELP: &str = "\
Wiretuna, a lightweight network packet analyzer

Usage:
  wiretuna inspect [--packets] [--] FILE
  wiretuna --help
  wiretuna --version

Options:
  --packets  Print one row per packet before the summary
  --         Treat the next argument as a file path";

fn main() -> ExitCode {
    let args: Vec<OsString> = env::args_os().skip(1).collect();
    match args.as_slice() {
        [] => print_help(),
        [arg] if arg == "-h" || arg == "--help" => print_help(),
        [arg] if arg == "-V" || arg == "--version" => {
            println!("wiretuna {}", env!("CARGO_PKG_VERSION"));
        }
        [command, flag] if command == "inspect" && (flag == "-h" || flag == "--help") => {
            print_help();
        }
        [command, rest @ ..] if command == "inspect" => return run_inspect(rest),
        #[cfg(all(target_os = "linux", feature = "live-capture"))]
        [command] if command == "interfaces" => return live_result(live_cli::list()),
        #[cfg(all(target_os = "linux", feature = "live-capture"))]
        [command, flag] if command == "capture" && (flag == "-h" || flag == "--help") => {
            println!("{}", live_cli::HELP);
        }
        #[cfg(all(target_os = "linux", feature = "live-capture"))]
        [command, rest @ ..] if command == "capture" => {
            return live_result(live_cli::capture(rest));
        }
        _ => return usage_error(),
    }
    ExitCode::SUCCESS
}

fn print_help() {
    println!("{HELP}");
    #[cfg(all(target_os = "linux", feature = "live-capture"))]
    println!("\n{}", live_cli::HELP);
}

#[cfg(all(target_os = "linux", feature = "live-capture"))]
fn live_result(result: io::Result<()>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("wiretuna: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run_inspect(args: &[OsString]) -> ExitCode {
    let (packets, args) = match args {
        [flag, rest @ ..] if flag == "--packets" => (true, rest),
        _ => (false, args),
    };
    let path = match args {
        [path] if !path.as_encoded_bytes().starts_with(b"-") => path,
        [separator, path] if separator == "--" => path,
        _ => return usage_error(),
    };
    let mut output = io::BufWriter::new(io::stdout().lock());
    match inspect::run(Path::new(path), packets, &mut output) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error)
            if error
                .downcast_ref::<io::Error>()
                .is_some_and(|error| error.kind() == io::ErrorKind::BrokenPipe) =>
        {
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("wiretuna: {error}");
            ExitCode::FAILURE
        }
    }
}

fn usage_error() -> ExitCode {
    eprintln!("wiretuna: invalid arguments. Run wiretuna --help for usage.");
    ExitCode::from(2)
}
