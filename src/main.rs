mod inspect;

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
        [] => println!("{HELP}"),
        [arg] if arg == "-h" || arg == "--help" => println!("{HELP}"),
        [arg] if arg == "-V" || arg == "--version" => {
            println!("wiretuna {}", env!("CARGO_PKG_VERSION"));
        }
        [command, flag] if command == "inspect" && (flag == "-h" || flag == "--help") => {
            println!("{HELP}");
        }
        [command, rest @ ..] if command == "inspect" => return run_inspect(rest),
        _ => return usage_error(),
    }
    ExitCode::SUCCESS
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
