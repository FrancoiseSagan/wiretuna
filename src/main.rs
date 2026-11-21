use std::{env, process::ExitCode};

const HELP: &str =
    "Wiretuna, a lightweight network packet analyzer\n\nUsage: wiretuna [--help | --version]";

fn main() -> ExitCode {
    let mut args = env::args_os().skip(1);
    let argument = args.next();
    match (
        argument.as_deref().and_then(|arg| arg.to_str()),
        args.next(),
    ) {
        (None, None) if argument.is_none() => println!("{HELP}"),
        (Some("-h" | "--help"), None) => println!("{HELP}"),
        (Some("-V" | "--version"), None) => println!("wiretuna {}", env!("CARGO_PKG_VERSION")),
        _ => {
            eprintln!("wiretuna: invalid arguments. Run wiretuna --help for usage.");
            return ExitCode::from(2);
        }
    }
    ExitCode::SUCCESS
}
