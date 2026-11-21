use std::{ffi::OsString, io, path::PathBuf, process::ExitCode};

use wiretuna::web::{self, Config};

pub const HELP: &str = "  wiretuna serve [--port PORT] [--input FILE]";

pub fn run(args: &[OsString]) -> ExitCode {
    let result = config(args).and_then(web::run);
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("wiretuna: {error}");
            ExitCode::FAILURE
        }
    }
}

fn config(args: &[OsString]) -> io::Result<Config> {
    let mut config = Config {
        port: 8765,
        input: None,
    };
    for pair in args.chunks(2) {
        let [flag, value] = pair else {
            return Err(bad("serve options require a value"));
        };
        match flag.to_str() {
            Some("--port") => {
                config.port = value
                    .to_str()
                    .and_then(|text| text.parse().ok())
                    .ok_or_else(|| bad("port must be a number from 0 to 65535"))?
            }
            Some("--input") => config.input = Some(PathBuf::from(value)),
            _ => return Err(bad(format!("unknown serve option {flag:?}"))),
        }
    }
    Ok(config)
}

fn bad(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}
