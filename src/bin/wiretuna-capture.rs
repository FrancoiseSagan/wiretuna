#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    use std::{env, process::ExitCode};
    use wiretuna::capture::{helper, live::Config};

    let args: Vec<_> = env::args_os().skip(1).collect();
    let [interface, snaplen, buffer_size, filter] = args.as_slice() else {
        return ExitCode::FAILURE;
    };
    let (Some(interface), Some(snaplen), Some(buffer_size), Some(filter)) = (
        interface.to_str(),
        snaplen.to_str().and_then(|value| value.parse().ok()),
        buffer_size.to_str().and_then(|value| value.parse().ok()),
        filter.to_str(),
    ) else {
        return ExitCode::FAILURE;
    };
    let config = Config {
        snaplen,
        buffer_size,
        filter: (!filter.is_empty()).then(|| filter.to_owned()),
    };
    if helper::run(interface, &config).is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("The capture helper is available on Linux.");
    std::process::exit(1);
}
