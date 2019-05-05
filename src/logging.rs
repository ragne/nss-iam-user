use std::fs::OpenOptions;
use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

pub(crate) fn setup_logging<F: AsRef<Path>>(
    verbosity: u64,
    filename: F,
) -> Result<(), fern::InitError> {
    let mut base_config = fern::Dispatch::new();

    base_config = match verbosity {
        0 => {
            // Let's say we depend on something which whose "info" level messages are too
            // verbose to include in end-user output. If we don't need them,
            // let's not include them.
            base_config
                .level(log::LevelFilter::Info)
                .level_for("overly-verbose-target", log::LevelFilter::Warn)
        }
        1 => base_config
            .level(log::LevelFilter::Debug)
            .level_for("overly-verbose-target", log::LevelFilter::Info),
        2 => base_config.level(log::LevelFilter::Debug),
        _3_or_more => base_config.level(log::LevelFilter::Trace),
    };

    // Separate file config so we can include year, month and day in file logs
    let file_config = if verbosity >= 1 {
        let mut logfile = OpenOptions::new();
        logfile.mode(0o666).create(true).append(true);
        match logfile.open(filename) {
            Ok(f) => {
                let logfile = f;
                fern::Dispatch::new()
                    .format(|out, message, record| {
                        out.finish(format_args!(
                            "{}[{}][{}] {}:{}::{} {}",
                            chrono::Local::now().format("[%Y-%m-%d][%H:%M:%S]"),
                            record.target(),
                            record.level(),
                            record.file().unwrap_or(""),
                            record.line().unwrap_or(0),
                            record.module_path().unwrap_or(""),
                            message
                        ))
                    })
                    .chain(logfile)
            }
            Err(e) => {
                error!("Cannot open logfile, not logging into file");
                fern::Dispatch::new()
            }
        }
    } else {
        fern::Dispatch::new()
    };

    let stdout_config = fern::Dispatch::new()
        .level(log::LevelFilter::Error)
        .format(|out, message, record| {
            out.finish(format_args!(
                "[{}][{}][{}] {}",
                chrono::Local::now().format("%H:%M:%S"),
                record.target(),
                record.level(),
                message
            ))
        })
        .chain(io::stdout());

    base_config
        .chain(file_config)
        .chain(stdout_config)
        .apply()?;

    Ok(())
}
