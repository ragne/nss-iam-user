use crate::utils::geteuid;
use std::fs::OpenOptions;
use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::thread;

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
            .level_for("rusoto_core", log::LevelFilter::Info)
            .level_for("hyper", log::LevelFilter::Info),
        2 => base_config.level(log::LevelFilter::Debug),
        _3_or_more => base_config.level(log::LevelFilter::Trace),
    };

    // Separate file config so we can include year, month and day in file logs
    let file_config = if verbosity >= 1 {
        use libc::{mode_t, umask};

        let old_umask: mode_t = unsafe { umask(0o011) };
        let mut logfile = OpenOptions::new();
        logfile.mode(0o666).create(true).append(true);
        let logfile = match logfile.open(filename) {
            Ok(f) => {
                let logfile = f;
                fern::Dispatch::new()
                    .format(|out, message, record| {
                        let thread = thread::current();
                        out.finish(format_args!(
                            "{}[{}][{}] {}:{}::{}[{}:{:?}] {}",
                            chrono::Local::now().format("[%Y-%m-%d][%H:%M:%S]"),
                            record.target(),
                            record.level(),
                            record.file().unwrap_or(""),
                            record.line().unwrap_or(0),
                            record.module_path().unwrap_or(""),
                            thread.name().unwrap_or(""),
                            thread.id(),
                            message
                        ))
                    })
                    .chain(logfile)
            }
            Err(e) => {
                warn!("Cannot open logfile, not logging into file");
                fern::Dispatch::new()
            }
        };
        unsafe {
            umask(old_umask);
        }
        logfile
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

    let syslog_fmt = syslog::Formatter3164 {
        facility: syslog::Facility::LOG_USER,
        hostname: None,
        process: "nss-iam-user".into(),
        pid: geteuid() as i32,
    };

    match syslog::unix(syslog_fmt) {
        Ok(syslog_logger) => {
            let c = fern::Dispatch::new()
                // by default only accept warning messages so as not to spam
                .level(log::LevelFilter::Warn)
                .chain(syslog_logger);
            base_config = base_config.chain(c);
        }
        Err(e) => println!("Cannot create syslog logger, error: {}", e),
    };

    base_config
        .chain(file_config)
        .chain(stdout_config)
        .apply()?;

    if cfg!(debug_assertions) {
        warn!("Should be in syslog!");
    }
    Ok(())
}
