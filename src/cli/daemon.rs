use std::io::Read;
use std::os::fd::FromRawFd;
use std::path::PathBuf;
use crate::{Config, Runtime};

pub(super) fn init_logging(
    path: Option<PathBuf>,
    configured_level: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(path) = path {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|error| format!("cannot open log file {}: {error}", path.display()))?;
        let filter = tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(configured_level));
        tracing_subscriber::fmt()
            .with_writer(file)
            .with_ansi(false)
            .with_env_filter(filter)
            .try_init()
            .map_err(|error| format!("cannot initialize logging: {error}"))?;
    }
    Ok(())
}

pub(super) fn daemonize(
    config: Config,
    log_path: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    let log_path = match log_path {
        Some(path) if !path.is_absolute() => Some(std::env::current_dir()?.join(path)),
        other => other,
    };
    let mut pipe_fds = [0; 2];
    if unsafe { libc::pipe2(pipe_fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    for index in 0..pipe_fds.len() {
        let fd = pipe_fds[index];
        if fd <= 2 {
            let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
            if duplicate < 0 {
                let error = std::io::Error::last_os_error();
                unsafe {
                    libc::close(pipe_fds[0]);
                    libc::close(pipe_fds[1]);
                }
                return Err(error.into());
            }
            unsafe {
                libc::close(fd);
            }
            pipe_fds[index] = duplicate;
        }
    }

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        let error = std::io::Error::last_os_error();
        unsafe {
            libc::close(pipe_fds[0]);
            libc::close(pipe_fds[1]);
        }
        return Err(error.into());
    }

    if pid > 0 {
        unsafe {
            libc::close(pipe_fds[1]);
        }
        let mut message = String::new();
        let mut reader = unsafe { std::fs::File::from_raw_fd(pipe_fds[0]) };
        reader.read_to_string(&mut message)?;
        if let Some(error) = message.strip_prefix("ERR ") {
            return Err(error.trim().to_owned().into());
        }
        if message.trim() != "OK" {
            return Err(format!(
                "background daemon exited before startup confirmation: {}",
                message.trim()
            )
            .into());
        }
        println!("vpn-relay started in background (pid {pid})");
        return Ok(());
    }

    unsafe {
        libc::close(pipe_fds[0]);
    }
    let startup_fd = pipe_fds[1];
    let log_level = config.daemon.log_level.clone();
    let startup_result = (|| -> Result<Runtime, Box<dyn std::error::Error>> {
        if unsafe { libc::setsid() } < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let root_path = std::ffi::CString::new("/")?;
        if unsafe { libc::chdir(root_path.as_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        unsafe {
            libc::umask(0o027);
        }
        let null_path = std::ffi::CString::new("/dev/null")?;
        let null_fd = unsafe { libc::open(null_path.as_ptr(), libc::O_RDWR) };
        if null_fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        for target in 0..=2 {
            if unsafe { libc::dup2(null_fd, target) } < 0 {
                let error = std::io::Error::last_os_error();
                unsafe {
                    libc::close(null_fd);
                }
                return Err(error.into());
            }
        }
        if null_fd > 2 {
            unsafe {
                libc::close(null_fd);
            }
        }
        close_extra_fds(startup_fd);
        init_logging(log_path, &log_level)?;
        tracing::info!(
            pid = std::process::id(),
            "vpn-relay background daemon starting"
        );
        Runtime::start(config).map_err(|error| -> Box<dyn std::error::Error> { Box::new(error) })
    })();

    match startup_result {
        Ok(runtime) => {
            let _ = unsafe { libc::write(startup_fd, b"OK".as_ptr().cast(), 2) };
            unsafe {
                libc::close(startup_fd);
            }
            let exit_code = match runtime.run() {
                Ok(()) => 0,
                Err(error) => {
                    tracing::error!(%error, "background daemon stopped after startup");
                    1
                }
            };
            unsafe {
                libc::_exit(exit_code);
            }
        }
        Err(error) => {
            let message = format!("ERR {error}");
            let _ = unsafe { libc::write(startup_fd, message.as_ptr().cast(), message.len()) };
            unsafe {
                libc::close(startup_fd);
                libc::_exit(1);
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn close_extra_fds(keep_fd: libc::c_int) {
    let max_fd = unsafe { libc::sysconf(libc::_SC_OPEN_MAX) };
    let max_fd = if max_fd < 0 { 1024 } else { max_fd.min(65_536) };
    for fd in 3..max_fd as libc::c_int {
        if fd != keep_fd {
            unsafe {
                libc::close(fd);
            }
        }
    }
}
