use super::LinuxError;
use std::process::Command;

pub(super) fn output(program: &str, args: &[String]) -> Result<std::process::Output, LinuxError> {
    Command::new(program)
        .args(args)
        .output()
        .map_err(|source| LinuxError::Spawn {
            program: program.to_owned(),
            source,
        })
}

pub(super) fn run(program: &str, args: &[String]) -> Result<(), LinuxError> {
    let output = output(program, args)?;
    if output.status.success() {
        return Ok(());
    }
    Err(LinuxError::Command {
        program: format!("{} {}", program, args.join(" ")),
        status: output.status.to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
    })
}

pub fn run_ip(args: &[String]) -> Result<(), LinuxError> {
    run("ip", args)
}
