use super::*;
use std::process::Command as ProcessCommand;

const SYSTEMD_SERVICE_NAME: &str = "apt-edge.service";
const SYSTEMD_SERVICE_PATH: &str = "/etc/systemd/system/apt-edge.service";

#[derive(Clone, Debug)]
pub(super) struct StartupInstallResult {
    pub service_name: &'static str,
    pub service_path: PathBuf,
}

pub(super) fn systemd_is_available() -> bool {
    cfg!(target_os = "linux")
        && Path::new("/run/systemd/system").exists()
        && ProcessCommand::new("systemctl")
            .arg("--version")
            .output()
            .is_ok_and(|output| output.status.success())
}

pub(super) fn install_and_enable_systemd_service(
    config_path: &Path,
) -> CliResult<StartupInstallResult> {
    if !cfg!(target_os = "linux") {
        return Err("startup service installation is currently only supported on Linux".into());
    }
    if !systemd_is_available() {
        return Err(
            "systemd was not detected on this host; install the service manually or use another init system"
                .into(),
        );
    }

    let service_path = PathBuf::from(SYSTEMD_SERVICE_PATH);
    let config_path = config_path.canonicalize()?;
    let exec_path = std::env::current_exe()?.canonicalize()?;
    let unit_body = render_systemd_unit(&exec_path, &config_path);

    if let Some(parent) = service_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&service_path, unit_body)?;

    run_systemctl(["daemon-reload"])?;
    run_systemctl(["enable", SYSTEMD_SERVICE_NAME])?;
    if service_is_active(SYSTEMD_SERVICE_NAME) {
        run_systemctl(["restart", SYSTEMD_SERVICE_NAME])?;
    } else {
        run_systemctl(["start", SYSTEMD_SERVICE_NAME])?;
    }

    Ok(StartupInstallResult {
        service_name: SYSTEMD_SERVICE_NAME,
        service_path,
    })
}

fn service_is_active(service_name: &str) -> bool {
    ProcessCommand::new("systemctl")
        .args(["is-active", "--quiet", service_name])
        .status()
        .is_ok_and(|status| status.success())
}

fn run_systemctl<const N: usize>(args: [&str; N]) -> CliResult {
    let output = ProcessCommand::new("systemctl").args(args).output()?;
    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let details = if !stderr.is_empty() {
        stderr
    } else if !stdout.is_empty() {
        stdout
    } else {
        "no output".to_string()
    };
    Err(format!("systemctl {} failed: {}", args.join(" "), details).into())
}

fn render_systemd_unit(exec_path: &Path, config_path: &Path) -> String {
    format!(
        "[Unit]\n\
Description=AdaPT Tunnel edge server\n\
After=network-online.target\n\
Wants=network-online.target\n\
\n\
[Service]\n\
Type=simple\n\
ExecStart={} start --config {}\n\
Restart=always\n\
RestartSec=5\n\
\n\
[Install]\n\
WantedBy=multi-user.target\n",
        quote_systemd_arg(&exec_path.display().to_string()),
        quote_systemd_arg(&config_path.display().to_string()),
    )
}

fn quote_systemd_arg(value: &str) -> String {
    let escaped = value
        .chars()
        .flat_map(|ch| match ch {
            '\\' => "\\\\".chars().collect::<Vec<_>>(),
            '"' => "\\\"".chars().collect::<Vec<_>>(),
            '\n' => "\\n".chars().collect::<Vec<_>>(),
            '\t' => "\\t".chars().collect::<Vec<_>>(),
            _ => vec![ch],
        })
        .collect::<String>();
    format!("\"{escaped}\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_systemd_unit_with_expected_command() {
        let unit = render_systemd_unit(
            Path::new("/usr/local/bin/apt-edge"),
            Path::new("/etc/adapt/server.toml"),
        );

        assert!(unit.contains("Description=AdaPT Tunnel edge server"));
        assert!(unit.contains(
            "ExecStart=\"/usr/local/bin/apt-edge\" start --config \"/etc/adapt/server.toml\""
        ));
        assert!(unit.contains("Restart=always"));
        assert!(unit.contains("WantedBy=multi-user.target"));
    }

    #[test]
    fn systemd_argument_quoting_escapes_special_characters() {
        let quoted = quote_systemd_arg("/tmp/path with spaces/\"server\".toml");
        assert_eq!(quoted, "\"/tmp/path with spaces/\\\"server\\\".toml\"");
    }
}
