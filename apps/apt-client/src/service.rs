use crate::cli::{ServiceArgs, ServiceCommand};
use apt_client_control::{default_client_root_dir, default_client_socket_path_in};
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

const SYSTEMD_SERVICE_NAME: &str = "apt-clientd.service";
const SYSTEMD_SERVICE_PATH: &str = "/etc/systemd/system/apt-clientd.service";
const LAUNCHD_LABEL: &str = "com.adapt-tunnel.clientd";
const LAUNCHD_PLIST_PATH: &str = "/Library/LaunchDaemons/com.adapt-tunnel.clientd.plist";

type CliResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

pub(super) async fn handle_service_command(command: ServiceCommand) -> CliResult {
    match command {
        ServiceCommand::Install { args } => install_service(args),
        ServiceCommand::Uninstall { args } => uninstall_service(args),
        ServiceCommand::Status { args } => {
            print_service_status(args)?;
            Ok(())
        }
    }
}

fn install_service(args: ServiceArgs) -> CliResult {
    ensure_root()?;
    let root_dir = resolve_target_root_dir(args.root_dir)?;
    create_client_root_dir(&root_dir)?;
    let daemon_path = daemon_executable_path()?;
    if cfg!(target_os = "linux") {
        install_systemd_service(&daemon_path, &root_dir)?;
    } else if cfg!(target_os = "macos") {
        install_launchd_service(&daemon_path, &root_dir)?;
    } else {
        return Err("client service installation is only supported on Linux and macOS".into());
    }
    println!(
        "Installed local client daemon service for {}",
        root_dir.display()
    );
    println!("Normal launches should now work without sudo.");
    print_service_status(ServiceArgs {
        root_dir: Some(root_dir),
    })?;
    Ok(())
}

fn uninstall_service(args: ServiceArgs) -> CliResult {
    ensure_root()?;
    let root_dir = resolve_target_root_dir(args.root_dir)?;
    if cfg!(target_os = "linux") {
        uninstall_systemd_service()?;
    } else if cfg!(target_os = "macos") {
        uninstall_launchd_service()?;
    } else {
        return Err("client service uninstallation is only supported on Linux and macOS".into());
    }
    let socket_path = default_client_socket_path_in(&root_dir);
    let _ = fs::remove_file(&socket_path);
    println!("Removed local client daemon service.");
    Ok(())
}

fn print_service_status(args: ServiceArgs) -> CliResult {
    let root_dir = resolve_target_root_dir(args.root_dir)?;
    let socket_path = default_client_socket_path_in(&root_dir);
    println!("Client root dir: {}", root_dir.display());
    println!("Control socket: {}", socket_path.display());
    println!(
        "Socket present: {}",
        if socket_path.exists() { "yes" } else { "no" }
    );
    if cfg!(target_os = "linux") {
        println!("Service file: {}", SYSTEMD_SERVICE_PATH);
        println!(
            "Installed: {}",
            yes_no(Path::new(SYSTEMD_SERVICE_PATH).exists())
        );
        println!(
            "Enabled: {}",
            yes_no(systemctl_ok(["is-enabled", SYSTEMD_SERVICE_NAME]))
        );
        println!(
            "Active: {}",
            yes_no(systemctl_ok(["is-active", "--quiet", SYSTEMD_SERVICE_NAME]))
        );
    } else if cfg!(target_os = "macos") {
        println!("LaunchDaemon plist: {}", LAUNCHD_PLIST_PATH);
        println!(
            "Installed: {}",
            yes_no(Path::new(LAUNCHD_PLIST_PATH).exists())
        );
        println!("Loaded: {}", yes_no(launchctl_print_ok()));
    }
    Ok(())
}

fn install_systemd_service(daemon_path: &Path, root_dir: &Path) -> CliResult {
    if !systemd_is_available() {
        return Err("systemd was not detected on this host".into());
    }
    let unit_body = render_systemd_unit(daemon_path, root_dir);
    fs::write(SYSTEMD_SERVICE_PATH, unit_body)?;
    run_command("systemctl", ["daemon-reload"])?;
    run_command("systemctl", ["enable", SYSTEMD_SERVICE_NAME])?;
    if systemctl_ok(["is-active", "--quiet", SYSTEMD_SERVICE_NAME]) {
        run_command("systemctl", ["restart", SYSTEMD_SERVICE_NAME])?;
    } else {
        run_command("systemctl", ["start", SYSTEMD_SERVICE_NAME])?;
    }
    Ok(())
}

fn uninstall_systemd_service() -> CliResult {
    let _ = run_command("systemctl", ["stop", SYSTEMD_SERVICE_NAME]);
    let _ = run_command("systemctl", ["disable", SYSTEMD_SERVICE_NAME]);
    if Path::new(SYSTEMD_SERVICE_PATH).exists() {
        fs::remove_file(SYSTEMD_SERVICE_PATH)?;
    }
    let _ = run_command("systemctl", ["daemon-reload"]);
    Ok(())
}

fn install_launchd_service(daemon_path: &Path, root_dir: &Path) -> CliResult {
    let plist_body = render_launchd_plist(daemon_path, root_dir);
    fs::write(LAUNCHD_PLIST_PATH, plist_body)?;
    set_launchd_plist_permissions()?;
    let _ = run_command("launchctl", ["bootout", &format!("system/{LAUNCHD_LABEL}")]);
    run_command("launchctl", ["enable", &format!("system/{LAUNCHD_LABEL}")])?;
    run_command("launchctl", ["bootstrap", "system", LAUNCHD_PLIST_PATH])?;
    run_command(
        "launchctl",
        ["kickstart", "-k", &format!("system/{LAUNCHD_LABEL}")],
    )?;
    Ok(())
}

fn set_launchd_plist_permissions() -> CliResult {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(LAUNCHD_PLIST_PATH, fs::Permissions::from_mode(0o644))?;
    }
    let _ = run_command("chown", ["root:wheel", LAUNCHD_PLIST_PATH]);
    Ok(())
}

fn uninstall_launchd_service() -> CliResult {
    let _ = run_command("launchctl", ["bootout", &format!("system/{LAUNCHD_LABEL}")]);
    let _ = run_command("launchctl", ["disable", &format!("system/{LAUNCHD_LABEL}")]);
    if Path::new(LAUNCHD_PLIST_PATH).exists() {
        fs::remove_file(LAUNCHD_PLIST_PATH)?;
    }
    Ok(())
}

fn resolve_target_root_dir(explicit: Option<PathBuf>) -> CliResult<PathBuf> {
    match explicit {
        Some(path) => Ok(path),
        None => {
            if current_uid()? == 0 {
                if let Some(sudo_user) = env::var_os("SUDO_USER") {
                    let home = resolve_home_for_user(&sudo_user.to_string_lossy())?;
                    return Ok(home.join(".adapt-tunnel"));
                }
            }
            Ok(default_client_root_dir()?)
        }
    }
}

fn create_client_root_dir(root_dir: &Path) -> CliResult {
    fs::create_dir_all(root_dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(root_dir, fs::Permissions::from_mode(0o700))?;
    }
    if let Some(sudo_user) = env::var_os("SUDO_USER") {
        let owner = sudo_user.to_string_lossy().to_string();
        let _ = run_command("chown", ["-R", &owner, &root_dir.display().to_string()]);
    }
    Ok(())
}

fn daemon_executable_path() -> CliResult<PathBuf> {
    let current_exe = std::env::current_exe()?;
    let daemon_path = current_exe.with_file_name("apt-clientd");
    if daemon_path.exists() {
        return Ok(daemon_path);
    }
    Err(format!(
        "could not find apt-clientd next to {}",
        current_exe.display()
    )
    .into())
}

fn systemd_is_available() -> bool {
    cfg!(target_os = "linux")
        && Path::new("/run/systemd/system").exists()
        && systemctl_ok(["--version"])
}

fn systemctl_ok<const N: usize>(args: [&str; N]) -> bool {
    Command::new("systemctl")
        .args(args)
        .status()
        .is_ok_and(|status| status.success())
}

fn launchctl_print_ok() -> bool {
    Command::new("launchctl")
        .args(["print", &format!("system/{LAUNCHD_LABEL}")])
        .status()
        .is_ok_and(|status| status.success())
}

fn render_systemd_unit(daemon_path: &Path, root_dir: &Path) -> String {
    format!(
        "[Unit]\nDescription=AdaPT Tunnel client daemon\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nExecStart={} --root-dir {}\nRestart=always\nRestartSec=2\n\n[Install]\nWantedBy=multi-user.target\n",
        quote_arg(&daemon_path.display().to_string()),
        quote_arg(&root_dir.display().to_string()),
    )
}

fn render_launchd_plist(daemon_path: &Path, root_dir: &Path) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n  <key>Label</key>\n  <string>{}</string>\n  <key>ProgramArguments</key>\n  <array>\n    <string>{}</string>\n    <string>--root-dir</string>\n    <string>{}</string>\n  </array>\n  <key>RunAtLoad</key>\n  <true/>\n  <key>KeepAlive</key>\n  <true/>\n</dict>\n</plist>\n",
        xml_escape(LAUNCHD_LABEL),
        xml_escape(&daemon_path.display().to_string()),
        xml_escape(&root_dir.display().to_string()),
    )
}

fn resolve_home_for_user(user: &str) -> CliResult<PathBuf> {
    if cfg!(target_os = "linux") {
        let output = Command::new("getent").args(["passwd", user]).output()?;
        if !output.status.success() {
            return Err(format!("getent passwd {user} failed").into());
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        let home = stdout
            .trim()
            .split(':')
            .nth(5)
            .ok_or("unable to parse passwd home directory")?;
        return Ok(PathBuf::from(home));
    }
    if cfg!(target_os = "macos") {
        let output = Command::new("dscl")
            .args([".", "-read", &format!("/Users/{user}"), "NFSHomeDirectory"])
            .output()?;
        if !output.status.success() {
            return Err(format!("dscl failed while resolving home for {user}").into());
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        let home = stdout
            .lines()
            .find_map(|line| line.trim().strip_prefix("NFSHomeDirectory:"))
            .map(str::trim)
            .ok_or("unable to parse NFSHomeDirectory")?;
        return Ok(PathBuf::from(home));
    }
    Err("unsupported platform for resolving the target home directory".into())
}

fn ensure_root() -> CliResult {
    if current_uid()? == 0 {
        return Ok(());
    }
    Err("this action must be run with sudo".into())
}

fn current_uid() -> CliResult<u32> {
    let output = Command::new("id").arg("-u").output()?;
    if !output.status.success() {
        return Err("failed to determine the current uid".into());
    }
    let uid = String::from_utf8_lossy(&output.stdout).trim().parse()?;
    Ok(uid)
}

fn run_command<const N: usize>(program: &str, args: [&str; N]) -> CliResult {
    let output = Command::new(program).args(args).output()?;
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
    Err(format!("{} {} failed: {}", program, args.join(" "), details).into())
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

fn quote_arg(value: &str) -> String {
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

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_systemd_unit_quotes_daemon_and_root_paths() {
        let daemon_path = Path::new("/opt/AdaPT Tunnel/bin/apt-clientd");
        let root_dir = Path::new("/Users/jerry/Library/Application Support/AdaPT Tunnel");

        let rendered = render_systemd_unit(daemon_path, root_dir);

        assert!(rendered.contains("Description=AdaPT Tunnel client daemon"));
        assert!(rendered.contains(
            "ExecStart=\"/opt/AdaPT Tunnel/bin/apt-clientd\" --root-dir \"/Users/jerry/Library/Application Support/AdaPT Tunnel\""
        ));
        assert!(rendered.contains("Restart=always"));
        assert!(rendered.contains("WantedBy=multi-user.target"));
    }

    #[test]
    fn render_launchd_plist_xml_escapes_arguments() {
        let daemon_path = Path::new("/Applications/AdaPT & Tunnel/apt-clientd");
        let root_dir = Path::new("/Users/jerry/AdaPT <Tunnel> \"Root\"");

        let rendered = render_launchd_plist(daemon_path, root_dir);

        assert!(rendered.contains("<string>com.adapt-tunnel.clientd</string>"));
        assert!(rendered.contains("<string>/Applications/AdaPT &amp; Tunnel/apt-clientd</string>"));
        assert!(rendered
            .contains("<string>/Users/jerry/AdaPT &lt;Tunnel&gt; &quot;Root&quot;</string>"));
        assert!(rendered.contains("<key>KeepAlive</key>"));
    }
}
