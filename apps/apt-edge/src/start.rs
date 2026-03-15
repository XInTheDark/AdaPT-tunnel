use super::*;

pub(super) async fn start_server(config: Option<PathBuf>, mode: Option<u8>) -> CliResult {
    let config_path = match config {
        Some(path) => path,
        None => match find_server_config() {
            Some(path) => path,
            None => prompt_path("Server config path", Some("/etc/adapt/server.toml"))?,
        },
    };
    println!("Starting APT server using {}", config_path.display());
    println!("Press Ctrl-C to stop.\n");
    let loaded = ServerConfig::load(&config_path)?;
    let _ = loaded.store(&config_path);
    let mut resolved = loaded.resolve()?;
    if let Some(mode) = mode {
        let mode = Mode::try_from(mode).expect("clap validated mode range");
        resolved.mode = mode;
        resolved.session_policy.initial_mode = mode.policy_mode();
        resolved.session_policy.allow_speed_first = mode.allow_speed_first();
    }
    let result = run_server(resolved).await?;
    println!("\nServer stopped.");
    println!(
        "Active sessions at shutdown: {}",
        result.status.active_sessions
    );
    Ok(())
}
