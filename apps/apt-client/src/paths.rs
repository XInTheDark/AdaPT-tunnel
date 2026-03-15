use apt_bundle::ensure_client_override_file;
use apt_client_control::{
    default_client_bundle_path, ensure_client_root_dir, DEFAULT_CLIENT_BUNDLE_FILE_NAME,
};
use std::{
    io::{self, Write},
    path::{Path, PathBuf},
};

pub(super) fn resolve_client_bundle_path(explicit: Option<PathBuf>) -> io::Result<PathBuf> {
    match explicit {
        Some(path) => Ok(path),
        None => Ok(find_client_bundle().unwrap_or(prompt_bundle_path()?)),
    }
}

pub(super) fn find_client_bundle() -> Option<PathBuf> {
    let default = default_client_bundle_path().ok();
    default
        .into_iter()
        .chain([
            PathBuf::from(format!("./{DEFAULT_CLIENT_BUNDLE_FILE_NAME}")),
            PathBuf::from("./adapt-client").join(DEFAULT_CLIENT_BUNDLE_FILE_NAME),
        ])
        .find(|path| path.exists())
}

pub(super) fn ensure_user_owned_override(bundle_path: &Path) -> io::Result<PathBuf> {
    if let Ok(default_path) = default_client_bundle_path() {
        if bundle_path == default_path {
            let _ = ensure_client_root_dir()?;
        }
    }
    ensure_client_override_file(bundle_path)
}

fn prompt_bundle_path() -> io::Result<PathBuf> {
    let default = default_client_bundle_path()?;
    let mut stdout = io::stdout();
    write!(stdout, "Path to client bundle [{}]: ", default.display())?;
    stdout.flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let trimmed = input.trim();
    Ok(if trimmed.is_empty() {
        default
    } else {
        PathBuf::from(trimmed)
    })
}
