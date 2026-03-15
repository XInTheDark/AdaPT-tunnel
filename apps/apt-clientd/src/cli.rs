use apt_client_control::{default_client_root_dir, default_client_socket_path_in};
use clap::Parser;
use std::{io, path::PathBuf};

#[derive(Debug, Parser)]
#[command(name = "apt-clientd", about = "Privileged local AdaPT client daemon")]
pub(crate) struct Cli {
    /// Explicit client root directory containing the control socket and default bundle path.
    #[arg(long)]
    pub root_dir: Option<PathBuf>,
    /// Explicit Unix socket path. Defaults to <root-dir>/clientd.sock.
    #[arg(long)]
    pub socket_path: Option<PathBuf>,
}

impl Cli {
    pub(crate) fn resolved_root_dir(&self) -> io::Result<PathBuf> {
        match self.root_dir.clone() {
            Some(path) => Ok(path),
            None => default_client_root_dir(),
        }
    }

    pub(crate) fn resolved_socket_path(&self) -> io::Result<PathBuf> {
        match self.socket_path.clone() {
            Some(path) => Ok(path),
            None => Ok(default_client_socket_path_in(self.resolved_root_dir()?)),
        }
    }
}
