use crate::error::RuntimeError;
use futures_util::{SinkExt, StreamExt};
use std::{
    net::{Ipv4Addr, Ipv6Addr},
    process::Command,
};
use tokio::sync::mpsc;
use tracing::{debug, warn};
use tun::AbstractDevice;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TunInterfaceConfig {
    pub name: Option<String>,
    pub local_ipv4: Ipv4Addr,
    pub peer_ipv4: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub local_ipv6: Option<Ipv6Addr>,
    pub ipv6_prefix_len: Option<u8>,
    pub mtu: u16,
}

#[derive(Debug)]
pub struct TunHandle {
    pub interface_name: String,
    pub inbound_rx: mpsc::Receiver<Vec<u8>>,
    pub outbound_tx: mpsc::Sender<Vec<u8>>,
}

pub async fn spawn_tun_worker(config: TunInterfaceConfig) -> Result<TunHandle, RuntimeError> {
    if config.local_ipv6.is_some() != config.ipv6_prefix_len.is_some() {
        return Err(RuntimeError::InvalidConfig(
            "IPv6 TUN settings require both local_ipv6 and ipv6_prefix_len".to_string(),
        ));
    }
    let mut tun_config = tun::Configuration::default();
    tun_config
        .address(config.local_ipv4)
        .destination(config.peer_ipv4)
        .netmask(config.netmask)
        .mtu(config.mtu)
        .up();
    if let Some(name) = &config.name {
        #[cfg(target_os = "macos")]
        {
            if name.starts_with("utun") {
                tun_config.tun_name(name);
            } else {
                warn!(
                    requested_name = %name,
                    "ignoring invalid macOS TUN interface name; allowing the OS to allocate a utun interface automatically"
                );
            }
        }

        #[cfg(not(target_os = "macos"))]
        tun_config.tun_name(name);
    }

    #[cfg(target_os = "linux")]
    tun_config.platform_config(|platform| {
        #[allow(deprecated)]
        platform.packet_information(false);
        platform.ensure_root_privileges(true);
    });

    let device = tun::create_as_async(&tun_config)
        .map_err(|error| RuntimeError::CommandFailed(error.to_string()))?;
    let interface_name = device
        .tun_name()
        .map_err(|error| RuntimeError::CommandFailed(error.to_string()))?;
    configure_ipv6_interface(&interface_name, config.local_ipv6, config.ipv6_prefix_len)?;
    let mut framed = device.into_framed();
    let (inbound_tx, inbound_rx) = mpsc::channel::<Vec<u8>>(1_024);
    let (outbound_tx, mut outbound_rx) = mpsc::channel::<Vec<u8>>(1_024);
    tokio::spawn(async move {
        loop {
            tokio::select! {
                packet = framed.next() => {
                    match packet {
                        Some(Ok(bytes)) => {
                            if inbound_tx.send(bytes).await.is_err() {
                                break;
                            }
                        }
                        Some(Err(error)) => {
                            warn!(error = %error, "tun read failure");
                            break;
                        }
                        None => break,
                    }
                }
                outbound = outbound_rx.recv() => {
                    match outbound {
                        Some(packet) => {
                            if let Err(error) = framed.send(packet).await {
                                warn!(error = %error, "tun write failure");
                                break;
                            }
                        }
                        None => break,
                    }
                }
            }
        }
        debug!("tun worker exiting");
    });

    Ok(TunHandle {
        interface_name,
        inbound_rx,
        outbound_tx,
    })
}

fn configure_ipv6_interface(
    interface_name: &str,
    local_ipv6: Option<Ipv6Addr>,
    ipv6_prefix_len: Option<u8>,
) -> Result<(), RuntimeError> {
    let (Some(local_ipv6), Some(prefix_len)) = (local_ipv6, ipv6_prefix_len) else {
        return Ok(());
    };
    if prefix_len > 128 {
        return Err(RuntimeError::InvalidConfig(
            "ipv6_prefix_len must be between 0 and 128".to_string(),
        ));
    }

    #[cfg(target_os = "linux")]
    {
        run_command(
            "ip",
            &[
                "-6".into(),
                "addr".into(),
                "add".into(),
                format!("{local_ipv6}/{prefix_len}"),
                "dev".into(),
                interface_name.into(),
            ],
        )
    }

    #[cfg(target_os = "macos")]
    {
        run_command(
            "ifconfig",
            &[
                interface_name.into(),
                "inet6".into(),
                local_ipv6.to_string(),
                "prefixlen".into(),
                prefix_len.to_string(),
                "alias".into(),
            ],
        )
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = interface_name;
        let _ = local_ipv6;
        let _ = prefix_len;
        Err(RuntimeError::UnsupportedPlatform(
            "IPv6 TUN setup is only implemented for Linux and macOS",
        ))
    }
}

fn run_command(program: &str, args: &[String]) -> Result<(), RuntimeError> {
    let output = Command::new(program).args(args).output()?;
    if output.status.success() {
        return Ok(());
    }
    Err(RuntimeError::CommandFailed(format!(
        "{} {} failed: {}",
        program,
        args.join(" "),
        String::from_utf8_lossy(&output.stderr)
    )))
}
