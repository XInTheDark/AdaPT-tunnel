use crate::error::RuntimeError;
use futures_util::{SinkExt, StreamExt};
use std::net::Ipv4Addr;
use tokio::sync::mpsc;
use tracing::{debug, warn};
use tun::AbstractDevice;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TunInterfaceConfig {
    pub name: Option<String>,
    pub local_ipv4: Ipv4Addr,
    pub peer_ipv4: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub mtu: u16,
}

#[derive(Debug)]
pub struct TunHandle {
    pub interface_name: String,
    pub inbound_rx: mpsc::Receiver<Vec<u8>>,
    pub outbound_tx: mpsc::Sender<Vec<u8>>,
}

pub async fn spawn_tun_worker(config: TunInterfaceConfig) -> Result<TunHandle, RuntimeError> {
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
