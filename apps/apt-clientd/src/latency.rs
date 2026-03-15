use std::{error::Error, net::Ipv4Addr, time::Duration};
use tokio::{process::Command, time::timeout};

pub(crate) async fn measure_tunnel_rtt_ms(
    target: Ipv4Addr,
) -> Result<Option<f64>, Box<dyn Error + Send + Sync>> {
    let output = timeout(
        Duration::from_secs(3),
        Command::new("ping")
            .arg("-n")
            .arg("-c")
            .arg("1")
            .arg(target.to_string())
            .output(),
    )
    .await??;
    if !output.status.success() {
        return Ok(None);
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(parse_ping_time_ms(&stdout))
}

fn parse_ping_time_ms(output: &str) -> Option<f64> {
    output.lines().find_map(|line| {
        let marker = line.find("time=")?;
        let suffix = &line[(marker + 5)..];
        let value = suffix
            .split_whitespace()
            .next()?
            .trim_end_matches("ms")
            .trim();
        value.parse::<f64>().ok()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_macos_ping_output() {
        let output = "64 bytes from 10.77.0.1: icmp_seq=0 ttl=64 time=18.455 ms";
        assert_eq!(parse_ping_time_ms(output), Some(18.455));
    }
}
