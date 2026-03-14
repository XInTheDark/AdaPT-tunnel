use super::*;

pub fn load_key32(spec: &str) -> Result<[u8; 32], RuntimeError> {
    let resolved = if let Some(path) = spec.strip_prefix("file:") {
        fs::read_to_string(path).map_err(|source| RuntimeError::IoWithPath {
            path: PathBuf::from(path),
            source,
        })?
    } else {
        spec.to_string()
    };

    let trimmed = resolved.trim();
    let bytes = if trimmed.len() == 64 && trimmed.chars().all(|value| value.is_ascii_hexdigit()) {
        decode_hex(trimmed)?
    } else {
        base64::engine::general_purpose::STANDARD
            .decode(trimmed)
            .map_err(|_| {
                RuntimeError::InvalidKeyMaterial("key must be 64 hex chars or base64".to_string())
            })?
    };
    bytes.try_into().map_err(|_| {
        RuntimeError::InvalidKeyMaterial("key material must decode to 32 bytes".to_string())
    })
}

fn decode_hex(input: &str) -> Result<Vec<u8>, RuntimeError> {
    let mut output = Vec::with_capacity(input.len() / 2);
    let bytes = input.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let hi = decode_nibble(bytes[index])?;
        let lo = decode_nibble(bytes[index + 1])?;
        output.push((hi << 4) | lo);
        index += 2;
    }
    Ok(output)
}

fn decode_nibble(byte: u8) -> Result<u8, RuntimeError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(RuntimeError::InvalidKeyMaterial(
            "invalid hex digit in key material".to_string(),
        )),
    }
}

pub fn encode_key_hex(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

pub(super) fn store_toml<T: Serialize>(path: &Path, value: &T) -> Result<(), RuntimeError> {
    let serialized = toml::to_string_pretty(value)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| RuntimeError::IoWithPath {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    fs::write(path, serialized).map_err(|source| RuntimeError::IoWithPath {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(())
}

pub(super) fn maybe_upgrade_toml_file<T: Serialize>(
    path: &Path,
    raw: &str,
    value: &T,
) -> Result<(), RuntimeError> {
    let serialized = toml::to_string_pretty(value)?;
    if raw.trim() == serialized.trim() {
        return Ok(());
    }
    fs::write(path, serialized).map_err(|source| RuntimeError::IoWithPath {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(())
}

pub(super) fn resolve_file_spec_relative_to_base(spec: &mut String, base: &Path) {
    if let Some(path) = spec.strip_prefix("file:") {
        let path = Path::new(path);
        if path.is_relative() {
            *spec = format!("file:{}", base.join(path).display());
        }
    }
}

pub(super) fn resolve_socket_addr(spec: &str) -> Result<SocketAddr, RuntimeError> {
    if spec.contains("example.com") {
        return Err(RuntimeError::InvalidConfig(format!(
            "server address `{spec}` still uses the example placeholder; replace it with the server's reachable IP:port or DNS name"
        )));
    }
    if let Ok(parsed) = spec.parse() {
        return Ok(parsed);
    }
    spec.to_socket_addrs()
        .map_err(|source| {
            RuntimeError::InvalidConfig(format!("unable to resolve {spec}: {source}"))
        })?
        .next()
        .ok_or_else(|| {
            RuntimeError::InvalidConfig(format!("no socket addresses resolved for {spec}"))
        })
}
