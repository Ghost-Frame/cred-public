use anyhow::{anyhow, Context, Result};
use tracing::{debug, info};

/// YubiKey HMAC-SHA1 challenge-response interface.
/// Uses ykman (yubikey-manager) via subprocess since there's no stable
/// Rust crate for OTP slot challenge-response on Linux.
///
/// Slot 2 is used by convention (same as KeePassXC).
const SLOT: u8 = 2;

/// Fixed challenge used for key derivation.
/// Stored in ~/.config/cred/challenge alongside the config.
/// Changing this invalidates all encrypted credentials.
const CHALLENGE_FILE: &str = "challenge";

/// Send a challenge to the YubiKey and get the HMAC-SHA1 response.
/// Returns 20 bytes (160-bit HMAC-SHA1 output).
pub fn challenge_response(challenge: &[u8]) -> Result<Vec<u8>> {
    let challenge_hex = hex::encode(challenge);

    #[cfg(windows)]
    let output = try_ykchallenge(&challenge_hex)
        .context("failed to get YubiKey challenge-response -- is ykchallenge.exe on PATH? (~/.local/bin/ykchallenge.exe)")?;

    #[cfg(not(windows))]
    let output = try_ykman_challenge(&challenge_hex)
        .or_else(|_| try_python_ykman_challenge(&challenge_hex))
        .context("failed to get YubiKey challenge-response -- is the YubiKey plugged in?")?;

    let response = hex::decode(output.trim()).context("invalid hex response from YubiKey")?;

    if response.len() != 20 {
        return Err(anyhow!(
            "unexpected HMAC response length: {} (expected 20)",
            response.len()
        ));
    }

    debug!("YubiKey challenge-response OK ({} bytes)", response.len());
    Ok(response)
}

/// Windows-only: call ykchallenge.exe (official Yubico .NET SDK).
/// ykman subprocess fails on Windows due to HID exclusive access restrictions.
#[cfg(windows)]
fn try_ykchallenge(challenge_hex: &str) -> Result<String> {
    let output = std::process::Command::new("ykchallenge")
        .arg(challenge_hex)
        .output()
        .context("ykchallenge.exe not found -- is it in PATH? (~/.local/bin/ykchallenge.exe)")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!("ykchallenge failed: {}", stderr));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Program slot 2 with an HMAC-SHA1 secret.
/// WARNING: This overwrites whatever is currently in the slot.
#[allow(dead_code)]
pub fn program_hmac_secret(secret: &[u8]) -> Result<()> {
    if secret.len() != 20 {
        return Err(anyhow!("HMAC secret must be exactly 20 bytes"));
    }

    let secret_hex = hex::encode(secret);

    // Try direct ykman, fall back to python3 invocation
    try_ykman_program(&secret_hex)
        .or_else(|_| try_python_ykman_program(&secret_hex))
        .context("failed to program YubiKey -- is the YubiKey plugged in?")?;

    info!("programmed HMAC-SHA1 secret on slot {}", SLOT);
    Ok(())
}

/// Delete the OTP slot configuration.
#[allow(dead_code)]
pub fn delete_slot() -> Result<()> {
    try_ykman_delete()
        .or_else(|_| try_python_ykman_delete())
        .context("failed to delete YubiKey slot")?;

    info!("deleted slot {} configuration", SLOT);
    Ok(())
}

/// Get YubiKey device info (serial, firmware, etc.)
#[allow(dead_code)]
pub fn device_info() -> Result<String> {
    try_ykman_info()
        .or_else(|_| try_python_ykman_info())
        .context("failed to get YubiKey info -- is the YubiKey plugged in?")
}

/// Check if a YubiKey is present and slot 2 is programmed.
#[allow(dead_code)]
pub fn is_available() -> bool {
    // Quick check: try to get info
    device_info().is_ok()
}

/// Get the challenge for key derivation.
/// Reads from ~/.config/cred/challenge, or generates and saves a new one.
pub fn get_or_create_challenge() -> Result<Vec<u8>> {
    let config_dir = config_dir();
    let challenge_path = config_dir.join(CHALLENGE_FILE);

    if challenge_path.exists() {
        let data = std::fs::read(&challenge_path).context("failed to read challenge file")?;
        if data.len() == 32 {
            return Ok(data);
        }
        // Invalid challenge file, regenerate
    }

    // Generate new challenge
    let mut challenge = vec![0u8; 32];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut challenge);

    std::fs::create_dir_all(&config_dir).context("failed to create config directory")?;
    std::fs::write(&challenge_path, &challenge).context("failed to write challenge file")?;

    // chmod 600
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&challenge_path, std::fs::Permissions::from_mode(0o600))?;
    }

    info!("generated new challenge at {}", challenge_path.display());
    Ok(challenge)
}

/// Derive the AES-256-GCM master key by sending the stored challenge
/// to the YubiKey and running the response through Argon2id.
pub fn derive_master_key() -> Result<aes_gcm::Key<aes_gcm::Aes256Gcm>> {
    let challenge = get_or_create_challenge()?;
    let response = challenge_response(&challenge)?;
    crate::crypto::derive_key_from_yubikey_response(&response)
}

// ---------------------------------------------------------------------------
// ykman subprocess helpers
// ---------------------------------------------------------------------------

fn try_ykman_challenge(challenge_hex: &str) -> Result<String> {
    let output = std::process::Command::new("ykman")
        .args(["otp", "calculate", &SLOT.to_string(), challenge_hex])
        .output()
        .context("ykman not found")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!("ykman challenge failed: {}", stderr));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn try_python_ykman_challenge(challenge_hex: &str) -> Result<String> {
    let script = format!(
        r#"
import sys
from ykman._cli.__main__ import main
sys.argv = ['ykman', 'otp', 'calculate', '{}', '{}']
main()
"#,
        SLOT, challenge_hex
    );

    let output = std::process::Command::new("sudo")
        .args(["python3", "-c", &script])
        .output()
        .context("sudo python3 ykman failed")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!("python ykman challenge failed: {}", stderr));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn try_ykman_program(secret_hex: &str) -> Result<()> {
    let output = std::process::Command::new("ykman")
        .args(["otp", "chalresp", &SLOT.to_string(), "--force", secret_hex])
        .output()
        .context("ykman not found")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!("ykman program failed: {}", stderr));
    }

    Ok(())
}

fn try_python_ykman_program(secret_hex: &str) -> Result<()> {
    let script = format!(
        r#"
import sys
from ykman._cli.__main__ import main
sys.argv = ['ykman', 'otp', 'chalresp', '{}', '--force', '{}']
main()
"#,
        SLOT, secret_hex
    );

    let output = std::process::Command::new("sudo")
        .args(["python3", "-c", &script])
        .output()
        .context("sudo python3 ykman failed")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!("python ykman program failed: {}", stderr));
    }

    Ok(())
}

fn try_ykman_delete() -> Result<()> {
    let output = std::process::Command::new("ykman")
        .args(["otp", "delete", &SLOT.to_string(), "--force"])
        .output()
        .context("ykman not found")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!("ykman delete failed: {}", stderr));
    }

    Ok(())
}

fn try_python_ykman_delete() -> Result<()> {
    let script = format!(
        r#"
import sys
from ykman._cli.__main__ import main
sys.argv = ['ykman', 'otp', 'delete', '{}', '--force']
main()
"#,
        SLOT
    );

    let output = std::process::Command::new("sudo")
        .args(["python3", "-c", &script])
        .output()
        .context("sudo python3 ykman failed")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!("python ykman delete failed: {}", stderr));
    }

    Ok(())
}

fn try_ykman_info() -> Result<String> {
    let output = std::process::Command::new("ykman")
        .args(["info"])
        .output()
        .context("ykman not found")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!("ykman info failed: {}", stderr));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn try_python_ykman_info() -> Result<String> {
    let script = r#"
import sys
from ykman._cli.__main__ import main
sys.argv = ['ykman', 'info']
main()
"#;

    let output = std::process::Command::new("sudo")
        .args(["python3", "-c", script])
        .output()
        .context("sudo python3 ykman failed")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!("python ykman info failed: {}", stderr));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Config directory: ~/.config/cred/
fn config_dir() -> std::path::PathBuf {
    std::env::var("XDG_CONFIG_HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            std::env::var("HOME")
                .map(|h| std::path::PathBuf::from(h).join(".config"))
                .unwrap_or_else(|_| std::path::PathBuf::from("."))
        })
        .join("cred")
}
