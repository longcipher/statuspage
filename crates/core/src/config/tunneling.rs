//! SSH tunnel configuration for monitoring hosts behind bastion servers.

use serde::{Deserialize, Serialize};

/// Named SSH tunnels that endpoints can reference.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct TunnelingConfig {
    /// Named tunnel definitions.
    #[serde(default)]
    pub tunnels: Vec<SshTunnel>,
}

/// A single SSH tunnel definition.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SshTunnel {
    /// Unique tunnel name referenced by endpoint client configs.
    pub name: String,
    /// Bastion host (e.g. "bastion.example.com").
    pub host: String,
    /// SSH port (default 22).
    #[serde(default = "default_ssh_port")]
    pub port: u16,
    /// SSH username.
    pub username: String,
    /// Path to SSH private key file.
    #[serde(default)]
    pub private_key_path: Option<String>,
    /// Target host to forward to.
    pub target_host: String,
    /// Target port to forward to.
    pub target_port: u16,
}

const fn default_ssh_port() -> u16 {
    22
}
