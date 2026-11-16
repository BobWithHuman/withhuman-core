//! The company's device list from its EDR (a Wazuh manager).

/// A device as the EDR lists it; a row of `edr_devices`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EdrDevice {
    /// The EDR's own ID of the device (`001`).
    pub agent_id: String,
    /// The name it enrolled under, its hostname unless someone chose another.
    pub name: Option<String>,
    pub os: Option<String>,
    /// `active`, `disconnected`, `never_connected` or `pending`.
    pub status: Option<String>,
    /// The motherboard's serial number, as the EDR's inventory reports it.
    pub serial: Option<String>,
    /// When the EDR last heard from it, epoch milliseconds.
    pub last_seen: Option<i64>,
    /// `claude-code` or `codex` when the EDR's inventory shows that program on the device.
    pub agent: Option<String>,
}
