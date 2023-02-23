use crate::Error;
use std::fmt::{Debug, Display, Formatter};
use std::str::FromStr;

const CLIENT_RANDOM: &str = "CLIENT_RANDOM";
const CLIENT_EARLY_TRAFFIC_SECRET: &str = "CLIENT_EARLY_TRAFFIC_SECRET";
const CLIENT_HANDSHAKE_TRAFFIC_SECRET: &str = "CLIENT_HANDSHAKE_TRAFFIC_SECRET";
const SERVER_HANDSHAKE_TRAFFIC_SECRET: &str = "SERVER_HANDSHAKE_TRAFFIC_SECRET";
const CLIENT_TRAFFIC_SECRET_0: &str = "CLIENT_TRAFFIC_SECRET_0";
const SERVER_TRAFFIC_SECRET_0: &str = "SERVER_TRAFFIC_SECRET_0";
const EXPORTER_SECRET: &str = "EXPORTER_SECRET";

/// Enumeration of the possible values for the keylog label.
/// See <https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format>
/// for details.
#[derive(Eq, PartialEq)]
pub enum KeyLogLabel {
    ClientRandom,
    ClientEarlyTrafficSecret,
    ClientHandshakeTrafficSecret,
    ServerHandshakeTrafficSecret,
    ClientTrafficSecret0,
    ServerTrafficSecret0,
    ExporterSecret,
}

impl KeyLogLabel {
    pub fn to_str(&self) -> &'static str {
        match self {
            KeyLogLabel::ClientRandom => CLIENT_RANDOM,
            KeyLogLabel::ClientEarlyTrafficSecret => CLIENT_EARLY_TRAFFIC_SECRET,
            KeyLogLabel::ClientHandshakeTrafficSecret => CLIENT_HANDSHAKE_TRAFFIC_SECRET,
            KeyLogLabel::ServerHandshakeTrafficSecret => SERVER_HANDSHAKE_TRAFFIC_SECRET,
            KeyLogLabel::ClientTrafficSecret0 => CLIENT_TRAFFIC_SECRET_0,
            KeyLogLabel::ServerTrafficSecret0 => SERVER_TRAFFIC_SECRET_0,
            KeyLogLabel::ExporterSecret => EXPORTER_SECRET,
        }
    }
}

impl Debug for KeyLogLabel {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.to_str())
    }
}

impl Display for KeyLogLabel {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.to_str())
    }
}

impl FromStr for KeyLogLabel {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            CLIENT_RANDOM => Ok(Self::ClientRandom),
            CLIENT_EARLY_TRAFFIC_SECRET => Ok(Self::ClientEarlyTrafficSecret),
            CLIENT_HANDSHAKE_TRAFFIC_SECRET => Ok(Self::ClientHandshakeTrafficSecret),
            SERVER_HANDSHAKE_TRAFFIC_SECRET => Ok(Self::ServerHandshakeTrafficSecret),
            CLIENT_TRAFFIC_SECRET_0 => Ok(Self::ClientTrafficSecret0),
            SERVER_TRAFFIC_SECRET_0 => Ok(Self::ServerTrafficSecret0),
            EXPORTER_SECRET => Ok(Self::ExporterSecret),
            _ => Err(Error::invalid_input(format!(
                "unable to parse keylog label: {}",
                s
            ))),
        }
    }
}

/// Provides a handler for logging key material. This is intended for debugging use with
/// tools like Wireshark.
pub trait KeyLog: Send + Sync {
    /// Logs the given `secret`. `client_random` is provided for
    /// session identification.  `label` describes precisely what
    /// `secret` means.
    ///
    /// Details of the format are described in:
    /// <https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format>
    fn log_key(&self, label: KeyLogLabel, client_random: &str, secret: &str);
}

/// A [KeyLog] that does nothing.
pub struct NoKeyLog;

impl KeyLog for NoKeyLog {
    fn log_key(&self, _: KeyLogLabel, _: &str, _: &str) {}
}
