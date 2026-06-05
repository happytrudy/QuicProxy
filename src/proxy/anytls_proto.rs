// ─── Shared Anytls Protocol Constants ─────────────────────────────────────────

/// Protocol version supported by this implementation
pub const PROTOCOL_VERSION: u8 = 2;

/// Agent name used in cmdSettings / cmdServerSettings handshake
pub const AGENT_NAME: &str = "quicproxy/0.1.0";

// ─── Frame layout ─────────────────────────────────────────────────────────────

pub const FRAME_HEADER_SIZE: usize = 7; // cmd(1) + streamId(4) + dataLen(2)
pub const AUTH_HASH_SIZE: usize = 32; // SHA-256 output
pub const AUTH_LENGTH_FIELD_SIZE: usize = 2; // BE u16

/// UDP-over-TCP target domain
pub const UDP_OVER_TCP_TARGET: &str = "sp.v2.udp-over-tcp.arpa";

// ─── Frame Commands ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Command {
    Waste = 0,
    Syn = 1,
    Psh = 2,
    Fin = 3,
    Settings = 4,
    Alert = 5,
    UpdatePaddingScheme = 6,
    SynAck = 7,
    HeartRequest = 8,
    HeartResponse = 9,
    ServerSettings = 10,
}

impl From<Command> for u8 {
    fn from(cmd: Command) -> u8 {
        cmd as u8
    }
}

impl From<u8> for Command {
    fn from(v: u8) -> Command {
        match v {
            0 => Command::Waste,
            1 => Command::Syn,
            2 => Command::Psh,
            3 => Command::Fin,
            4 => Command::Settings,
            5 => Command::Alert,
            6 => Command::UpdatePaddingScheme,
            7 => Command::SynAck,
            8 => Command::HeartRequest,
            9 => Command::HeartResponse,
            10 => Command::ServerSettings,
            _ => panic!("unknown anytls command: {}", v),
        }
    }
}
