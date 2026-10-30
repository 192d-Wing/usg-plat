//! TCP session state machine (RFC 6146 §3.5.2), without simultaneous open:
//! an unsolicited inbound SYN is dropped rather than held (POAM-008).

/// Which side a packet came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    V6,
    V4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    V6Init,
    V4Init,
    Established,
    V6FinRcv,
    V4FinRcv,
    BothFinRcv,
    Trans,
    /// Picked up on an adopted BIB after a takeover (POAM-028): runs on the
    /// transitory timer until the IPv4 side confirms the connection.
    Pickup,
}

pub const FIN: u8 = 0x01;
pub const SYN: u8 = 0x02;
pub const RST: u8 = 0x04;

/// Which idle timer applies after a transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Timer {
    Established,
    Transitory,
    /// Leave the current deadline unchanged.
    Keep,
}

/// Initial state for a session created by `side` (RFC 6146 §3.5.2.2), or
/// `None` if only a SYN may create state.
pub fn initial(side: Side, flags: u8) -> Option<TcpState> {
    if flags & SYN == 0 || flags & RST != 0 {
        return None;
    }
    Some(match side {
        Side::V6 => TcpState::V6Init,
        Side::V4 => TcpState::V4Init,
    })
}

/// State of a session picked up from a non-SYN, non-RST outbound segment
/// on an adopted BIB (RFC-002 / SEC-8): a FIN maps to V6 FIN RCV, anything
/// else to [`TcpState::Pickup`]. Both start on the transitory timer.
pub fn pickup(flags: u8) -> TcpState {
    if flags & FIN != 0 { TcpState::V6FinRcv } else { TcpState::Pickup }
}

/// Advances the state machine for one packet.
///
/// COMPLIANCE MAPPING:
/// - RFC 6146 §3.5.2.2 - TCP session state machine
/// - NIST 800-53: SC-10 - a RST cannot extend an INIT/BOTH-FIN/TRANS
///   session's lifetime
pub fn step(s: TcpState, side: Side, flags: u8) -> (TcpState, Timer) {
    use TcpState::*;
    if flags & RST != 0 {
        return match s {
            // INIT and BOTH FIN RCV already run on the transitory timer;
            // TRANS keeps its deadline (repeated RSTs never refresh it).
            V6Init | V4Init | BothFinRcv | Trans | Pickup => (s, Timer::Keep),
            _ => (Trans, Timer::Transitory),
        };
    }
    let fin = flags & FIN != 0;
    let syn = flags & SYN != 0;
    match (s, side) {
        (V6Init, Side::V4) if syn => (Established, Timer::Established),
        (V4Init, Side::V6) if syn => (Established, Timer::Established),
        // A retransmitted SYN from the opening side refreshes TCP_TRANS.
        (V6Init, Side::V6) | (V4Init, Side::V4) if syn => (s, Timer::Transitory),
        (V6Init | V4Init, _) => (s, Timer::Keep),
        (Established, Side::V6) if fin => (V6FinRcv, Timer::Established),
        (Established, Side::V4) if fin => (V4FinRcv, Timer::Established),
        (Established, _) => (Established, Timer::Established),
        (V6FinRcv, Side::V4) if fin => (BothFinRcv, Timer::Transitory),
        (V4FinRcv, Side::V6) if fin => (BothFinRcv, Timer::Transitory),
        (V6FinRcv | V4FinRcv, _) => (s, Timer::Established),
        (BothFinRcv, _) => (BothFinRcv, Timer::Keep),
        // RFC-002 / SEC-8: only the IPv4 peer's answer proves the picked-up
        // connection is live; the IPv6 side alone never extends it.
        (Pickup, Side::V4) if fin => (V4FinRcv, Timer::Established),
        (Pickup, Side::V4) => (Established, Timer::Established),
        (Pickup, Side::V6) if fin => (V6FinRcv, Timer::Transitory),
        (Pickup, Side::V6) => (Pickup, Timer::Keep),
        (Trans, _) => (Established, Timer::Established),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_and_close() {
        let s = initial(Side::V6, SYN).unwrap();
        assert_eq!(s, TcpState::V6Init);
        let (s, t) = step(s, Side::V4, SYN | 0x10);
        assert_eq!((s, t), (TcpState::Established, Timer::Established));
        let (s, _) = step(s, Side::V6, FIN | 0x10);
        assert_eq!(s, TcpState::V6FinRcv);
        let (s, t) = step(s, Side::V4, FIN | 0x10);
        assert_eq!((s, t), (TcpState::BothFinRcv, Timer::Transitory));
    }

    #[test]
    fn rst_and_syn_retransmit_in_each_state() {
        use TcpState::*;
        assert_eq!(step(V6Init, Side::V4, RST), (V6Init, Timer::Keep));
        assert_eq!(step(V4Init, Side::V6, RST), (V4Init, Timer::Keep));
        assert_eq!(step(BothFinRcv, Side::V4, RST), (BothFinRcv, Timer::Keep));
        assert_eq!(step(Trans, Side::V6, RST), (Trans, Timer::Keep));
        assert_eq!(step(V6FinRcv, Side::V4, RST), (Trans, Timer::Transitory));
        assert_eq!(step(V6Init, Side::V6, SYN), (V6Init, Timer::Transitory));
        assert_eq!(step(V4Init, Side::V4, SYN), (V4Init, Timer::Transitory));
        assert_eq!(step(V6Init, Side::V6, 0x10), (V6Init, Timer::Keep));
    }

    #[test]
    fn pickup_needs_the_v4_side() {
        use TcpState::*;
        assert_eq!(pickup(0x10), Pickup);
        assert_eq!(pickup(FIN | 0x10), V6FinRcv);
        assert_eq!(step(Pickup, Side::V6, 0x10), (Pickup, Timer::Keep));
        assert_eq!(step(Pickup, Side::V6, FIN | 0x10), (V6FinRcv, Timer::Transitory));
        assert_eq!(step(Pickup, Side::V4, 0x10), (Established, Timer::Established));
        assert_eq!(step(Pickup, Side::V4, FIN | 0x10), (V4FinRcv, Timer::Established));
        assert_eq!(step(Pickup, Side::V4, RST), (Pickup, Timer::Keep));
    }

    #[test]
    fn rst_goes_transitory_and_non_syn_cannot_create() {
        assert_eq!(step(TcpState::Established, Side::V4, RST).0, TcpState::Trans);
        assert!(initial(Side::V6, 0x10).is_none());
        assert!(initial(Side::V6, SYN | RST).is_none());
    }
}
