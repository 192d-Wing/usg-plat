//! In-memory queue for tests, simulation and non-Linux development.

use std::io;

use crossbeam_channel::{Receiver, RecvTimeoutError, Sender};

use crate::{POLL_INTERVAL, PacketQueue};

#[derive(Debug)]
pub struct MemQueue {
    rx: Receiver<Vec<u8>>,
    tx: Sender<Vec<u8>>,
}

/// Returns `(device_side, host_side)`: packets sent on one are received on the other.
pub fn pair(capacity: usize) -> (MemQueue, MemQueue) {
    let (atx, arx) = crossbeam_channel::bounded(capacity);
    let (btx, brx) = crossbeam_channel::bounded(capacity);
    (MemQueue { rx: arx, tx: btx }, MemQueue { rx: brx, tx: atx })
}

impl PacketQueue for MemQueue {
    fn recv(&mut self, buf: &mut [u8]) -> io::Result<Option<usize>> {
        match self.rx.recv_timeout(POLL_INTERVAL) {
            Ok(p) => {
                let n = p.len().min(buf.len());
                buf[..n].copy_from_slice(&p[..n]);
                Ok(Some(n))
            }
            Err(RecvTimeoutError::Timeout) => Ok(None),
            Err(RecvTimeoutError::Disconnected) => Err(io::ErrorKind::BrokenPipe.into()),
        }
    }

    fn send(&mut self, pkt: &[u8]) -> io::Result<()> {
        self.tx.try_send(pkt.to_vec()).map_err(|_| io::Error::from(io::ErrorKind::WouldBlock))
    }
}
