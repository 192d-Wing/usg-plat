//! In-test HTTP responder / CRL distribution point on 127.0.0.1 with a
//! request counter and fault injection.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

/// A parsed request as the handler sees it.
#[derive(Debug, Clone)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// What the handler wants sent back.
#[derive(Debug, Clone)]
pub enum Reply {
    /// Status, content type, body (Content-Length set).
    Ok { status: u16, content_type: String, body: Vec<u8> },
    /// Raw bytes written as-is, then the connection is closed.
    Raw(Vec<u8>),
    /// Wait, then send the inner reply.
    Delay(Duration, Box<Reply>),
    /// Close without answering.
    Close,
}

impl Reply {
    pub fn ok(content_type: &str, body: Vec<u8>) -> Self {
        Reply::Ok { status: 200, content_type: content_type.into(), body }
    }
}

type Handler = dyn Fn(&Request) -> Reply + Send + Sync;

#[derive(Debug)]
pub struct HttpServer {
    pub addr: SocketAddr,
    pub requests: Arc<AtomicUsize>,
    pub last: Arc<Mutex<Option<Request>>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl HttpServer {
    pub fn start(handler: impl Fn(&Request) -> Reply + Send + Sync + 'static) -> Self {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let requests = Arc::new(AtomicUsize::new(0));
        let last = Arc::new(Mutex::new(None));
        let stop = Arc::new(AtomicBool::new(false));
        let handler: Arc<Handler> = Arc::new(handler);
        let (r, la, st) = (requests.clone(), last.clone(), stop.clone());
        let thread = std::thread::spawn(move || {
            for s in l.incoming() {
                if st.load(Ordering::Acquire) {
                    break;
                }
                let Ok(s) = s else { continue };
                let (h, r, la) = (handler.clone(), r.clone(), la.clone());
                std::thread::spawn(move || serve(s, &*h, &r, &la));
            }
        });
        Self { addr, requests, last, stop, thread: Some(thread) }
    }

    pub fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.addr)
    }

    pub fn count(&self) -> usize {
        self.requests.load(Ordering::Acquire)
    }
}

impl Drop for HttpServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = TcpStream::connect(self.addr);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

fn read_request(s: &mut TcpStream) -> Option<Request> {
    s.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i;
        }
        let n = s.read(&mut chunk).ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8(buf[..end].to_vec()).ok()?;
    let mut lines = head.split("\r\n");
    let mut first = lines.next()?.split(' ');
    let method = first.next()?.to_owned();
    let path = first.next()?.to_owned();
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':').map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_owned())))
        .collect();
    let len = headers.iter().find(|(k, _)| k == "content-length").and_then(|(_, v)| v.parse().ok()).unwrap_or(0);
    let mut body = buf[end + 4..].to_vec();
    while body.len() < len {
        let n = s.read(&mut chunk).ok()?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    Some(Request { method, path, headers, body })
}

fn send(s: &mut TcpStream, reply: Reply) {
    match reply {
        Reply::Ok { status, content_type, body } => {
            let head = format!(
                "HTTP/1.0 {status} X\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\r\n",
                body.len()
            );
            let _ = s.write_all(head.as_bytes());
            let _ = s.write_all(&body);
        }
        Reply::Raw(b) => {
            let _ = s.write_all(&b);
        }
        Reply::Delay(d, inner) => {
            std::thread::sleep(d);
            send(s, *inner);
        }
        Reply::Close => {}
    }
}

fn serve(mut s: TcpStream, h: &Handler, count: &AtomicUsize, last: &Mutex<Option<Request>>) {
    let Some(req) = read_request(&mut s) else { return };
    count.fetch_add(1, Ordering::AcqRel);
    let reply = h(&req);
    *last.lock().unwrap() = Some(req);
    send(&mut s, reply);
}
