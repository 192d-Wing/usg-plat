//! The bounded HTTP/1.0 client against an in-test server (SC-5, SI-10).

#![allow(clippy::unwrap_used, clippy::expect_used)]

pub mod support;

use std::time::{Duration, Instant};

use plat_common::HttpUrl;
use plat_tls::revocation::http::{HttpError, Request, fetch};
use support::http_server::{HttpServer, Reply};

const TYPES: &[&str] = &["application/ocsp-response"];

fn get(deadline_ms: u64, max_body: usize) -> Request<'static> {
    Request {
        post: None,
        accept: "application/ocsp-response",
        accept_types: TYPES,
        max_body,
        deadline: Instant::now() + Duration::from_millis(deadline_ms),
    }
}

#[test]
fn post_and_get() {
    let srv = HttpServer::start(|r| Reply::ok("application/ocsp-response", r.body.iter().rev().copied().collect()));
    let url = HttpUrl::parse(&srv.url("/ocsp")).unwrap();
    let req = Request { post: Some(("application/ocsp-request", b"abc")), ..get(2000, 1024) };
    assert_eq!(fetch(&url, &req).unwrap().body, b"cba");
    let last = srv.last.lock().unwrap().clone().unwrap();
    assert_eq!((last.method.as_str(), last.path.as_str()), ("POST", "/ocsp"));
    assert!(last.headers.iter().any(|(k, v)| k == "content-type" && v == "application/ocsp-request"));
    assert!(last.headers.iter().any(|(k, v)| k == "host" && *v == srv.addr.to_string()));
    let g = fetch(&HttpUrl::parse(&srv.url("/ocsp/MEow")).unwrap(), &get(2000, 1024)).unwrap();
    assert!(g.body.is_empty());
    assert_eq!(srv.last.lock().unwrap().as_ref().unwrap().method, "GET");
    assert_eq!(srv.count(), 2);
}

#[test]
fn faults() {
    let srv = HttpServer::start(|r| match r.path.as_str() {
        "/500" => Reply::Ok { status: 500, content_type: "text/plain".into(), body: vec![] },
        "/redirect" => Reply::Raw(b"HTTP/1.0 301 Moved\r\nLocation: http://192.0.2.1/\r\n\r\n".to_vec()),
        "/type" => Reply::ok("text/html", b"<html>".to_vec()),
        "/big" => Reply::ok("application/ocsp-response", vec![0; 64]),
        "/huge-len" => Reply::Raw(
            b"HTTP/1.0 200 OK\r\nContent-Type: application/ocsp-response\r\nContent-Length: 1073741824\r\n\r\n"
                .to_vec(),
        ),
        "/slow" => Reply::Delay(Duration::from_millis(800), Box::new(Reply::ok("application/ocsp-response", vec![]))),
        "/close" => Reply::Close,
        _ => Reply::ok("application/ocsp-response", vec![1]),
    });
    let f = |p: &str, ms: u64| fetch(&HttpUrl::parse(&srv.url(p)).unwrap(), &get(ms, 32));
    assert_eq!(f("/500", 2000).unwrap_err(), HttpError::Status(500));
    assert_eq!(f("/redirect", 2000).unwrap_err(), HttpError::Status(301));
    assert_eq!(f("/type", 2000).unwrap_err(), HttpError::ContentType);
    assert_eq!(f("/big", 2000).unwrap_err(), HttpError::TooLarge);
    let t = Instant::now();
    assert_eq!(f("/huge-len", 2000).unwrap_err(), HttpError::TooLarge);
    assert!(t.elapsed() < Duration::from_secs(1), "refused on the declared length");
    let t = Instant::now();
    assert_eq!(f("/slow", 200).unwrap_err(), HttpError::Timeout);
    assert!(t.elapsed() < Duration::from_millis(700), "bounded by the deadline");
    assert_eq!(f("/close", 2000).unwrap_err(), HttpError::Malformed);
    assert_eq!(f("/ok", 2000).unwrap().body, [1]);
    // Nothing listening.
    let dead = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = HttpUrl::parse(&format!("http://{}/", dead.local_addr().unwrap())).unwrap();
    drop(dead);
    assert_eq!(fetch(&url, &get(1000, 32)).unwrap_err(), HttpError::Connect);
}
