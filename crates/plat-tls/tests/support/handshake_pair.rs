//! In-memory mutual-TLS 1.3 handshake over the policy's FIPS provider, for
//! the control-plane handshake cost test and bench. rcgen P-256 PKI, no
//! revocation, no sockets: records move between the two connections through
//! `Vec`s, so byte counts are exact and the timing excludes the network.

use std::sync::Arc;

use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, SignatureAlgorithm};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};

const NAME: &str = "plat.example";

/// Client and server configs for one key-exchange policy.
#[derive(Debug)]
pub struct Pair {
    pub client: Arc<ClientConfig>,
    pub server: Arc<ServerConfig>,
}

/// Bytes on the wire per flight of one handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Flights {
    /// First client flight (ClientHello).
    pub client_hello: usize,
    /// First server flight (ServerHello .. server Finished).
    pub server_flight: usize,
    /// Second client flight (Certificate, CertificateVerify, Finished).
    pub client_finish: usize,
    /// Server flights sent before the handshake completed (1 = no HelloRetryRequest).
    pub server_flights: usize,
}

impl Flights {
    pub fn total(&self) -> usize {
        self.client_hello + self.server_flight + self.client_finish
    }
}

fn ok<T, E: std::fmt::Debug>(r: Result<T, E>, what: &str) -> T {
    r.unwrap_or_else(|e| panic!("{what}: {e:?}"))
}

fn leaf(
    issuer: &Issuer<'_, KeyPair>,
    alg: &'static SignatureAlgorithm,
) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let key = ok(KeyPair::generate_for(alg), "leaf key");
    let params = ok(CertificateParams::new(vec![NAME.to_owned()]), "leaf params");
    let cert = ok(params.signed_by(&key, issuer), "leaf cert");
    (cert.der().clone(), PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())))
}

impl Pair {
    /// Configs with `pq_hybrid` key exchange and leaves signed with `alg`.
    pub fn new(pq_hybrid: bool, alg: &'static SignatureAlgorithm) -> Self {
        let provider = ok(plat_tls::policy::fips_provider(pq_hybrid), "fips provider");
        let ca_key = ok(KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256), "ca key");
        let mut ca = ok(CertificateParams::new(Vec::<String>::new()), "ca params");
        ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_der = ok(ca.self_signed(&ca_key), "ca cert").der().clone();
        let issuer = Issuer::new(ca, ca_key);
        let mut roots = RootCertStore::empty();
        ok(roots.add(ca_der), "root");
        let roots = Arc::new(roots);

        let (s_cert, s_key) = leaf(&issuer, alg);
        let verifier =
            ok(WebPkiClientVerifier::builder_with_provider(roots.clone(), provider.clone()).build(), "client verifier");
        let mut server = ok(
            ok(
                ServerConfig::builder_with_provider(provider.clone())
                    .with_protocol_versions(&[&rustls::version::TLS13]),
                "server versions",
            )
            .with_client_cert_verifier(verifier)
            .with_single_cert(vec![s_cert], s_key),
            "server config",
        );
        server.send_tls13_tickets = 0;

        let (c_cert, c_key) = leaf(&issuer, alg);
        let client = ok(
            ok(
                ClientConfig::builder_with_provider(provider).with_protocol_versions(&[&rustls::version::TLS13]),
                "client versions",
            )
            .with_root_certificates(roots)
            .with_client_auth_cert(vec![c_cert], c_key),
            "client config",
        );
        Self { client: Arc::new(client), server: Arc::new(server) }
    }

    /// Runs one full handshake and returns the bytes per flight.
    pub fn handshake(&self) -> Flights {
        let name = ok(ServerName::try_from(NAME), "name");
        let mut c = ok(ClientConnection::new(self.client.clone(), name), "client");
        let mut s = ok(ServerConnection::new(self.server.clone()), "server");
        let mut buf = Vec::with_capacity(8192);
        let mut client_flights = Vec::new();
        let mut server_flights = Vec::new();
        for _ in 0..8 {
            if !c.is_handshaking() && !s.is_handshaking() {
                break;
            }
            buf.clear();
            while c.wants_write() {
                ok(c.write_tls(&mut buf), "client write");
            }
            if !buf.is_empty() {
                client_flights.push(buf.len());
                let mut rd = buf.as_slice();
                while !rd.is_empty() {
                    ok(s.read_tls(&mut rd), "server read");
                }
                ok(s.process_new_packets(), "server process");
            }
            buf.clear();
            while s.wants_write() {
                ok(s.write_tls(&mut buf), "server write");
            }
            if !buf.is_empty() {
                server_flights.push(buf.len());
                let mut rd = buf.as_slice();
                while !rd.is_empty() {
                    ok(c.read_tls(&mut rd), "client read");
                }
                ok(c.process_new_packets(), "client process");
            }
        }
        assert!(!c.is_handshaking() && !s.is_handshaking(), "handshake did not complete");
        let at = |v: &[usize], i: usize| v.get(i).copied().unwrap_or(0);
        Flights {
            client_hello: at(&client_flights, 0),
            server_flight: at(&server_flights, 0),
            client_finish: at(&client_flights, 1),
            server_flights: server_flights.len(),
        }
    }
}
