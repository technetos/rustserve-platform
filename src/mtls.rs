use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;

use rustls_pemfile::certs;

use tokio_rustls::rustls;

use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::OwnedTrustAnchor;
use tokio_rustls::{webpki, TlsConnector};

use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;
use tokio::net::TcpStream;

use bytes::Buf;
use http_body_util::BodyExt;

use hyper::client::conn::http1::Connection;
use hyper::client::conn::http1::SendRequest;

pub struct Mtls {
    addr: String,
    root_cert_store: rustls::RootCertStore,
    host: String,
}

impl Mtls {
    pub fn new(
        addr: impl Into<String>,
        full_path: impl Into<String>,
        host: impl Into<String>,
    ) -> anyhow::Result<Self> {
        let full_path = full_path.into();
        let chain_file = &mut BufReader::new(File::open(&full_path)?);
        let chain = certs(chain_file).unwrap();

        let mut root_cert_store = rustls::RootCertStore::empty();

        root_cert_store.add_server_trust_anchors(chain.iter().map(|cert| {
            let ta = webpki::TrustAnchor::try_from_cert_der(&cert[..]).unwrap();
            OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            )
        }));

        Ok(Self {
            addr: addr.into(),
            host: host.into(),
            root_cert_store,
        })
    }

    pub async fn connect<B>(
        &self,
    ) -> anyhow::Result<(
        SendRequest<B>,
        Connection<TlsStream<impl AsyncRead + AsyncWrite + Send + 'static>, B>,
    )>
    where
        B: hyper::body::Body + Send + 'static,
        B::Data: Send,
        B::Error: Send + Sync + std::error::Error,
    {
        let config = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(self.root_cert_store.clone())
            .with_no_client_auth();

        let connector = TlsConnector::from(Arc::new(config));

        let tcp_stream = TcpStream::connect(self.addr.clone()).await?;

        let domain = rustls::ServerName::try_from(&self.host.clone()[..])?;

        let tls_stream = connector.connect(domain, tcp_stream).await?;

        Ok(hyper::client::conn::http1::handshake(tls_stream).await?)
    }

    pub async fn send<B>(&self, req: hyper::Request<B>) -> anyhow::Result<hyper::Response<Vec<u8>>>
    where
        B: hyper::body::Body + Send + std::fmt::Debug + 'static,
        B::Data: Send,
        B::Error: Send + Sync + std::error::Error,
    {
        let (mut request_sender, connection) = self.connect().await?;

        // spawn a task to poll the connection and drive the HTTP state
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                eprintln!("Error in connection: {}", e);
            }
        });

        let res = request_sender.send_request(req).await?;

        let (parts, body) = res.into_parts();

        let mut buf = body.collect().await?.aggregate();
        let bytes = buf.copy_to_bytes(buf.remaining());

        Ok(hyper::Response::from_parts(parts, bytes.to_vec()))
    }
}
