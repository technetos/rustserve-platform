use rustserve::Route;

use std::fs::File;
use std::io::{self, BufReader};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use rustls_pemfile::{certs, pkcs8_private_keys};

use tokio_rustls::rustls::{self, Certificate, PrivateKey};
use tokio_rustls::TlsAcceptor;

use tokio::net::TcpListener;
use tokio::net::TcpStream;

use bytes::Buf;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper::{body::Incoming, server::conn::http1, service::service_fn};

fn load_certs(path: &Path) -> io::Result<Vec<Certificate>> {
    certs(&mut BufReader::new(File::open(path)?))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid cert"))
        .map(|mut certs| certs.drain(..).map(Certificate).collect())
}

fn load_keys(path: &Path) -> io::Result<Vec<PrivateKey>> {
    pkcs8_private_keys(&mut BufReader::new(File::open(path)?))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid key"))
        .map(|mut keys| keys.drain(..).map(PrivateKey).collect())
}

pub async fn drive(
    server_addr: SocketAddr,
    routes: Arc<Vec<Route>>,
    use_tls: bool,
    service_name: impl Into<String>,
) -> anyhow::Result<()> {
    let name = service_name.into();
    let listener = TcpListener::bind(server_addr).await?;

    if use_tls {
        let cert_root_path = std::env::var("CERTIFICATE_ROOT").unwrap_or(".".into());
        let certs = load_certs(Path::new(&format!("{cert_root_path}/{name}/rsa/end.cert")))?;
        let mut keys = load_keys(Path::new(&format!("{cert_root_path}/{name}/rsa/end.key")))?;
        let config = rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(certs, keys.remove(0))
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;

        //config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        let acceptor = TlsAcceptor::from(Arc::new(config));

        loop {
            let (tcp_stream, _) = listener.accept().await?;
            serve_tls_connection(tcp_stream, &acceptor, routes.clone()).await?;
        }
    } else {
        loop {
            let (tcp_stream, _) = listener.accept().await?;
            serve_connection(tcp_stream, routes.clone()).await?;
        }
    }
}

async fn serve_tls_connection(
    tcp_stream: TcpStream,
    acceptor: &TlsAcceptor,
    routes: Arc<Vec<Route>>,
) -> anyhow::Result<()> {
    let acceptor = acceptor.clone();
    let routes = routes.clone();
    tokio::spawn(async move {
        let routes = routes.clone();

        let tls_stream = acceptor.accept(tcp_stream).await?;

        let service = service_fn(move |req: Request<Incoming>| {
            let routes = routes.clone();
            async move { Ok::<_, anyhow::Error>(handle_request(req, routes).await?) }
        });

        if let Err(err) = http1::Builder::new()
            .serve_connection(tls_stream, service)
            .await
        {
            println!("Error serving connection: {:?}", err);
        }

        Ok::<_, anyhow::Error>(())
    });

    Ok(())
}

async fn serve_connection(tcp_stream: TcpStream, routes: Arc<Vec<Route>>) -> anyhow::Result<()> {
    let routes = routes.clone();

    tokio::spawn(async move {
        let service = service_fn(move |req: Request<Incoming>| {
            let routes = routes.clone();
            async move { Ok::<_, anyhow::Error>(handle_request(req, routes).await?) }
        });

        if let Err(err) = http1::Builder::new()
            .serve_connection(tcp_stream, service)
            .await
        {
            println!("Error serving connection: {:?}", err);
        }

        Ok::<_, anyhow::Error>(())
    });

    Ok(())
}

async fn handle_request<'a>(
    req: Request<Incoming>,
    routes: Arc<Vec<Route>>,
) -> anyhow::Result<http::Response<Full<Bytes>>> {
    let (parts, body) = req.into_parts();

    let mut buf = body.collect().await?.aggregate();
    let bytes = buf.copy_to_bytes(buf.remaining());

    let res = rustserve::route_request(Request::from_parts(parts, &bytes[..]), routes).await?;

    Ok::<_, anyhow::Error>(res.map(|body| Full::new(Bytes::from(body))))
}
