use std::sync::Arc;

use bytes::Bytes;
use futures::future::BoxFuture;
use http::Method;
use http_body_util::{Empty, Full};
use rustserve::ServiceRequest;
use serde_json::Value;

use crate::mtls;

/// Send a request to `path` using `controller` with payload `req`
pub async fn make_and_send_request<'a, C, Req, Res>(
    controller: Arc<C>,
    path: &'a str,
    req: Req,
) -> anyhow::Result<http::Response<Res>>
where
    C: ServiceRequest<'a, Req, Res> + CertificatePath<'a, Req, Res>,
    Req: serde::Serialize + Send + 'a,
    Res: for<'de> serde::Deserialize<'de> + Send + Unpin + 'a,
{
    let res = send_request(controller.clone(), &path, req).await?;

    if res.status().as_u16() == 200 {
        Ok(controller.parse_response(res).await?)
    } else {
        let (_, body) = res.into_parts();
        let error_payload: Value = serde_json::from_slice(&body)?;
        Err(anyhow::anyhow!("{error_payload}"))
    }
}

/// Trait mixin to determine the location of the certificates to use when establishing a TLS
/// connection.
pub trait CertificatePath<'a, Req, Res>: Send + Sync
where
    Req: serde::Serialize + Send + 'a,
    Res: for<'de> serde::Deserialize<'de> + Send + 'a,
{
    /// Returns the location of the certificates to use for this Req/Res pair.
    fn cert_path(self: Arc<Self>) -> BoxFuture<'a, anyhow::Result<String>>;
}

/// Establish a TLS connection to a TLS host and send an HTTP request to that host.
///
/// Returns Response parameterized by the payload as an array of bytes.
pub async fn send_request<'a, C, Req, Res>(
    controller: Arc<C>,
    path: &'a str,
    req: Req,
) -> anyhow::Result<http::Response<Vec<u8>>>
where
    C: ServiceRequest<'a, Req, Res> + CertificatePath<'a, Req, Res>,
    Req: serde::Serialize + Send + 'a,
    Res: for<'de> serde::Deserialize<'de> + Send + Unpin + 'a,
{
    let cert_path = controller.clone().cert_path().await?;
    tls_connect_and_send(controller, &path, cert_path, req).await
}

async fn tls_connect_and_send<'a, C, Req, Res>(
    controller: Arc<C>,
    path: &'a str,
    full_cert_path: String,
    req: Req,
) -> anyhow::Result<http::Response<Vec<u8>>>
where
    C: ServiceRequest<'a, Req, Res>,
    Req: serde::Serialize + Send + 'a,
    Res: for<'de> serde::Deserialize<'de> + Send + Unpin + 'a,
{
    let addr = controller.clone().addr().await?;
    let request = controller.clone().create_request(addr.clone(), path, req).await?;

    let mtls = mtls::Mtls::new(
        addr,
        full_cert_path,
        request.headers().get("host").unwrap().to_str()?,
    )?;

    let res = if C::method() == Method::GET {
        mtls.send(request.map(|_| Empty::<Bytes>::new())).await?
    } else {
        mtls.send(request.map(|bytes| Full::new(Bytes::from(bytes))))
            .await?
    };

    Ok(res)
}
