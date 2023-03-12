use std::collections::HashMap;
use std::sync::Arc;

use bytes::Bytes;
use futures::future::BoxFuture;
use http::Method;
use http_body_util::{Empty, Full};
use rustserve::ServiceRequest;
use serde_json::Value;

use crate::mtls;

/// Service details
#[derive(Clone)]
pub struct ServiceProfile {
    addr: String,
}

impl ServiceProfile {
    /// Create a new ServiceProfile
    pub fn new(addr: impl Into<String>) -> Self {
        Self { addr: addr.into() }
    }

    /// Get the address for the service
    pub fn addr(&self) -> String {
        self.addr.clone()
    }
}

/// The service for looking up other services by name
pub struct Registry {
    map: HashMap<String, ServiceProfile>,
}

impl Registry {
    /// Create a new registry instance initialized with an array of key value pairs
    pub fn new<const N: usize>(values: [(impl Into<String>, ServiceProfile); N]) -> Self {
        Self {
            map: HashMap::from_iter(values.into_iter().map(|(s, u)| (s.into(), u.into()))),
        }
    }

    /// Look up a name in the registry
    pub async fn lookup(self: Arc<Self>, name: &str) -> anyhow::Result<ServiceProfile> {
        Ok(self.map.get(name).cloned().unwrap())
    }
}

// -------------------

/// Send a request to `path` using `controller` with payload `req`
pub async fn make_and_send_request<'a, C, Req, Res>(
    controller: Arc<C>,
    path: &'a str,
    req: Req,
) -> anyhow::Result<http::Response<Res>>
where
    C: ServiceRequest<'a, Req, Res> + CertificatePath<'a, Req, Res>,
    Req: serde::Serialize + Send + 'a,
    Res: for<'de> serde::Deserialize<'de> + Send + 'a,
{
    let github_res = send_request(controller.clone(), &path, req).await?;

    if github_res.status().as_u16() == 200 {
        Ok(controller.parse_response(github_res).await?)
    } else {
        let (_, body) = github_res.into_parts();
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
    Res: for<'de> serde::Deserialize<'de> + Send + 'a,
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
    Res: for<'de> serde::Deserialize<'de> + Send + 'a,
{
    let request = controller.clone().create_request(path, req).await?;

    let addr = controller.clone().addr().await?;

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

/// Utility macro for implementing the ServiceRequest trait.
#[macro_export]
macro_rules! impl_service_request {
    (
        method: $method:ident,
        request: $req:ty,
        response: $res:ty,
        service_name: $service_name:literal,
        for: $controller:ident,
    ) => {
        impl<'a> ServiceRequest<'a, $req, $res> for $controller {
            fn addr(self: Arc<Self>) -> BoxFuture<'a, anyhow::Result<String>> {
                Box::pin(
                    async move { Ok(self.registry.clone().lookup($service_name).await?.addr()) },
                )
            }

            fn method() -> http::Method {
                http::Method::$method
            }

            fn service_name() -> &'static str {
                $service_name
            }
        }
    };
    // Notice the lack of trailing comma here
    (
        method: $method:ident,
        request: $req:ty,
        response: $res:ty,
        service_name: $service_name:literal
        for: $controller:ident,
    ) => {
        impl_service_request!(
            method: $method,
            request: $req,
            response: $res,
            service_name: $service_name,
            for: $controller,
        )
    };
}

pub use impl_service_request;
