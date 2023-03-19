#![deny(missing_docs)]
#![deny(warnings)]

//! rustserve-platform
//!
//! A microservice platform library

use std::collections::HashMap;
use std::sync::Arc;

use futures::future::BoxFuture;

use rustserve::Filter;
use rustserve::IdParam;
use rustserve::NotFound;
use rustserve::RequestFilterOutcome;
use rustserve::ResponseFilterOutcome;

mod mtls;

/// Common utility for all clients.
pub mod client;

/// Runtime for services built using rustserve.
pub mod runtime;

/// A filter for POST requests that only allow the requests through if the route parameters contain
/// the ID param.
pub struct PostFilter<T> {
    phantom: std::marker::PhantomData<T>,
}

impl<T> PostFilter<T> {
    /// Create a new PostFilter
    pub fn new() -> Self {
        Self {
            phantom: std::marker::PhantomData,
        }
    }
}

impl<T: IdParam + NotFound> Filter for PostFilter<T> {
    fn filter_request<'a>(
        self: Arc<Self>,
        req: http::Request<&'a [u8]>,
        params: HashMap<String, String>,
    ) -> BoxFuture<'a, anyhow::Result<RequestFilterOutcome<'a>>> {
        Box::pin(async move {
            if req.method() == "POST" && params.contains_key(&T::id()) {
                return Ok(RequestFilterOutcome::Fail(T::not_found()?));
            }
            Ok(RequestFilterOutcome::Pass(req, params))
        })
    }

    fn filter_response<'a>(
        self: Arc<Self>,
        res: http::Response<Vec<u8>>,
    ) -> BoxFuture<'a, anyhow::Result<ResponseFilterOutcome>> {
        Box::pin(async move { Ok(ResponseFilterOutcome::Pass(res)) })
    }
}

/// A filter for PUT requests that only allow the requests through if the route parameters dont
/// contain the ID param.
pub struct PutFilter<T> {
    phantom: std::marker::PhantomData<T>,
}

impl<T> PutFilter<T> {
    /// Create a new PutFilter
    pub fn new() -> Self {
        Self {
            phantom: std::marker::PhantomData,
        }
    }
}

impl<T: IdParam + NotFound> Filter for PutFilter<T> {
    fn filter_request<'a>(
        self: Arc<Self>,
        req: http::Request<&'a [u8]>,
        params: HashMap<String, String>,
    ) -> BoxFuture<'a, anyhow::Result<RequestFilterOutcome<'a>>> {
        Box::pin(async move {
            if req.method() == "PUT" && !params.contains_key(&T::id()) {
                return Ok(RequestFilterOutcome::Fail(T::not_found()?));
            }
            Ok(RequestFilterOutcome::Pass(req, params))
        })
    }

    fn filter_response<'a>(
        self: Arc<Self>,
        res: http::Response<Vec<u8>>,
    ) -> BoxFuture<'a, anyhow::Result<ResponseFilterOutcome>> {
        Box::pin(async move { Ok(ResponseFilterOutcome::Pass(res)) })
    }
}

/// Default filters for most controllers
pub fn default_filters<T: IdParam + NotFound + 'static>() -> Vec<Arc<dyn Filter>> {
    vec![
        Arc::new(PutFilter::<T>::new()),
        Arc::new(PostFilter::<T>::new()),
    ]
}

// -------------------

/// Generic reusable wrapper with an id field around an entity.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct EntityWithId<T: serde::Serialize> {
    /// The id of the entity
    pub id: u64,
    /// The remaining fields of the entity
    #[serde(flatten)]
    pub entity: T,
}
impl<T: serde::Serialize + for<'de> serde::Deserialize<'de>> EntityWithId<T> {
    /// Creates a new [`EntityWithId<T>`].
    ///
    /// # Examples
    ///
    /// ```
    /// use rustserve_platform::EntityWithId;
    ///
    /// struct Test {
    ///     name: String,
    /// }
    ///
    /// let id = 1;
    /// let entity = Test { name: String::new() };
    ///
    /// assert_eq!(EntityWithId::new(id, entity), EntityWithId { id: 1, entity });
    /// ```
    pub fn new(id: u64, entity: T) -> Self {
        Self { id, entity }
    }
}

// -------------------

/// General reusable paginated entity response.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct SeqApiResponse<T: serde::Serialize> {
    total: usize,
    count: usize,
    offset: usize,
    entity_name: String,
    entities: T,
}

impl<'a, T: serde::Serialize> SeqApiResponse<Vec<T>> {
    /// Creates a new [`SeqApiResponse<T>`].
    ///
    /// Its is like an [`ApiResponse<T>`] but with pagination
    ///
    /// # Examples
    ///
    /// ```
    /// use rustserve_platform::SeqApiResponse;
    ///
    /// struct TestEntity {
    ///     id: u64,
    /// }
    /// let entity_name = "users".into();
    /// let offset = 0;
    /// let total = 0;
    /// let entities = vec![TestEntity { id: 1 }, TestEntity { id: 2 }];
    ///
    /// let result = SeqApiResponse::new(entity_name, offset, total, entities);
    ///
    /// assert_eq!(result, SeqApiResponse {
    ///     total: 0,
    ///     count: 2,
    ///     offset: 0,
    ///     entity_name,
    ///     entities,
    /// });
    /// ```
    pub fn new(
        entity_name: impl Into<String>,
        offset: usize,
        total: usize,
        entities: Vec<T>,
    ) -> Self {
        Self {
            total,
            count: entities.len(),
            offset,
            entity_name: entity_name.into(),
            entities,
        }
    }
}

/// Generic reusable entity response.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct ApiResponse<T: serde::Serialize> {
    /// Name of entity type
    pub entity_name: String,
    /// Inner entity stored within the response
    pub entity: T,
}

impl<'a, T: serde::Serialize> ApiResponse<T> {
    /// Creates a new [`ApiResponse<T>`].
    ///
    /// # Examples
    ///
    /// ```
    /// use rustserve_platform::ApiResponse;
    ///
    /// struct TestEntity {
    ///     id: u64,
    /// }
    /// let entity_name = "tests".into();
    /// let entity = TestEntity { id: 1 };
    ///
    /// assert_eq!(ApiResponse::new(entity_name, entity), ApiResponse { entity_name, entity });
    /// ```
    pub fn new(entity_name: impl Into<String>, entity: T) -> Self {
        Self {
            entity_name: entity_name.into(),
            entity,
        }
    }
}

// -------------------

/// General reusable invalid parameter error
#[derive(serde::Serialize)]
pub struct InvalidParameterError {
    param: String,
    value: String,
    error: String,
}

impl InvalidParameterError {
    /// Construct a new instance of the InvalidParameterError struct with a predefined error
    /// message.
    pub fn new(param: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            param: param.into(),
            value: value.into(),
            error: "invalid parameter".into(),
        }
    }
}

/// General reusable invalid payload error
#[derive(serde::Serialize)]
pub struct InvalidPayloadError {
    message: String,
    error: String,
}

impl InvalidPayloadError {
    /// Construct a new instance of the InvalidPayloadError struct with a predefined error
    /// message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            error: "invalid payload".into(),
        }
    }
}

/// General reusable missing parameter error
#[derive(serde::Serialize)]
pub struct MissingParameterError {
    param: String,
    error: String,
}

impl MissingParameterError {
    /// Construct a new instance of the MissingParameterError struct with a predefined error
    /// message.
    pub fn new(param: impl Into<String>) -> Self {
        Self {
            param: param.into(),
            error: "missing parameter".into(),
        }
    }
}

/// General reusable service unavailable error
#[derive(serde::Serialize)]
pub struct ServiceUnavailableError {
    error: String,
}

impl ServiceUnavailableError {
    /// Construct a new instance of the ServiceUnavailableError struct with a predefined error
    /// message.
    pub fn new() -> Self {
        Self {
            error: "service unavailable".into(),
        }
    }
}

/// General reusable entity not found error
#[derive(serde::Serialize)]
pub struct EntityNotFoundError {
    id: u64,
    entity: String,
    error: String,
}

impl EntityNotFoundError {
    /// Construct a new instance of the EntityNotFound struct with a predefined error
    /// message.
    pub fn new(entity: impl Into<String>, id: u64) -> Self {
        Self {
            id,
            entity: entity.into(),
            error: "entity not found".into(),
        }
    }
}

/// General reusable internal server error
#[derive(serde::Serialize)]
pub struct InternalServerError {
    error: String,
}

impl InternalServerError {
    /// Construct a new instance of the InternalServerError struct with a predefined error
    /// message.
    pub fn new(error: impl Into<String>) -> Self {
        Self {
            error: error.into(),
        }
    }
}
