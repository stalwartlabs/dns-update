/*
 * Copyright Stalwart Labs Ltd. See the COPYING
 * file at the top-level directory of this distribution.
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 */

use std::time::Duration;

use reqwest::{
    header::{HeaderMap, HeaderValue, CONTENT_TYPE},
    Method,
};
use serde::{de::DeserializeOwned, Serialize};

use crate::Error;

#[derive(Debug, Clone)]
pub struct HttpClientBuilder {
    timeout: Duration,
    headers: HeaderMap<HeaderValue>,
}

#[derive(Debug, Default, Clone)]
pub struct HttpClient {
    method: Method,
    timeout: Duration,
    url: String,
    headers: HeaderMap<HeaderValue>,
    body: Option<String>,
}

impl Default for HttpClientBuilder {
    fn default() -> Self {
        let mut headers = HeaderMap::new();
        headers.append(CONTENT_TYPE, HeaderValue::from_static("application/json"));

        Self {
            timeout: Duration::from_secs(30),
            headers,
        }
    }
}

impl HttpClientBuilder {
    pub fn build(&self, method: Method, url: impl Into<String>) -> HttpClient {
        HttpClient {
            method,
            url: url.into(),
            headers: self.headers.clone(),
            body: None,
            timeout: self.timeout,
        }
    }

    pub fn get(&self, url: impl Into<String>) -> HttpClient {
        self.build(Method::GET, url)
    }

    pub fn post(&self, url: impl Into<String>) -> HttpClient {
        self.build(Method::POST, url)
    }

    pub fn put(&self, url: impl Into<String>) -> HttpClient {
        self.build(Method::PUT, url)
    }

    pub fn delete(&self, url: impl Into<String>) -> HttpClient {
        self.build(Method::DELETE, url)
    }

    pub fn patch(&self, url: impl Into<String>) -> HttpClient {
        self.build(Method::PATCH, url)
    }

    pub fn with_header(mut self, name: &'static str, value: impl AsRef<str>) -> Self {
        if let Ok(value) = HeaderValue::from_str(value.as_ref()) {
            self.headers.append(name, value);
        }
        self
    }

    pub fn with_timeout(mut self, timeout: Option<Duration>) -> Self {
        if let Some(timeout) = timeout {
            self.timeout = timeout;
        }
        self
    }
}

impl HttpClient {
    pub fn with_header(mut self, name: &'static str, value: impl AsRef<str>) -> Self {
        if let Ok(value) = HeaderValue::from_str(value.as_ref()) {
            self.headers.append(name, value);
        }
        self
    }

    pub fn with_body<B: Serialize>(mut self, body: B) -> crate::Result<Self> {
        match serde_json::to_string(&body) {
            Ok(body) => {
                self.body = Some(body);
                Ok(self)
            }
            Err(err) => Err(Error::Serialize(format!(
                "Failed to serialize request: {err}"
            ))),
        }
    }

    pub fn with_raw_body(mut self, body: String) -> Self {
        self.body = Some(body);
        self
    }

    pub async fn send<T>(self) -> crate::Result<T>
    where
        T: DeserializeOwned,
    {
        let response = self.send_raw().await?;
        serde_json::from_slice::<T>(response.as_bytes())
            .map_err(|err| Error::Serialize(format!("Failed to deserialize response: {err}")))
    }

    pub async fn send_raw(self) -> crate::Result<String> {
        let mut request = reqwest::Client::builder()
            .timeout(self.timeout)
            .build()
            .unwrap_or_default()
            .request(self.method, &self.url)
            .headers(self.headers);

        if let Some(body) = self.body {
            request = request.body(body);
        }

        let response = request
            .send()
            .await
            .map_err(|err| Error::Api(format!("Failed to send request to {}: {err}", self.url)))?;

        match response.status().as_u16() {
            200..=299 => response.text().await.map_err(|err| {
                Error::Api(format!("Failed to read response from {}: {err}", self.url))
            }),
            401 => Err(Error::Unauthorized),
            404 => Err(Error::NotFound),
            code => Err(Error::Api(format!(
                "Invalid HTTP response code {code}: {:?}",
                response.error_for_status()
            ))),
        }
    }
}
