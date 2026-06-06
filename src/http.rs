/*
 * Copyright Stalwart Labs LLC See the COPYING
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
    Method,
    header::{CONTENT_TYPE, HeaderMap, HeaderValue},
};
use serde::{Serialize, de::DeserializeOwned};

use crate::Error;

#[derive(Debug, Clone)]
pub struct HttpClientBuilder {
    timeout: Duration,
    headers: HeaderMap<HeaderValue>,
}

#[derive(Debug, Clone)]
pub struct HttpClient {
    headers: HeaderMap<HeaderValue>,
    client: reqwest::Client,
}

#[derive(Debug, Clone)]
pub struct HttpRequest {
    method: Method,
    url: String,
    headers: HeaderMap<HeaderValue>,
    body: Option<String>,
    client: reqwest::Client,
}

impl Default for HttpClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpClientBuilder {
    pub fn new() -> Self {
        let mut headers = HeaderMap::new();
        headers.append(CONTENT_TYPE, HeaderValue::from_static("application/json"));

        Self {
            timeout: Duration::from_secs(30),
            headers,
        }
    }

    pub fn with_header(mut self, name: &'static str, value: impl AsRef<str>) -> Self {
        if let Ok(value) = HeaderValue::from_str(value.as_ref()) {
            self.headers.append(name, value);
        }
        self
    }

    pub fn set_header(mut self, name: &'static str, value: impl AsRef<str>) -> Self {
        if let Ok(value) = HeaderValue::from_str(value.as_ref()) {
            self.headers.insert(name, value);
        }
        self
    }

    pub fn with_timeout(mut self, timeout: Option<Duration>) -> Self {
        if let Some(timeout) = timeout {
            self.timeout = timeout;
        }
        self
    }

    pub fn build(self) -> HttpClient {
        let client = reqwest::Client::builder()
            .timeout(self.timeout)
            .build()
            .unwrap_or_default();
        HttpClient {
            headers: self.headers,
            client,
        }
    }
}

impl HttpClient {
    pub fn request(&self, method: Method, url: impl Into<String>) -> HttpRequest {
        HttpRequest {
            method,
            url: url.into(),
            headers: self.headers.clone(),
            body: None,
            client: self.client.clone(),
        }
    }

    pub fn get(&self, url: impl Into<String>) -> HttpRequest {
        self.request(Method::GET, url)
    }

    pub fn post(&self, url: impl Into<String>) -> HttpRequest {
        self.request(Method::POST, url)
    }

    pub fn put(&self, url: impl Into<String>) -> HttpRequest {
        self.request(Method::PUT, url)
    }

    pub fn delete(&self, url: impl Into<String>) -> HttpRequest {
        self.request(Method::DELETE, url)
    }

    pub fn patch(&self, url: impl Into<String>) -> HttpRequest {
        self.request(Method::PATCH, url)
    }
}

impl HttpRequest {
    pub fn with_header(mut self, name: &'static str, value: impl AsRef<str>) -> Self {
        if let Ok(value) = HeaderValue::from_str(value.as_ref()) {
            self.headers.append(name, value);
        }
        self
    }

    pub fn set_header(mut self, name: &'static str, value: impl AsRef<str>) -> Self {
        if let Ok(value) = HeaderValue::from_str(value.as_ref()) {
            self.headers.insert(name, value);
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
        self.send_raw_with_headers().await.map(|(body, _)| body)
    }

    pub async fn send_raw_with_headers(self) -> crate::Result<(String, HeaderMap<HeaderValue>)> {
        let mut request = self
            .client
            .request(self.method, &self.url)
            .headers(self.headers);

        if let Some(body) = self.body {
            request = request.body(body);
        }

        let response = request
            .send()
            .await
            .map_err(|err| Error::Api(format!("Failed to send request to {}: {err}", self.url)))?;

        let code = response.status().as_u16();
        let headers = response.headers().clone();
        match code {
            204 => Ok((String::new(), headers)),
            200..=299 => response
                .text()
                .await
                .map(|body| (body, headers))
                .map_err(|err| {
                    Error::Api(format!("Failed to read response from {}: {err}", self.url))
                }),
            401 => Err(Error::Unauthorized),
            404 => Err(Error::NotFound),
            _ => {
                let text = response.text().await.unwrap_or_default();
                Err(Error::Api(http_status_message(code, &text)))
            }
        }
    }

    pub async fn send_with_retry<T>(self, max_retries: u32) -> crate::Result<T>
    where
        T: DeserializeOwned,
    {
        let mut attempts = 0;
        let body = self.body;
        loop {
            let mut request = self
                .client
                .request(self.method.clone(), &self.url)
                .headers(self.headers.clone());

            if let Some(body) = body.as_ref() {
                request = request.body(body.clone());
            }

            let response = request.send().await.map_err(|err| {
                Error::Api(format!("Failed to send request to {}: {err}", self.url))
            })?;

            let code = response.status().as_u16();
            return match code {
                204 => serde_json::from_str("{}").map_err(|err| {
                    Error::Serialize(format!("Failed to create empty response: {err}"))
                }),
                200..=299 => {
                    let text = response.text().await.map_err(|err| {
                        Error::Api(format!("Failed to read response from {}: {err}", self.url))
                    })?;
                    let parse_target = if text.trim().is_empty() { "{}" } else { &text };
                    serde_json::from_str(parse_target).map_err(|err| {
                        Error::Serialize(format!("Failed to deserialize response: {err}"))
                    })
                }
                429 | 503 if attempts < max_retries => {
                    let delay = retry_after(response.headers())
                        .unwrap_or_else(|| Duration::from_secs(1u64 << attempts.min(6)));
                    tokio::time::sleep(delay.min(MAX_RETRY_DELAY)).await;
                    attempts += 1;
                    continue;
                }
                401 => Err(Error::Unauthorized),
                404 => Err(Error::NotFound),
                _ => {
                    let text = response.text().await.unwrap_or_default();
                    Err(Error::Api(http_status_message(code, &text)))
                }
            };
        }
    }
}

const MAX_RETRY_DELAY: Duration = Duration::from_secs(60);

fn retry_after(headers: &HeaderMap<HeaderValue>) -> Option<Duration> {
    headers
        .get("retry-after")?
        .to_str()
        .ok()?
        .parse::<u64>()
        .ok()
        .map(Duration::from_secs)
}

fn http_status_message(code: u16, body: &str) -> String {
    let trimmed = body.trim();
    if code == 400 {
        if trimmed.is_empty() {
            "BadRequest".to_string()
        } else {
            format!("BadRequest {trimmed}")
        }
    } else if trimmed.is_empty() {
        format!("HTTP {code}")
    } else {
        format!("HTTP {code}: {trimmed}")
    }
}
