#[test]
fn test_strip_origin_from_name() {
    assert_eq!(
        crate::strip_origin_from_name("www.example.com", "example.com"),
        "www"
    );
    assert_eq!(
        crate::strip_origin_from_name("example.com", "example.com"),
        "@"
    );
    assert_eq!(
        crate::strip_origin_from_name("api.v1.example.com", "example.com"),
        "api.v1"
    );
    assert_eq!(
        crate::strip_origin_from_name("example.com", "google.com"),
        "example.com"
    );
}

#[cfg(feature = "aws-lc-rs")]
#[tokio::test]
async fn test_https_mock() {
    if cfg!(all(feature = "aws-lc-rs", feature = "ring")) {
        panic!("Cannot enable both aws-lc-rs and ring features simultaneously");
    }
    #[cfg(feature = "aws-lc-rs")]
    {
        ::rustls::crypto::aws_lc_rs::default_provider()
            .install_default()
            .expect("Failed to set AWS LC RS provider");
    }
    #[cfg(feature = "ring")]
    {
        ::rustls::crypto::ring::default_provider()
            .install_default()
            .expect("Failed to set ring provider");
    }
    #[cfg(not(any(feature = "aws-lc-rs", feature = "ring")))]
    {
        panic!("No TLS backend feature enabled");
    }
    let server = httpmock::MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/test");
        then.status(200).body("hello");
    });
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    let resp = client
        .get(server.base_url() + "/test")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "hello");
    mock.assert_calls(1);
}
