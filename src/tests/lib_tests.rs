

#[cfg(test)]
mod tests {
    use crate::{strip_origin_from_name};

    #[test]
    fn test_strip_origin_from_name() {
        assert_eq!(
            strip_origin_from_name("www.example.com", "example.com"),
            "www"
        );
        assert_eq!(
            strip_origin_from_name("example.com", "example.com"),
            "@"
        );
        assert_eq!(
            strip_origin_from_name("api.v1.example.com", "example.com"),
            "api.v1"
        );
        assert_eq!(
            strip_origin_from_name("example.com", "google.com"),
            "example.com"
        );
    }
}
