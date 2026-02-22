pub fn sha1_digest(data: &[u8]) -> Vec<u8> {
    #[cfg(feature = "aws-lc-rs")]
    return aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA1_FOR_LEGACY_USE_ONLY, data)
        .as_ref()
        .to_vec();

    #[cfg(feature = "ring")]
    return ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, data)
        .as_ref()
        .to_vec();

    #[cfg(not(any(feature = "aws-lc-rs", feature = "ring")))]
    unimplemented!();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha1_digest() {
        let data = b"hello world";
        let digest = sha1_digest(data);
        let hex_digest = digest
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();

        assert_eq!(hex_digest, "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed");
    }
}
