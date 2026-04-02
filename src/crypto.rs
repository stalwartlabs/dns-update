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

#[inline(always)]
pub fn sha1_digest(data: &[u8]) -> Vec<u8> {
    #[cfg(feature = "aws-lc-rs")]
    return aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA1_FOR_LEGACY_USE_ONLY, data)
        .as_ref()
        .to_vec();

    #[cfg(all(feature = "ring", not(feature = "aws-lc-rs")))]
    return ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, data)
        .as_ref()
        .to_vec();

    #[cfg(not(any(feature = "aws-lc-rs", feature = "ring")))]
    unimplemented!();
}

#[inline(always)]
pub fn sha256_digest(data: &[u8]) -> Vec<u8> {
    #[cfg(feature = "aws-lc-rs")]
    return aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, data)
        .as_ref()
        .to_vec();

    #[cfg(all(feature = "ring", not(feature = "aws-lc-rs")))]
    return ring::digest::digest(&ring::digest::SHA256, data)
        .as_ref()
        .to_vec();

    #[cfg(not(any(feature = "aws-lc-rs", feature = "ring")))]
    unimplemented!();
}

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    #[cfg(feature = "aws-lc-rs")]
    {
        let key = aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA256, key);
        let tag = aws_lc_rs::hmac::sign(&key, data);
        tag.as_ref().to_vec()
    }

    #[cfg(all(feature = "ring", not(feature = "aws-lc-rs")))]
    {
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key);
        let tag = ring::hmac::sign(&key, data);
        tag.as_ref().to_vec()
    }

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
