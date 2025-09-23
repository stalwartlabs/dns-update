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

#[cfg(test)]
mod tests {
    use crate::strip_origin_from_name;

    #[test]
    fn test_strip_origin_from_name() {
        assert_eq!(
            strip_origin_from_name("www.example.com", "example.com"),
            "www"
        );
        assert_eq!(strip_origin_from_name("example.com", "example.com"), "@");
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
