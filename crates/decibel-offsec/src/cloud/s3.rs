//! Extract S3 bucket names from arbitrary text — `s3://`, virtual-hosted
//! (`bucket.s3[.region].amazonaws.com`), and path-style
//! (`s3[.region].amazonaws.com/bucket`).

use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct S3Extract {
    pub buckets: Vec<String>,
}

fn valid_bucket(name: &str) -> bool {
    // AWS bucket naming: 3–63 chars, lowercase letters/digits/hyphens/dots.
    let n = name.len();
    (3..=63).contains(&n)
        && name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '.')
        && !name.starts_with(['-', '.'])
        && !name.ends_with(['-', '.'])
}

/// Pull every distinct S3 bucket name out of `text`, sorted.
pub fn extract(text: &str) -> S3Extract {
    // Three shapes, each capturing the bucket in group 1.
    let patterns = [
        r"s3://([a-z0-9.\-]{3,63})",                              // s3://bucket/...
        r"([a-z0-9.\-]{3,63})\.s3[.a-z0-9\-]*\.amazonaws\.com",   // virtual-hosted
        r"s3[.a-z0-9\-]*\.amazonaws\.com/([a-z0-9.\-]{3,63})",    // path-style
    ];
    let mut set: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for p in patterns {
        let re = Regex::new(p).expect("static regex");
        for cap in re.captures_iter(&text.to_lowercase()) {
            if let Some(m) = cap.get(1) {
                let b = m.as_str();
                if valid_bucket(b) {
                    set.insert(b.to_string());
                }
            }
        }
    }
    S3Extract { buckets: set.into_iter().collect() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_all_three_url_shapes() {
        let text = "\
            grab s3://prod-assets/logo.png then \
            https://user-uploads.s3.us-east-1.amazonaws.com/x and \
            https://s3.amazonaws.com/legacy-backups/db.sql";
        let e = extract(text);
        assert_eq!(e.buckets, vec!["legacy-backups", "prod-assets", "user-uploads"]);
    }

    #[test]
    fn dedupes_and_rejects_invalid_names() {
        let e = extract("s3://ab and s3://good-bucket and s3://good-bucket again");
        // "ab" is too short; the valid one appears once.
        assert_eq!(e.buckets, vec!["good-bucket"]);
    }

    #[test]
    fn empty_when_no_buckets() {
        assert!(extract("nothing to see here").buckets.is_empty());
    }
}
