//! The live model catalog: `GET /api/v1/models`.
//!
//! This is the data behind the model picker. The endpoint is public (no key),
//! and every field the picker shows — context size, free/paid, and whether the
//! model can call tools — is derived here so the UI renders a flat list.

use serde_json::Value;

use crate::error::OpenRouterError;
use crate::DEFAULT_BASE_URL;

/// One model as the picker needs it: identity, context size, cost, and the two
/// capabilities that decide whether it is usable as an agent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelInfo {
    /// The id passed to the API (e.g. `x-ai/grok-4-fast:free`).
    pub id: String,
    /// Human-readable name for the picker.
    pub name: String,
    /// Maximum combined request+response context in tokens.
    pub context_length: u64,
    /// Raw prompt price per token, as the API reports it ("0" for free).
    pub prompt_price: String,
    /// Raw completion price per token, as the API reports it ("0" for free).
    pub completion_price: String,
    /// Whether both prompt and completion price are exactly zero.
    pub is_free: bool,
    /// Whether the model advertises tool calling (`"tools"` in supported_parameters).
    /// A coding/red-team agent is useless without this — the picker flags it.
    pub supports_tools: bool,
    /// Accepted input modalities (e.g. `["text"]`, `["text","image"]`).
    pub input_modalities: Vec<String>,
}

impl ModelInfo {
    /// Parse one `data[]` entry defensively; unknown/missing fields degrade to
    /// sensible defaults rather than failing the whole catalog.
    fn from_json(entry: &Value) -> Option<ModelInfo> {
        let id = entry.get("id")?.as_str()?.to_string();
        let name = entry
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or(&id)
            .to_string();
        let context_length = entry
            .get("context_length")
            .and_then(Value::as_u64)
            .or_else(|| {
                entry
                    .get("top_provider")
                    .and_then(|tp| tp.get("context_length"))
                    .and_then(Value::as_u64)
            })
            .unwrap_or(0);
        let pricing = entry.get("pricing");
        let prompt_price = price_field(pricing, "prompt");
        let completion_price = price_field(pricing, "completion");
        let is_free = is_zero(&prompt_price) && is_zero(&completion_price);
        let supports_tools = entry
            .get("supported_parameters")
            .and_then(Value::as_array)
            .map(|params| {
                params
                    .iter()
                    .any(|p| p.as_str() == Some("tools") || p.as_str() == Some("tool_choice"))
            })
            .unwrap_or(false);
        let input_modalities = entry
            .get("architecture")
            .and_then(|a| a.get("input_modalities"))
            .and_then(Value::as_array)
            .map(|mods| {
                mods.iter()
                    .filter_map(|m| m.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_else(|| vec!["text".to_string()]);

        Some(ModelInfo {
            id,
            name,
            context_length,
            prompt_price,
            completion_price,
            is_free,
            supports_tools,
            input_modalities,
        })
    }
}

fn price_field(pricing: Option<&Value>, key: &str) -> String {
    pricing
        .and_then(|p| p.get(key))
        .map(|v| match v {
            Value::String(s) => s.clone(),
            Value::Number(n) => n.to_string(),
            _ => "0".to_string(),
        })
        .unwrap_or_else(|| "0".to_string())
}

/// Whether a price string parses to exactly zero.
fn is_zero(price: &str) -> bool {
    price.trim().parse::<f64>().map(|n| n == 0.0).unwrap_or(false)
}

/// Parse the full `/api/v1/models` response body into models. Entries that do
/// not parse are skipped, so one malformed row never blanks the catalog.
pub fn parse_catalog(body: &str) -> Result<Vec<ModelInfo>, OpenRouterError> {
    let root: Value = serde_json::from_str(body)?;
    let data = root.get("data").and_then(Value::as_array);
    let Some(data) = data else {
        return Ok(Vec::new());
    };
    Ok(data.iter().filter_map(ModelInfo::from_json).collect())
}

/// Fetch the live model catalog. No API key required — this endpoint is public.
/// `base_url` is the API root (e.g. the [`DEFAULT_BASE_URL`]).
pub async fn fetch_models(
    client: &reqwest::Client,
    base_url: &str,
) -> Result<Vec<ModelInfo>, OpenRouterError> {
    let url = format!("{}/models", base_url.trim_end_matches('/'));
    let response = client.get(url).send().await?;
    let status = response.status();
    let body = response.text().await?;
    if !status.is_success() {
        return Err(OpenRouterError::Http {
            status: status.as_u16(),
            body: body.chars().take(500).collect(),
        });
    }
    parse_catalog(&body)
}

/// Fetch the catalog from the default OpenRouter endpoint with a fresh client.
pub async fn fetch_default_models() -> Result<Vec<ModelInfo>, OpenRouterError> {
    let client = reqwest::Client::new();
    fetch_models(&client, DEFAULT_BASE_URL).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_free_tool_capable_model() {
        let body = r#"{
          "data": [
            {
              "id": "x-ai/grok-4-fast:free",
              "name": "xAI: Grok 4 Fast (free)",
              "context_length": 2000000,
              "pricing": { "prompt": "0", "completion": "0" },
              "supported_parameters": ["tools", "tool_choice", "temperature"],
              "architecture": { "input_modalities": ["text", "image"] }
            },
            {
              "id": "some/paid-no-tools",
              "name": "Paid, no tools",
              "context_length": 8192,
              "pricing": { "prompt": "0.0000005", "completion": "0.0000015" },
              "supported_parameters": ["temperature"],
              "architecture": { "input_modalities": ["text"] }
            }
          ]
        }"#;
        let models = parse_catalog(body).unwrap();
        assert_eq!(models.len(), 2);

        let free = &models[0];
        assert_eq!(free.id, "x-ai/grok-4-fast:free");
        assert_eq!(free.context_length, 2_000_000);
        assert!(free.is_free);
        assert!(free.supports_tools);
        assert_eq!(free.input_modalities, vec!["text", "image"]);

        let paid = &models[1];
        assert!(!paid.is_free);
        assert!(!paid.supports_tools);
    }

    #[test]
    fn empty_or_missing_data_is_empty_catalog() {
        assert!(parse_catalog(r#"{}"#).unwrap().is_empty());
        assert!(parse_catalog(r#"{"data":[]}"#).unwrap().is_empty());
    }

    #[test]
    fn malformed_entry_is_skipped_not_fatal() {
        let body = r#"{"data":[{"no_id":true},{"id":"ok/model","name":"OK"}]}"#;
        let models = parse_catalog(body).unwrap();
        assert_eq!(models.len(), 1);
        assert_eq!(models[0].id, "ok/model");
    }
}
