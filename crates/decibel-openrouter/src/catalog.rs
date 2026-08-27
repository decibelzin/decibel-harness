//! The model catalog — the data behind the model picker.
//!
//! Two providers now feed one list: the paid **DeepSeek** API (the fixed
//! [`deepseek_models`] list — its `/models` endpoint needs a key and carries no
//! capability metadata) and the free **DeepSeek-on-OpenRouter** models (fetched
//! from OpenRouter's public catalog via [`fetch_models`]/[`parse_catalog`], an
//! OpenAI-style `data[]` with pricing + `supported_parameters`). Each model
//! carries a [`ModelInfo::provider`] tag so a run routes to the right endpoint
//! and key. [`fetch_full_catalog`] returns both.

use serde_json::Value;

use crate::error::OpenRouterError;
use crate::OPENROUTER_BASE_URL;

/// Which backend serves a model — decides the endpoint and API key a run uses.
pub const PROVIDER_DEEPSEEK: &str = "deepseek";
/// The OpenRouter provider tag (free DeepSeek models).
pub const PROVIDER_OPENROUTER: &str = "openrouter";

/// One model as the picker needs it: identity, context size, cost, and the two
/// capabilities that decide whether it is usable as an agent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelInfo {
    /// The id passed to the API (e.g. `deepseek-v4-flash` or `deepseek/deepseek-r1:free`).
    pub id: String,
    /// Human-readable name for the picker.
    pub name: String,
    /// Backend that serves this model: [`PROVIDER_DEEPSEEK`] or [`PROVIDER_OPENROUTER`].
    pub provider: String,
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
            // parse_catalog is only used for OpenRouter's catalog.
            provider: PROVIDER_OPENROUTER.to_string(),
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

/// The fixed DeepSeek model catalog. DeepSeek's `/models` endpoint needs the API
/// key and carries no capability metadata (context, pricing, tool support), so
/// the picker's fields are filled in here from the published model list. Every
/// current DeepSeek V4 model is OpenAI-compatible, supports tool calls, and
/// exposes a 1M-token context window. Prices are per-token, off-peak.
pub fn deepseek_models() -> Vec<ModelInfo> {
    let model = |id: &str, name: &str, prompt: &str, completion: &str, vision: bool| ModelInfo {
        id: id.to_string(),
        name: name.to_string(),
        provider: PROVIDER_DEEPSEEK.to_string(),
        context_length: 1_000_000,
        prompt_price: prompt.to_string(),
        completion_price: completion.to_string(),
        is_free: false,
        supports_tools: true,
        input_modalities: if vision {
            vec!["text".to_string(), "image".to_string()]
        } else {
            vec!["text".to_string()]
        },
    };
    vec![
        model("deepseek-v4-flash", "DeepSeek V4 Flash", "0.00000022", "0.00000066", false),
        model("deepseek-v4-pro", "DeepSeek V4 Pro", "0.00000066", "0.00000198", false),
        model("deepseek-v4-flash-vision-exp", "DeepSeek V4 Flash Vision (exp)", "0.00000022", "0.00000066", true),
    ]
}

/// The paid DeepSeek models only (no network). Used by the CLI demos, which run
/// against the DeepSeek API directly.
pub async fn fetch_default_models() -> Result<Vec<ModelInfo>, OpenRouterError> {
    Ok(deepseek_models())
}

/// The free, tool-capable models on OpenRouter (any provider), from OpenRouter's
/// public `/models` endpoint (no key). OpenRouter no longer lists any *free*
/// DeepSeek models, so this is the free tier at large — usable as an agent
/// because each supports tool calling. `thinkingmachines/*` is skipped (gated to
/// approved apps: a generic client gets an AUTH error). Each is tagged with the
/// `openrouter` provider so a run routes there with the OpenRouter key. Sorted by
/// context desc. A fetch failure yields an empty list, not an error, so the paid
/// DeepSeek models still show if OpenRouter is unreachable.
pub async fn openrouter_free_tool_models() -> Vec<ModelInfo> {
    let client = reqwest::Client::new();
    let Ok(models) = fetch_models(&client, OPENROUTER_BASE_URL).await else {
        return Vec::new();
    };
    let mut free: Vec<ModelInfo> = models
        .into_iter()
        .filter(|m| m.is_free && m.supports_tools && !m.id.starts_with("thinkingmachines/"))
        .collect();
    free.sort_by(|a, b| b.context_length.cmp(&a.context_length));
    free
}

/// The full picker catalog: the paid DeepSeek API models first, then the free
/// tool-capable OpenRouter models. This is what the desktop app's `list_models`
/// returns.
pub async fn fetch_full_catalog() -> Result<Vec<ModelInfo>, OpenRouterError> {
    let mut catalog = deepseek_models();
    catalog.extend(openrouter_free_tool_models().await);
    Ok(catalog)
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
