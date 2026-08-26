//! Fetch the live OpenRouter model catalog and print the free, tool-capable
//! models — exactly the data the desktop model picker will show.
//!
//! No API key required (the /models endpoint is public):
//!     cargo run -p decibel-openrouter --example catalog_demo
//!
//! Pass `all` to list every free model, including ones without tool calling:
//!     cargo run -p decibel-openrouter --example catalog_demo all

use decibel_openrouter::fetch_default_models;

#[tokio::main]
async fn main() {
    let show_all = std::env::args().nth(1).as_deref() == Some("all");

    let models = match fetch_default_models().await {
        Ok(models) => models,
        Err(err) => {
            eprintln!("failed to fetch catalog: {err}");
            std::process::exit(1);
        }
    };

    let total = models.len();
    let free: Vec<&_> = models.iter().filter(|m| m.is_free).collect();
    let free_tools: Vec<&_> = free.iter().copied().filter(|m| m.supports_tools).collect();

    println!(
        "OpenRouter catalog: {total} models total, {} free, {} free WITH tool calling.\n",
        free.len(),
        free_tools.len()
    );

    // Sort by context size, largest first — the most useful agents up top.
    let mut listed: Vec<_> = if show_all {
        free.clone()
    } else {
        free_tools.clone()
    };
    listed.sort_by(|a, b| b.context_length.cmp(&a.context_length));

    let heading = if show_all {
        "All free models (tools = can act as an agent):"
    } else {
        "Free models that can call tools (usable as a red-team agent):"
    };
    println!("{heading}");
    println!("{:<44} {:>9}  {:<5}  {}", "MODEL", "CONTEXT", "TOOLS", "INPUT");
    println!("{}", "-".repeat(80));
    for m in &listed {
        println!(
            "{:<44} {:>9}  {:<5}  {}",
            truncate(&m.id, 44),
            fmt_ctx(m.context_length),
            if m.supports_tools { "yes" } else { "NO" },
            m.input_modalities.join(","),
        );
    }
}

/// Human-friendly context size: `2M`, `131K`, `8192`.
fn fmt_ctx(n: u64) -> String {
    if n >= 1_000_000 {
        let m = n as f64 / 1_000_000.0;
        if (m.fract()).abs() < 0.05 {
            format!("{}M", m.round() as u64)
        } else {
            format!("{m:.1}M")
        }
    } else if n >= 1000 {
        format!("{}K", n / 1000)
    } else {
        n.to_string()
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max - 1])
    }
}
