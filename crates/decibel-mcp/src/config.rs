//! How to reach one external MCP server: a name plus the command to launch it.

/// Configuration for a single stdio MCP server the client will spawn.
///
/// `name` is the logical server label (used to prefix its tools:
/// `mcp_<name>_<remote>`). `command`/`args` are the executable and its
/// arguments; `env` are extra environment variables set on the child.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct McpServerConfig {
    /// Logical server name, used to namespace its tools.
    pub name: String,
    /// The executable to launch (e.g. `python`, `hexstrike-mcp`).
    pub command: String,
    /// Arguments passed to the executable.
    pub args: Vec<String>,
    /// Extra environment variables for the child process.
    pub env: Vec<(String, String)>,
}

impl McpServerConfig {
    /// A config with the given name and command, no args or extra env.
    pub fn new(name: impl Into<String>, command: impl Into<String>) -> Self {
        McpServerConfig {
            name: name.into(),
            command: command.into(),
            args: Vec::new(),
            env: Vec::new(),
        }
    }

    /// Builder: set the argument list.
    pub fn with_args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args = args.into_iter().map(Into::into).collect();
        self
    }

    /// Builder: add one environment variable.
    pub fn with_env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.push((key.into(), value.into()));
        self
    }
}
