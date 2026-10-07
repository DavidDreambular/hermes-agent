# Owner deployment overlay

These configuration and packaging files belong to the owner's deployment fork,
`DavidDreambular/hermes-agent`. They are not proposed for the NousResearch upstream
repository. The agent core and native provider implementation remain unchanged.

The owner requested native Hermes-managed OpenAI OAuth with an OpenRouter fallback.
The canonical workflow builds and attests this committed recipe together with its
consumer. Missing build inputs fail rather than reporting a successful empty build.

The initial API profile uses supplied CRM context and scoped native tools. It does
not register the CRM action bridge automatically. Production still requires
verified installation, preserved-state compatibility, and native account login.
