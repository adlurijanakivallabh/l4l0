# LLM provider configuration

ReachAgent keeps provider keys on the server. The GUI sends only the selected
provider name; proposal output remains allowlist-validated and reports still
contain the deterministic confirmed-finding table.

The GUI always sets `use_llm=true`; configure one of these server-side choices:

```sh
# DeepSeek (OpenAI-compatible chat completions)
export REACHAGENT_LLM_PROVIDER=deepseek
export REACHAGENT_DEEPSEEK_API_KEY='...'
export REACHAGENT_DEEPSEEK_MODEL=deepseek-chat  # or the model enabled for your account

# OpenAI or another compatible gateway
export REACHAGENT_LLM_PROVIDER=openai-compatible
export REACHAGENT_LLM_API_KEY='...'
export REACHAGENT_LLM_BASE_URL='https://gateway.example/v1'
export REACHAGENT_LLM_MODEL='...'

# For a provider exposing the Responses API instead of Chat Completions
export REACHAGENT_LLM_API_STYLE=responses
# Set REACHAGENT_LLM_BASE_URL to that provider's /responses base or parent URL.
```

For a custom gateway, `REACHAGENT_LLM_API_KEY`, `REACHAGENT_LLM_BASE_URL`, and
`REACHAGENT_LLM_MODEL` are all required. `REACHAGENT_LLM_PROVIDER` may be left
unset when those generic settings are present; ReachAgent then selects its
OpenAI-compatible adapter without guessing from vendor-specific keys.

`REACHAGENT_DEEPSEEK_BASE_URL` and `REACHAGENT_DEEPSEEK_MODEL` override the
DeepSeek defaults. Requests use HTTPX, a 30-second timeout, bearer auth, and a
single prompt. The GUI performs a local key preflight and rejects an
unconfigured provider before starting a scan. In strict GUI mode, provider
errors, malformed JSON, or unallowlisted proposals fail the scan; compatibility
fallback remains only for library/fixture callers.

## Named provider configs (GUI Settings panel)

The GUI Settings page lets you add, test, edit, and delete named provider
configurations without restarting the server. Each config stores:

- **Name** - label shown in the launch-form dropdown
- **Type** - openai-compatible, deepseek, or openai
- **Base URL** - API endpoint base (e.g. https://gateway.example/v1/responses)
- **Model** - model identifier
- **API endpoint shape** - /responses or /chat/completions
- **API key** - stored server-side only; never sent to the browser after save

Configs persist to config/providers.json (gitignored). The launch form's
provider dropdown lists all saved configs as named:<id> entries. Selecting
one applies that provider's key/URL/model/style for the duration of that
scan only.

The Test button sends a tiny prompt through the saved config and reports the
reply or error, so you can verify connectivity before launching a scan.

### API endpoints (for automation)

- GET /api/providers - list all named configs + server-default summary
- POST /api/providers - create or update (name, provider, base_url, model, api_style, api_key)
- DELETE /api/providers/{id} - remove a config
- POST /api/providers/{id}/test - connection test (returns ok+reply or ok=false+error)

