# NIMROD: AI Agentic Tool for Red/Blue/Purple Teaming

NIMROD is an AI-powered, user-governed agentic framework designed for cybersecurity learning and authorized penetration testing. By leveraging a locally proxied, uncensored Qwen 27B model, NIMROD enables role-specific reconnaissance and vulnerability discovery while maintaining strict human-in-the-loop safety controls.

---

## Architecture Overview

This project uses a distributed inference architecture to provide flagship-level reasoning without local hardware costs or cloud API data leakage:

- **Inference Engine:** Uncensored Qwen 3.8 27B (Abliterated) hosted on ephemeral Kaggle T4 GPUs.
- **Secure Tunneling:** Encrypted Cloudflare/Ngrok tunnel exposing the Ollama API securely.
- **API Gateway:** Local LiteLLM proxy standardizing the endpoint to OpenAI-compatible format.
- **Agent Framework:** Python-based TUI with plan-level approval, parallel execution, and automated reporting.

---

## Prerequisites

- Kali Linux (or Debian-based OS)
- Python 3.9+
- Active Kaggle account (for free GPU inference)
- Ngrok free account (for secure tunneling)

---

## Setup Instructions

### Step 1: Configure the Kaggle Inference Cell

Create a new Kaggle Notebook and paste the provided master cell code AND aliving session code. This handles environment setup, model download, Ollama initialization, and tunnel creation.

> **CRITICAL:** Replace `YOUR_NGROK_TOKEN` and `EXAMPLE_NAME` in the first cell with your actual credentials before running. Ensure **Internet** is enabled in Kaggle Notebook Settings.

Run the keep-alive second cell immediately after the master cell completes successfully to prevent session timeouts and auto-restart Ollama if it crashes.

### Step 2: Configure the Local Proxy

NIMROD requires a dedicated LiteLLM configuration file to route requests to the Kaggle tunnel.

1. Create the file at the **exact** path: `/home/user/nimrod_config.yaml`
   > The script expects this absolute path. Do not place it elsewhere.

2. Paste the following base configuration:

```yaml
model_list:
  - model_name: nimrod-brain
    litellm_params:
      model: ollama/abliterated
      api_base: https://PLACEHOLDER/v1
      api_key: sk-dummy

litellm_settings:
  drop_params: true
```

The `nimrod-start.sh` script automatically updates the `api_base` field when executed.

### Step 3: Install & Launch NIMROD

Clone or copy the NIMROD agent files to your machine, then run:

```bash
# Make the startup script executable
chmod +x nimrod-start.sh

# Start the local LiteLLM proxy (connects to Kaggle tunnel)
./nimrod-start.sh

# Launch the NIMROD agent
python3 nimrod.py
```

---

## Safety & Compliance

NIMROD implements a 5-layer defense-in-depth safety model:

1. **Blocked Patterns:** Destructive commands (`rm`, `sudo`, `wget`) are rejected pre-execution.
2. **Binary Whitelist:** Only approved security tools can be proposed.
3. **Report Policy:** File writes restricted to bare `.txt` reports in CWD only.
4. **Human Gate:** Plan-level approval required before any autonomous execution.
5. **Containment:** Hard timeouts and output truncation prevent context overflow.

> **Legal Disclaimer:** NIMROD is intended for educational purposes and authorized security assessments only. Always obtain written permission before testing any system you do not own. Unauthorized access is illegal.

---

## Automated Reporting

Upon mission completion or interruption, NIMROD automatically generates a structured `.txt` report containing:

- AI-written executive summary
- Verbatim tool execution outputs
- Per-step analysis and findings
- Mission metadata (mode, scope, timestamp)

Reports are saved in the directory where NIMROD was launched.

---

## Troubleshooting

| Issue | Solution |
|---|---|
| Could not resolve host | Enable the Internet toggle in Kaggle Notebook Settings |
| Connection refused | Verify `nimrod-start.sh` ran successfully and LiteLLM is listening on port 4001 |
| Model not found | Ensure `nimrod_config.yaml` is at `/home/user/` and `api_base` matches the current tunnel URL |
| Plan unparsable | Retry the `/plan` command; some quantizations struggle with JSON output |

---

## Infrastructure Security Concepts Applied

Building NIMROD served as a practical implementation of enterprise security patterns:

- **Zero Trust Network Access (ZTNA)** via encrypted tunnels
- **API Gateway Security** through LiteLLM standardization
- **Privileged Access Management (PAM)** via human-in-the-loop approval
- **Data Loss Prevention (DLP)** through local-only inference
- **Ephemeral Infrastructure Security** using disposable Kaggle sessions
- **Input Validation & Command Sanitization** via multi-layer safety gates

---

## Contributing

This project is actively refined through real-world testing scenarios. Feedback on planning logic, tool whitelists, and safety improvements is welcome.

Built for the cybersecurity learning community. Stay curious, stay ethical, stay safe.
