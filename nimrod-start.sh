#!/bin/bash

CONFIG_FILE="$HOME/nimrod_config.yaml"
NTFY_TOPIC="my-secret-qwen-123" # MUST MATCH THE KAGGLE CELL EXACTLY

echo "========================================="
echo "         nimrod proxy starter"
echo "========================================="
echo ""
echo " Checking for new link from Kaggle..."

# Try to fetch the latest message from ntfy.sh
NEW_URL=$(curl -s "https://ntfy.sh/$NTFY_TOPIC/json?poll=1" | python3 -c "import sys,json; print(json.load(sys.stdin)['message'])" 2>/dev/null)

# If auto-fetch fails or is empty, ask for manual input
if [ -z "$NEW_URL" ] || [[ "$NEW_URL" != http* ]]; then
  echo " Could not fetch automatically. (Did you run the Kaggle cell?)"
  read -p "Paste your new Kaggle ngrok URL manually: " NEW_URL
fi

# Clean up the URL (remove trailing slashes)
NEW_URL="${NEW_URL%/}"

# Ollama-native API (what the Kaggle cell exposes) — no /v1 prefix.
# LiteLLM's ollama/ provider appends /api/generate to api_base itself.
echo "pdating config to: ${NEW_URL}"

# Safely update the YAML file without adding spaces
sed -i "s|api_base:.*|api_base: \"${NEW_URL}\"|" "$CONFIG_FILE"

echo "Starting LiteLLM proxy..."
echo ""

# Start LiteLLM
LITELLM_DANGEROUSLY_PERMIT_WEAK_OR_UNSET_MASTER_KEY=true ~/.local/bin/litellm --config "$CONFIG_FILE" --port 4001
