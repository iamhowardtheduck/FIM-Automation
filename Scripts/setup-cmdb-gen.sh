#!/usr/bin/env bash
# =============================================================================
# FIM-Automation Workshop Setup Script
# https://github.com/iamhowardtheduck/FIM-Automation
# =============================================================================
set -euo pipefail

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${CYAN}[INFO]${RESET}  $*"; }
ok()      { echo -e "${GREEN}[OK]${RESET}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
error()   { echo -e "${RED}[ERROR]${RESET} $*"; exit 1; }
section() { echo -e "\n${BOLD}${CYAN}━━━  $*  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"; }

# ── Config ────────────────────────────────────────────────────────────────────
WORKSPACE="${WORKSPACE:-/workspace/workshop/FIM-Automation}"
REPO_URL="https://github.com/iamhowardtheduck/FIM-Automation.git"
ES_ENDPOINT="${ES_ENDPOINT:-http://localhost:30920}"
KIBANA_ENDPOINT="${KIBANA_ENDPOINT:-http://localhost:30002}"
ES_USER="${ES_USER:-elastic-rocks}"
ES_PASS="${ES_PASS:-splunk-sucks}"
HTTP_PORT="${HTTP_PORT:-8080}"

# Allow overrides via args
while [[ $# -gt 0 ]]; do
  case $1 in
    --workspace)  WORKSPACE="$2";      shift 2 ;;
    --es)         ES_ENDPOINT="$2";    shift 2 ;;
    --kibana)     KIBANA_ENDPOINT="$2";shift 2 ;;
    --user)       ES_USER="$2";        shift 2 ;;
    --pass)       ES_PASS="$2";        shift 2 ;;
    --port)       HTTP_PORT="$2";      shift 2 ;;
    --help|-h)
      echo "Usage: $0 [options]"
      echo "  --workspace DIR   Install path (default: /workspace/workshop/FIM-Automation)"
      echo "  --es URL          Elasticsearch endpoint (default: http://localhost:30920)"
      echo "  --kibana URL      Kibana endpoint (default: http://localhost:30002)"
      echo "  --user USER       ES username (default: elastic-rocks)"
      echo "  --pass PASS       ES password (default: splunk-sucks)"
      echo "  --port PORT       Local HTTP server port (default: 8080)"
      exit 0 ;;
    *) warn "Unknown argument: $1"; shift ;;
  esac
done

# ── Banner ────────────────────────────────────────────────────────────────────
echo -e "${BOLD}"
echo "  ███████╗██╗███╗   ███╗      █████╗ ██╗   ██╗████████╗ ██████╗ "
echo "  ██╔════╝██║████╗ ████║     ██╔══██╗██║   ██║╚══██╔══╝██╔═══██╗"
echo "  █████╗  ██║██╔████╔██║     ███████║██║   ██║   ██║   ██║   ██║"
echo "  ██╔══╝  ██║██║╚██╔╝██║     ██╔══██║██║   ██║   ██║   ██║   ██║"
echo "  ██║     ██║██║ ╚═╝ ██║     ██║  ██║╚██████╔╝   ██║   ╚██████╔╝"
echo "  ╚═╝     ╚═╝╚═╝     ╚═╝     ╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝ "
echo -e "${CYAN}  File Integrity Monitoring & Automation Workshop${RESET}"
echo -e "  Elastic Stack + Workflows + ServiceNow CMDB\n"

# ── 1. Prerequisites ──────────────────────────────────────────────────────────
section "Checking Prerequisites"

check_cmd() {
  if command -v "$1" &>/dev/null; then
    ok "$1 found: $(command -v $1)"
  else
    warn "$1 not found — will attempt install"
    return 1
  fi
}

MISSING_PKGS=()
check_cmd git     || MISSING_PKGS+=(git)
check_cmd curl    || MISSING_PKGS+=(curl)
check_cmd python3 || MISSING_PKGS+=(python3)
check_cmd jq      || MISSING_PKGS+=(jq)

if [[ ${#MISSING_PKGS[@]} -gt 0 ]]; then
  info "Installing missing packages: ${MISSING_PKGS[*]}"
  if command -v apt-get &>/dev/null; then
    sudo apt-get update -qq && sudo apt-get install -y -qq "${MISSING_PKGS[@]}"
  elif command -v dnf &>/dev/null; then
    sudo dnf install -y -q "${MISSING_PKGS[@]}"
  elif command -v yum &>/dev/null; then
    sudo yum install -y -q "${MISSING_PKGS[@]}"
  else
    error "Cannot auto-install packages. Please install manually: ${MISSING_PKGS[*]}"
  fi
fi

ok "All prerequisites satisfied"

# ── 2. Clone / Update Repo ────────────────────────────────────────────────────
section "Setting Up Repository"

if [[ -d "${WORKSPACE}/.git" ]]; then
  info "Repository already exists at ${WORKSPACE}, pulling latest..."
  cd "${WORKSPACE}"
  git pull --ff-only origin main && ok "Repository updated"
else
  info "Cloning repository to ${WORKSPACE}..."
  mkdir -p "$(dirname "${WORKSPACE}")"
  git clone "${REPO_URL}" "${WORKSPACE}"
  ok "Repository cloned"
fi

cd "${WORKSPACE}"

# ── 3. SSL Certificate Setup (skipped — localhost HTTP) ──────────────────────
section "SSL Certificate Setup"
info "Using HTTP endpoints on localhost — skipping SSL certificate setup"

# ── 4. Test Elasticsearch Connectivity ───────────────────────────────────────
section "Testing Elasticsearch Connectivity"

info "Connecting to ${ES_ENDPOINT}..."

ES_RESPONSE=$(curl -sk -u "${ES_USER}:${ES_PASS}" \
  --connect-timeout 5 \
  "${ES_ENDPOINT}/" 2>&1) || true

if echo "${ES_RESPONSE}" | jq -e '.version.number' &>/dev/null; then
  ES_VERSION=$(echo "${ES_RESPONSE}" | jq -r '.version.number')
  CLUSTER_NAME=$(echo "${ES_RESPONSE}" | jq -r '.cluster_name')
  ok "Connected to Elasticsearch ${ES_VERSION} — cluster: ${CLUSTER_NAME}"
else
  warn "Could not connect to Elasticsearch at ${ES_ENDPOINT}"
  warn "Response: ${ES_RESPONSE:0:200}"
  warn "Continuing setup — you can re-test connectivity once the cluster is ready"
fi

# ── 5. Create Index Templates ─────────────────────────────────────────────────
section "Creating Elasticsearch Index Templates"

es_put() {
  local path="$1"
  local body="$2"
  local label="$3"
  local result
  result=$(curl -sk -u "${ES_USER}:${ES_PASS}" \
    -X PUT "${ES_ENDPOINT}/${path}" \
    -H 'Content-Type: application/json' \
    -d "${body}" 2>&1) || true

  if echo "${result}" | jq -e '.acknowledged == true or .["_index"]' &>/dev/null 2>/dev/null; then
    ok "${label}"
  else
    warn "${label} — ${result:0:200}"
  fi
}

# logs-cmdb.updates template
es_put "_index_template/logs-cmdb.updates" '{
  "index_patterns": ["logs-cmdb.updates*"],
  "priority": 100,
  "template": {
    "settings": { "number_of_shards": 1, "number_of_replicas": 0 },
    "mappings": {
      "properties": {
        "@timestamp":          { "type": "date" },
        "cmdb.sys_id":         { "type": "keyword" },
        "cmdb.host_name":      { "type": "keyword" },
        "cmdb.ip_address":     { "type": "ip", "ignore_malformed": true },
        "cmdb.os":             { "type": "keyword" },
        "cmdb.install_status": { "type": "keyword" },
        "cmdb.environment":    { "type": "keyword" },
        "cmdb.classification": { "type": "keyword" },
        "cmdb.sys_class_name": { "type": "keyword" },
        "change.type":         { "type": "keyword" },
        "change.fields":       { "type": "keyword" },
        "change.previous":     { "type": "object", "enabled": false },
        "change.current":      { "type": "object", "enabled": false },
        "servicenow.event_id": { "type": "keyword" },
        "action.required":     { "type": "keyword" },
        "action.status":       { "type": "keyword" },
        "action.processed_at": { "type": "date" }
      }
    }
  }
}' "Index template: logs-cmdb.updates"

# logs-fim_policy.updates template
es_put "_index_template/logs-fim_policy.updates" '{
  "index_patterns": ["logs-fim_policy.updates*"],
  "priority": 100,
  "template": {
    "settings": { "number_of_shards": 1, "number_of_replicas": 0 },
    "mappings": {
      "properties": {
        "@timestamp":          { "type": "date" },
        "cmdb_update_id":      { "type": "keyword" },
        "host.name":           { "type": "keyword" },
        "fleet.policy_id":     { "type": "keyword" },
        "fleet.policy_name":   { "type": "keyword" },
        "fleet.agent_id":      { "type": "keyword" },
        "fim.paths_to_add":    { "type": "keyword" },
        "fim.paths_to_remove": { "type": "keyword" },
        "fim.current_paths":   { "type": "keyword" },
        "action.type":         { "type": "keyword" },
        "action.status":       { "type": "keyword" },
        "action.applied_at":   { "type": "date" },
        "action.error":        { "type": "text" }
      }
    }
  }
}' "Index template: logs-fim_policy.updates"

# Create the initial write indices
es_put "logs-cmdb.updates-000001" '{
  "aliases": { "logs-cmdb.updates": { "is_write_index": true } }
}' "Index: logs-cmdb.updates-000001"

es_put "logs-fim_policy.updates-000001" '{
  "aliases": { "logs-fim_policy.updates": { "is_write_index": true } }
}' "Index: logs-fim_policy.updates-000001"

# ── 6. Update HTML with correct endpoints ────────────────────────────────────
section "Configuring cmdb_generator.html"

HTML_FILE="${WORKSPACE}/cmdb_generator.html"

if [[ -f "${HTML_FILE}" ]]; then
  # Patch in the correct endpoints and credentials
  sed -i \
    -e "s|value=\"http://localhost:30920\"|value=\"${ES_ENDPOINT}\"|g" \
    -e "s|value=\"http://localhost:30002\"|value=\"${KIBANA_ENDPOINT}\"|g" \
    -e "s|value=\"elastic-rocks\"|value=\"${ES_USER}\"|g" \
    -e "s|value=\"splunk-sucks\"|value=\"${ES_PASS}\"|g" \
    "${HTML_FILE}"
  ok "cmdb_generator.html patched with correct endpoints"
else
  warn "cmdb_generator.html not found — skipping patch"
fi

# ── 7. Start HTTP Server ──────────────────────────────────────────────────────
section "Starting HTTP Server"

# Kill any existing server on this port
if lsof -Pi :${HTTP_PORT} -sTCP:LISTEN -t &>/dev/null 2>&1; then
  warn "Port ${HTTP_PORT} already in use — killing existing process"
  kill $(lsof -Pi :${HTTP_PORT} -sTCP:LISTEN -t) 2>/dev/null || true
  sleep 1
fi

# Write a PID-tracked launcher
cat > "${WORKSPACE}/.server.sh" << EOF
#!/usr/bin/env bash
cd "${WORKSPACE}"
python3 -m http.server ${HTTP_PORT} > "${WORKSPACE}/.server.log" 2>&1 &
echo \$! > "${WORKSPACE}/.server.pid"
echo "HTTP server started on port ${HTTP_PORT} (PID: \$!)"
EOF
chmod +x "${WORKSPACE}/.server.sh"

cd "${WORKSPACE}"
python3 -m http.server ${HTTP_PORT} > "${WORKSPACE}/.server.log" 2>&1 &
SERVER_PID=$!
echo ${SERVER_PID} > "${WORKSPACE}/.server.pid"

sleep 1
if kill -0 ${SERVER_PID} 2>/dev/null; then
  ok "HTTP server running on port ${HTTP_PORT} (PID: ${SERVER_PID})"
else
  error "HTTP server failed to start — check ${WORKSPACE}/.server.log"
fi

# ── 8. Summary ────────────────────────────────────────────────────────────────
section "Setup Complete"

LOCAL_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "localhost")

echo -e "\n${BOLD}Workshop URLs:${RESET}"
echo -e "  ${GREEN}CMDB Generator:${RESET}  http://localhost:${HTTP_PORT}/cmdb_generator.html"
echo -e "  ${GREEN}              :${RESET}  http://${LOCAL_IP}:${HTTP_PORT}/cmdb_generator.html"
echo -e "  ${GREEN}Kibana:${RESET}          ${KIBANA_ENDPOINT}"
echo -e "  ${GREEN}Elasticsearch:${RESET}   ${ES_ENDPOINT}"

echo -e "\n${BOLD}Elasticsearch:${RESET}"
echo -e "  User: ${ES_USER}"
echo -e "  Pass: ${ES_PASS}"

echo -e "\n${BOLD}Indices Created:${RESET}"
echo -e "  logs-servicenow.event-default   (ServiceNow CMDB source)"
echo -e "  logs-cmdb.updates               (CMDB change tracking)"
echo -e "  logs-fim_policy.updates         (Fleet policy update queue)"

echo -e "\n${BOLD}Manage HTTP Server:${RESET}"
echo -e "  Stop:    kill \$(cat ${WORKSPACE}/.server.pid)"
echo -e "  Restart: ${WORKSPACE}/.server.sh"
echo -e "  Logs:    tail -f ${WORKSPACE}/.server.log"

echo -e "\n${BOLD}Next Steps:${RESET}"
echo -e "  1. Open the CMDB Generator URL above"
echo -e "  2. Click ${CYAN}TEST CONNECTION${RESET} to verify Elasticsearch auth"
echo -e "  3. Set distribution and press ${CYAN}GENERATE & INGEST CMDB${RESET}"
echo -e "  4. Verify data in Kibana Discover → logs-servicenow.event-default"
echo -e "  5. Proceed to Workflow 1: CMDB Change Detector\n"
