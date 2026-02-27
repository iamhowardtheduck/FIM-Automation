# Set up environment variables
echo 'ELASTICSEARCH_USERNAME=elastic' >> /root/.env
#echo -n 'ELASTICSEARCH_PASSWORD=' >> /root/.env
kubectl get secret elasticsearch-es-elastic-user -n default -o go-template='ELASTICSEARCH_PASSWORD={{.data.elastic | base64decode}}' >> /root/.env
echo '' >> /root/.env
echo 'ELASTICSEARCH_URL="http://localhost:30920"' >> /root/.env
echo 'KIBANA_URL="http://localhost:30002"' >> /root/.env
echo 'BUILD_NUMBER="10"' >> /root/.env
echo 'ELASTIC_VERSION="9.1.0"' >> /root/.env
echo 'ELASTIC_APM_SERVER_URL=http://apm.default.svc:8200' >> /root/.env
echo 'ELASTIC_APM_SECRET_TOKEN=pkcQROVMCzYypqXs0b' >> /root/.env

# Set up environment
export $(cat /root/.env | xargs)

BASE64=$(echo -n "elastic:${ELASTICSEARCH_PASSWORD}" | base64)
KIBANA_URL_WITHOUT_PROTOCOL=$(echo $KIBANA_URL | sed -e 's#http[s]\?://##g')

# Add sdg user with superuser role
curl -X POST "http://localhost:30920/_security/user/elastic-rocks" -H "Content-Type: application/json" -u "elastic:${ELASTICSEARCH_PASSWORD}" -d '{
  "password" : "splunk-sucks",
  "roles" : [ "superuser" ],
  "full_name" : "Elastic Rocks",
  "email" : "sdg@elastic-pahlsoft.com"
}'


# Install LLM Connector
bash /opt/workshops/elastic-llm.sh -k false -m claude-sonnet-4 -d true

echo
echo "AI Assistant Connector configured as OpenAI"
echo

# Use Security view
bash /opt/workshops/elastic-view.sh -v classic

echo
echo "Default Kibana view applied"
echo

# Enable workflows
curl -X POST "http://localhost:30002/api/kibana/settings" -H "Content-Type: application/json" -H "kbn-xsrf: true" -H "x-elastic-internal-origin: featureflag" -u "elastic-rocks:splunk-sucks"  -d '{
    "changes": {
      "workflows:ui:enabled": true
    }
  }'

clear

# Create Elastic-Agent policies
curl -X POST "http://localhost:30002/api/fleet/agent_policies?sys_monitoring=true" --header "kbn-xsrf: true"  -H "Content-Type: application/json" -u "elastic-rocks:splunk-sucks" -d @/root/FIM-Automation/Agent-Policies/Linux.json
curl -X POST "http://localhost:30002/api/fleet/agent_policies?sys_monitoring=true" --header "kbn-xsrf: true"  -H "Content-Type: application/json" -u "elastic-rocks:splunk-sucks" -d @/root/FIM-Automation/Agent-Policies/Windows.json
curl -X POST "http://localhost:30002/api/fleet/agent_policies?sys_monitoring=true" --header "kbn-xsrf: true"  -H "Content-Type: application/json" -u "elastic-rocks:splunk-sucks" -d @/root/FIM-Automation/Agent-Policies/AppOps.json
curl -X POST "http://localhost:30002/api/fleet/agent_policies?sys_monitoring=true" --header "kbn-xsrf: true"  -H "Content-Type: application/json" -u "elastic-rocks:splunk-sucks" -d @/root/FIM-Automation/Agent-Policies/Database.json
curl -X POST "http://localhost:30002/api/fleet/agent_policies?sys_monitoring=true" --header "kbn-xsrf: true"  -H "Content-Type: application/json" -u "elastic-rocks:splunk-sucks" -d @/root/FIM-Automation/Agent-Policies/SecOps.json
curl -X POST "http://localhost:30002/api/fleet/agent_policies?sys_monitoring=true" --header "kbn-xsrf: true"  -H "Content-Type: application/json" -u "elastic-rocks:splunk-sucks" -d @/root/FIM-Automation/Agent-Policies/NetOps.json

# Add ServiceNow integration assets
curl -X POST "http://localhost:30002/api/fleet/epm/packages/servicenow/1.3.3" -H "Content-Type: application/json" -u "elastic-rocks:splunk-sucks"  -H "kbn-xsrf: true

clear


echo
echo
python3 /root/FIM-Automation/cmdb_server.py
echo
echo "You are now ready to begin the workshop."
