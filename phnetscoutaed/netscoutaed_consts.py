# Define your constants here
# Configuration fields
NETSCOUTAED_TA_CONFIG_SERVER_URL = "server_url"
NETSCOUTAED_TA_CONFIG_API_TOKEN = "api_token"
NETSCOUTAED_TA_CONFIG_VERIFY_SSL = "verify_server_cert"

NETSCOUTAED_TA_PARAM_IP = "ip"

# Rest endpoints
NETSCOUTAED_REST_SUMMARY = '/api/aed/v3/summary/'
NETSCOUTAED_REST_BLOCKED_IPS = '/api/aed/v3/otf/denied-hosts/'
NETSCOUTAED_REST_ALLOWED_IPS = '/api/aed/v3/otf/allowed-hosts/'

NETSCOUTAED_REST_INBOUND_ALLOWED_HOSTS = '/api/aed/v3/protection-groups/allowed-hosts/'
NETSCOUTAED_REST_INBOUND_DENIED_HOSTS = '/api/aed/v3/protection-groups/denied-hosts/'

# Messages
NETSCOUTAED_DEFAULT_ANNOTATION = 'Added by Splunk SOAR'
NETSCOUTAED_INVALID_IP = "Parameter 'ip' failed validation"
