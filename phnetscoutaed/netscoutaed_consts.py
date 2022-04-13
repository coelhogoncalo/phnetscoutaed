#
# Netscout AED for Splunk SOAR
#
# Author: Diogo Silva
#
#

# ASSET CONFIGURATION ##########
NETSCOUTAED_TA_CONFIG_SERVER_URL = 'base_url'
NETSCOUTAED_TA_CONFIG_API_TOKEN = 'api_token'
NETSCOUTAED_TA_CONFIG_VERIFY_SSL = 'verify_server_cert'


# REST ENDPOINTS ####################
NETSCOUTAED_REST_SUMMARY = "/api/aed/v3/summary/"

# Outbound Connections
NETSCOUTAED_REST_OUTBOUND_ALLOWED_HOSTS = "/api/aed/v3/otf/allowed-hosts/"

NETSCOUTAED_REST_OUTBOUND_DENIED_COUNTRIES = "/api/aed/v3/otf/denied-countries/"
NETSCOUTAED_REST_OUTBOUND_DENIED_HOSTS = "/api/aed/v3/otf/denied-hosts/"


# Inbound Connections
NETSCOUTAED_REST_INBOUND_ALLOWED_HOSTS = "/api/aed/v3/protection-groups/allowed-hosts/"

NETSCOUTAED_REST_INBOUND_DENIED_COUNTRIES = "/api/aed/v3/protection-groups/denied-countries/"
NETSCOUTAED_REST_INBOUND_DENIED_DOMAINS = "/api/aed/v3/protection-groups/denied-domains/"
NETSCOUTAED_REST_INBOUND_DENIED_HOSTS = "/api/aed/v3/protection-groups/denied-hosts/"
NETSCOUTAED_REST_INBOUND_DENIED_URLS = "/api/aed/v3/protection-groups/denied-urls/"


# DEFAULT MESSAGES ####################
NETSCOUTAED_MSG_DEFAULT_ANNOTATION = "Added by Splunk SOAR"
NETSCOUTAED_MSG_INVALID_IP = "Parameter 'ip' failed validation"
