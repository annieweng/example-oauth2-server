#LADP configs
LDAP_PROVIDER = 'localladp'
LDAP_BINDDN = 'cn=users,cn=accounts,dc=xdata,dc=data-tactics-corp,dc=com'
#client configs, update client id/secret to reflect the one you registered
CLIENT_ID = 'QYRoovUXCg6WAWLmaH7qfdOBhmnPRSwPvpHgwPrq'
CLIENT_SECRET = 'FFLvsV9foMQ5quhlA0WFY8UVfzOHnTMY9lVE8YkqHBuGMijDlZ'
#local oauth2 provider url
PROVIDER_BASE_URL='http://localhost:5000/oauth/api/'
PROVIDER_ACCESS_TOKEN_URL='http://localhost:5000/oauth/token',
PROVIDER_AUTHORIZE_URL='http://localhost:5000/oauth/authorize'
