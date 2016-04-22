#LADP configs
LDAP_PROVIDER = '10.1.90.11'
LDAP_BINDDN = 'cn=users,cn=accounts,dc=xdata,dc=data-tactics-corp,dc=com'
#client configs, update client id/secret to reflect the one you registered
#CLIENT_ID = 'QYRoovUXCg6WAWLmaH7qfdOBhmnPRSwPvpHgwPrq'
#CLIENT_SECRET = 'FFLvsV9foMQ5quhlA0WFY8UVfzOHnTMY9lVE8YkqHBuGMijDlZ'
CLIENT_ID = 'Z5jHax6Y4gdphSeGHsSVzEyIipasvd6jBQXW4YJ5'
CLIENT_SECRET='AepYi4UjtY8dyO6bTFO6M7eO5J0rb9lsHlrlKJe75q3Quk2jwR'
#oauth 2 provider url
#PROVIDER_BASE_URL = 'https://xdataproxy.com/oauth/api/'
#PROVIDER_ACCESS_TOKEN_URL = 'https://xdataproxy.com/oauth/token'
#PROVIDER_AUTHORIZE_URL = 'https://xdataproxy.com/oauth/authorize'
#local oauth2 provider url:
#VERY IMPORTANT: use 127.0.0.1 for server, use localhost for client to aviod session override#
PROVIDER_BASE_URL = 'http://127.0.0.1:5000/oauth/api/'
PROVIDER_ACCESS_TOKEN_URL = 'http://127.0.0.1:5000/oauth/token'
PROVIDER_AUTHORIZE_URL = 'http://127.0.0.1:5000/oauth/authorize'