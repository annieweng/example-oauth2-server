
Installation for provider:

		#install python dependencies and Nginx web container
		sudo apt-get install python-pip python-dev libldap2-dev libsasl2-dev
		#git clone the source code
		export GIT_SSL_NO_VERIFY=1
		cd /srv
		git clone https://gitlab.xdataproxy.com/aweng/dsra-oauth2-server.git 
		cd dsra-oauth2-server
	 	pip install -r requirements.txt
		#initialized the database
		python dbInit.py
	development:
		python app.py
		open browser and navigate to http://localhost:5000/oauth
		
	production: 
		#install nginx and serve oauth2 provider with uWSGI and Nginx
		#change permission to nginx
		chown -R nginx:root /srv/dsra-oauth2-server

		#change owner of database file to nginx
		cd /srv/dsra-oauth2-server
		chmod 755 db.sqlite
		chown nginx:www-data db.sqlite
 				
		copy oauth2.conf to /etc/init to upstart service to automatically start it as uwsgi process
		add following nginx.conf

 		 location /oauth { try_files $uri @oauth; }
 		location @oauth {
         		include uwsgi_params;
         		uwsgi_pass unix:/srv/dsra-oauth2-server/oauth2.sock;
		}

	this will server oauth2 provider under http[s]://hostname/oauth.

Installation for Client
	follow instruction for installation for provider
	python client.py
	navigate to http://localhost:8000


	

 DSRA Oauth2 provider Authorization Code Flow

	•	resource owner login to Oauth2 server, register a application/client, and obtain client id/secret for the application
	•	application/client provide client id and redirection URI to authorization server, and have user authenticated as needed to obtain authorization code.
	•	client post authorization code and redirection url to obtain access token.
	•	client can invoke protected resource/api by adding "Authorization: Bearer $bearerAccessToken” to their header.

	

    Authorization Code Flow
    
     +----------+
     | Resource |
     |   Owner  |
     |          |
     +----------+
          ^
          |
         (B)
     +----|-----+          Client Identifier      +---------------+
     |         -+----(A)-- & Redirection URI ---->|               |
     |  User-   |                                 | Authorization |
     |  Agent/ -+----(B)-- User authenticates --->|     Server    |
     |          |                                 |               |
     | browser -+----(C)-- Authorization Code ---<|               |
     +-|----|---+                                 +---------------+
       |    |                                         ^      v
      (A)  (C)                                        |      |
       |    |                                         |      |
       ^    v                                         |      |
     +---------+                                      |      |
     |         |>---(D)-- Authorization Code ---------'      |
     |  Client |          & Redirection URI                  |
     |         |                                             |
     |         |<---(E)----- Access Token -------------------'
     +---------+       (w/ Optional Refresh Token)

   Note: The lines illustrating steps (A), (B), and (C) are broken into
   two parts as they pass through the user-agent.

see http://tools.ietf.org/html/rfc6749#section-4 for more detail. 


