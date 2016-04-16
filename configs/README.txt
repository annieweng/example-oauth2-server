#git clone oauth2-server to /srv directory
export GIT_SSL_NO_VERIFY=1
cd /srv
git clone https://github.com/annieweng/oauth2-server.git /srv/

chown -R nginx:root /srv/oauth2-server

 apt-get install python-dev python-pip 
 sudo apt-get install libsasl2-dev
 pip install -r requirements.txt
chown nginx:root /srv/dsra-oauth2-server
copy oauth2.conf to /etc/init to upstart service, this will run python program as wsgi to act as gateway between nginx and python app. 

add following nginx.conf to /etc/config/nginx.conf to serve the endpoint as localhost/oauth,


 #uncomment, if want to rewrite the root context
 #location = /oauth { rewrite ^ /oauth/; }
 location /oauth { try_files $uri @oauth; }


 location @oauth {
         include uwsgi_params;
         #uwsgi_param SCRIPT_NAME /oauth;
         #uwsgi_modifier1 30;
         uwsgi_pass unix:/srv/dsra-oauth2-server/oauth2.sock;
         }
