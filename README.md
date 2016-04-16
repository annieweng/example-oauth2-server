
OAuth 2 Server 

fork from lepture/example-oauth2-server Find more details on http://lepture.com/en/2013/create-oauth-server
use LADP to authenticate client in addition to client id/secret
add redirect logic base on login status
add registration page

# INSTALLATION

$ pip install -r requirements.txt
python dbInit.py
chmod 755 db.sqlite

#if running within nginx, change permission of data to nginx 
chown nginx:www-data db.sqlite

see configs/README for more detail of setting it up as wsgi application running in nginx
