from flask import Flask, url_for, redirect, session, request, jsonify
from flask_oauthlib.client import OAuth
import logging
import sys
# create logger
logger = logging.getLogger('oauth client')
logger.setLevel(logging.DEBUG)

# create console handler and set level to debug
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG)

# create formatter
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# add formatter to ch
ch.setFormatter(formatter)

# add ch to logger
logger.addHandler(ch)

CLIENT_ID = 'CgPSlVTKyFrVhrZ8eiqZOt0KqF4NvF4NMGmRXTjV'
CLIENT_SECRET = 'k3k03aYH4sOvLzIpKC1aFSbQTvlawp8IDWwB4O7t6fPO5LCLlv'
#CLIENT_SECRET = 'test'

app = Flask(__name__)
app.debug = True
app.secret_key = 'secret'
oauth = OAuth(app)

remote = oauth.remote_app(
    'remote',
    consumer_key=CLIENT_ID,
    consumer_secret=CLIENT_SECRET,
    request_token_params={'scope': 'email'},
    base_url='http://127.0.0.1:5000/oauth/api/',
    request_token_url=None,
    access_token_url='http://127.0.0.1:5000/oauth/token',
    authorize_url='http://127.0.0.1:5000/oauth/authorize'
)


@app.route('/')
def index():
    if 'remote_oauth' in session:
        me = remote.get('me')
        return jsonify(me.data)
    return redirect(url_for('login'))
 
@app.route('/logout')
def logout():
	session.pop('remote_oauth', None)
	return redirect(url_for('index'))

@app.route('/authorized')
def authorized():
    resp = remote.authorized_response()
    if resp is None:
        return 'Access denied: reason=%s error=%s' % (
            request.args['error_reason'],
            request.args['error_description']
        )
    print resp
    if resp['access_token'] is None:
    	return 'Access denied. access_token not granted, please check your client id/secret'
    session['remote_oauth'] = (resp['access_token'], '')
    #test getting protected api/me method
    me = remote.get('me')
    return jsonify(me.data)
    #return jsonify(oauth_token=resp['access_token'])

@app.route('/login')
def login():
	next_url = request.args.get('next') or request.referrer or None
	return remote.authorize(callback=url_for('authorized', next=next_url, _external=True))
	    
@remote.tokengetter
def get_oauth_token():
    return session.get('remote_oauth')


if __name__ == '__main__':
    import os
    os.environ['DEBUG'] = 'true'
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = 'true'
    app.run(host='localhost', port=8000)
