from flask import Flask, url_for, redirect, session, request, jsonify
from flask_oauthlib.client import OAuth
from flask import render_template
import logging
import sys
import config
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


app = Flask(__name__)
app.debug = True
app.secret_key = 'secret'
oauth = OAuth(app)

remote = oauth.remote_app(
    'remote',
    consumer_key=config.CLIENT_ID,
    consumer_secret=config.CLIENT_SECRET,
    request_token_params={'scope': 'email'},
    base_url=config.PROVIDER_BASE_URL,
    request_token_url=None,
    access_token_url=config.PROVIDER_ACCESS_TOKEN_URL,
    authorize_url=config.PROVIDER_AUTHORIZE_URL
)


@app.route('/')
def index():
   
    return redirect(url_for('login'))
 
@app.route('/logout')
def logout():
	if 'remote_oauth' in session:
		remote.get('signout')
	session.pop('remote_oauth', None)
	session.clear()
	return render_template("logout.html")

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
    
    return jsonify(oauth_token=resp['access_token'], user=me.data)
    

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
    app.run(host='0.0.0.0', port=8000)
