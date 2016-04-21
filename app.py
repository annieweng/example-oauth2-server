# coding: utf-8
from urlparse import urlparse
from datetime import datetime, timedelta
from flask import Flask
from flask import session, request
from flask import render_template, redirect, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import gen_salt
from flask_oauthlib.provider import OAuth2Provider
#from flask.ext.sqlalchemy import SQLAlchemy
#from flask.ext.login import LoginManager
from sqlalchemy_utils.types.password import PasswordType
from functools import wraps
from flask import g, request, redirect, url_for
import uuid
import simpleldap
import config
import logging
import sys
import os
# create logger
logger = logging.getLogger()
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

#from views import auth
app = Flask(__name__, template_folder='templates')
app.debug = True
app.secret_key = os.urandom(24)
app.config.update({
    'SQLALCHEMY_DATABASE_URI': 'sqlite:///db.sqlite',
})
app.config['WTF-CSRF_SECRET_KEY']=str(uuid.uuid4())

app.config['APPLICATION_ROOT']='oauth'

db = SQLAlchemy(app)
oauth = OAuth2Provider(app)
#conn = None
conn = simpleldap.Connection(config.LDAP_PROVIDER)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(40), unique=True)
    password = db.Column(PasswordType(
        schemes=[
            'pbkdf2_sha512',
            'md5_crypt'
        ],

        deprecated=['md5_crypt']
    ))


class Client(db.Model):
    client_id = db.Column(db.String(40), primary_key=True)
    client_secret = db.Column(db.String(55), nullable=False)
    application_name=db.Column(db.Text)
    application_url=db.Column(db.Text)
    user_id = db.Column(db.ForeignKey('user.id'))
    user = db.relationship('User')

    _redirect_uris = db.Column(db.Text)
    _default_scopes = db.Column(db.Text)

    @property
    def client_type(self):
        return 'public'

    @property
    def redirect_uris(self):
        if self._redirect_uris:
            return self._redirect_uris.split()
        return []

    @property
    def default_redirect_uri(self):
        return self.redirect_uris[0]

    @property
    def default_scopes(self):
        if self._default_scopes:
            return self._default_scopes.split()
        return []


class Grant(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(
        db.Integer, db.ForeignKey('user.id', ondelete='CASCADE')
    )
    user = db.relationship('User')

    client_id = db.Column(
        db.String(40), db.ForeignKey('client.client_id'),
        nullable=False,
    )
    client = db.relationship('Client')

    code = db.Column(db.String(255), index=True, nullable=False)

    redirect_uri = db.Column(db.String(255))
    expires = db.Column(db.DateTime)

    _scopes = db.Column(db.Text)

    def delete(self):
        db.session.delete(self)
        db.session.commit()
        return self

    @property
    def scopes(self):
        if self._scopes:
            return self._scopes.split()
        return []


class Token(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(
        db.String(40), db.ForeignKey('client.client_id'),
        nullable=False,
    )
    client = db.relationship('Client')

    user_id = db.Column(
        db.Integer, db.ForeignKey('user.id')
    )
    user = db.relationship('User')

    # currently only bearer is supported
    token_type = db.Column(db.String(40))

    access_token = db.Column(db.String(255), unique=True)
    refresh_token = db.Column(db.String(255), unique=True)
    expires = db.Column(db.DateTime)
    _scopes = db.Column(db.Text)

    @property
    def scopes(self):
        if self._scopes:
            return self._scopes.split()
        return []


def current_user():
    if 'id' in session:
    	logger.debug( 'user id in session %s', session['id'])
        uid = session['id']
        return User.query.get(uid)
    return None

#target_url for_url('target') next_url is usually request.url
def forwardNextUrl(target_url, next_url):
    return'%s?next=%s' % (target_url, next_url)

@app.route('/oauth/login', methods=('GET', 'POST'))       
def login():
	#logger.debug( 'in login request.ur'+request.url+' request.referrer '+request.referrer)
	user=None
	msg=''
	username = request.form.get('username')
	password = request.form.get('password')
	is_valid = conn.authenticate('uid='+username+','+config.LDAP_BINDDN, password)
	logger.debug(" querying database for matching username and password %s, %s", username, password)
	logger.debug(" connection to ldap using username "+username+ " is valid: "+ str(is_valid))
	if is_valid:
		user=User.query.filter_by(username=username).first()
		
		if user:
			logger.debug("user already in local database. setting session id to user.id %s", user.id)
			session['id']=user.id
			#redirect the request back to next parameter of original request url, which is usually /authorize
			next=urlparse(request.referrer).query
			#request is coming from client, has ?next=url in the request, go ahead redirect back to the
			#requester. 
			if len(next)>5:
				next_url=next[5:len(next)]
				print 'query next:'+ str(next_url)
					
				return redirect(next_url)
				
					
			client=Client.query.filter_by(user_id=user.id).first()
			if client:
				print 'client id/secret for user is '+client.client_id+' : '+client.client_secret
				msg = msg + 'clientId: '+client.client_id+' client_secret:'+client.client_secret
				
		else:
			user = User(username=username, password=password)
			db.session.add(user)
			db.session.commit()
			session['id'] = user.id
			msg='login success!'
			logger.debug( ' user.id :%s' , user.id)
	else:
		msg='login failed'
	return render_template('home.html', user=user, msg=msg)
	
		
	
@app.route('/oauth', methods=('GET', 'POST'))
def home():
	#logger.debug( 'in home request.url '+str(request.url)+' request.referrer '+str(request.referrer))
	user = current_user()
	return render_template('home.html', user=user)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
    	
        if current_user() is None:
        	logger.debug( "login_required: url"+request.url)
    		logger.debug( "login_required: redirect url"+ str(request.args.get("redirect_uri")))
    		next_url = request.url
    		login_url = '%s?next=%s' % (url_for('home'), next_url)
    		return redirect(login_url)
        return f(*args, **kwargs)
    return decorated_function
 
@login_required
@app.route('/oauth/register', methods=('GET', 'POST'))
def register():
	logger.debug(" in register session[id] is %s", session['id'])
	user = current_user()
	
	if request.method == 'GET':
		return render_template('register.html', user=user)
	if request.method == 'POST':
		applicationName = request.form.get('applicationName')
		applicationUrl = request.form.get('applicationUrl')
		applcationDescription=request.form.get('applcationDescription')
		applicationCallbackUrl=request.form.get('applicationCallbackUrl')
		userId=request.form.get('userId')
		item = Client(
        client_id=gen_salt(40),
        client_secret=gen_salt(50),
        application_name=applicationName,
        application_url=applicationUrl,
        _redirect_uris=' '.join([
        	applicationCallbackUrl,
            ]),
        _default_scopes='email',
        user_id=userId,
    	)
		from pprint import pprint
		pprint (vars(item))
        db.session.add(item)
        db.session.commit()
        
    	return jsonify(
        client_id=item.client_id,
        client_secret=item.client_secret,
        )
	

	


@oauth.clientgetter
def load_client(client_id):
    return Client.query.filter_by(client_id=client_id).first()


@oauth.grantgetter
def load_grant(client_id, code):
    return Grant.query.filter_by(client_id=client_id, code=code).first()


@oauth.grantsetter
def save_grant(client_id, code, request, *args, **kwargs):
    # decide the expires time yourself
    expires = datetime.utcnow() + timedelta(seconds=100)
    grant = Grant(
        client_id=client_id,
        code=code['code'],
        redirect_uri=request.redirect_uri,
        _scopes=' '.join(request.scopes),
        user=current_user(),
        expires=expires
    )
    db.session.add(grant)
    db.session.commit()
    return grant


@oauth.tokengetter
def load_token(access_token=None, refresh_token=None):
    if access_token:
        return Token.query.filter_by(access_token=access_token).first()
    elif refresh_token:
        return Token.query.filter_by(refresh_token=refresh_token).first()


@oauth.tokensetter
def save_token(token, request, *args, **kwargs):
    toks = Token.query.filter_by(
        client_id=request.client.client_id,
        user_id=request.user.id
    )
    # make sure that every client has only one token connected to a user
    for t in toks:
        db.session.delete(t)

    expires_in = token.pop('expires_in')
    expires = datetime.utcnow() + timedelta(seconds=expires_in)

    tok = Token(
        access_token=token['access_token'],
        refresh_token=token['refresh_token'],
        token_type=token['token_type'],
        _scopes=token['scope'],
        expires=expires,
        client_id=request.client.client_id,
        user_id=request.user.id,
    )
    db.session.add(tok)
    db.session.commit()
    return tok



@app.route('/oauth/token', methods=['GET', 'POST'])
@oauth.token_handler
def access_token():
    return {'version': '0.1.0'}
    		
    		


@oauth.usergetter
def get_user(username, password, *args, **kwargs):
	print 'in get_user method'
	user = User.query.filter_by(username=username).filter_by(password=password).first()
	if user:
		session['id'] = user.id
		return user
	else:
		print username+' is not in database, querying ladp server'
		is_valid = conn.authenticate('uid='+username+','+config.LDAP_BINDDN, password)
		print " connection to ldap using username "+username+ " is valid: "+ str(is_valid)
		if is_valid:
			user = User(username=username, password=password)
			db.session.add(user)
			db.session.commit()
			session['id'] = user.id
			return user			
		else:
			return none
    

        

@app.route('/oauth/authorize', methods=['GET', 'POST'])
@login_required
@oauth.authorize_handler
def authorize(*args, **kwargs):
	#print "redirect uri"+ str(request.arg.get("redirect_uri"))
	user = current_user()
	if user is None:
		logger.debug( ' in authorized, user is not defined, redirect to home url')
		return redirect(url_for('home', next=url_for("authorize", next=request.url)))
	if request.method == 'GET':
		client_id = kwargs.get('client_id')
		client = Client.query.filter_by(client_id=client_id).first()
		kwargs['client'] = client
		kwargs['user'] = user
		return render_template('authorize.html', **kwargs)
	confirm = request.form.get('confirm', 'no')
	return confirm == 'yes'
	

@app.route('/oauth/sign_out', methods=('GET', 'POST'))
def signout():
	
	session.pop('id', None)
	session.clear()
	user = None
	logger.debug( 'sign out...')
	return redirect(url_for('home'))


@app.route('/oauth/api/me')
@oauth.require_oauth()
def me():
    user = request.oauth.user
    return jsonify(username=user.username)
    

@app.route('/oauth/api/user/<username>')
@oauth.require_oauth()
def user(username):
	user = request.oauth.user
	if user is None:
		user = User.query.filter_by(username=username).first()
	#todo: get the email from ladp
	return jsonify(username=user.username)
    
    
@app.route('/oauth2/revoke', methods=['POST'])
@oauth.revoke_handler
def revoke_token(): pass

if __name__ == '__main__':
    db.create_all()
    app.run( host='0.0.0.0')

