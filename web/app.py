from jwt import decode, InvalidTokenError
from jwt import encode
from uuid import uuid4
from flask import Flask,session
from flask import request, Response
from flask import redirect
from flask import render_template
from flask import make_response
import os
from flask_sqlalchemy import SQLAlchemy
import datetime
import requests
import json
from flask import send_file
from authlib.flask.client import OAuth
from six.moves.urllib.parse import urlencode
from functools import wraps
from dotenv import load_dotenv
load_dotenv(verbose=True)


def requires_auth(f):
  @wraps(f)
  def decorated(*args, **kwargs):
    session_id = request.cookies.get('session_id')
    if not db.session.query(db.exists().where(Session.session == session_id)).scalar():
      return redirect('/login')
    return f(*args, **kwargs)
  return decorated

SESSION_TIME=300

app = Flask(__name__)
app.config["SECRET_KEY"]=os.getenv('SECRET_KEY')
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///app.sqlite"
db = SQLAlchemy(app)
oauth = OAuth(app)


auth0 = oauth.register(
    'auth0',
    client_id='fsnqPLmYr90AjRI3VvcW75HD5pQvNX42',
    client_secret='TosKiBpDxUIYrkZanIIEc0nQ8SngHk1FqQveyfHLecgfiGqaPYjwtUNZeNHtk8kF',
    api_base_url='https://web1337.eu.auth0.com',
    access_token_url='https://web1337.eu.auth0.com/oauth/token',
    authorize_url='https://web1337.eu.auth0.com/authorize',
    client_kwargs={
        'scope': 'openid profile email',
    },
)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String, unique=True, nullable=False)
    password = db.Column(db.String, nullable=False)

class Session(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    session = db.Column(db.String)
    session_time = db.Column(db.String)
    login = db.Column(db.String)

db.create_all()


INVALIDATE = -1
JWT_SECRET=os.getenv('JWT_SECRET')
JWT_SESSION_TIME=30
HTML = """<!doctype html>
<head><meta charset="utf-8"/></head>"""

@app.route('/callback')
def callback_handling():
    # Handles response from token endpoint
    auth0.authorize_access_token()
    resp = auth0.get('userinfo')
    userinfo = resp.json()

    # Store the user information in flask session.
    session_id = str(uuid4())
    db.session.add(Session(session=session_id,login=userinfo['name']))
    db.session.commit()
    response = make_response('proceed to login', 303)
    response.set_cookie("session_id", session_id, max_age=SESSION_TIME)
    response.headers["Location"] = "/"
    
    return response

@app.route('/')
@requires_auth
def index():
  return redirect('/welcome')

@app.route('/login')
def login():
  session_id = request.cookies.get('session_id')
  return f"""{HTML}
  	<h1>APP</h1>
  	<div class="login-box auth0-box before">
    <img src="https://i.cloudup.com/StzWWrY34s.png" />
    <h3>Auth0 Example</h3>
    <p>Zero friction identity infrastructure, built for developers</p>
    <a class="btn btn-primary btn-lg btn-login btn-block" href="/loginauth">Log In</a>
</div>"""

@app.route('/loginauth')
def loginauth():
  return auth0.authorize_redirect(redirect_uri='http://localhost:5000/callback')



@app.route('/auth', methods=['POST'])
def auth():
  login = request.form.get('login')
  password = request.form.get('password')
  response = make_response('proceed to login', 303)
  if db.session.query(db.exists().where(User.login == login).where(User.password==password)).scalar():
    session_id = str(uuid4())
    db.session.add(Session(session=session_id,login=login))
    db.session.commit()
    response.set_cookie("session_id", session_id, max_age=SESSION_TIME)
    response.headers["Location"] = "/welcome"
  else:
    response.set_cookie("session_id", "INVALIDATE", max_age=INVALIDATE)
    response.headers["Location"] = "/login"
  return response

@app.route('/logout')
@requires_auth
def logout():
  session_id = request.cookies.get('session_id')
  Session.query.filter_by(session=session_id).delete()
  response = redirect("/login")
  response.set_cookie("session_id", "INVALIDATE", max_age=INVALIDATE)
  return response

@app.route('/<user>/status')
@requires_auth
def status(user):
  resp = requests.get('http://jwt:5000/'+user+'/status')
  return json.dumps(resp.text)

@app.route('/welcome')
@requires_auth
def welcome():
  session_id = request.cookies.get('session_id')
  if session_id:
    if db.session.query(db.exists().where(Session.session == session_id)).scalar():
      col=db.session.query(Session).filter_by(session=session_id).first()
      login=col.login
      resp = requests.get('http://jwt:5000/'+login)
      download_token = create_download_token(login).decode('ascii')
      upload_token = create_upload_token().decode('ascii')
      js = json.loads(resp.text)

      return render_template('layout.html',user=login,publications=js['publications'])
  return redirect("/login")

@app.route('/upload', methods=['POST'])
@requires_auth
def upload():
  f = request.files.get('file')
  user = request.form.get('user')
  author = request.form.get('author')
  title = request.form.get('title')
  year = request.form.get('year')
  upload_token = create_upload_token()
  s = requests.Session()
  x=s.post('http://jwt:5000/upload',files={'file':(f.filename,f)},params={
  'user':user,
  'token':upload_token,
  'author' : author,
  'title' : title,
  'year' : year
  })
  return redirect('/welcome')

@app.route('/download', methods=['POST'])
@requires_auth
def download():
  f = request.form.get('file')
  user = request.form.get('user')
  token = create_download_token(user)
  s = requests.Session()
  x=s.get('http://jwt:5000/'+user+'/'+f,params={
  'token':token}
  )
  contentType = x.headers['content-type']
  resp = Response(x.content, content_type=contentType)
  return resp

@app.route('/downloadref', methods=['POST'])
@requires_auth
def downloadref():
  f = request.form.get('file')
  user = request.form.get('user')
  id = request.form.get('id')
  token = create_download_token(user)
  s = requests.Session()
  x=s.get('http://jwt:5000/'+user+'/'+id+'/'+f,params={
  'token':token}
  )
  contentType = x.headers['content-type']
  resp = Response(x.content, content_type=contentType)
  return resp

@app.route('/uploadref', methods=['POST'])
@requires_auth
def uploadref():
  f = request.files.get('file')
  user = request.form.get('user')
  id = request.form.get('id')
  s = requests.Session()
  x=s.post('http://jwt:5000/'+user+'/'+str(id),files={'file':(f.filename,f)}
  )
  return redirect('/welcome')


@app.route('/delete', methods=['POST'])
@requires_auth
def delete():
  f = request.form.get('resource')
  user = request.form.get('user')
  s = requests.Session()
  x=s.delete('http://jwt:5000/'+user+'/'+f
  )
  return redirect('/welcome')

@app.route('/deleteref', methods=['POST'])
@requires_auth
def deleteref():
  f = request.form.get('resource')
  user = request.form.get('user')
  id = request.form.get('id')
  s = requests.Session()
  x=s.delete('http://jwt:5000/'+user+'/'+id+'/'+f
  )
  return redirect('/welcome')


def create_download_token(user):
  exp = datetime.datetime.utcnow() + datetime.timedelta(seconds=JWT_SESSION_TIME)
  return encode({
  	 "iss":"web",
     "user":user,
  	 "exp":exp},
     JWT_SECRET, "HS256")


def create_upload_token():
  exp = datetime.datetime.utcnow() + datetime.timedelta(seconds=JWT_SESSION_TIME)
  return encode({
  	"iss":"web",
    "exp":exp},
    JWT_SECRET, "HS256")