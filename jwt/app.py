from jwt import decode, InvalidTokenError
from jwt import encode
from uuid import uuid4
from flask import Flask
from flask import request
from flask import redirect
from flask import render_template
from flask import make_response
import os
from flask_sqlalchemy import SQLAlchemy
import datetime
import requests
import json
from flask import send_file
import random
from dotenv import load_dotenv
load_dotenv(verbose=True)


JWT_SECRET=os.getenv('JWT_SECRET')

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///app.sqlite"
db = SQLAlchemy(app)

class Publications(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user = db.Column(db.String, nullable=False)
    author = db.Column(db.String, nullable=False)
    title = db.Column(db.String, nullable=False)
    year = db.Column(db.Integer, nullable=False)
    publication = db.Column(db.String, nullable=False)
    filename = db.Column(db.String, nullable=False)
    references = db.relationship('References', backref='publications',passive_deletes=True, lazy=True)

class References(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    id_pub = db.Column(db.Integer,db.ForeignKey('publications.id', ondelete='CASCADE'), nullable=False)
    path = db.Column(db.String, nullable=False)
    filename = db.Column(db.String, nullable=False)

class Changes(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user = db.Column(db.String, nullable=False)
    changeid = db.Column(db.String, nullable=False)
    

db.create_all()

def registerChange(user):
  if bool(Changes.query.filter_by(user=user).first()):
    change = Changes.query.filter_by(user=user).first()
    change.changeid = hex(random.getrandbits(128))[2:-1]
    db.session.commit()
  else:
    db.session.add(Changes(
      user=user,
      changeid=hex(random.getrandbits(128))[2:-1]
    ))
    db.session.commit()



@app.route('/')
def index():
  if os.path.isdir('/'):
    r=os.listdir('/')
    return json.dumps(r)
  else:
    return json.dumps("")

@app.route('/<user>')
def inde(user):
  if not db.session.query(db.exists().where(Changes.user == user)).scalar():
    registerChange(user)
  publist = Publications.query.filter_by(user=user).all()
  links = []
  pubs = []
  for publication in publist:
    links.append(user+"/"+str(publication.id))
    refs = []
    for ref in publication.references:
      refs.append({'path':ref.path,'filename':ref.filename})
      links.append(ref.path)
    pubs.append({'id':publication.id,'author':publication.author,'title':publication.title,'year':publication.year, 'publication':publication.publication,'filename':publication.filename,'references':refs})
  links.append(user+'/upload')
  links.append(user+'/status')
  return json.dumps({'publications':pubs,"changeid":Changes.query.filter_by(user=user).first().changeid,'links':links})

@app.route('/<user>/status')
def status(user):
  return Changes.query.filter_by(user=user).first().changeid

@app.route('/<user>/<pubid>',methods=['DELETE'])
def delete(user,pubid):
  if bool(Publications.query.filter_by(id=pubid).first()):
    pub = Publications.query.filter_by(id=pubid).one()
    os.remove(pub.publication)
    for ref in pub.references:
      os.remove(ref.path)
    db.session.delete(pub)
    db.session.commit()
    return make_response('',200)
  return make_response('',401)

@app.route('/<user>/<pubid>/<ref>',methods=['DELETE'])
def deleteref(user,pubid,ref):
  path = os.path.join(user,pubid,ref)
  if bool(References.query.filter_by(path=path).first()):
    os.remove(path)
    ref = References.query.filter_by(path=path).first()
    db.session.delete(ref)
    db.session.commit()
    return make_response('',200)
  return make_response('',401)

@app.route('/<user>/<pubid>',methods=['POST'])
def addref(user,pubid):
  if db.session.query(db.exists().where(Publications.id == pubid)).scalar():
    f = request.files['file']
    if f is None or f.filename is '':
      return make_response('',401)
    if os.path.exists(os.path.join(user,pubid,f.filename)):
      return make_response('',401)
    if not os.path.isdir(os.path.join(user,pubid)):
      os.mkdir(os.path.join(user,pubid))
    path = os.path.join(user,pubid,f.filename)
    db.session.add(References(
      id_pub=pubid,
      path=path,
      filename=f.filename))
    db.session.commit()
    f.save(path)
    registerChange(user)
    return make_response('', 200)
  return make_response('',401)


@app.route('/upload',methods=['POST'])
def upload():
  f = request.files['file']
  t = request.args.get('token')
  user = request.args.get('user')
  author = request.args.get('author')
  title = request.args.get('title')
  year = request.args.get('year')
  if f is "":
    return ('<h1>CDN</h1> No file provided', 400)
  if t is None:
    return ('<h1>CDN</h1> No token provided', 401) 
  if author is "":
    return ('<h1>CDN</h1> No author provided', 401) 
  if title is "":
    return ('<h1>CDN</h1> No title provided', 401) 
  if year is "":
    return ('<h1>CDN</h1> No year provided', 401) 
  if not valid(t):
    return ('<h1>CDN</h1> Invalid token', 401)
  if db.session.query(db.exists().where(Publications.title == title)).scalar():
    return make_response('',401)
  if not os.path.isdir(user):
    os.mkdir(user)
    db.session.add(Changes(
      user=user,
      changeid=hex(random.getrandbits(128))[2:-1]))
    db.session.commit()
  path = os.path.join(user,f.filename)
  f.save(path)
  f.close()
  db.session.add(Publications(
    user=user,
    author=author,
    title=title,
    year=year,
    publication=path,
    filename=f.filename))
  db.session.commit()
  registerChange(user)
  return make_response('', 200)


def valid(token):
  try:
    decode(token, JWT_SECRET)
  except InvalidTokenError as e:
    app.logger.error(str(e))
    return False
  return True

@app.route('/<user>/<file>',methods=['GET'])
def download(user,file):
  if not os.path.exists(user+'/'+file):
    return '<h1>CDN</h1> Missing file', 404
  token = request.headers.get('token') or request.args.get('token')
  if token is None:
    return '<h1>CDN</h1> No token', 401
  if not valid(token):
    return '<h1>CDN</h1> Invalid token', 401
  payload = decode(token, JWT_SECRET)
  if payload.get('file', file) != file and payload.get('user', user) != user:
    return '<h1>CDN</h1> Incorrect token payload', 401
  return send_file(user+'/'+file)

@app.route('/<user>/<pubid>/<ref>',methods=['GET'])
def downloadref(user,pubid,ref):
  if not os.path.exists(user+'/'+pubid+'/'+ref):
    return '<h1>CDN</h1> Missing file', 404
  token = request.headers.get('token') or request.args.get('token')
  if token is None:
    return '<h1>CDN</h1> No token', 401
  if not valid(token):
    return '<h1>CDN</h1> Invalid token', 401
  payload = decode(token, JWT_SECRET)
  if payload.get('file', ref) != ref and payload.get('user', user) != user:
    return '<h1>CDN</h1> Incorrect token payload', 401
  return send_file(user+'/'+pubid+'/'+ref)
