#!/usr/bin/env python3

import json
from datetime import datetime
from os.path import dirname, abspath, join
cwd = abspath(dirname(__file__))

from flask import *
from flask.ext.oauthlib.client import OAuth
from flask.ext.sqlalchemy import SQLAlchemy
import flask.ext.login as fl

from sqlalchemy.exc import IntegrityError


app = Flask(__name__)
app.debug = True
app.config['SQLALCHEMY_DATABASE_URI'] = join('sqlite:///', cwd, 'circles.db')
oauth = OAuth(app)
db = SQLAlchemy(app)
login_manager = fl.LoginManager()
login_manager.init_app(app)

import string
from random import SystemRandom
secure_random = SystemRandom()
key_chars = string.ascii_letters + string.digits
def key_gen(n):
    return ''.join(secure_random.choice(key_chars) for i in range(n))


# load stored configuration

try:
    # get a stored secret key
    with open(join(cwd, 'secret_key.json'), 'r') as f:
        app.secret_key = json.load(f)['secret_key']
except:
    app.secret_key = key_gen(64)
    with open(join(cwd, 'secret_key.json'), 'w') as f:
        json.dump({'secret_key' : app.secret_key}, f)

with open(join(cwd, 'client_secrets.json'), 'r') as f:
    client_secrets = json.load(f)['web']
    app.config['GOOGLE_ID'] = client_secrets['client_id']
    app.config['GOOGLE_SECRET'] = client_secrets['client_secret']

# google auth info

google = oauth.remote_app(
    'google',
    consumer_key=app.config.get('GOOGLE_ID'),
    consumer_secret=app.config.get('GOOGLE_SECRET'),
    request_token_params={
        'scope': 'https://www.googleapis.com/auth/userinfo.email'
    },
    base_url='https://www.googleapis.com/oauth2/v1/',
    request_token_url=None,
    access_token_method='POST',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
)

# models

class User(db.Model, fl.UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    google_id = db.Column(db.String(100), unique = True)
    name = db.Column(db.String(120), unique=True)

    def __init__(self, google_id, email, name):
        self.google_id = google_id 
        self.email = email
        self.name = name

    def __repr__(self):
        return '<User {}>'.format(self.name)


class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True)

    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return '<Category {}>'.format(self.name)


class Circle(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    topic = db.Column(db.String(200), unique=True)

    founder_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    founder = db.relationship("User")

    def __init__(self, topic, founder_id):
        self.topic = topic
        self.founder_id = founder_id

    def __repr__(self):
        return '<Circle {}>'.format(self.topic)


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    content = db.Column(db.Text)

    deletor_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    deletor = db.relationship('User', foreign_keys=[deletor_id])
    deletion_time = db.Column(db.DateTime)
    deleted = db.Column(db.Boolean)

    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    author = db.relationship('User', foreign_keys=[author_id])

    last_editor_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    last_editor = db.relationship('User', foreign_keys=[last_editor_id])
    edited = db.Column(db.Boolean)

    circle_id = db.Column(db.Integer, db.ForeignKey('circle.id'))
    circle = db.relationship('Circle')

    time = db.Column(db.DateTime) 
    last_rev_time = db.Column(db.DateTime) 

    def __init__(self, content, author_id, circle_id):
        self.content = content
        self.deleted = False
        self.author_id = author_id
        self.last_editor_id = author_id
        self.edited = False
        self.circle_id = circle_id
        self.time = datetime.utcnow()
        self.last_rev_time = datetime.utcnow()


class PostHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    post_id = db.Column(db.Integer, db.ForeignKey('post.id'))
    post = db.relationship('Post')

    content = db.Column(db.Text)

    editor_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    editor = db.relationship('User')

    time = db.Column(db.DateTime) 

    def __init__(self, post_id, content, editor_id, time):
        self.post_id = post_id
        self.content = content
        self.editor_id = editor_id
        self.time = time


# login callbacks

@login_manager.user_loader
def load_user(userid):
    return User.query.get(userid)


# controllers

login_manager.login_view = 'login'
@app.route('/login')
def login():
    get_flashed_messages()
    return google.authorize(callback=url_for('authorized', _external=True),
        state=request.args.get('next') or request.referrer or None)

@google.tokengetter
def get_google_oauth_token():
    return session.get('google_token')

@app.route('/logout')
def logout():
    session.pop('google_token', None)
    fl.logout_user()
    return redirect(url_for('index'))

@app.route('/login/authorized')
@google.authorized_handler
def authorized(resp):
    if resp is None:
        return 'Access denied: reason=%s error=%s' % (
            request.args['error_reason'],
            request.args['error_description']
        )
    session['google_token'] = (resp['access_token'], '')
    guser = google.get('userinfo')
    user = User.query.filter_by(google_id=guser.data['id']).first()

    if user:
        # user exists
        fl.login_user(user)

    else:
        # is user on the allowed list?
        allowed = json.load(open('allowed.json', 'r'))['allowed']
        if guser.data['email'] in allowed:
            # create, commit, and login new user
            gid = guser.data['id']
            email = guser.data['email']
            name = guser.data['name']
            user = User(gid, email, name)
            db.session.add(user)
            db.session.commit()
            fl.login_user(user)
        else:
            return "unauthorized"
            
    if request.args.get('state'):
        return redirect(request.args.get('state'))
    else:
        return redirect(url_for('index'))

# logic

@app.route('/', methods=['POST', 'GET'])
def index():
    if not fl.current_user.is_authenticated():
        return render_template('splash.html')

    if request.method == 'POST':
        topic = request.form.get('topic')
        if topic:
            try:
                circle = Circle(topic, fl.current_user.id)
                db.session.add(circle)
                db.session.commit()
            except (IntegrityError):
                db.session.rollback()
                flash('A circle with topic "{}" already exists.'.format(topic))

    context = dict()
    context['user'] = fl.current_user
    circles = Circle.query.order_by(Circle.topic.asc()).all()
    counts = [Post.query.filter_by(circle_id=circle.id, deleted=False).count()
            for circle in circles]
    context['circles_and_counts'] = zip(circles, counts)

    return render_template('index.html', **context)

@app.route('/circle/<int:circle_id>', methods=['POST', 'GET'])
@fl.login_required
def circle(circle_id):

    if request.method == 'POST':
        content = request.form.get('input-content')
        if content:
            post = Post(content, fl.current_user.id, circle_id)
            db.session.add(post)
            db.session.commit()

    posts = Post.query.filter_by(circle_id=circle_id)
    if not request.args.get('all') == '1':
        posts = posts.filter_by(deleted=False)

    context = dict()
    context['user'] = fl.current_user
    context['circle'] = Circle.query.get(circle_id)
    context['posts'] = posts.order_by(Post.time.asc()).all()

    return render_template('circle.html', **context)

@app.route('/circle/<int:circle_id>/post/<int:post_id>/history')
@fl.login_required
def history(circle_id, post_id):
    context = dict()
    context['user'] = fl.current_user
    context['circle'] = Circle.query.get(circle_id)
    context['post'] = Post.query.get(post_id)
    history = PostHistory.query.filter_by(post_id=post_id)
    context['history'] = history.order_by(PostHistory.time.desc()).all()

    return render_template('history.html', **context)

@app.route('/circle/<int:circle_id>/post/<int:post_id>/edit',
        methods=['POST', 'GET'])
@fl.login_required
def edit(circle_id, post_id):
    post = Post.query.get(post_id)

    if request.method == 'POST':
        new_content = request.form.get('input-content')
        if new_content:
            history = PostHistory(post_id, post.content, post.last_editor_id,
                    post.last_rev_time)
            db.session.add(history)

            post.last_editor_id = fl.current_user.id
            post.edited = True
            post.last_rev_time = datetime.utcnow()
            post.content = new_content
            db.session.commit()
        else:
            flash('Unable to save edit: no new content')

        return redirect(url_for('circle', circle_id=circle_id))


    context = dict()
    context['user'] = fl.current_user
    context['circle'] = Circle.query.get(circle_id)
    context['post'] = post

    return render_template('edit.html', **context)

@app.route('/circle/<int:circle_id>/post/<int:post_id>/delete')
@fl.login_required
def delete(circle_id, post_id):
    post = Post.query.get(post_id)
    if request.args.get('undelete') == '1':
        post.deleted = False
    else:
        post.deletor_id = fl.current_user.id
        post.deletion_time = datetime.utcnow()
        post.deleted = True
    db.session.commit()

    return redirect(request.referrer or url_for('circle', circle_id=circle_id))


if __name__ == '__main__':
    app.debug = True
    app.run()
