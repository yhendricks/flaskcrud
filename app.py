import os
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DB_URL', 'sqlite:///db.sqlite')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Models
user_group = db.Table('user_group',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('group_id', db.Integer, db.ForeignKey('group.id'))
)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    password_hash = db.Column(db.String(128))
    groups = db.relationship('Group', secondary=user_group, backref='users')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True)
    permissions = db.relationship('Permission', backref='group', lazy='dynamic')

class Permission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Decorator for permission checking
def permission_required(permission):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                flash('You must be logged in to view this page.', 'danger')
                return redirect(url_for('login'))
            
            for group in current_user.groups:
                for p in group.permissions:
                    if p.name == permission:
                        return f(*args, **kwargs)
            
            flash('You do not have the required permissions to view this page.', 'danger')
            return redirect(url_for('index'))
        return decorated_function
    return decorator

# Routes
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if User.query.filter_by(username=username).first():
            flash('User already exists.', 'danger')
            return redirect(url_for('register'))

        new_user = User(username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        flash('User created successfully. Please login.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()

        if not user or not user.check_password(password):
            flash('Invalid credentials.', 'danger')
            return redirect(url_for('login'))

        login_user(user)
        flash('Logged in successfully.', 'success')
        return redirect(url_for('profile'))
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('index'))

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html')

@app.route('/group', methods=['POST'])
@login_required
def create_group():
    data = request.get_json()
    name = data.get('name')

    if Group.query.filter_by(name=name).first():
        return jsonify({'message': 'Group already exists'}), 400

    new_group = Group(name=name)
    db.session.add(new_group)
    db.session.commit()

    return jsonify({'message': 'Group created successfully'}), 201

@app.route('/group/<group_name>/user/<username>', methods=['POST'])
@login_required
def add_user_to_group(group_name, username):
    group = Group.query.filter_by(name=group_name).first()
    user = User.query.filter_by(username=username).first()

    if not group or not user:
        return jsonify({'message': 'Group or user not found'}), 404

    user.groups.append(group)
    db.session.commit()

    return jsonify({'message': f'User {username} added to group {group_name}'}), 200

@app.route('/group/<group_name>/permission', methods=['POST'])
@login_required
def add_permission_to_group(group_name):
    data = request.get_json()
    permission_name = data.get('permission_name')
    group = Group.query.filter_by(name=group_name).first()

    if not group:
        return jsonify({'message': 'Group not found'}), 404

    if Permission.query.filter_by(name=permission_name, group_id=group.id).first():
        return jsonify({'message': 'Permission already exists for this group'}), 400

    new_permission = Permission(name=permission_name, group_id=group.id)
    db.session.add(new_permission)
    db.session.commit()

    return jsonify({'message': f'Permission {permission_name} added to group {group_name}'}), 200


@app.route('/protected')
@login_required
@permission_required('can_view_protected')
def protected():
    return render_template('protected.html')

@app.route('/')
def index():
    return render_template('index.html')

import click
from flask.cli import with_appcontext

@click.command(name='init-db')
@with_appcontext
def init_db():
    db.create_all()

app.cli.add_command(init_db)

if __name__ == '__main__':
    app.run(debug=True)
