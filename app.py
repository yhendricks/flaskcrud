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

group_permission = db.Table('group_permission',
    db.Column('group_id', db.Integer, db.ForeignKey('group.id')),
    db.Column('permission_id', db.Integer, db.ForeignKey('permission.id'))
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
    permissions = db.relationship('Permission', secondary=group_permission, backref='groups')

class Permission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Decorator for permission checking
def permission_required(permission_name):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                flash('You must be logged in to view this page.', 'danger')
                return redirect(url_for('login'))
            
            # Check if the user has the required permission through any of their groups
            has_permission = False
            for group in current_user.groups:
                for p in group.permissions:
                    if p.name == permission_name:
                        has_permission = True
                        break
                if has_permission:
                    break

            if has_permission:
                return f(*args, **kwargs)
            else:
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

@app.route('/manage-groups')
@login_required
def manage_groups():
    users = User.query.all()
    groups = Group.query.all()
    permissions = Permission.query.all()
    return render_template('manage_groups.html', users=users, groups=groups, permissions=permissions)

@app.route('/create-group', methods=['POST'])
@login_required
def create_group():
    name = request.form.get('name')

    if Group.query.filter_by(name=name).first():
        flash('Group already exists.', 'danger')
    else:
        new_group = Group(name=name)
        db.session.add(new_group)
        db.session.commit()
        flash('Group created successfully.', 'success')

    return redirect(url_for('manage_groups'))

@app.route('/create-permission', methods=['POST'])
@login_required
def create_permission():
    name = request.form.get('name')

    if Permission.query.filter_by(name=name).first():
        flash('Permission with this name already exists.', 'danger')
    else:
        new_permission = Permission(name=name)
        db.session.add(new_permission)
        db.session.commit()
        flash('Permission created successfully.', 'success')

    return redirect(url_for('manage_groups'))

@app.route('/add-user-to-group', methods=['POST'])
@login_required
def add_user_to_group():
    username = request.form.get('username')
    group_name = request.form.get('group_name')

    user = User.query.filter_by(username=username).first()
    group = Group.query.filter_by(name=group_name).first()

    if not user or not group:
        flash('User or group not found.', 'danger')
    elif group in user.groups:
        flash(f'User {username} is already in group {group_name}.', 'warning')
    else:
        user.groups.append(group)
        db.session.commit()
        flash(f'User {username} added to group {group_name}.', 'success')

    return redirect(url_for('manage_groups'))

@app.route('/add-permission-to-group', methods=['POST'])
@login_required
def add_permission_to_group():
    permission_name = request.form.get('permission_name')
    group_name = request.form.get('group_name')

    group = Group.query.filter_by(name=group_name).first()
    permission = Permission.query.filter_by(name=permission_name).first()

    if not group or not permission:
        flash('Group or permission not found.', 'danger')
    elif permission in group.permissions:
        flash(f'Permission {permission_name} is already in group {group_name}.', 'warning')
    else:
        group.permissions.append(permission)
        db.session.commit()
        flash(f'Permission {permission_name} added to group {group_name}.', 'success')

    return redirect(url_for('manage_groups'))


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
