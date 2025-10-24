from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from os import environ

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = environ.get('DB_URL')
db = SQLAlchemy(app)

class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)

    def json(self):
        return {'id': self.id, 'username': self.username, 'email': self.email}
    

db.create_all()

@app.route("/test", methods=['GET'])
def test():
    return make_response(jsonify({'message': 'test route'}), 200)

# create a user
@app.route('/users', methods=['POST'])
def create_user():
    try:
        # 1. Get and validate JSON
        data = request.get_json()
        if not data:
            return make_response(jsonify({'message': 'no data provided'}), 400)

        # 2. Extract and validate required fields
        username = data.get('username')
        email = data.get('email')

        if not username or not email:
            return make_response(jsonify({'message': 'username and email are required'}), 400)

        if not isinstance(username, str) or not isinstance(email, str):
            return make_response(jsonify({'message': 'username and email must be strings'}), 400)

        username = username.strip()
        email = email.strip()

        if username == '' or email == '':
            return make_response(jsonify({'message': 'username and email cannot be empty'}), 400)

        # Optional: Basic email format check
        if '@' not in email or '.' not in email:
            return make_response(jsonify({'message': 'invalid email format'}), 400)

        # 3. Create user
        new_user = User(username=username, email=email)
        db.session.add(new_user)
        db.session.commit()

        return make_response(jsonify({ 'message': 'user created',
            'user': {'id': new_user.id, 'username': username, 'email': email}
        }), 201)

    except IntegrityError as e:
        db.session.rollback()
        # Likely duplicate username/email (if unique constraints exist)
        return make_response(jsonify({'message': 'user with this username or email already exists'}), 409)

    except SQLAlchemyError as e:
        db.session.rollback()
        return make_response(jsonify({'message': 'database error', 'error': str(e)}), 500)

    except Exception as e:
        db.session.rollback()
        return make_response(jsonify({'message': 'error creating user', 'error': str(e)}), 500)
    
# get all users    
@app.route('/users', methods=['GET'])
def get_users():
    try:
        # Optional: Pagination
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        per_page = min(per_page, 100)  # Limit max

        # Query with pagination
        paginated = User.query.paginate(
            page=page, per_page=per_page, error_out=False
        )

        users = paginated.items

        # Ensure every user has .json() method
        user_list = []
        for user in users:
            if not hasattr(user, 'json') or not callable(getattr(user, 'json')):
                return make_response(jsonify({'message': 'user object missing json() method'}), 500)
            user_list.append(user.json())

        # Build response with pagination metadata
        response = {
            'users': user_list,
            'total': paginated.total,
            'pages': paginated.pages,
            'current_page': page,
            'per_page': per_page
        }

        return make_response(jsonify(response), 200)

    except SQLAlchemyError as e:
        return make_response(jsonify({
            'message': 'database error',
            'error': str(e)
        }), 500)
    except Exception as e:
        return make_response(jsonify({
            'message': 'error retrieving users',
            'error': str(e)
        }), 500)

# get a user by id
@app.route('/users/<int:id>', methods=['GET'])
def get_user(id):
    try:
        user = User.query.get(id)  # Faster + cleaner
        if not user:
            return make_response(jsonify({'message': 'user not found'}), 404)

        return make_response(jsonify({'user': user.json()}), 200)

    except SQLAlchemyError as e:
        return make_response(jsonify({'message': 'database error'}), 500)
    except Exception as e:
        return make_response(jsonify({'message': 'error retrieving user'}), 500)
    
# update a user
@app.route('/users/<int:id>', methods=['PUT'])
def update_user(id):
    try:
        user = User.query.filter_by(id=id).first()
        if not user:
            return make_response(jsonify({'message': 'user not found'}), 404)

        data = request.get_json()
        if not data:
            return make_response(jsonify({'message': 'no data provided'}), 400)

        updated = False

        # Safely check and update fields
        if 'username' in data and data['username'] not in (None, ''):
            user.username = data['username']
            updated = True

        if 'email' in data and data['email'] not in (None, ''):
            user.email = data['email']
            updated = True

        if not updated:
            return make_response(jsonify({'message': 'no valid fields to update'}), 400)

        db.session.commit()
        return make_response(jsonify({'message': 'user updated'}), 200)

    except SQLAlchemyError as e:
        db.session.rollback()
        return make_response(jsonify({'message': 'database error', 'error': str(e)}), 500)
    except Exception as e:
        return make_response(jsonify({'message': 'error updating user', 'error': str(e)}), 500)


# delete a user
@app.route('/users/<int:id>', methods=['DELETE'])
def delete_user(id):  # Fixed: singular + correct name
    try:
        user = User.query.get(id)  # Faster: uses primary key directly
        if not user:
            return make_response(jsonify({'message': 'user not found'}), 404)

        db.session.delete(user)
        db.session.commit()

        # 204 No Content is REST standard for successful DELETE
        return make_response('', 204)

    except SQLAlchemyError as e:
        db.session.rollback()
        return make_response(jsonify({
            'message': 'database error',
            'error': str(e)
        }), 500)
    except Exception as e:
        db.session.rollback()
        return make_response(jsonify({
            'message': 'error deleting user',
            'error': str(e)
        }), 500)

