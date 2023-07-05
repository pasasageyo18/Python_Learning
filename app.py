from flask import Flask, request, jsonify
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from bson.objectid import ObjectId
import jwt

app = Flask(__name__)

secret_key = 'mamamia'

app.config['MONGO_URI'] = 'mongodb://localhost:27017/todo'

mongo = PyMongo(app)


@app.route("/api/auth/register", methods=['POST'])
def register():
    data = request.form.to_dict()
    if mongo.db['user'].find_one({'username': data['username']}):
        return jsonify({'message': 'Username already exist'})
    elif data['username'] and data['password']:
        user_id = mongo.db['user'].insert_one(
            {'username': data['username'], 'password': generate_password_hash(data['password'])})
        return jsonify({'message': 'User Registered Successfully!'})
    else:
        return jsonify({'message': 'data empty'})


@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.form.to_dict()
    user = mongo.db['user'].find_one({'username': data['username']})
    if not user or not check_password_hash(user['password'], data['password']):
        return jsonify({'message': 'Invalid Credential'}), 401

    payload = {'_id': str(user['_id']),
               'exp': datetime.utcnow() + timedelta(minutes=130)}
    access_token = jwt.encode(payload, secret_key, algorithm='HS256')
    return jsonify({'access_token': access_token})


@app.route('/api/todo', methods=['POST'])
def add_todo_item():
    try:
        data = request.form.to_dict()
        data_token = jwt.decode(data['token'], secret_key, algorithms=[
                                'HS256'], verify=True)
        user_id = data_token['_id']
        todo_id = mongo.db['todos'].insert_one(
            {'title': data['title'], 'completed': '0', 'user_id': user_id})
        return jsonify({'message': 'Todo item added successfully!', 'id': str(todo_id.inserted_id)})
    except jwt.ExpiredSignatureError:
        # Token telah kedaluwarsa
        return jsonify({'message': 'Expired token!'})
    except jwt.InvalidTokenError:
        # Token tidak valid
        return jsonify({'message': 'Invalid token!'})


@app.route('/api/todo/listall', methods=['POST'])
def get_todo_list():
    try:
        data = request.form.to_dict()
        data_token = jwt.decode(data['token'], secret_key, algorithms=[
                                'HS256'], verify=True)
        user_id = data_token['_id']
        todos = mongo.db['todos'].find({'user_id': user_id})
        result = []
        for todo in todos:
            result.append({
                'id': str(todo['_id']),
                'title': todo['title'],
                'completed': todo['completed']
            })

        return jsonify({'message': 'ok', 'data': result})
    except jwt.ExpiredSignatureError:
        # Token telah kedaluwarsa
        return jsonify({'message': 'Expired token!'})
    except jwt.InvalidTokenError:
        # Token tidak valid
        return jsonify({'message': 'Invalid token!'})


@app.route('/api/todo/status', methods=['POST'])
def update_todo_item():
    try:
        data = request.form.to_dict()
        data_token = jwt.decode(data['token'], secret_key, algorithms=[
                                'HS256'], verify=True)
        user_id = data_token['_id']
        todos = mongo.db['todos'].find_one(
            {'_id': ObjectId(data['todo_id']), 'user_id': user_id}), 404
        updated_data = {
            'completed': data['completed']
        }
        mongo.db['todos'].update_one(
            {'_id': ObjectId(data['todo_id'])}, {'$set': updated_data})
        return jsonify({'message': 'Todo item updated successfully!'})
    except jwt.ExpiredSignatureError:
        # Token telah kedaluwarsa
        return jsonify({'message': 'Expired token!'})
    except jwt.InvalidTokenError:
        # Token tidak valid
        return jsonify({'message': 'Invalid token!'})


@app.route('/api/todo/delete', methods=['POST'])
def delete_todo_item():
    try:
        data = request.form.to_dict()
        data_token = jwt.decode(data['token'], secret_key, algorithms=[
                                'HS256'], verify=True)
        user_id = data_token['_id']
        todo = mongo.db['todos'].find_one(
            {'_id': ObjectId(data['todo_id']), 'user_id': user_id})
        if not todo:
            return jsonify({'message': 'Todo item not found!'}), 404

        mongo.db['todos'].delete_one({'_id': ObjectId(data['todo_id'])})
        return jsonify({'message': 'Todo item deleted successfully!'})

    except jwt.ExpiredSignatureError:
        # Token telah kedaluwarsa
        return jsonify({'message': 'Expired token!'})
    except jwt.InvalidTokenError:
        # Token tidak valid
        return jsonify({'message': 'Invalid token!'})


if __name__ == '__main__':
    app.run(port=5000, debug=True)
