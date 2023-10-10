from flask import Flask, request, jsonify, redirect, make_response
from flask_login import LoginManager, login_user, current_user, login_required

from models import DB, DBException
import utils
import os
import json

app = Flask(__name__)
login_manager = LoginManager(app)


app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'secret')
EN_HOST = os.environ.get('EN_HOST', 'en.just_l33t.fibonhack.it')
TO_HOST = os.environ.get('TO_HOST', 'to.just_l33t.fibonhack.it')
ADMIN_HOST = os.environ.get('ADMIN_HOST', 'admin.just_l33t.fibonhack.it')


@login_manager.user_loader
def load_user(user_id):
    db = DB()
    current_user = db.get_user_from_id(user_id)
    return current_user


@app.route('/api/register', methods=['POST'])
def register_view():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({
            'error' : 'Invalid username or password'
        }), 400

    db = DB()

    if db.register(username, password):
        return jsonify({}), 201

    return jsonify({
        'error' : "User already exists"
    }), 400


@app.route('/api/login', methods=['POST'])
def login_view():
    data = request.json

    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({
            'error' : 'Invalid username or password'
        }), 400
    
    db = DB()

    user = db.login(username, password)

    if user:
        login_user(user)
        return jsonify({
            'id' : current_user.id,
            'username' : current_user.username,
            'is_admin' : current_user.is_admin,
        }), 200

    return jsonify({
        'error' : 'Invalid credentials'
    }), 400


@app.route('/api/user', methods=['GET'])
@login_required
def user_view():
    return jsonify({
        'id' : current_user.id,
        'username' : current_user.username,
        'is_admin' : current_user.is_admin,
    }), 200


@app.route('/api/items', methods=['GET'])
@login_required
def items_view():
    db = DB()

    items = db.get_items()

    return jsonify([item.to_dict() for item in items]), 200


@app.route('/api/order', methods=['GET', 'POST'])
@login_required
def order_view():
    if request.method == 'GET':
        db = DB()

        orders = db.get_orders_of_user(current_user.id)

        return jsonify([order.to_dict() for order in orders]), 200
    else:
        data = request.json
        items = data.get('items', None)
        tip = data.get('tip', None)

        if items is None:
            return jsonify({
                'error' : 'Invalid items'
            }), 400

        if tip:
            try:
                tip = float(tip)
                if tip < 0 or tip > 1:
                    raise ValueError
            except ValueError:
                return jsonify({
                    'error' : 'Invalid tip'
                }), 400

        if type(items) != list or len(items) == 0:
            return jsonify({
                'error' : 'Invalid items'
            }), 400

        if len(items) > 10:
            return jsonify({
                'error' : 'Too many items'
            }), 400

        for i in items:
            if type(i) != dict or 'id' not in i or 'quantity' not in i or type(i['id']) != int or type(i['quantity']) != int or i['quantity'] <= 0:
                return jsonify({
                    'error' : 'Invalid items'
                }), 400

        db = DB()

        try:
            db.add_order(current_user.id, tip, items)
        except DBException as e:
            return jsonify({
                'error' : str(e)
            }), 400

        return jsonify({}), 201


@app.route('/api/cookie_bridge', methods=['GET'])
def cookie_bridge():
    if 'token' in request.args:
        token = request.args.get('token')

        db = DB()

        try:
            cookies = db.get_cookies(token)
            user_cookies = json.loads(cookies)

            res = make_response(redirect('/'))
            for k, v in user_cookies.items():
                res.set_cookie(k, v)

            return res
        except DBException as e:
            pass
        except TypeError as e:
            pass

        return redirect('/')
    else:
        to = request.args.get('to', 'to')
        user_cookies = request.cookies.to_dict()
        user_cookies = {k:v for k, v in user_cookies.items() if k != "session"}
        user_cookies = json.dumps(user_cookies)

        db = DB()

        try:
            token = db.save_cookies(current_user.id, user_cookies)
        except Exception as e:
            if to == 'en':
                return redirect(f'http://{EN_HOST}/')
            return redirect(f'http://{TO_HOST}/')


        if to == 'en':
            return redirect(f'http://{EN_HOST}/api/cookie_bridge?token={token}')
        if to == 'admin':
            return redirect(f'http://{ADMIN_HOST}/api/cookie_bridge?token={token}')

        return redirect(f'http://{TO_HOST}/api/cookie_bridge?token={token}')


if __name__ == '__main__':
    app.run(debug=False, port=5000, host='0.0.0.0')