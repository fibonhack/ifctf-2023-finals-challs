import mysql.connector
import utils
import hashlib
import os


class DBException(Exception):
    pass


class DB:
    hostname = os.environ.get('DBHOST', '127.0.0.1')
    dbname = os.environ.get('MYSQL_DATABASE', 'just_l33t_db')
    username = 'root'
    password = os.environ.get('MYSQL_ROOT_PASSWORD', 'password')

    def __init__(self):
        data = {
            "user": DB.username,
            "password": DB.password,
            "host": DB.hostname,
            "database": DB.dbname
        }

        try:
            self.connection = mysql.connector.connect(**data)
        except mysql.connector.Error as err:
            raise DBException("Error on database connection")

    def __del__(self):
        self.connection.close()

    def get_cursor(self):
        return self.connection.cursor(dictionary=True, prepared=True)

    def commit(self):
        try:
            return self.connection.commit()
        except mysql.connector.Error as err:
            raise DBException("Error on commit")

    def compute_hash(self, password, salt):
        h = hashlib.sha256()
        h.update(password.encode())
        h.update(salt.encode())
        return h.hexdigest()


    def register(self, username, password):
        cursor = self.get_cursor()

        try:
            cursor.execute(
                "SELECT id FROM user WHERE username = %s", (username,))
        except mysql.connector.Error as err:
            cursor.close()
            raise DBException("Error in select in register")

        users = cursor.fetchall()
        if len(users) == 1:
            cursor.close()
            return False

        salt = utils.random_string(10)
        password_hash = self.compute_hash(password, salt)

        try:
            cursor.execute("""
                INSERT INTO user(id, username, password_hash, salt, is_admin)
                VALUES (DEFAULT, %s, %s, %s, FALSE); 
                """, (username, password_hash, salt))

            self.commit()
            cursor.close()

            return True
        except mysql.connector.Error as err:
            raise DBException("Error in insert in register")

    def login(self, username, password):
        cursor = self.get_cursor()

        try:
            cursor.execute(
                "SELECT id, username, password_hash, salt, is_admin FROM user WHERE username = %s;", (username,))
        except mysql.connector.Error as err:
            raise DBException("Error in select in login")

        users = cursor.fetchall()
        cursor.close()

        if len(users) == 0:
            return None

        user = users[0]

        if self.compute_hash(password, user['salt']) != user['password_hash']:
            return None

        return User(user)

    def get_user_from_id(self, user_id):
        cursor = self.get_cursor()

        try:
            cursor.execute(
                "SELECT id, username, password_hash, salt, is_admin FROM user WHERE id = %s;", (user_id,))
        except mysql.connector.Error as err:
            raise DBException("Error in select in get_user_from_id")

        users = cursor.fetchall()
        cursor.close()

        if len(users) == 0:
            return None

        return User(users[0])
    
    def get_items(self):
        cursor = self.get_cursor()

        try:
            cursor.execute(
                "SELECT id, name_en, name_to, price FROM item;")
        except mysql.connector.Error as err:
            raise DBException("Error in select in get_items")

        items = cursor.fetchall()
        cursor.close()

        return [Item(item) for item in items]

    def get_item(self, item_id):
        cursor = self.get_cursor()

        try:
            cursor.execute(
                "SELECT id, name_en, name_to, price FROM item WHERE id = %s;", (item_id,))
        except mysql.connector.Error as err:
            raise DBException("Error in select in get_item")

        items = cursor.fetchall()
        cursor.close()

        return Item(items[0])
    
    def get_orders_of_user(self, user_id):
        cursor = self.get_cursor()

        try:
            cursor.execute(
                "SELECT id, tip, user_id FROM `order` WHERE user_id = %s;", (user_id,))
        except mysql.connector.Error as err:
            raise DBException("Error in select in get_orders")

        orders = cursor.fetchall()

        for order in orders:
            try:
                cursor.execute("""SELECT item_id, i.name_en, i.name_to, i.price, quantity
                               FROM order_item INNER JOIN item i ON item_id = i.id 
                               WHERE order_id = %s;""", (order['id'],))
            except mysql.connector.Error as err:
                raise DBException("Error in select in get_orders")

            order['items'] = cursor.fetchall()

        cursor.close()

        return [Order(order) for order in orders]

    def add_order(self, user_id, tip, items):
        cursor = self.get_cursor()

        try:
            cursor.execute("""
                INSERT INTO `order`(id, tip, user_id)
                VALUES (DEFAULT, %s, %s); 
                """, (tip, user_id))

            order_id = cursor.lastrowid

            for item in items:
                cursor.execute("""
                    INSERT INTO order_item(order_id, item_id, quantity)
                    VALUES (%s, %s, %s); 
                    """, (order_id, item['id'], item['quantity']))
            
            self.commit()
            cursor.close()

            return True
        except mysql.connector.Error as err:
            raise DBException(str(err))
            raise DBException("Error in insert in add_order")

    def get_order(self, order_id):
        cursor = self.get_cursor()

        try:
            cursor.execute(
                "SELECT id, tip, user_id FROM `order` WHERE id = %s;", (order_id,))
        except mysql.connector.Error as err:
            raise DBException("Error in select in get_order")

        orders = cursor.fetchall()

        if len(orders) == 0:
            return None

        order = orders[0]

        try:
            cursor.execute("""SELECT item_id, i.name_en, i.name_to, i.price, quantity
                            FROM order_item INNER JOIN item i ON item_id = i.id 
                            WHERE order_id = %s;""", (order['id'],))
        except mysql.connector.Error as err:
            raise DBException("Error in select in get_order")

        order['items'] = cursor.fetchall()

        cursor.close()

        return Order(order)

    def save_cookies(self, user_id, cookies):
        cursor = self.get_cursor()

        token = utils.random_string(32)

        try:
            cursor.execute("""
                INSERT INTO cookie(id, cookies, user_id)
                VALUES (%s, %s, %s);
                """, (token, cookies, user_id))
            
            self.commit()
            cursor.close()

            return token
        except mysql.connector.Error as err:
            raise DBException("Error in insert in save_cookies")

    def get_cookies(self, token):
        cursor = self.get_cursor()
        cookies = []

        try:
            cursor.execute(
                "SELECT cookies FROM cookie WHERE id = %s;", (token,))

            cookies = cursor.fetchall()

            cursor.execute(
                "DELETE FROM cookie WHERE id = %s;", (token,))
        except mysql.connector.Error as err:
            raise DBException("Error in select in get_cookies")

        if len(cookies) == 0:
            return None

        self.commit()
        cursor.close()

        return cookies[0]['cookies']

class User:
    def __init__(self, user_dict):
        self.id = user_dict['id']
        self.username = user_dict['username']
        self.password_hash = user_dict['password_hash']
        self.salt = user_dict['salt']
        self.is_admin = user_dict['is_admin']

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return self.id


class Item:
    def __init__(self, item_dict):
        self.id = item_dict['id']
        self.name_en = item_dict['name_en']
        self.name_to = item_dict['name_to']
        self.price = item_dict['price']

    def to_dict(self):
        return {
            'id': self.id,
            'name_en': self.name_en,
            'name_to': self.name_to,
            'price': self.price
        }

class Order:
    def __init__(self, order_dict):
        self.id = order_dict['id']
        self.tip = order_dict['tip']
        self.user_id = order_dict['user_id']

        # Foreign
        self.items = order_dict['items'] if 'items' in order_dict else []

    def to_dict(self):
        return {
            'id': self.id,
            'tip': self.tip,
            'user_id': self.user_id,
            'items': self.items
        }

class OrderItem:
    def __init__(self, order_item_dict):
        self.order_id = order_item_dict['order_id']
        self.item_id = order_item_dict['item_id']
        self.quantity = order_item_dict['quantity']