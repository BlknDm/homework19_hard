import hashlib
from datetime import datetime, timedelta

import jwt

from dao.user import UserDAO
from constants import PWD_HASH_SALT, PWD_HASH_ITERATIONS


class UserService:
    def __init__(self, dao: UserDAO):
        self.dao = dao

    def get_one(self, uid):
        return self.dao.get_one(uid)

    def get_all(self):
        return self.dao.get_all()

    def create(self, user_data):
        user_data["password"] = self.get_hash(user_data["password"])
        return self.dao.create(user_data)

    def update(self, user_data):
        user_data["password"] = self.get_hash(user_data["password"])
        return self.dao.create(user_data)

    def delete(self, uid):
        self.dao.delete(uid)

    def get_hash(self, password):
        return hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),  # Convert the password to bytes
            PWD_HASH_SALT,
            PWD_HASH_ITERATIONS
        ).decode("utf-8", "ignore")

    def get_access_token(self, data):
        min10 = datetime.utcnow() + timedelta(days=10)
        data['exp'] = int(min10.timestamp())
        access_token = jwt.encode(data, PWD_HASH_SALT)

        days130 = datetime.utcnow() + timedelta(days=130)
        data['exp'] = int(days130.timestamp())
        refresh_token = jwt.encode(data, PWD_HASH_SALT)

        return {'access_token': access_token, 'refresh_token': refresh_token}

    def auth_user(self, username, password):
        user = self.dao.get_user_by_username(username)
        if not user:
            return None

        hash_password = self.get_hash(password)
        if hash_password != user.password:
            return None

        data = {
            'username': user.username,
            'role': user.role
        }

        return self.get_access_token(data)

    def check_refresh_token(self, refresh_token):
        try:
            data = jwt.decode(jwt=refresh_token, key=PWD_HASH_SALT, algorithms='HS256')
        except Exception as e:
            return None

        return self.get_access_token(data)
