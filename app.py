from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
import jwt
import bcrypt
import datetime
from markupsafe import escape

app = Flask(__name__)
app.config['SECRET_KEY'] = "my-super-secret-key-change-me-in-production"
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///app.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# 用户表
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.LargeBinary, nullable=False)

# JWT鉴权装饰器，增加wraps修复名字冲突
from functools import wraps
def token_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        token = None
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]
        if not token:
            return jsonify({"message":"Token missing"}),401
        try:
            payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.filter_by(id=payload["user_id"]).first()
        except Exception:
            return jsonify({"message":"Invalid token"}),401
        return func(current_user, *args, **kwargs)
    return wrapper

# 接口1 登录 POST /auth/login
@app.route("/auth/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username")
    password_raw = data.get("password")
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"msg":"wrong username or password"}),401
    if bcrypt.checkpw(password_raw.encode("utf-8"), user.password_hash):
        token = jwt.encode({
            "user_id": user.id,
            "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=2)
        }, app.config['SECRET_KEY'], algorithm="HS256")
        return jsonify({"access_token": token})
    return jsonify({"msg":"wrong username or password"}),401

# 接口2 受保护数据接口 GET /api/data
@app.route("/api/data", methods=["GET"])
@token_required
def get_data(current_user):
    resp_data = {
        "user": escape(current_user.username),
        "posts": [
            {"id":1,"content":escape("hello post 1")},
            {"id":2,"content":escape("test post 2")}
        ]
    }
    return jsonify(resp_data)

# 接口3 自定义接口 GET /api/userinfo
@app.route("/api/userinfo", methods=["GET"])
@token_required
def user_info(current_user):
    return jsonify({"uid": current_user.id, "username": escape(current_user.username)})

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        # 初始化测试账号 admin / Admin123!
        exist_user = User.query.filter_by(username="admin").first()
        if not exist_user:
            hash_pw = bcrypt.hashpw(b"Admin123!", bcrypt.gensalt())
            new_user = User(username="admin", password_hash=hash_pw)
            db.session.add(new_user)
            db.session.commit()
    app.run(debug=False)


