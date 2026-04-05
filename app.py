import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv  # 비밀번호를 몰래 가져오는 도구

load_dotenv()

app = Flask(__name__)

db_password = os.getenv("DB_PASSWORD")

DB_URL = f'mysql+pymysql://sim:{db_password}@13.125.19.182:3306/capstone_db'

app.config['SQLALCHEMY_DATABASE_URI'] = DB_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    login_id = db.Column(db.String(50), unique=True, nullable=False)
    name = db.Column(db.String(100))

@app.route('/')
def index():
    try:
        user = User.query.first()
        if user:
            return f"<h1>연결 성공!</h1><p>DB 관리자: <b>{user.name}</b>님 반갑습니다.</p>"
        else:
            return "<h1>연결 성공!</h1><p>데이터가 없습니다.</p>"
    except Exception as e:
        return f"<h1>연결 실패...</h1><p>에러: {str(e)}</p>"

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)