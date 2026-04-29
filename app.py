from flask import Flask, request, jsonify
from flasgger import Swagger
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_socketio import SocketIO, emit
from datetime import date, datetime, timedelta
import jwt
from functools import wraps

app = Flask(__name__)
swagger = Swagger(app)
app.config['SECRET_KEY'] = 'capston'
app.config['JSON_AS_ASCII'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:capston@localhost/capstone_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

class Violation(db.Model):
    __tablename__ = 'violations'
    id = db.Column(db.Integer, primary_key=True)
    violation_type = db.Column(db.String(50), nullable=False)
    detected_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    area = db.Column(db.String(50))
    image_path = db.Column(db.String(255))
    is_checked = db.Column(db.Boolean, default=False)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': '권한이 없습니다'}), 401
        try:
            jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        except:
            return jsonify({'message': '유효하지 않습니다'}), 401
        return f(*args, **kwargs)
    return decorated

@app.route('/api/login', methods=['POST'])
def login():
    auth = request.json
    if auth.get('id') == 'sim' and auth.get('pw') == 'capston':
        token = jwt.encode({
            'user': auth.get('id'),
            'exp': datetime.utcnow() + timedelta(minutes=30)
        }, app.config['SECRET_KEY'], algorithm="HS256")
        return jsonify({'status': 'success', 'token': token}), 200
    return jsonify({'status': 'fail', 'message': '로그인 실패'}), 401

@app.route('/api/violations', methods=['GET'])
@token_required
def get_violations():
    try:
        violations = Violation.query.order_by(Violation.detected_at.desc()).all()
        data = []
        for v in violations:
            data.append({
                "id": v.id,
                "type": v.violation_type,
                "area": v.area,
                "time": v.detected_at.strftime('%Y-%m-%d %H:%M:%S'),
                "checked": v.is_checked
            })
        return jsonify({"status": "success", "data": data}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/violations', methods=['POST'])
def receive_violation():
    try:
        data = request.json
        new_violation = Violation(
            violation_type=data.get('type'),
            area=data.get('area'),
            image_path=data.get('image_path')
        )
        db.session.add(new_violation)
        db.session.commit()
        socketio.emit('new_violation', data)
        return jsonify({"status": "success"}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/stats', methods=['GET'])
@token_required
def get_stats(current_user):
    """
    실시간 통계 데이터 조회 API
    ---
    tags:
      - Statistics
    responses:
      200:
        description: 성공적으로 통계 데이터를 반환했습니다.
        schema:
          properties:
            status:
              type: string
              example: success
            data:
              type: object
              example: {"today": 0, "total": 1}
    """
    try:
        total_count = Violation.query.count()
        today = date.today()
        today_count = Violation.query.filter(db.func.date(Violation.detected_at) == today).count()
        return jsonify({
            "status": "success",
            "data": {
                "total": total_count,
                "today": today_count,
                "update_time": today.strftime('%Y-%m-%d')
            }
        }), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0', port=5000, allow_unsafe_werkzeug=True)
