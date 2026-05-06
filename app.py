import requests
from flask import Flask, request, jsonify
from flasgger import Swagger
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_socketio import SocketIO, emit
from datetime import date, datetime, timedelta, timezone
import jwt
from functools import wraps

app = Flask(__name__)
swagger_config = {
    "headers": [],
    "specs": [
        {
            "endpoint": 'apispec_1',
            "route": '/apispec_1.json',
            "rule_filter": lambda rule: True,
            "model_filter": lambda rule: True,
        }
    ],
    "static_url_path": "/flasgger_static",
    "swagger_ui": True,
    "specs_route": "/apidocs/"
}

template = {
    "swagger": "2.0",
    "info": {
        "title": "PPE-Safence API",
        "description": "실시간 데이터 및 스트리밍 연동 문서",
        "version": "1.0.1"
    },
    "securityDefinitions": {
        "BearerAuth": {
            "type": "apiKey",
            "name": "Authorization",
            "in": "header",
            "description": "JWT 토큰을 입력하세요. (형식: Bearer {token})"
        }
    },
    "security": [
        {
            "BearerAuth": []
        }
    ]
}
swagger = Swagger(app, config=swagger_config, template=template)

app.config['SECRET_KEY'] = 'capston'
app.config['JSON_AS_ASCII'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:capston@43.200.27.117/capstone_db'
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

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    login_id = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    name = db.Column(db.String(100))
    role = db.Column(db.String(50))
    zone = db.Column(db.String(50))

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({'message': '권한이 없습니다 (헤더 없음)'}), 401
            
        try:
            token = auth_header.replace('Bearer ', '').strip()
            print(f"--- 해독 시도 토큰: {token[:15]}... ---")
            

            jwt.decode(token, 'capston', algorithms=["HS256"])
            
        except Exception as e:
            print(f"!!! 해독 실패 원인: {str(e)} !!!")
            return jsonify({'message': f'유효하지 않습니다 ({str(e)})'}), 401
            
        return f(*args, **kwargs)
    return decorated

@app.route('/api/login', methods=['POST'])
def login():
    auth = request.json
    input_id = auth.get('login_id')
    input_pw = auth.get('password')

    user = User.query.filter_by(login_id=input_id).first()

    if user and user.password == input_pw:
        if user.role == '작업자':
            return jsonify({'status': 'fail', 'message': '작업자 계정은 로그인이 제한됩니다.'}), 403
        now = datetime.now(timezone.utc) 
        token = jwt.encode({
            'user': user.login_id,
            'role': user.role,  
            'zone': user.zone,  
            'iat': now,
            'exp': now + timedelta(hours=24) 
        }, 'capston', algorithm="HS256") 
        
        return jsonify({'status': 'success', 'token': token}), 200
    
    return jsonify({'status': 'fail', 'message': '아이디 또는 비밀번호가 틀렸습니다.'}), 401

@app.route('/api/alarms', methods=['GET'])
@token_required  
def get_alarms(current_user):
    user_role = current_user.get('role')
    user_zone = current_user.get('zone')

    if user_role == '최고 관리자':
        alarms = Violation.query.all()
    else:
        alarms = Violation.query.filter_by(zone=user_zone).all()

    output = []
    for alarm in alarms:
        output.append({
            "Id": alarm.id,
            "Uid": alarm.uid,
            "Type": alarm.type,
            "Time": alarm.time.strftime('%Y-%m-%d %H:%M:%S'),
            "Zone": alarm.zone,
            "Cam": alarm.cam,
            "Status": alarm.status,
            "Image": alarm.image_url
        })

    return jsonify(output), 200

@app.route('/api/stream-urls', methods=['GET'])
@token_required
def stream_urls():
    """
    실시간 카메라 스트리밍 URL 조회 API
    ---
    tags:
      - Camera
    security:      
      - BearerAuth: []      
    responses:
      200:
        description: 카메라 목록 및 접속 URL 반환 성공
      503:
        description: 현장 Jetson 장비 오프라인 상태
    """
    try:
        res = requests.get('http://localhost:5001/cameras', timeout=3)
        cameras = res.json().get('cameras', [])
        
        return {
            'status': 'success',
            'cameras': [
                {
                    'name': cam,
                    'url': f'http://43.200.27.117:5001/stream/{cam}'
                }
                for cam in cameras
            ]
        }, 200
    except Exception as e:
        return {
            'status': 'jetson_offline',
            'cameras': [],
            'message': '현장 Jetson 디바이스와 연결할 수 없습니다.'
        }, 503

@app.route('/api/stats', methods=['GET'])
@token_required
def get_starts():
    """
    실시간 통계 데이터 조회 API
    ---
    tags:
      - Statistics
    security:
      - BearerAuth: []
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
              properties:
                today:
                  type: integer
                total:
                  type: integer
                update_time:
                  type: string
    """
    try:
        
        from datetime import date
        today_date = date.today()

        
        try:
            total_count = Violation.query.count()
        except:
            total_count = 0

        
        try:
            
            today_count = Violation.query.filter(
                db.func.date(Violation.detected_at) == today_date
            ).count()
        except:
            today_count = 0

        
        return jsonify({
            "status": "success",
            "data": {
                "total": total_count,
                "today": today_count,
                "update_time": today_date.strftime('%Y-%m-%d')
            }
        }), 200

    except Exception as e:
        
        return jsonify({
            "status": "error", 
            "message": f"DB 처리 중 에러 발생: {str(e)}"
        }), 500

if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0', port=5000, allow_unsafe_werkzeug=True)
