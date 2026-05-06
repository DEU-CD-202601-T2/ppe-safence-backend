import requests
from flask import Flask, request, jsonify, g
from flasgger import Swagger
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_socketio import SocketIO, emit
from datetime import date, datetime, timedelta, timezone
import jwt
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash

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

# 깃허브 및 서버 업로드 시 주석 해제
# app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:capston@43.200.27.117/capstone_db'

# 로컬 환경에서 코드 수정 후 테스트 시 주석 해제 (교내 내부망 특정 포트 차단 issue)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:capston@127.0.0.1:3307/capstone_db'

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

            decoded = jwt.decode(token, 'capston', algorithms=["HS256"])
            g.current_user = decoded  # ← 추가: 요청 컨텍스트에 저장

        except Exception as e:
            print(f"!!! 해독 실패 원인: {str(e)} !!!")
            return jsonify({'message': f'유효하지 않습니다 ({str(e)})'}), 401

        return f(*args, **kwargs)
    return decorated

def role_required(*allowed_roles):
    """
    허용된 role을 가진 사용자만 통과시키는 데코레이터.
    반드시 @token_required 다음에 사용해야 한다.
    예시: @role_required('최고 관리자', '보안 팀장')
    """
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            user_role = g.current_user.get('role')
            if user_role not in allowed_roles:
                return jsonify({
                    'status': 'fail',
                    'message': f'이 작업을 수행할 권한이 없습니다. (필요 권한: {", ".join(allowed_roles)} / 현재: {user_role})'
                }), 403
            return f(*args, **kwargs)
        return decorated
    return decorator

@app.route('/api/register', methods=['POST'])
def register():
    """
    사용자 추가 API
    ---
    tags:
      - Auth
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - login_id
            - password
          properties:
            login_id:
              type: string
              example: a002
            password:
              type: string
              example: capston2
            name:
              type: string
              example: 홍길동
            role:
              type: string
              example: 관리자
              description: "최고 관리자 / 구역 매니저 / 보안 팀장 / 작업자 등"
            zone:
              type: string
              example: A구역
    responses:
      201:
        description: 사용자 등록 성공
      400:
        description: 필수 필드 누락
      409:
        description: 이미 존재하는 login_id
      500:
        description: DB 처리 중 에러
    """
    data = request.json or {}
    login_id = data.get('login_id')
    password = data.get('password')
    name = data.get('name')
    role = data.get('role')
    zone = data.get('zone')

    if not login_id or not password:
        return jsonify({
            'status': 'fail',
            'message': 'login_id와 password는 필수입니다.'
        }), 400

    if User.query.filter_by(login_id=login_id).first():
        return jsonify({
            'status': 'fail',
            'message': '이미 존재하는 아이디입니다.'
        }), 409

    hashed_pw = generate_password_hash(password)

    new_user = User(
        login_id=login_id,
        password=hashed_pw,
        name=name,
        role=role,
        zone=zone
    )

    try:
        db.session.add(new_user)
        db.session.commit()
        return jsonify({
            'status': 'success',
            'message': '사용자가 등록되었습니다.',
            'user_id': new_user.id
        }), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'status': 'error',
            'message': f'등록 중 오류 발생: {str(e)}'
        }), 500

@app.route('/api/login', methods=['POST'])
def login():
    """
        로그인 및 JWT 토큰 발급 API
        ---
        tags:
          - Auth
        parameters:
          - in: body
            name: body
            required: true
            schema:
              type: object
              required:
                - login_id
                - password
              properties:
                login_id:
                  type: string
                  example: a001
                password:
                  type: string
                  example: capston1
        responses:
          200:
            description: 로그인 성공, JWT 토큰 반환
            schema:
              properties:
                status:
                  type: string
                  example: success
                token:
                  type: string
          401:
            description: 아이디 또는 비밀번호 불일치
          403:
            description: 작업자 계정은 로그인 제한
        """
    auth = request.json
    input_id = auth.get('login_id')
    input_pw = auth.get('password')

    user = User.query.filter_by(login_id=input_id).first()

    if user and check_password_hash(user.password, input_pw):
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

@app.route('/api/users/<int:user_id>', methods=['PUT'])
@token_required
@role_required('최고 관리자', '보안 팀장')
def update_user(user_id):
    """
    사용자 정보 수정 API
    ---
    tags:
      - Auth
    security:
      - BearerAuth: []
    parameters:
      - in: path
        name: user_id
        type: integer
        required: true
        description: 수정할 사용자의 id (PK)
      - in: body
        name: body
        required: true
        schema:
          type: object
          properties:
            password:
              type: string
              example: newpassword1
              description: 새 비밀번호 (생략 시 기존 비밀번호 유지, 입력 시 자동으로 해시 처리)
            name:
              type: string
              example: 김도윤
            role:
              type: string
              example: 구역 매니저
              description: "최고 관리자 / 구역 매니저 / 보안 팀장 / 작업자 등"
            zone:
              type: string
              example: A구역
        description: |
          제공된 필드만 부분 수정됩니다.
          login_id와 id는 불변값으로 본 API에서 변경할 수 없습니다.
          (변경이 필요한 경우 사용자 삭제 후 재등록하세요.)
    responses:
      200:
        description: 수정 성공
      400:
        description: 수정할 필드가 제공되지 않음
      401:
        description: 토큰 없음 또는 유효하지 않음
      403:
        description: 권한 부족 (최고 관리자 또는 보안 팀장만 가능)
      404:
        description: 해당 사용자를 찾을 수 없음
      500:
        description: DB 처리 중 에러
    """
    user = User.query.get(user_id)
    if not user:
        return jsonify({
            'status': 'fail',
            'message': '해당 사용자를 찾을 수 없습니다.'
        }), 404

    data = request.json or {}

    updatable_fields = ['name', 'role', 'zone']
    changed = []

    for field in updatable_fields:
        if field in data:
            setattr(user, field, data[field])
            changed.append(field)

    if 'password' in data and data['password']:
        user.password = generate_password_hash(data['password'])
        changed.append('password')

    if not changed:
        return jsonify({
            'status': 'fail',
            'message': '수정할 필드가 제공되지 않았습니다. (수정 가능: name, role, zone, password)'
        }), 400

    try:
        db.session.commit()
        return jsonify({
            'status': 'success',
            'message': '사용자 정보가 수정되었습니다.',
            'changed_fields': changed,
            'user': {
                'id': user.id,
                'login_id': user.login_id,
                'name': user.name,
                'role': user.role,
                'zone': user.zone
            }
        }), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'status': 'error',
            'message': f'수정 중 오류 발생: {str(e)}'
        }), 500

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@token_required
@role_required('최고 관리자', '보안 팀장')
def delete_user(user_id):
    """
    사용자 삭제 API
    ---
    tags:
      - Auth
    security:
      - BearerAuth: []
    parameters:
      - in: path
        name: user_id
        type: integer
        required: true
        description: 삭제할 사용자의 id (PK)
    responses:
      200:
        description: 삭제 성공
      401:
        description: 토큰 없음 또는 유효하지 않음
      404:
        description: 해당 사용자를 찾을 수 없음
      403:
        description: 권한 부족 (최고 관리자 또는 보안 팀장만 가능) 또는 자기 자신 삭제 시도
      500:
        description: DB 처리 중 에러 (외래키 제약 등)
    """
    user = User.query.get(user_id)
    if not user:
        return jsonify({
            'status': 'fail',
            'message': '해당 사용자를 찾을 수 없습니다.'
        }), 404

    # 자기 자신 삭제 방지
    if user.login_id == g.current_user.get('user'):
        return jsonify({
            'status': 'fail',
            'message': '자기 자신의 계정은 삭제할 수 없습니다.'
        }), 403

    deleted_info = {
        'id': user.id,
        'login_id': user.login_id,
        'name': user.name
    }

    try:
        db.session.delete(user)
        db.session.commit()
        return jsonify({
            'status': 'success',
            'message': '사용자가 삭제되었습니다.',
            'deleted_user': deleted_info
        }), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'status': 'error',
            'message': f'삭제 중 오류 발생: {str(e)}'
        }), 500

@app.route('/api/alarms', methods=['GET'])
@token_required  
def get_alarms(current_user):
    """
        위반 알림 목록 조회 API
        ---
        tags:
          - Alarms
        security:
          - BearerAuth: []
        responses:
          200:
            description: 위반 알림 목록 반환 (최고 관리자는 전체, 그 외는 자신의 zone만)
            schema:
              type: array
              items:
                type: object
                properties:
                  Id:
                    type: integer
                  Type:
                    type: string
                  Time:
                    type: string
                  Zone:
                    type: string
                  Status:
                    type: string
                  Image:
                    type: string
          401:
            description: 토큰 없음 또는 유효하지 않음
        """
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

# 교내 내부망 5000 포트 차단으로 인한 포트 변경 (5000 -> 5002)
if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0', port=5002, allow_unsafe_werkzeug=True)
