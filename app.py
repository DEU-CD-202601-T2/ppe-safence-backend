import os
import time
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
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:capston@43.200.27.117/capstone_db'

# 로컬 환경에서 코드 수정 후 테스트 시 주석 해제 (교내 내부망 특정 포트 차단 issue)
# app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:capston@127.0.0.1:3307/capstone_db'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Jetson 보드 카메라 서버 주소 (default = AWS 외부 IP, 보드↔AWS SSH 리버스 터널 경유)
# 환경별 override:
#   - Tailscale 직결: export JETSON_BASE_URL=http://100.113.160.25:5001
#   - 같은 LAN:       export JETSON_BASE_URL=http://192.168.45.86:5001
JETSON_BASE_URL = os.environ.get('JETSON_BASE_URL', 'http://100.113.160.25:5001')

db = SQLAlchemy(app)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

class Alarm(db.Model):
    __tablename__ = 'alarms'
    id        = db.Column(db.String(100), primary_key=True)
    type      = db.Column(db.String(100))
    time      = db.Column(db.DateTime)
    area_id   = db.Column(db.Integer, db.ForeignKey('areas.area_id'), nullable=True)
    status    = db.Column(db.String(20), default='미해결')
    image_url = db.Column(db.Text)

    area = db.relationship('Area', backref='alarms', lazy='joined')

    def to_dict(self):
        return {
            'id':        self.id,
            'type':      self.type,
            'time':      self.time.strftime('%Y-%m-%d %H:%M:%S') if self.time else None,
            'area_id':   self.area_id,
            'area':      self.area.to_dict() if self.area else None,
            'status':    self.status,
            'image_url': self.image_url,
        }

class Violation(db.Model):
    __tablename__ = 'violations'
    id             = db.Column(db.Integer, primary_key=True)
    violation_type = db.Column(db.String(50), nullable=False)
    detected_at    = db.Column(db.DateTime, default=db.func.current_timestamp())
    area_id        = db.Column(db.Integer, db.ForeignKey('areas.area_id'), nullable=True)
    image_path     = db.Column(db.String(255))
    is_checked     = db.Column(db.Boolean, default=False)

    # Area 객체로 바로 접근하기 위한 관계 (lazy='joined' = SELECT 시 자동 JOIN)
    area = db.relationship('Area', backref='violations', lazy='joined')

    def to_dict(self):
        return {
            'id':             self.id,
            'violation_type': self.violation_type,
            'detected_at':    self.detected_at.strftime('%Y-%m-%d %H:%M:%S') if self.detected_at else None,
            'area_id':        self.area_id,
            'area':           self.area.to_dict() if self.area else None,
            'image_path':     self.image_path,
            'is_checked':     self.is_checked,
        }

user_areas = db.Table(
    'user_areas',
    db.Column('user_id', db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'),       primary_key=True),
    db.Column('area_id', db.Integer, db.ForeignKey('areas.area_id', ondelete='CASCADE'), primary_key=True),
    db.Column('created_at', db.DateTime, default=db.func.current_timestamp()),
)

class User(db.Model):
    __tablename__ = 'users'
    id       = db.Column(db.Integer, primary_key=True)
    login_id = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    name     = db.Column(db.String(100))
    role     = db.Column(db.String(50))

    # 다중 구역 N:M
    areas = db.relationship(
        'Area',
        secondary=user_areas,
        lazy='joined',
        backref=db.backref('users', lazy='dynamic')
    )

    def has_global_access(self) -> bool:
        """최고 관리자거나 area 미지정이면 전체 구역 접근 가능."""
        return self.role == '최고 관리자' or len(self.areas) == 0

    def to_dict(self):
        return {
            'id':            self.id,
            'login_id':      self.login_id,
            'name':          self.name,
            'role':          self.role,
            'area_ids':      [a.area_id for a in self.areas],
            'areas':         [a.to_dict() for a in self.areas],
            'global_access': self.has_global_access(),
        }

class Area(db.Model):
    __tablename__ = 'areas'
    area_id     = db.Column(db.Integer, primary_key=True)
    area_name   = db.Column(db.String(50),  unique=True, nullable=False)
    area_code   = db.Column(db.String(20),  unique=True)
    camera_key  = db.Column(db.String(100), unique=True)   # NULL 허용
    description = db.Column(db.String(255))
    risk_level  = db.Column(db.String(20),  default='normal')
    is_active   = db.Column(db.Boolean,     default=True)
    created_at  = db.Column(db.DateTime,    default=db.func.current_timestamp())
    updated_at  = db.Column(db.DateTime,    default=db.func.current_timestamp(),
                            onupdate=db.func.current_timestamp())

    def to_dict(self):
        return {
            'area_id':     self.area_id,
            'area_name':   self.area_name,
            'area_code':   self.area_code,
            'camera_key':  self.camera_key,
            'description': self.description,
            'risk_level':  self.risk_level,
            'is_active':   self.is_active,
        }

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
            area_ids:
              type: array
              items:
                type: integer
              example: [1, 2]
              description: |
                담당 구역 area_id 목록.
                빈 배열 또는 미지정 시 전체 구역 접근 권한.
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
    area_ids = data.get('area_ids') or []

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

    # area_ids 유효성 검증
    selected_areas = []
    if area_ids:
        selected_areas = Area.query.filter(Area.area_id.in_(area_ids)).all()
        if len(selected_areas) != len(set(area_ids)):
            return jsonify({'status': 'fail', 'message': '존재하지 않는 area_id가 포함되어 있습니다.'}), 400

    new_user = User(
        login_id=login_id,
        password=hashed_pw,
        name=name,
        role=role
    )
    new_user.areas = selected_areas

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
            'area_ids': [a.area_id for a in user.areas],
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
            area_ids:
              type: array
              items:
                type: integer
              example: [1, 2]
              description: |
                담당 구역 area_id 목록.
                빈 배열 또는 미지정 시 전체 구역 접근 권한.
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

    updatable_fields = ['name', 'role']
    changed = []

    for field in updatable_fields:
        if field in data:
            setattr(user, field, data[field])
            changed.append(field)

    if 'password' in data and data['password']:
        user.password = generate_password_hash(data['password'])
        changed.append('password')

    if 'area_ids' in data:
        area_ids = data['area_ids'] or []
        if area_ids:
            selected = Area.query.filter(Area.area_id.in_(area_ids)).all()
            if len(selected) != len(set(area_ids)):
                return jsonify({'status': 'fail', 'message': '존재하지 않는 area_id가 포함되어 있습니다.'}), 400
            user.areas = selected
        else:
            user.areas = []
        changed.append('area_ids')

    if not changed:
        return jsonify({
            'status': 'fail',
            'message': '수정할 필드가 제공되지 않았습니다. (수정 가능: name, role, password)'
        }), 400

    try:
        db.session.commit()
        return jsonify({
            'status': 'success',
            'message': '사용자 정보가 수정되었습니다.',
            'changed_fields': changed,
            'user': user.to_dict()
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
def get_alarms():
    """
    위반 알림 목록 조회 API
    ---
    tags:
      - Alarms
    security:
      - BearerAuth: []
    responses:
      200:
        description: 알림 목록 반환 (최고 관리자/area_ids 빈 배열은 전체, 그 외는 본인 area만)
      401:
        description: 토큰 없음 또는 유효하지 않음
    """
    user_role = g.current_user.get('role')
    user_area_ids = g.current_user.get('area_ids', [])

    q = Alarm.query

    # 전체 접근 조건: 최고 관리자 OR area_ids 비어있음
    if user_role != '최고 관리자' and user_area_ids:
        q = q.filter(Alarm.area_id.in_(user_area_ids))

    alarms = q.order_by(Alarm.time.desc()).all()
    return jsonify([a.to_dict() for a in alarms]), 200


@app.route('/api/stream-urls', methods=['GET'])
@token_required
def stream_urls():
    """
    실시간 카메라 스트리밍 URL + 구역 매핑 조회 API

    응답 구조:
    - cameras       : 보드에서 잡힌 활성 카메라 (각각에 매핑된 area 정보 포함)
    - offline_areas : DB에 등록되어 있지만 카메라가 현재 보드에 안 잡히는 구역
    - online_count / offline_count : UI에서 카운터로 사용
    ---
    tags:
      - Camera
    security:
      - BearerAuth: []
    responses:
      200:
        description: 카메라 목록 + 구역 매핑 + 오프라인 구역 반환 성공
      503:
        description: 현장 Jetson 디바이스 오프라인
    """
    # 활성 구역을 미리 dict로 (N+1 회피)
    active_areas = Area.query.filter_by(is_active=True).all()
    area_map = {a.camera_key: a for a in active_areas if a.camera_key}

    try:
        res = requests.get(f'{JETSON_BASE_URL}/cameras', timeout=3)
        res.raise_for_status()
        live_cams = res.json().get('cameras', [])  # [{"name":..., "key":...}, ...]
    except requests.exceptions.RequestException as e:
        return jsonify({
            'status': 'jetson_offline',
            'cameras': [],
            'offline_areas': [a.to_dict() for a in active_areas if a.camera_key],
            'online_count': 0,
            'offline_count': len([a for a in active_areas if a.camera_key]),
            'message': f'현장 Jetson 디바이스와 연결할 수 없습니다. ({type(e).__name__})'
        }), 503

    cameras_out = []
    for cam in live_cams:
        area = area_map.get(cam.get('key'))
        cameras_out.append({
            'name': cam.get('name'),
            'key': cam.get('key'),
            'url': f"{JETSON_BASE_URL}/stream/{cam.get('name')}",
            'area': area.to_dict() if area else None  # 미등록 카메라면 null
        })

    online_keys = {c['key'] for c in cameras_out if c['key']}
    offline_areas = [
        a.to_dict() for a in active_areas
        if a.camera_key and a.camera_key not in online_keys
    ]

    return jsonify({
        'status': 'success',
        'online_count': len(cameras_out),
        'offline_count': len(offline_areas),
        'cameras': cameras_out,
        'offline_areas': offline_areas,
    }), 200


@app.route('/api/areas', methods=['POST'])
@token_required
@role_required('최고 관리자', '보안 팀장', '구역 매니저')
def create_area():
    """
    구역 생성/재등록 API (블루투스 페어링 패턴)

    동일한 camera_key가 이미 등록되어 있으면 (활성/비활성 무관)
    그 행을 새 데이터로 갱신하고 is_active=true로 부활시킨다.
    그렇지 않으면 신규 INSERT.
    ---
    tags:
      - Area
    security:
      - BearerAuth: []
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - area_name
          properties:
            area_name:
              type: string
              example: B구역
            area_code:
              type: string
              example: ZONE_B
            camera_key:
              type: string
              example: USB_2304_4922_PORT_1-2.2
            description:
              type: string
            risk_level:
              type: string
              example: high
              description: low | normal | high
    responses:
      201: {description: 신규 생성}
      200: {description: 기존 비활성/활성 행이 재활성화 및 갱신됨}
      400: {description: 필수 필드 누락}
      409: {description: area_name이 다른 구역에서 사용 중}
    """
    data = request.json or {}
    if not data.get('area_name'):
        return jsonify({'status': 'fail', 'message': 'area_name은 필수입니다.'}), 400

    camera_key = data.get('camera_key')

    # ── ① camera_key 기준 기존 행 매칭 (블루투스 재페어링 패턴) ──
    existing = Area.query.filter_by(camera_key=camera_key).first() if camera_key else None

    if existing:
        # 다른 행에서 area_name이 이미 점유 중인지 검증 (자기 자신 제외)
        if data['area_name'] != existing.area_name:
            dup = Area.query.filter_by(area_name=data['area_name']).first()
            if dup and dup.area_id != existing.area_id:
                return jsonify({
                    'status': 'fail',
                    'message': '이미 다른 구역에서 사용 중인 area_name입니다.'
                }), 409

        # 갱신 + 부활
        was_inactive = not existing.is_active
        existing.area_name = data['area_name']
        existing.area_code = data.get('area_code', existing.area_code)
        existing.description = data.get('description', existing.description)
        existing.risk_level = data.get('risk_level', existing.risk_level)
        existing.is_active = True

        try:
            db.session.commit()
            return jsonify({
                'status': 'reactivated',
                'message': ('비활성화되었던 카메라가 재등록되었습니다.'
                            if was_inactive else
                            '동일 카메라 재매핑으로 기존 정보가 갱신되었습니다.'),
                'was_inactive': was_inactive,
                'area': existing.to_dict()
            }), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({'status': 'error', 'message': f'재활성화 중 오류: {str(e)}'}), 500

    # ── ② 신규 등록 ──
    if Area.query.filter_by(area_name=data['area_name']).first():
        return jsonify({
            'status': 'fail',
            'message': '이미 존재하는 area_name입니다.'
        }), 409

    area = Area(
        area_name=data['area_name'],
        area_code=data.get('area_code'),
        camera_key=camera_key,
        description=data.get('description'),
        risk_level=data.get('risk_level', 'normal'),
    )
    try:
        db.session.add(area)
        db.session.commit()
        return jsonify({
            'status': 'success',
            'message': '구역이 등록되었습니다.',
            'area': area.to_dict()
        }), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': f'등록 중 오류: {str(e)}'}), 500

@app.route('/api/areas', methods=['GET'])
@token_required
def list_areas():
    """
    구역 목록 조회 API
    ---
    tags:
      - Area
    security:
      - BearerAuth: []
    parameters:
      - in: query
        name: include_inactive
        type: boolean
        required: false
        description: true면 비활성화된 구역도 포함
    responses:
      200:
        description: 구역 목록 반환
    """
    include_inactive = request.args.get('include_inactive', 'false').lower() == 'true'
    q = Area.query if include_inactive else Area.query.filter_by(is_active=True)
    areas = q.order_by(Area.area_id).all()
    return jsonify({
        'status': 'success',
        'count': len(areas),
        'areas': [a.to_dict() for a in areas]
    }), 200

@app.route('/api/areas/<int:area_id>', methods=['PUT'])
@token_required
@role_required('최고 관리자', '보안 팀장', '구역 매니저')
def update_area(area_id):
    """
    구역 정보 수정 API (camera_key 재매핑 포함)
    ---
    tags:
      - Area
    security:
      - BearerAuth: []
    parameters:
      - in: path
        name: area_id
        type: integer
        required: true
      - in: body
        name: body
        required: true
        schema:
          type: object
          properties:
            area_name:   {type: string}
            area_code:   {type: string}
            camera_key:  {type: string}
            description: {type: string}
            risk_level:  {type: string}
            is_active:   {type: boolean}
    responses:
      200: {description: 수정 성공}
      400: {description: 수정할 필드 없음}
      404: {description: 구역 없음}
      409: {description: 중복 충돌}
    """
    area = Area.query.get(area_id)
    if not area:
        return jsonify({'status': 'fail', 'message': '구역을 찾을 수 없습니다.'}), 404

    data = request.json or {}

    # 중복 검증 (자기 자신 제외)
    if 'area_name' in data and data['area_name'] != area.area_name:
        if Area.query.filter_by(area_name=data['area_name']).first():
            return jsonify({'status': 'fail', 'message': '이미 존재하는 area_name입니다.'}), 409
    if 'camera_key' in data and data['camera_key'] and data['camera_key'] != area.camera_key:
        if Area.query.filter_by(camera_key=data['camera_key']).first():
            return jsonify({'status': 'fail', 'message': '이미 등록된 camera_key입니다.'}), 409

    updatable = ['area_name', 'area_code', 'camera_key', 'description', 'risk_level', 'is_active']
    changed = []
    for field in updatable:
        if field in data:
            setattr(area, field, data[field])
            changed.append(field)

    if not changed:
        return jsonify({'status': 'fail', 'message': '수정할 필드가 없습니다.'}), 400

    try:
        db.session.commit()
        return jsonify({
            'status': 'success', 'message': '구역 정보가 수정되었습니다.',
            'changed_fields': changed,
            'area': area.to_dict()
        }), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': f'수정 중 오류: {str(e)}'}), 500

@app.route('/api/areas/<int:area_id>', methods=['DELETE'])
@token_required
@role_required('최고 관리자', '보안 팀장', '구역 매니저')
def delete_area(area_id):
    """
    구역 비활성화 API (기본: soft delete / ?hard=true: 영구 삭제)
    ---
    tags:
      - Area
    security:
      - BearerAuth: []
    parameters:
      - in: path
        name: area_id
        type: integer
        required: true
      - in: query
        name: hard
        type: boolean
        required: false
        description: true면 영구 삭제 (위반 이력 FK 없을 때만 권장)
    responses:
      200: {description: 비활성화/삭제 성공}
      404: {description: 구역 없음}
    """
    area = Area.query.get(area_id)
    if not area:
        return jsonify({'status': 'fail', 'message': '구역을 찾을 수 없습니다.'}), 404

    hard = request.args.get('hard', 'false').lower() == 'true'

    try:
        if hard:
            db.session.delete(area)
            db.session.commit()
            return jsonify({'status': 'success', 'message': '구역이 영구 삭제되었습니다.'}), 200
        else:
            area.is_active = False
            db.session.commit()
            return jsonify({
                'status': 'success', 'message': '구역이 비활성화되었습니다.',
                'area': area.to_dict()
            }), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': f'삭제 중 오류: {str(e)}'}), 500

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
