from flask import Flask, jsonify, request
from flask_caching import Cache
import requests
import jwt
import datetime
import warnings
from urllib3.exceptions import InsecureRequestWarning
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
import my_pb2
import output_pb2
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

# Ignore SSL warnings
warnings.filterwarnings("ignore", category=InsecureRequestWarning)

# Encryption Keys
AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV = b'6oyZDr22E3ychjM%'

# Secret Key for JWT
SECRET_KEY = "your_secret_key_here"

# Initialize Flask
app = Flask(__name__)

# Setup Cache (In-memory)
cache = Cache(app, config={'CACHE_TYPE': 'simple'})

# Function to get access token
def get_token(password, uid):
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    headers = {
        "Host": "100067.connect.garena.com",
        "User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 9;en;US;)", 
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "close"
    }
    data = {
        "uid": uid,
        "password": password,
        "response_type": "token",
        "client_type": "2",
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        "client_id": "100067"
    }
    response = requests.post(url, headers=headers, data=data, verify=False, timeout=10)
    if response.status_code != 200:
        return None
    return response.json()

# Encrypt Message
def encrypt_message(key, iv, plaintext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(plaintext, AES.block_size)
    encrypted_message = cipher.encrypt(padded_message)
    return encrypted_message

# Process Token
def process_token(uid, password):
    token_data = get_token(password, uid)
    if not token_data:
        return {"uid": uid, "error": "Failed to retrieve token"}

    game_data = my_pb2.GameData()
game_data.timestamp = "2024-12-05 18:15:32"
game_data.game_name = "free fire"
game_data.game_version = 1
game_data.version_code = "1.108.3"
game_data.os_info = "Android OS 9 / API-28 (PI/rel.cjw.20220518.114133)"
game_data.device_type = "Handheld"
game_data.network_provider = "Verizon Wireless"
game_data.connection_type = "WIFI"
game_data.screen_width = 1280
game_data.screen_height = 960
game_data.dpi = "240"
game_data.cpu_info = "ARMv7 VFPv3 NEON VMH | 2400 | 4"
game_data.total_ram = 5951
game_data.gpu_name = "Adreno (TM) 640"
game_data.gpu_version = "OpenGL ES 3.0"
game_data.user_id = "Google|74b585a9-0268-4ad3-8f36-ef41d2e53610"
game_data.ip_address = "172.190.111.97"
game_data.language = "en"
game_data.open_id = token_data['open_id']
game_data.access_token = token_data['access_token']
game_data.platform_type = 4
game_data.device_form_factor = "Handheld"
game_data.device_model = "Asus ASUS_I005DA"
game_data.field_60 = 32968
game_data.field_61 = 29815
game_data.field_62 = 2479
game_data.field_63 = 914
game_data.field_64 = 31213
game_data.field_65 = 32968
game_data.field_66 = 31213
game_data.field_67 = 32968
game_data.field_70 = 4
game_data.field_73 = 2
game_data.library_path = "/data/app/com.dts.freefireth-QPvBnTUhYWE-7DMZSOGdmA==/lib/arm"
game_data.field_76 = 1
game_data.apk_info = "5b892aaabd688e571f688053118a162b|/data/app/com.dts.freefireth-QPvBnTUhYWE-7DMZSOGdmA==/base.apk"
game_data.field_78 = 6
game_data.field_79 = 1
game_data.os_architecture = "32"
game_data.build_number = "2019117877"
game_data.field_85 = 1
game_data.graphics_backend = "OpenGLES2"
game_data.max_texture_units = 16383
game_data.rendering_api = 4
game_data.encoded_field_89 = "\u0017T\u0011\u0017\u0002\b\u000eUMQ\bEZ\u0003@ZK;Z\u0002\u000eV\ri[QVi\u0003\ro\t\u0007e"
game_data.field_92 = 9204
game_data.marketplace = "3rd_party"
game_data.encryption_key = "KqsHT2B4It60T/65PGR5PXwFxQkVjGNi+IMCK3CFBCBfrNpSUA1dZnjaT3HcYchlIFFL1ZJOg0cnulKCPGD3C3h1eFQ="
game_data.total_storage = 111107
game_data.field_97 = 1
game_data.field_98 = 1
game_data.field_99 = "4"
game_data.field_100 = "4"

    serialized_data = game_data.SerializeToString()
    encrypted_data = encrypt_message(AES_KEY, AES_IV, serialized_data)
    hex_encrypted_data = binascii.hexlify(encrypted_data).decode('utf-8')

    url = "https://loginbp.common.ggbluefox.com/MajorLogin"
    headers = {
        'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
        'Content-Type': "application/octet-stream"
    }
    edata = bytes.fromhex(hex_encrypted_data)

    try:
        response = requests.post(url, data=edata, headers=headers, verify=False, timeout=10)
        if response.status_code == 200:
            example_msg = output_pb2.Krishna()
            try:
                example_msg.ParseFromString(response.content)
                return {"uid": uid, "token": example_msg.token}
            except Exception:
                return {"uid": uid, "error": "Failed to deserialize response"}
        else:
            return {"uid": uid, "error": f"HTTP {response.status_code}"}
    except requests.RequestException as e:
        return {"uid": uid, "error": f"Request failed: {e}"}

# Generate JWT Token
@app.route('/generate_jwt', methods=['GET'])
def generate_jwt():
    access_token = request.args.get('access_token')
    if not access_token:
        return jsonify({"error": "Access token is required"}), 400

    try:
        payload = {
            "sub": "user",
            "iat": datetime.datetime.utcnow(),
            "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1),
            "access_token": access_token
        }
        jwt_token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
        return jsonify({"jwt_token": jwt_token})
    except Exception as e:
        return jsonify({"error": f"Failed to generate JWT: {e}"}), 500

# Verify JWT Token
@app.route('/verify_jwt', methods=['POST'])
def verify_jwt():
    data = request.get_json()
    token = data.get('jwt_token')

    if not token:
        return jsonify({"error": "JWT token is required"}), 400

    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return jsonify({"valid": True, "decoded": decoded})
    except jwt.ExpiredSignatureError:
        return jsonify({"valid": False, "error": "Token has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"valid": False, "error": "Invalid token"}), 401

# Run Flask App
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5030)