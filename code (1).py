import os
from flask import Flask, request, jsonify
from datetime import datetime, timedelta
import re
import time

app = Flask(__name__)

# --- Configuration (Load from Environment Variables) ---
# These should be set on Render's dashboard as Environment Variables.

# API Keys (scoped as per spec)
API_KEYS = {
    "CUSTOMER_API_KEY": os.environ.get("CUSTOMER_API_KEY", "DEFAULT_CUSTOMER_KEY_FOR_LOCAL_DEV"),
    "BILLING_API_KEY": os.environ.get("BILLING_API_KEY", "DEFAULT_BILLING_KEY_FOR_LOCAL_DEV"),
    "CHATLOG_API_KEY": os.environ.get("CHATLOG_API_KEY", "DEFAULT_CHATLOG_KEY_FOR_LOCAL_DEV")
}

# Mapping endpoints to required API keys
ENDPOINT_API_KEY_MAP = {
    "/api/v1/customers/create": API_KEYS["CUSTOMER_API_KEY"],
    "/api/v1/payments": API_KEYS["BILLING_API_KEY"],
    "/api/v1/chat-logs": API_KEYS["CHATLOG_API_KEY"],
}

# IP Whitelisting (for local testing, use '127.0.0.1' or your machine's local IP)
# For Render deployment, this MUST be the static IP of the Viber bot middleware.
# You will get this IP after the middleware is deployed by ShweChat.
# For initial deployment, you might temporarily set this to '0.0.0.0' or the IP of your testing machine.
WHITELISTED_IP = os.environ.get("WHITELISTED_IP", "127.0.0.1") # Replace with the actual middleware IP for production!

# Rate Limiting Configuration (Suggested: 5 requests/minute per IP)
RATE_LIMIT_DURATION_SECONDS = 60
RATE_LIMIT_MAX_REQUESTS = 5

# --- In-memory storage for rate limiting (for demonstration only) ---
# In a production environment, use a persistent store like Redis.
request_counts = {}

# --- Helper Functions and Decorators ---

def log_request(ip_address, endpoint, status, user_id=None, message=""):
    """Logs API request details."""
    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "requesting_ip": ip_address,
        "endpoint_path": endpoint,
        "status": status,
        "user_identifier": user_id,
        "message": message
    }
    # In production, use a proper logging system (e.g., Python's logging module, sent to stdout/stderr)
    print(f"API LOG: {log_entry}")

def api_key_required(f):
    def decorated_function(*args, **kwargs):
        endpoint_path = request.path
        expected_key = ENDPOINT_API_KEY_MAP.get(endpoint_path)

        if not expected_key:
            log_request(request.remote_addr, endpoint_path, "failure", message="No API key configured for this endpoint.")
            return jsonify({"status": "error", "message": "API key configuration error"}), 500

        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            log_request(request.remote_addr, endpoint_path, "failure", message="Missing or malformed Authorization header.")
            return jsonify({"status": "error", "message": "Unauthorized access"}), 401

        provided_key = auth_header.split(' ')[1]

        if provided_key != expected_key:
            log_request(request.remote_addr, endpoint_path, "failure", message=f"Invalid API key provided for {endpoint_path}.")
            return jsonify({"status": "error", "message": "Unauthorized access"}), 401

        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

def ip_whitelisted(f):
    def decorated_function(*args, **kwargs):
        requester_ip = request.remote_addr
        # This check is crucial for security. Make sure WHITELISTED_IP is correct.
        if requester_ip != WHITELISTED_IP:
            log_request(requester_ip, request.path, "failure", message=f"IP '{requester_ip}' not whitelisted. Configured IP: {WHITELISTED_IP}")
            return jsonify({"status": "error", "message": "Access denied from this IP address"}), 403
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

def apply_rate_limit(f):
    def decorated_function(*args, **kwargs):
        requester_ip = request.remote_addr
        current_time = datetime.now()

        if requester_ip not in request_counts:
            request_counts[requester_ip] = {'count': 0, 'last_reset_time': current_time}

        if (current_time - request_counts[requester_ip]['last_reset_time']).total_seconds() >= RATE_LIMIT_DURATION_SECONDS:
            request_counts[requester_ip]['count'] = 0
            request_counts[requester_ip]['last_reset_time'] = current_time

        request_counts[requester_ip]['count'] += 1

        remaining_requests = RATE_LIMIT_MAX_REQUESTS - request_counts[requester_ip]['count']

        if request_counts[requester_ip]['count'] > RATE_LIMIT_MAX_REQUESTS:
            reset_in_seconds = RATE_LIMIT_DURATION_SECONDS - (current_time - request_counts[requester_ip]['last_reset_time']).total_seconds()
            response = jsonify({"status": "error", "message": "Rate limit exceeded. Too many requests."})
            response.status_code = 429
            response.headers['X-RateLimit-Limit'] = RATE_LIMIT_MAX_REQUESTS
            response.headers['X-RateLimit-Remaining'] = 0
            response.headers['Retry-After'] = int(max(0, reset_in_seconds))
            log_request(requester_ip, request.path, "failure", message="Rate limit exceeded.")
            return response

        response = f(*args, **kwargs)
        if isinstance(response, tuple) and len(response) == 2:
            data, status_code = response
            if isinstance(data, dict):
                response = jsonify(data)
                response.status_code = status_code
        elif not isinstance(response, (jsonify, Flask.response_class)):
            response = jsonify(response)
            response.status_code = 200

        response.headers['X-RateLimit-Limit'] = RATE_LIMIT_MAX_REQUESTS
        response.headers['X-RateLimit-Remaining'] = remaining_requests
        response.headers['Retry-After'] = int(RATE_LIMIT_DURATION_SECONDS - (current_time - request_counts[requester_ip]['last_reset_time']).total_seconds())

        return response
    decorated_function.__name__ = f.__name__
    return decorated_function

# --- API Endpoints ---

@app.route('/api/v1/customers/create', methods=['POST'])
@ip_whitelisted
@api_key_required
@apply_rate_limit
def create_customer():
    data = request.get_json()
    requester_ip = request.remote_addr
    user_id_for_log = data.get('phone')

    if not data:
        log_request(requester_ip, request.path, "failure", user_id_for_log, "No JSON payload provided.")
        return jsonify({"status": "error", "message": "Invalid JSON payload"}), 400

    required_fields = ["name", "phone", "region"]
    for field in required_fields:
        if field not in data or not data[field]:
            log_request(requester_ip, request.path, "failure", user_id_for_log, f"Missing required field: {field}.")
            return jsonify({"status": "error", "message": f"Missing required field: {field}"}), 400

    phone_pattern = re.compile(r"^09[0-9]{7,9}$")
    if not phone_pattern.match(data["phone"]):
        log_request(requester_ip, request.path, "failure", user_id_for_log, f"Invalid phone number format: {data['phone']}.")
        return jsonify({"status": "error", "message": "Invalid phone number format"}), 400

    log_request(requester_ip, request.path, "success", user_id_for_log, "Customer created successfully.")
    return jsonify({"status": "success", "message": "Customer created successfully"}), 200

@app.route('/api/v1/payments', methods=['POST'])
@ip_whitelisted
@api_key_required
@apply_rate_limit
def record_payment():
    data = request.get_json()
    requester_ip = request.remote_addr
    user_id_for_log = data.get('user_id')

    if not data:
        log_request(requester_ip, request.path, "failure", user_id_for_log, "No JSON payload provided.")
        return jsonify({"status": "error", "message": "Invalid JSON payload"}), 400

    required_fields = ["user_id", "amount", "method", "reference_id"]
    for field in required_fields:
        if field not in data or not data[field]:
            log_request(requester_ip, request.path, "failure", user_id_for_log, f"Missing required field: {field}.")
            return jsonify({"status": "error", "message": f"Missing required field: {field}"}), 400

    if not isinstance(data["amount"], (int, float)) or data["amount"] <= 0:
        log_request(requester_ip, request.path, "failure", user_id_for_log, f"Invalid amount: {data['amount']}.")
        return jsonify({"status": "error", "message": "Invalid amount"}), 400

    log_request(requester_ip, request.path, "success", user_id_for_log, "Payment recorded.")
    return jsonify({"status": "success", "message": "Payment recorded"}), 200

@app.route('/api/v1/chat-logs', methods=['POST'])
@ip_whitelisted
@api_key_required
@apply_rate_limit
def save_chat_log():
    data = request.get_json()
    requester_ip = request.remote_addr
    user_id_for_log = data.get('viber_id')

    if not data:
        log_request(requester_ip, request.path, "failure", user_id_for_log, "No JSON payload provided.")
        return jsonify({"status": "error", "message": "Invalid JSON payload"}), 400

    required_fields = ["viber_id", "message", "timestamp", "type"]
    for field in required_fields:
        if field not in data or not data[field]:
            log_request(requester_ip, request.path, "failure", user_id_for_log, f"Missing required field: {field}.")
            return jsonify({"status": "error", "message": f"Missing required field: {field}"}), 400

    try:
        datetime.fromisoformat(data["timestamp"].replace('Z', '+00:00'))
    except ValueError:
        log_request(requester_ip, request.path, "failure", user_id_for_log, f"Invalid timestamp format: {data['timestamp']}.")
        return jsonify({"status": "error", "message": "Invalid timestamp format"}), 400

    log_request(requester_ip, request.path, "success", user_id_for_log, "Chat log saved.")
    return jsonify({"status": "success", "message": "Chat log saved"}), 200

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({"status": "ok", "message": "API is running"}), 200

# This part is removed because Gunicorn will handle running the app in production.
# if __name__ == '__main__':
#     app.run(debug=True, host='0.0.0.0', port=5000)