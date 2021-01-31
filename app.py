from flask import Flask, request
from datetime import datetime, timezone
import hashlib
import hmac
import base64
app = Flask(__name__)

time_step = 30 # time step in seconds
t0 = 0
algorithm = hashlib.sha1
order_of_power = [1,10,100,1000,10000,100000,1000000,10000000,100000000]
digits = 6

@app.route('/generate')
def generate_totp():
    code_query_param = request.args.get('code')
    hashing_algorithm = request.args.get('alg')
    digits_to_return = request.args.get('digits')

    if digits_to_return is not None and str(digits_to_return).isnumeric:
        digits = int(digits_to_return)

    if digits > 8:
        return "Bad input, max supported digit is 8.", 400

    if code_query_param is None:
        return "Bad input, expected non-null or non-empty code.", 400

    secretKey = str(code_query_param)

    if "".__eq__(secretKey) or len(secretKey) < 20:
        return "Bad input, expected non-null or non-empty code.", 400

    algorithm = identify_algorithm_to_use(hashing_algorithm)    

    number_of_time_steps =  get_number_of_time_steps()

    time_str = get_time(number_of_time_steps)

    computed_hash = compute_hash(secretKey, time_str)

    response = get_otp(computed_hash)

    return response

def get_time(number_of_time_steps):
    time_str = str(number_of_time_steps)

    while (len(time_str) < 16):
        time_str = "0" + time_str

    return time_str

def get_otp(computed_hash):
    offset = computed_hash[len(computed_hash) - 1] & 0xf

    binary = ((computed_hash[offset] & 0x7f) << 24) | ((computed_hash[offset + 1] & 0xff) << 16) | ((computed_hash[offset + 2] & 0xff) << 8) | (computed_hash[offset + 3] & 0xff)

    otp = binary % order_of_power[digits]

    result = str(otp)

    while (len(result) < digits):
        result = "0" + result

    return result

def identify_algorithm_to_use(alg):
    if alg is None:
        return hashlib.sha1
    
    str_alg = str(alg).lower
    
    if "sha1".__eq__(str_alg):
        return hashlib.sha1
    elif "sha224".__eq__(str_alg):
        return hashlib.sha224
    elif "sha256".__eq__(str_alg):
        return hashlib.sha256
    elif "sha512".__eq__(str_alg):
        return hashlib.sha512
    else:
        return hashlib.sha1

def compute_hash(secretKey, time):
    key = bytes(secretKey, 'UTF-8')
    message = bytes(time, 'UTF-8')

    digester = hmac.new(key, message, algorithm)
    signature1 = digester.digest()

    return signature1

def get_number_of_time_steps():
    unix_utc_time = int(datetime.now(tz=timezone.utc).timestamp())
    number_of_time_steps =  ( unix_utc_time - t0 / time_step )

    return number_of_time_steps;

if __name__ == '__main__':
    app.run()