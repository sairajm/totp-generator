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
    global digits, algorithm

    code_query_param = request.args.get('code')
    hashing_algorithm = request.args.get('alg')
    digits_to_return = request.args.get('digits')

    if digits_to_return is not None and str(digits_to_return).isnumeric:
        digits = int(digits_to_return)

    print('OTP length: ', digits)

    if digits > 8:
        return "Bad input, max supported digit is 8.", 400

    if code_query_param is None:
        return "Bad input, expected non-null or non-empty code.", 400

    secretKey = str(code_query_param)

    if "".__eq__(secretKey) or len(secretKey) < 20:
        return "Bad input, expected non-null or non-empty code.", 400

    algorithm = identify_algorithm_to_use(hashing_algorithm)

    print("Using algorithm: ", algorithm)

    number_of_time_steps =  get_number_of_time_steps()

    computed_hash = compute_hash(secretKey, number_of_time_steps)

    response = get_otp(computed_hash)

    return response

def get_otp(computed_hash):
    offset = computed_hash[len(computed_hash) - 1] & 0xf # 0-15 low-order 4 bits of computed_hash[19]

    # Ref: https://tools.ietf.org/html/rfc4226#section-5.4

    shift_24 = ((computed_hash[offset] & 0x7f) << 24)
    shift_16 = ((computed_hash[offset + 1] & 0xff) << 16)
    shift_8 = ((computed_hash[offset + 2] & 0xff) << 8)
    convert = (computed_hash[offset + 3] & 0xff) # Convert to a number in 0...2^{31}-1

    dynamic_binary = shift_24 | shift_16 | shift_8 | convert

    otp = dynamic_binary % order_of_power[digits]

    result = str(otp)

    while (len(result) < digits):
        result = "0" + result

    return result

def identify_algorithm_to_use(alg):
    if alg is None:
        return hashlib.sha1
    
    str_alg = str(alg).lower()
    
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

    key = bytearray.fromhex(secretKey)
    message = bytearray.fromhex(time)

    digester = hmac.new(key, message, algorithm)
    signature1 = digester.digest()

    return signature1

def get_number_of_time_steps():
    unix_utc_time = int(datetime.now(tz=timezone.utc).timestamp())
    number_of_time_steps =  ( unix_utc_time - t0 / time_step )

    hex_steps = hex(int(number_of_time_steps))

    hex_steps = hex_steps[2:len(hex_steps)]

    while (len(hex_steps) < 16):
        hex_steps = "0" + hex_steps

    return hex_steps

if __name__ == '__main__':
    app.run()