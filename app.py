from flask import Flask, request
from datetime import datetime, timezone
import hashlib
import hmac
import base64
app = Flask(__name__)

time_step = 30 # time step in seconds
t0 = 0

@app.route('/generate')
def generate_totp():
    code_query_param = request.args.get('code')
    if code_query_param is None:
        return "Bad input, expected non-null or non-empty code.", 400

    secretKey = str(code_query_param)

    if "".__eq__(secretKey):
        return "Bad input, expected non-null or non-empty code.", 400

    number_of_time_steps =  get_number_of_time_steps()
    response = str(number_of_time_steps)
    return response

def get_number_of_time_steps():
    unix_utc_time = int(datetime.now(tz=timezone.utc).timestamp())
    number_of_time_steps =  ( unix_utc_time - t0 / time_step )

    return number_of_time_steps;

if __name__ == '__main__':
    app.run()