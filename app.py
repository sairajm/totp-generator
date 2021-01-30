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
    secretKey = request.args.get('code')
    unix_utc_time = int(datetime.now(tz=timezone.utc).timestamp())
    number_of_time_steps =  ( unix_utc_time - t0 / time_step )
    response = str(number_of_time_steps)
    return response

if __name__ == '__main__':
    app.run()