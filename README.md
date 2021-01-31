# totp-generator
A free time based OTP generator(client). Based on [RFC-6238](https://tools.ietf.org/html/rfc6238) spec.

## Setup
1. Requires python3.

    `brew install python3`
2. Setup virtual environment

    `python3 -m venv env`

3. Activate virtual environment

    `source env/bin/activate`
4. Run the app locally

    `python app.py`

5. Deploy it in a cloud function or run it locally :)

## Input

Sample input:
`http://127.0.0.1:5000/generate?code=3132333435363738393031323334353637383930&digits=6`

`code` is the secret key for the SHA-1 hash.
`digits` is number of digits you want the algorithm to return (max 8).
`alg` is the type of SHA algorithm to be used based on the code provided. `SHA-1, SHA-256, SHA-512` supported.
