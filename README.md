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
`http://127.0.0.1:5000/generate?code=1d319930bdb2ea7d580080f637cd9e53d6ef1767&digits=6`

`code` is the secret key for the SHA-1 hash(hex encoded).
`digits` is number of digits you want the algorithm to return (max 8).
`alg` is the type of SHA algorithm to be used based on the code provided. `SHA-1, SHA-256, SHA-512` supported.

If you're a fan of the curl command:

```
curl -X GET "http://127.0.0.1:5000/generate?code=1d319930bdb2ea7d580080f637cd9e53d6ef1767&digits=6&alg=sha256"
```

## Output
Here is a sample output:

![img](sample.png)
