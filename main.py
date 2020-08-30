import logging
import sys
import json
import argparse
import pprint

import requests
from aes import AESCipher

# API URI
TOKEN_API = "https://api-my.te.eg/api/user/generatetoken?channelId=WEB_APP"
SIGNIN_API = "https://api-my.te.eg/api/user/login?channelId=WEB_APP"
BALANCE_API = "https://api-my.te.eg/api/line/postpaid/balance"
FREEUNITS_API = "https://api-my.te.eg/api/line/freeunitusage"

# Command line arguments
parser = argparse.ArgumentParser(description="WE command line")
parser.add_argument("msisdn")
parser.add_argument("password")
args = parser.parse_args()

# Start requests session
s = requests.Session()

# Get initial JWT Tocken
r = s.get(TOKEN_API)

if not r:
    print('Error: Guest Token!')
    exit()
jwt = r.json()["body"]["jwt"]

# Login
# AES encryption kets extracted from browser
# Key = 0f0e0d0c0b0a09080706050403020100
# iv = 000102030405060708090a0b0c0d0e0f

key = (
    b"\x0f\x0e\x0d\x0c\x0b\x0a\x09\x08\x07\x06\x05\x04\x03\x02\x01\x00")
iv = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"

# AES implementation from
# https://gist.github.com/wowkin2/a2b234c87290f6959c815d3c21336278

password_enc = AESCipher(key, iv).encrypt(args.password)
data = {
    "header": {
        "msisdn": args.msisdn,
        "locale": "En"
    },
    "body": {
        "password": password_enc
    }
}

headers = {
    "jwt": jwt
}

r = s.post(SIGNIN_API, json=data, headers=headers)

if r.json()["header"]["customerId"] is None:
    print('Error: Can\'t login! Check phone number or password')
    exit()

customerId = r.json()["header"]["customerId"]
jwt = r.json()["body"]["jwt"]

# Hit the API
headers = {
    "jwt": jwt
}

data = {
    "header": {
        "customerId": customerId,
        "msisdn": args.msisdn,
        "locale": "En"
    },
    "body": {}
}

r = s.post(BALANCE_API, json=data, headers=headers)
outstandingAmount, unbilledFees = [
    r.json(
    )["body"][k] for k in ('outstandingAmount', 'unbilledFees')]
print(f"outstanding Amount: {outstandingAmount} EGP")
print(f"unbilled Amount: {unbilledFees} EGP")

r = s.post(FREEUNITS_API, json=data, headers=headers)
initialTotalAmount, usedAmount, freeAmount = [
    r.json(
    )["body"]["summarizedLineUsageList"][0][k] for k in ('initialTotalAmount', 'usedAmount', 'freeAmount')]
print(f"Total Amount: {initialTotalAmount} Gb")
print(f"Used Amount: {usedAmount} Gb")
print(f"Free Amount: {freeAmount} Gb")
