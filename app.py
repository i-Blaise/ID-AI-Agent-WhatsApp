from flask import Flask, request, jsonify
import os
import hmac
import hashlib
import requests
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

APP_SECRET = os.getenv("APP_SECRET")
VERIFY_TOKEN = os.getenv("VERIFY_TOKEN")
ACCESS_TOKEN = os.getenv("ACCESS_TOKEN")
GENAI_ENDPOINT = os.getenv("GENAI_ENDPOINT")
GENAI_API_KEY = os.getenv("GENAI_API_KEY")


@app.route('/webhook', methods=['GET', 'POST'])
def webhook():
    if request.method == 'GET':
        # Verification challenge
        mode = request.args.get('hub.mode')
        token = request.args.get('hub.verify_token')
        challenge = request.args.get('hub.challenge')
        if mode == 'subscribe' and token == VERIFY_TOKEN:
            return challenge, 200
        else:
            return 'Verification token mismatch', 403

    elif request.method == 'POST':
        # Signature verification
        signature = request.headers.get('X-Hub-Signature-256')
        if not verify_signature(request.get_data(), signature):
            return 'Invalid signature', 403

        data = request.get_json()
        process_message(data)
        return 'EVENT_RECEIVED', 200

def verify_signature(payload, signature):
    if not signature:
        return False
    sha_name, signature = signature.split('=')
    if sha_name != 'sha256':
        return False
    mac = hmac.new(APP_SECRET.encode('utf-8'), msg=payload, digestmod=hashlib.sha256)
    return hmac.compare_digest(mac.hexdigest(), signature)

def process_message(data):
    for entry in data.get('entry', []):
        for change in entry.get('changes', []):
            value = change.get('value', {})
            messages = value.get('messages', [])
            for message in messages:
                phone_number_id = value['metadata']['phone_number_id']
                from_number = message['from']
                msg_body = message['text']['body']
                send_message(phone_number_id, from_number, f"You said: {msg_body}")

def send_message(phone_number_id, to, message):
    url = f"https://graph.facebook.com/v17.0/{phone_number_id}/messages"
    headers = {
        "Authorization": f"Bearer {ACCESS_TOKEN}",
        "Content-Type": "application/json"
    }
    data = {
        "messaging_product": "whatsapp",
        "to": to,
        "type": "text",
        "text": {"body": message}
    }
    response = requests.post(url, headers=headers, json=data)
    print(response.status_code, response.text)

if __name__ == '__main__':
    app.run(port=5000)
