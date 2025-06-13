import os
import hmac
import hashlib
import requests
import logging
from flask import Flask, request, jsonify
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
t_logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')

app = Flask(__name__)

# Environment variables
APP_SECRET = os.getenv("APP_SECRET")
VERIFY_TOKEN = os.getenv("VERIFY_TOKEN")
ACCESS_TOKEN = os.getenv("ACCESS_TOKEN")
GENAI_ENDPOINT = os.getenv("GENAI_ENDPOINT")
GENAI_API_KEY = os.getenv("GENAI_API_KEY")


def verify_signature(request):
    """Verify the request signature using the app secret."""
    signature = request.headers.get('X-Hub-Signature-256')
    if not signature:
        logging.warning("Missing X-Hub-Signature-256 header")
        return False
    sha_name, signature_hash = signature.split('=', 1)
    if sha_name != 'sha256':
        logging.warning(f"Unexpected signature method: {sha_name}")
        return False
    mac = hmac.new(APP_SECRET.encode('utf-8'), msg=request.data, digestmod=hashlib.sha256)
    valid = hmac.compare_digest(mac.hexdigest(), signature_hash)
    if not valid:
        logging.warning("Signature verification failed")
    return valid


@app.route('/webhook', methods=['GET', 'POST'])
def webhook():
    if request.method == 'GET':
        mode = request.args.get('hub.mode')
        token = request.args.get('hub.verify_token')
        challenge = request.args.get('hub.challenge')
        logging.info(f"Webhook verification attempt: mode={mode}, token={token}")
        if mode == 'subscribe' and token == VERIFY_TOKEN:
            logging.info("Verification successful")
            return challenge, 200
        else:
            logging.error("Verification token mismatch")
            return 'Verification token mismatch', 403

    elif request.method == 'POST':
        if not verify_signature(request):
            return 'Invalid signature', 403

        data = request.get_json()
        entry = data.get('entry', [])[0]
        changes = entry.get('changes', [])[0]
        value = changes.get('value', {})
        messages = value.get('messages', [])

        if messages:
            message = messages[0]
            sender = message.get('from')
            text = message.get('text', {}).get('body')
            phone_number_id = value.get('metadata', {}).get('phone_number_id')
            logging.info(f"📥 Received from {sender}: {text}")

            genai_response = send_to_genai(sender, text)
            if genai_response:
                logging.info(f"🤖 GenAI replied: {genai_response}")
                send_whatsapp_message(phone_number_id, sender, genai_response)

        return 'EVENT_RECEIVED', 200


conversation_histories = {}
def send_to_genai(user_id, user_input):
    history = conversation_histories.get(user_id, [])
    history.append({"role": "user", "content": user_input})

    headers = {
        "Authorization": f"Bearer {GENAI_API_KEY}",
        "Content-Type": "application/json"
    }
    payload = {
        "messages": history,
        "stream": False
    }
    try:
        response = requests.post(f"{GENAI_ENDPOINT}/api/v1/chat/completions", headers=headers, json=payload)
        response.raise_for_status()
        data = response.json()
        assistant_message = data['choices'][0]['message']['content']

        history.append({"role": "assistant", "content": assistant_message})
        conversation_histories[user_id] = history

        return assistant_message
    except requests.exceptions.RequestException as e:
        logging.error(f"Error communicating with GenAI agent: {e}")
        return None


def send_whatsapp_message(phone_number_id, recipient, message):
    url = f"https://graph.facebook.com/v22.0/{phone_number_id}/messages"
    headers = {
        "Authorization": f"Bearer {ACCESS_TOKEN}",
        "Content-Type": "application/json"
    }
    data = {
        "messaging_product": "whatsapp",
        "to": recipient,
        "type": "text",
        "text": {"body": message}
    }
    logging.info(f"📤 Sending to {recipient}: {message}")
    try:
        response = requests.post(url, headers=headers, json=data)
        response.raise_for_status()
        logging.info(f"WhatsApp API response status: {response.status_code}")
    except requests.exceptions.RequestException as e:
        logging.error(f"Error sending message via WhatsApp: {e}")


if __name__ == '__main__':
    app.run(port=5555, debug=False)
