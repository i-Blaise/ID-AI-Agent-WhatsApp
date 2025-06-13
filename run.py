import os
import hmac
import hashlib
import requests
from flask import Flask, request, jsonify
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Environment variables
APP_SECRET = os.getenv("APP_SECRET")
VERIFY_TOKEN = os.getenv("VERIFY_TOKEN")
ACCESS_TOKEN = os.getenv("ACCESS_TOKEN")
# print(f"access token {ACCESS_TOKEN}")
GENAI_ENDPOINT = os.getenv("GENAI_ENDPOINT")
GENAI_API_KEY = os.getenv("GENAI_API_KEY")

def verify_signature(request):
    """Verify the request signature using the app secret."""
    signature = request.headers.get('X-Hub-Signature-256')
    if not signature:
        return False
    sha_name, signature_hash = signature.split('=')
    if sha_name != 'sha256':
        return False
    mac = hmac.new(APP_SECRET.encode('utf-8'), msg=request.data, digestmod=hashlib.sha256)
    return hmac.compare_digest(mac.hexdigest(), signature_hash)

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
        if not verify_signature(request):
            return 'Invalid signature', 403

        data = request.get_json()
        # Extract message details
        entry = data.get('entry', [])[0]
        changes = entry.get('changes', [])[0]
        value = changes.get('value', {})
        messages = value.get('messages', [])
        if messages:
            message = messages[0]
            sender = message['from']
            text = message['text']['body']
            phone_number_id = value['metadata']['phone_number_id']

            # Send message to GenAI agent
            genai_response = send_to_genai(sender, text)
            if genai_response:
                # Send response back via WhatsApp
                send_whatsapp_message(phone_number_id, sender, genai_response)

        return 'EVENT_RECEIVED', 200


conversation_histories = {}
def send_to_genai(user_id, user_input):
    """Send user input to the GenAI agent and return the response."""
    # Retrieve the user's conversation history or start a new one
    history = conversation_histories.get(user_id, [])

    # Add the new user message to the history
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

        # Add the assistant's response to the history
        history.append({"role": "assistant", "content": assistant_message})

        # Update the user's conversation history
        conversation_histories[user_id] = history
        # print(f"User {user_id} conversation history: {history}")

        return assistant_message
    except requests.exceptions.RequestException as e:
        print(f"Error communicating with GenAI agent: {e}")
        return None


def send_whatsapp_message(phone_number_id, recipient, message):
    """Send a message via WhatsApp Business API."""
    
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
    try:
        response = requests.post(url, headers=headers, json=data)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"Error sending message via WhatsApp: {e}")

if __name__ == '__main__':
    app.run(port=5555, debug=False)
