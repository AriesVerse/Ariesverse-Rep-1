from flask import Flask, request, jsonify
from flask_cors import CORS
import requests

app = Flask(__name__)
CORS(app) # Allows all headers and origins

@app.route('/', methods=['POST'])
def proxy():
    try:
        response = requests.post('http://localhost:11434/api/chat', json=request.json)
        return jsonify(response.json())
    except Exception as e:
        return str(e), 500

if __name__ == '__main__':
    app.run(port=8080)