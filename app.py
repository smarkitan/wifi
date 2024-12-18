from flask import Flask, jsonify
from flask_cors import CORS


app = Flask(__name__)

# Configurare CORS pentru Netlify
CORS(app, resources={r"/*": {"origins": "https://wifidevices.netlify.app"}})


@app.route('/api/network-details')
def home():
    return "Aplicația este live!"


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
