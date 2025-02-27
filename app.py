import io
from PIL import Image
from flask import Flask, request, jsonify
from flask_cors import CORS  
from Notebook.fraud_detection_model_ import HybridFraudDetector
import pyzbar.pyzbar

app = Flask(__name__)

CORS(app)  


detector = HybridFraudDetector()


@app.route('/analyze-url', methods=['POST'])
def analyze_url():
    try:
        data = request.get_json()
        url = data.get('url', '')

        if not url:
            return jsonify({'error': 'URL is required'}), 400

        result = detector.analyze_url(url)
        if result:
            return jsonify(result)
        else:
            return jsonify({'error': 'Failed to analyze URL'}), 500

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/analyze-qr', methods=['POST'])
def analyze_qr():
    try:
        print(pyzbar.pyzbar) 
        if 'file' not in request.files:
            return jsonify({'error': 'No file part'}), 400
        file = request.files['file']
        img = Image.open(file)
        qr_codes = pyzbar.pyzbar.decode(img)
        if not qr_codes:
            return jsonify({'error': 'No QR code found'}), 400
        url = qr_codes[0].data.decode('utf-8')
        result = detector.analyze_url(url)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    detector.train_model()
    app.run(debug=True)