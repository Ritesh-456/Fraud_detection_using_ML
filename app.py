import io
from PIL import Image
from flask import Flask, request, jsonify
from flask_cors import CORS
from Notebook.fraud_detection_model_ import HybridFraudDetector
import pyzbar.pyzbar
import qrcode
import base64

app = Flask(__name__)
CORS(app)

detector = HybridFraudDetector()

def create_qr_image_data_url(url):
    """Generates a data URL for a QR code image."""
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=4,  
        border=1,    
    )
    qr.add_data(url)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")
    img_io = io.BytesIO()
    img.save(img_io, format="PNG")
    img_base64 = base64.b64encode(img_io.getvalue()).decode()
    data_url = f"data:image/png;base64,{img_base64}"
    return data_url

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

@app.route('/generate-qr', methods=['POST'])
def generate_qr():
    try:
        data = request.get_json()
        url = data.get('url', '')
        if not url:
            return jsonify({'error': 'URL is required'}), 400

        qr_data_url = create_qr_image_data_url(url)
        if qr_data_url:
            return jsonify({'data': qr_data_url})
        else:
            return jsonify({'error': 'Failed to generate QR code'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    detector.train_model()
    app.run(debug=True)