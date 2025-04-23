import io
import qrcode
import time
import re
import hashlib
import pandas as pd
import numpy as np
import subprocess
import sys
from PIL import Image
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split


# def install_requirements():
#     packages = [
#         'qrcode',
#         'opencv-python',
#         'pillow',
#         'scikit-learn',
#         'pandas',
#         'numpy'
#     ]
#     for package in packages:
#         try:
#             print(f"Installing {package}...")
#             subprocess.check_call([sys.executable, "-m", "pip", "install", package])
#         except subprocess.CalledProcessError as e:
#             print(f"Error installing {package}: {e}")
#             return False
#     return True

# if not install_requirements():
#     print("Error installing dependencies. Please install manually using:")
#     print("pip install qrcode opencv-python pillow scikit-learn pandas numpy")
#     sys.exit(1)

try:
    import cv2
except ImportError:
    print("Warning: OpenCV import failed. QR code features will be limited.")

class HybridFraudDetector:
    def __init__(self):
        self.link_model = None
        self.link_scaler = None
        self.qr_model = None
        self.qr_scaler = None
        self.confidence_threshold = 0.7
        self.has_cv2 = 'cv2' in sys.modules

    def _extract_link_features(self, url):
        try:
            length = len(url)
            suspicious_domains = ['free', 'click', 'win', 'promo', 'temp']
            domain_score = sum(1 for domain in suspicious_domains if domain in url.lower())
            special_chars = len(re.findall(r'[!@#$%^&*()_+\-\=\[\]{};:\'",.<>?/\\]', url))
            special_char_ratio = special_chars / length if length > 0 else 0
            url_hash = hashlib.md5(url.encode()).hexdigest()
            hash_complexity = len(set(url_hash))
            ip_presence = bool(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url))
            return [
                length,
                domain_score,
                special_char_ratio,
                hash_complexity,
                int(ip_presence),
                url.count('.'),
                url.count('/'),
                int('https' in url),
                len(re.findall(r'\d', url))
            ]
        except Exception as e:
            print(f"Error extracting features from URL {url}: {e}")
            return [0] * 9

    def generate_synthetic_data(self, n_samples=100):
        urls = []
        labels = []
        try:
            base_domains = ['http://example', 'https://secure', 'http://temp']
            suspicious_keywords = ['win', 'free', 'click', 'promo', 'temp']
            for _ in range(n_samples):
                is_fraud = np.random.random() < 0.4
                if is_fraud:
                    domain = np.random.choice(base_domains)
                    keyword = np.random.choice(suspicious_keywords)
                    url = f"{domain}.{keyword}/{self._generate_random_path()}"
                    label = 1
                else:
                    url = f"{np.random.choice(base_domains)}.com/{self._generate_random_path()}"
                    label = 0
                urls.append(url)
                labels.append(label)
        except Exception as e:
            print(f"Error generating synthetic data: {e}")
            return [], []
        return urls, labels

    def _generate_random_path(self):
        return ''.join(np.random.choice(list('abcdefghijklmnopqrstuvwxyz0123456789'))
                       for _ in range(np.random.randint(5, 20)))

    def train_model(self, n_samples=1000):
        try:
            print("Generating synthetic training data...")
            urls, labels = self.generate_synthetic_data(n_samples)
            if not urls or not labels:
                raise ValueError("No training data generated")
            print("Extracting features...")
            X = np.array([self._extract_link_features(url) for url in urls])
            y = np.array(labels)
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)
            print("Training model...")
            self.link_scaler = StandardScaler()
            X_train_scaled = self.link_scaler.fit_transform(X_train)
            X_test_scaled = self.link_scaler.transform(X_test)
            self.link_model = RandomForestClassifier(n_estimators=100, random_state=42)
            self.link_model.fit(X_train_scaled, y_train)
            y_pred = self.link_model.predict(X_test_scaled)
            print("\nModel Training Complete!")
            print("\nFraud Detection Metrics:")
            print(classification_report(y_test, y_pred))
            return True
        except Exception as e:
            print(f"Error training model: {e}")
            return False

    def analyze_url(self, url):
        try:
            if not self.link_model or not self.link_scaler:
                raise ValueError("Model not trained. Please run train_model() first.")
            features = np.array([self._extract_link_features(url)])
            features_scaled = self.link_scaler.transform(features)
            prediction = self.link_model.predict(features_scaled)[0]
            probabilities = self.link_model.predict_proba(features_scaled)[0]
            confidence = probabilities[prediction] * 100
            if confidence > 90:
                risk_level = 'Critical'
            elif confidence > 80:
                risk_level = 'High'
            elif confidence > 50:
                risk_level = 'Medium'   
            else:
                risk_level = 'Low'
            risk_factors = []
            if len(url) > 50:
                risk_factors.append("Unusually long URL")
            if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
                risk_factors.append("Contains IP address")
            if any(domain in url.lower() for domain in ['free', 'win', 'click']):
                risk_factors.append("Contains suspicious keywords")
            if url.count('/') > 3:
                risk_factors.append("Excessive slashes in the URL")
            if re.search(r'\.xyz|\.top|\.club', url):
                risk_factors.append("Uses a suspicious domain extension")
            if 'http' in url and not 'https' in url:
                risk_factors.append("Non-secure HTTP protocol")
            if len(re.findall(r'\d', url)) > 5:
                risk_factors.append("Contains excessive numbers in URL")
            return {
                'url': url,
                'is_fraud': bool(prediction),
                'confidence': round(confidence, 2),
                'risk_level': risk_level,
                'risk_factors': risk_factors
            }
        except Exception as e:
            print(f"Error analyzing URL: {e}")
            return None

if __name__ == "__main__":
    print("Initializing Fraud Detector...")
    detector = HybridFraudDetector()
    if detector.train_model():
        test_urls = [
            "https://www.legitimate-bank.com/login",
            "http://malicious-site.win/free-money",
            "https://suspicious.click/promo-offer",
            "http://192.168.1.1/admin-login",
            "https://secure-payment.com/checkout"
        ]
        print("\nAnalyzing Test URLs:")
        for url in test_urls:
            result = detector.analyze_url(url)
            if result:
                print(result)
