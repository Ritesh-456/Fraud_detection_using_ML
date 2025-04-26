import io
import qrcode
import time
import re
import hashlib
import pandas as pd
import numpy as np
import subprocess
import sys
import math
import json
from PIL import Image
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, precision_score, recall_score, f1_score # Added more metrics
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split, cross_val_score # Added cross_val_score
from collections import Counter

try:
    import cv2
except ImportError:
    print("Warning: OpenCV import failed. QR code features will be limited.")

class HybridFraudDetector:
    def __init__(self):
        self.link_model = None
        self.link_scaler = None
        # QR model/scaler are placeholders as QR analysis currently relies on link analysis
        self.qr_model = None
        self.qr_scaler = None
        self.confidence_threshold = 0.7 # This threshold isn't strictly used in the current analyze_url logic, but kept for reference
        self.has_cv2 = 'cv2' in sys.modules

    def _extract_link_features(self, url):
        """
        Extracts features from a given URL.
        TODO: Expand this function with more sophisticated features.
        """
        try:
            # Basic Lexical Features
            length = len(url)
            num_dots = url.count('.')
            num_slashes = url.count('/')
            num_digits = len(re.findall(r'\d', url))
            has_https = int('https' in url.lower())
            has_http = int('http' in url.lower()) # Feature: presence of http (non-secure)
            has_ip = int(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url) is not None) # Feature: IP address in URL
            has_at_symbol = int('@' in url) # Feature: presence of @ symbol (often used in phishing)
            has_double_slash_after_http = int(re.search(r'https?://[^/]+//', url) is not None) # Feature: double slash after protocol (suspicious)

            # Keyword Features
            suspicious_keywords = ["login", "verify", "update", "bank", "secure", "account", "free", "win", "promo", "temp", "gift"]
            keyword_count = sum(1 for keyword in suspicious_keywords if keyword in url.lower())

            # Domain-based Features (Basic)
            # More advanced domain features would require external lookups (WHOIS, etc.)
            domain = re.findall(r'https?://([^/]+)', url)
            domain = domain[0] if domain else ''
            domain_length = len(domain)
            # Simple check for common suspicious TLDs
            suspicious_tlds = ['.xyz', '.top', '.club', '.online', '.site', '.bid']
            has_suspicious_tld = int(any(url.lower().endswith(tld) for tld in suspicious_tlds))

            # Entropy (as before)
            probs = [n / len(domain) for n in Counter(domain).values()]
            entropy = -sum(p * math.log2(p) for p in probs) if probs else 0 # Handle empty domain case

            # Combine features into a list
            features = [
                length,
                num_dots,
                num_slashes,
                num_digits,
                has_https,
                has_http,
                has_ip,
                has_at_symbol,
                has_double_slash_after_http,
                keyword_count,
                domain_length,
                has_suspicious_tld,
                round(entropy, 3)
            ]

            # Ensure all features are numeric
            return [float(f) for f in features]

        except Exception as e:
            print(f"Error extracting features from URL {url}: {e}")
            # Return a list of zeros matching the expected number of features
            # Update this number if you add/remove features above
            return [0.0] * 13 # Ensure this matches the number of features returned above


    def generate_synthetic_data(self, n_samples=1000):
        """
        Generates synthetic URL data for training.
        TODO: Replace this with loading and preprocessing real-world datasets.
        """
        print("Generating synthetic training data...")
        urls = []
        labels = []
        try:
            base_domains_safe = ['https://www.example.com', 'https://secure-site.org', 'https://mybank.net']
            base_domains_fraud = ['http://temp-offer.xyz', 'http://free-money.top', 'https://login-verify.club']
            suspicious_keywords = ['win', 'free', 'click', 'promo', 'temp', 'update', 'verify', 'login', 'account']

            for _ in range(n_samples):
                is_fraud = np.random.random() < 0.4 # Adjust fraud ratio if needed
                if is_fraud:
                    # Create a potentially fraudulent URL
                    domain = np.random.choice(base_domains_fraud)
                    keyword = np.random.choice(suspicious_keywords)
                    path = self._generate_random_path()
                    # Add some common phishing patterns
                    patterns = [
                        f"{domain}/{keyword}/{path}",
                        f"{domain}.{keyword}/{path}", # Subdomain-like
                        f"http://{keyword}-{domain.split('//')[-1]}/{path}", # Keyword in subdomain
                        f"{domain}/login?user={self._generate_random_string(5)}", # Login form pattern
                        f"{domain}//{path}" # Double slash
                    ]
                    url = np.random.choice(patterns)
                    label = 1
                else:
                    # Create a likely safe URL
                    domain = np.random.choice(base_domains_safe)
                    path = self._generate_random_path()
                    url = f"{domain}/{path}"
                    label = 0
                urls.append(url)
                labels.append(label)
        except Exception as e:
            print(f"Error generating synthetic data: {e}")
            return [], []
        return urls, labels

    def _generate_random_path(self):
        """Generates a random URL path segment."""
        return ''.join(np.random.choice(list('abcdefghijklmnopqrstuvwxyz0123456789-'))
                         for _ in range(np.random.randint(5, 20)))

    def _generate_random_string(self, length):
         """Generates a random string of specified length."""
         return ''.join(np.random.choice(list('abcdefghijklmnopqrstuvwxyz0123456789'))
                         for _ in range(length))


    def train_model(self, n_samples=1000):
        """
        Trains the fraud detection model.
        TODO: Implement loading real data, more robust evaluation (cross-validation),
              and potentially saving/loading the trained model and scaler.
        """
        try:
            print("Generating synthetic training data...")
            urls, labels = self.generate_synthetic_data(n_samples)
            if not urls or not labels:
                print("No training data generated. Model training aborted.", file=sys.stderr)
                return False

            print(f"Generated {len(urls)} samples ({labels.count(1)} fraudulent, {labels.count(0)} safe).")

            print("Extracting features...")
            X = np.array([self._extract_link_features(url) for url in urls])
            y = np.array(labels)

            # Check if feature extraction resulted in consistent number of features
            if X.shape[1] != 13: # Update this number if you change the number of features
                 print(f"Error: Inconsistent number of features extracted. Expected 13, got {X.shape[1]}", file=sys.stderr)
                 return False

            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42, stratify=y) # Use stratify for imbalanced data

            print("Training model...")
            self.link_scaler = StandardScaler()
            X_train_scaled = self.link_scaler.fit_transform(X_train)
            X_test_scaled = self.link_scaler.transform(X_test)

            self.link_model = RandomForestClassifier(n_estimators=100, random_state=42, class_weight='balanced') # Use class_weight for imbalanced data
            self.link_model.fit(X_train_scaled, y_train)

            print("\nModel Training Complete!")

            # Evaluate the model
            y_pred = self.link_model.predict(X_test_scaled)
            y_proba = self.link_model.predict_proba(X_test_scaled)[:, 1] # Probability of being the positive class (fraudulent)

            print("\nFraud Detection Metrics (on test set):")
            print(f"Accuracy: {accuracy_score(y_test, y_pred):.4f}")
            print(f"Precision: {precision_score(y_test, y_pred):.4f}")
            print(f"Recall: {recall_score(y_test, y_pred):.4f}")
            print(f"F1-Score: {f1_score(y_test, y_pred):.4f}")
            print("\nClassification Report:")
            print(classification_report(y_test, y_pred))
            print("\nConfusion Matrix:")
            print(confusion_matrix(y_test, y_pred))

            # Optional: Cross-validation for more robust evaluation
            # print("\nCross-validation scores (5-fold):")
            # cv_scores = cross_val_score(RandomForestClassifier(n_estimators=100, random_state=42, class_weight='balanced'), self.link_scaler.transform(X), y, cv=5, scoring='f1') # Example using F1-score
            # print(f"F1-Scores: {cv_scores}")
            # print(f"Mean F1-Score: {cv_scores.mean():.4f}")


            # TODO: Save the trained model and scaler to disk (e.g., using joblib or pickle)
            # This avoids retraining every time the app starts.
            # Then, load them in __init__ or a separate load_model method.

            return True # Indicate training was attempted (even if metrics are poor with synthetic data)

        except Exception as e:
            print(f"Error training model: {e}", file=sys.stderr)
            return False

    def analyze_url(self, url):
        """
        Analyzes a URL using the trained model.
        TODO: Integrate external API checks for enhanced detection.
        """
        try:
            if not self.link_model or not self.link_scaler:
                print("Model not trained. Cannot analyze URL.", file=sys.stderr)
                # Attempt to train if not trained? Or just return error?
                # For now, return error.
                return {'url': url, 'is_fraud': False, 'confidence': 0, 'risk_level': 'Error', 'risk_factors': ["Model not trained"]}

            features = np.array([self._extract_link_features(url)])

            # Check if the number of features matches the scaler's expected input
            if features.shape[1] != self.link_scaler.n_features_in_:
                 print(f"Error: Feature mismatch during analysis. Expected {self.link_scaler.n_features_in_}, got {features.shape[1]}", file=sys.stderr)
                 return {'url': url, 'is_fraud': False, 'confidence': 0, 'risk_level': 'Error', 'risk_factors': ["Feature extraction mismatch"]}


            features_scaled = self.link_scaler.transform(features)

            # Get prediction and probabilities
            prediction = self.link_model.predict(features_scaled)[0]
            probabilities = self.link_model.predict_proba(features_scaled)[0]
            # Confidence is the probability of the predicted class
            confidence = probabilities[prediction] * 100

            # Determine risk level based on confidence and prediction
            risk_level = 'Unknown'
            if prediction == 1: # Predicted as fraudulent
                 if confidence > 90:
                     risk_level = 'Critical'
                 elif confidence > 80:
                     risk_level = 'High'
                 else: # Confidence 50-80 for fraud prediction
                     risk_level = 'Medium'
            else: # Predicted as safe
                 if confidence > 90:
                     risk_level = 'Safe' # High confidence in being safe
                 elif confidence > 70: # Confidence 70-90 for safe prediction
                     risk_level = 'Low'
                 else: # Confidence 50-70 for safe prediction - might still be medium risk depending on factors
                     risk_level = 'Medium' # Could be borderline or have some warning signs


            # Identify specific risk factors based on extracted features (heuristic)
            # This is separate from the model's prediction but helps explain the result
            risk_factors = []
            extracted_features = self._extract_link_features(url) # Re-extract to check individual values
            # Map features back to their meaning - ensure order matches _extract_link_features
            feature_names = [
                "length", "num_dots", "num_slashes", "num_digits", "has_https",
                "has_http", "has_ip", "has_at_symbol", "has_double_slash_after_http",
                "keyword_count", "domain_length", "has_suspicious_tld", "entropy"
            ]
            feature_dict = dict(zip(feature_names, extracted_features))


            if feature_dict["length"] > 75: # Adjusted threshold
                risk_factors.append("Unusually long URL")
            if feature_dict["has_ip"]:
                risk_factors.append("Contains IP address instead of domain name")
            if feature_dict["keyword_count"] > 0:
                risk_factors.append(f"Contains suspicious keywords ({feature_dict['keyword_count']})")
            if feature_dict["num_slashes"] > 5: # Adjusted threshold
                risk_factors.append("Excessive slashes in the URL path")
            if feature_dict["has_suspicious_tld"]:
                risk_factors.append("Uses a suspicious domain extension (TLD)")
            if feature_dict["has_http"] and not feature_dict["has_https"]:
                risk_factors.append("Uses non-secure HTTP protocol")
            if feature_dict["num_digits"] > 8: # Adjusted threshold
                risk_factors.append("Contains excessive numbers in URL")
            if feature_dict["has_at_symbol"]:
                 risk_factors.append("Contains '@' symbol (often used to hide true domain)")
            if feature_dict["has_double_slash_after_http"]:
                 risk_factors.append("Contains '//' after protocol (suspicious structure)")
            if feature_dict["entropy"] < 3.0 and feature_dict["domain_length"] > 15: # Example heuristic for low entropy on long domain
                 risk_factors.append("Low domain entropy for its length (might be machine generated)")


            # TODO: Add checks based on external API results here
            # Example:
            # external_check_result = check_external_apis(url)
            # if external_check_result['is_known_malicious']:
            #     risk_factors.append("Flagged by external reputation service")
            #     # Potentially adjust confidence/risk_level based on external findings


            # If predicted as fraud but no specific factors found (unlikely with current features, but good practice)
            if prediction == 1 and not risk_factors:
                 risk_factors.append("Flagged as fraudulent by the model")

            # If predicted as safe but some factors found (common for 'Medium' risk)
            if prediction == 0 and risk_factors and risk_level == 'Low':
                 # If predicted safe with low confidence but factors exist, maybe bump to Medium
                 if confidence < 70:
                      risk_level = 'Medium'


            return {
                'url': url,
                'is_fraud': bool(prediction), # Convert numpy bool to standard bool
                'confidence': round(confidence, 2),
                'risk_level': risk_level,
                'risk_factors': risk_factors if risk_factors else ["No specific risk factors identified"] # Ensure list is not empty
            }
        except Exception as e:
            print(f"Error analyzing URL: {e}", file=sys.stderr)
            return {'url': url, 'is_fraud': False, 'confidence': 0, 'risk_level': 'Error', 'risk_factors': [f"Analysis failed: {str(e)}"]}


    # TODO: Implement QR code specific feature extraction if needed,
    # beyond just decoding the URL and analyzing the URL.
    # E.g., analyze image properties, size, error correction level, etc.
    # def _extract_qr_features(self, image):
    #     pass # Placeholder

    # TODO: Implement a separate QR analysis method if QR-specific features/model are used
    # def analyze_qr_code(self, image):
    #     pass # Placeholder


if __name__ == "__main__":
    print("Initializing Fraud Detector...")
    detector = HybridFraudDetector()

    # Train the model when the script is run directly
    if detector.train_model(n_samples=2000): # Increased synthetic data samples
        test_urls = [
            "https://www.legitimate-bank.com/login", # Safe
            "http://malicious-site.win/free-money", # Fraudulent (http, .win, free, money)
            "https://suspicious.click/promo-offer", # Fraudulent (.click, promo)
            "http://192.168.1.1/admin-login", # Fraudulent (IP, http, login)
            "https://secure-payment.com/checkout", # Safe
            "https://www.google.com", # Safe
            "http://short.xyz/abc", # Fraudulent (http, .xyz, short path)
            "https://verylongdomainnameforaphishingattempt.online/verify/account/update/details/index.php?user=12345&sessionid=abcde", # Fraudulent (long domain, .online, verify, account, update, details, query params)
            "https://www.example.com/safe/path/to/page", # Safe
            "http://phishing.site//login" # Fraudulent (http, .site, double slash, login)
        ]
        print("\nAnalyzing Test URLs:")
        for url in test_urls:
            result = detector.analyze_url(url)
            if result:
                print(json.dumps(result, indent=2)) # Print results nicely formatted
            else:
                 print(f"Analysis failed for {url}")
    else:
         print("\nModel training failed. Cannot run analysis examples.")