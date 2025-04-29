# D:\Projects\Fraud Detection using ML\Fraud_detection_using_ML\Notebook\fraud_detection_model_.py

# This script contains the core machine learning model logic for fraud detection.
# It includes feature extraction, model training, saving, loading, and analysis functions.

# --- Standard Library Imports ---
import io
import time
import re
import hashlib
import json
import os
import sys
import math
import subprocess
import urllib.parse # Used for parsing URLs into components

# --- Third-Party Library Imports ---
# Ensure these are in your pyproject.toml and installed (uv sync or uv pip install .)
import pandas as pd # Useful for data handling (especially for loading data from files)
import numpy as np # Essential for numerical operations and array handling
from PIL import Image # Pillow for image handling (used with pyzbar)
import pyzbar.pyzbar # For decoding QR codes from images
# scikit-learn (Machine Learning library)
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, precision_score, recall_score, f1_score # Evaluation metrics
from sklearn.ensemble import RandomForestClassifier # The ML model
from sklearn.preprocessing import StandardScaler # For feature scaling
from sklearn.model_selection import train_test_split # For splitting data
from sklearn.model_selection import cross_val_score # For cross-validation
# joblib (For efficient saving/loading of Python objects)
import joblib
# collections (For counting elements)
from collections import Counter

# Optional: OpenCV (cv2) for more advanced image processing if needed for QR codes.
import logging # Ensure logging is imported
logger = logging.getLogger(__name__) # Get logger for this module
try:
    import cv2
    logger.debug("OpenCV imported successfully.")
except ImportError:
    logger.warning("OpenCV import failed. Advanced QR code features (if implemented) might be limited.")


# --- Model Saving/Loading Paths ---
# Define the directory where the trained model and scaler files will be saved.
MODEL_DIR = os.path.join(os.path.dirname(__file__), 'trained_models')
MODEL_FILE = os.path.join(MODEL_DIR, 'fraud_detection_model.pkl')
SCALER_FILE = os.path.join(MODEL_DIR, 'fraud_detection_scaler.pkl')

# Create the model directory if it doesn't exist.
os.makedirs(MODEL_DIR, exist_ok=True)


# --- Feature Names Definition ---
# Define a global list of the names of features extracted from URLs.
# This list must exactly match the order and count of features returned by _extract_link_features.
feature_names = [
    "length", "num_dots", "num_slashes", "num_digits", "has_https",
    "has_http", "has_ip", "has_at_symbol", "has_double_slash_after_protocol",
    "keyword_count", "domain_length", "has_suspicious_tld", "entropy",
    "path_length", "has_query", "has_fragment"
]
EXPECTED_FEATURE_COUNT = len(feature_names)


class HybridFraudDetector:
    """
    A hybrid system for detecting potential fraud in URLs or QR code contents.
    Combines heuristic feature extraction with a machine learning classifier.
    """
    def __init__(self):
        """Initializes the detector."""
        self.link_model = None
        self.link_scaler = None
        self.qr_model = None
        self.qr_scaler = None
        self.confidence_threshold = 0.7

        self.has_cv2 = 'cv2' in sys.modules

        if os.path.exists(MODEL_FILE) and os.path.exists(SCALER_FILE):
            logger.info(f"Found existing trained model and scaler files at '{MODEL_DIR}'.")
        else:
            logger.info(f"Trained model or scaler files not found at '{MODEL_DIR}'. Training may be required.")


    def _extract_link_features(self, url):
        """
        Extracts a numerical feature vector from a given URL string.
        Based on lexical and simple domain-based properties.
        TODO: Enhance with more advanced features for real-world accuracy (e.g., domain age, blacklist checks, content analysis).
        Args:
            url (str): The URL string to extract features from.
        Returns:
            list: A list of numerical features.
        """
        global EXPECTED_FEATURE_COUNT
        try:
            # Feature Engineering steps:

            # 1. Basic Lexical Features (Properties of the URL string itself)
            length = len(url)
            num_dots = url.count('.')
            num_slashes = url.count('/')
            num_digits = len(re.findall(r'\d', url))

            has_https = int('https://' in url.lower())
            has_http = int('http://' in url.lower())

            has_ip = int(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url) is not None)
            has_at_symbol = int('@' in url)

            has_double_slash_after_protocol = int(re.search(r'https?://[^/]+/+', url) is not None)


            # 2. Keyword Features (Presence of suspicious words)
            suspicious_keywords = ["login", "verify", "update", "bank", "secure", "account", "free", "win", "promo", "temp", "gift", "download", "file", "admin", "backup"]
            keyword_count = sum(1 for keyword in suspicious_keywords if keyword in url.lower())


            # 3. Domain-based Features (Properties of the domain/hostname part)
            domain = ''
            parsed_url = None
            try:
                 parsed_url = urllib.parse.urlparse(url)
                 domain = parsed_url.netloc
                 if '@' in domain:
                      domain = domain.split('@')[-1]
                 if ':' in domain:
                      domain = domain.split(':')[0]
            except Exception as e:
                 logger.debug(f"Could not parse domain from URL {url[:100]}... during feature extraction: {e}")
                 domain = ''

            domain_length = len(domain)

            suspicious_tlds = ['.xyz', '.top', '.club', '.online', '.site', '.bid', '.cn', '.ru', '.gq', '.cf', '.tk', '.ml', '.ga']
            tld = ''
            if domain:
                 parts = domain.split('.')
                 if len(parts) > 1:
                      tld = '.' + parts[-1].lower()
                 has_suspicious_tld = int(tld in suspicious_tlds)
            else:
                 has_suspicious_tld = 0

            domain_no_tld = '.'.join(domain.split('.')[:-1]) if domain and len(domain.split('.')) > 1 else domain
            domain_no_tld = domain_no_tld.replace('.', '')
            probs = [domain_no_tld.count(c) / len(domain_no_tld) for c in set(domain_no_tld)] if domain_no_tld else []
            entropy = -sum(p * math.log2(p) for p in probs) if probs else 0

            # TODO: Add Advanced Domain Features here (Requires external libraries/APIs)
            # Example placeholders (need actual implementation):
            # domain_age = self._get_domain_age(domain)
            # is_known_malicious_domain = self._check_domain_blacklist(domain)
            # domain_has_mx = self._check_mx_records(domain)


            # 4. Path and Query Features
            path = parsed_url.path if parsed_url else ''
            path_length = len(path)
            has_query = int(bool(parsed_url.query if parsed_url else ''))
            has_fragment = int(bool(parsed_url.fragment if parsed_url else ''))

            # TODO: Add Path/Query/Fragment Features here
            # Example:
            # has_risky_extension = int(path.lower().endswith(('.exe', '.zip', '.rar', '.tgz', '.bat')))
            # query_string_length = len(parsed_url.query if parsed_url else '')
            # num_query_params = len(urllib.parse.parse_qs(parsed_url.query).keys() if parsed_url and parsed_url.query else 0)


            # TODO: Add Content-based Features here (Requires fetching the page content)
            # Example placeholders:
            # page_content = self._fetch_page_content(url)
            # has_login_form = self._check_for_login_form(page_content)
            # content_has_keywords = sum(1 for kw in suspicious_keywords if kw in page_content.lower())
            # page_similarity_score = self._compare_to_known_sites(page_content, domain)


            # TODO: Add Redirect Features (Requires making network requests)
            # final_url, num_redirects = self._follow_redirects(url)
            # final_url_is_different = int(url != final_url)
            # final_domain_is_suspicious = self._extract_link_features(final_url).get('has_suspicious_tld', 0)


            features = [
                length,
                num_dots,
                num_slashes,
                num_digits,
                has_https,
                has_http,
                has_ip,
                has_at_symbol,
                has_double_slash_after_protocol,
                keyword_count,
                domain_length,
                has_suspicious_tld,
                round(entropy, 3),
                path_length,
                has_query,
                has_fragment,
                # TODO: Add your new feature variables here in the same order every time
                # domain_age, is_known_malicious_domain, domain_has_mx, ...
                # has_risky_extension, query_string_length, num_query_params, ...
                # has_login_form, content_has_keywords, page_similarity_score, ...
                # final_url_is_different, num_redirects, final_domain_is_suspicious, ...
            ]

            if len(features) != EXPECTED_FEATURE_COUNT:
                logger.error(f"Feature extraction resulted in incorrect number of features for URL {url[:100]}... Expected {EXPECTED_FEATURE_COUNT}, got {len(features)}. Check _extract_link_features and feature_names list.")
                return [0.0] * EXPECTED_FEATURE_COUNT

            return [float(f) for f in features]

        except Exception as e:
            logger.exception(f"Critical Error during feature extraction from URL {url[:100]}...")
            return [0.0] * EXPECTED_FEATURE_COUNT

    # TODO: Implement new feature extraction helper methods (if adding advanced features)
    # def _get_domain_age(self, domain):
    #      # Implement using python-whois or external API lookup
    #      return 0 # Dummy return
    # def _check_domain_blacklist(self, domain):
    #      # Implement using blacklist APIs (e.g., Google Safe Browsing)
    #      return 0 # Dummy return
    # ... add other helper methods here ...


    def load_real_data(self, file_path):
        """
        Loads labeled real-world URL data from a specified file.
        TODO: Implement actual loading and initial preprocessing based on your dataset format.
        This function needs to read the file at file_path and return two lists: urls and labels.
        Args:
            file_path (str): Path to the dataset file (e.g., CSV, JSON).
        Returns:
            tuple: (list of URLs, list of integer labels), or ([], []) on error.
        """
        logger.info(f"Attempting to load real-world data from '{file_path}'...")
        urls = []
        labels = []
        try:
            # --- TODO: YOUR IMPLEMENTATION GOES HERE ---
            # This is where you write the code to read your specific dataset file.
            # Example for a CSV file with columns 'url' and 'label' (0 or 1):
            if not os.path.exists(file_path):
                logger.error(f"Data file not found at '{file_path}'.")
                return [], [] # Return empty lists if file doesn't exist

            # Example using pandas to read CSV:
            # Ensure you have pandas installed (`uv pip install pandas`)
            try:
                df = pd.read_csv(file_path)
            except Exception as e:
                logger.error(f"Error reading data file '{file_path}': {e}")
                return [], []

            # Ensure necessary columns ('url' and 'label') exist in the DataFrame
            if 'url' not in df.columns or 'label' not in df.columns:
                logger.error(f"Data file '{file_path}' must contain 'url' and 'label' columns.")
                return [], []

            # Extract the 'url' and 'label' columns as lists
            urls = df['url'].tolist()
            labels = df['label'].tolist()
            # Ensure labels are integers (0 or 1)
            labels = [int(label) for label in labels]

            # --- END YOUR IMPLEMENTATION ---


            if not urls or len(urls) != len(labels) or len(urls) < 2: # Need at least 2 samples for train/test split
                 logger.error(f"Loaded insufficient or mismatched data from '{file_path}'. Found {len(urls)} URLs and {len(labels)} labels.")
                 return [], []


            logger.info(f"Successfully loaded {len(urls)} samples from '{file_path}'. ({labels.count(1)} fraudulent, {labels.count(0)} safe).")
            return urls, labels

        except Exception as e:
            logger.exception(f"Unexpected error loading real-world data from '{file_path}'.")
            return [], [] # Return empty on unexpected error


    def generate_synthetic_data(self, n_samples=10000):
        """
        Generates synthetic URL strings and corresponding fraud/safe labels (0 or 1) for training.
        This is a placeholder for using real-world datasets.
        Args:
            n_samples (int): The number of synthetic URL samples to generate.
        Returns:
            tuple: (list of generated urls, list of corresponding integer labels), or ([], []) on error.
        """
        logger.info(f"Generating {n_samples} synthetic training data samples...")
        urls = []
        labels = []
        try:
            base_domains_safe = ['https://www.google.com', 'https://www.microsoft.com', 'https://secure-bank.org', 'https://myonlinestore.net', 'https://docs.example.com', 'https://github.com', 'https://stackoverflow.com']
            base_domains_fraud = ['http://temp-offer.xyz', 'http://free-money.top', 'https://login-verify.club', 'http://suspicious-site.bid', 'https://update-your-info.online', 'http://phishing.gq', 'https://myaccount.ga']
            suspicious_keywords = ['win', 'free', 'click', 'promo', 'temp', 'update', 'verify', 'login', 'account', 'giftcard', 'alert', 'security', 'payment', 'download', 'bonus']
            common_paths = ['/', '/index.html', '/home', '/about', '/products', '/contact', '/blog/article', '/docs/manual']
            suspicious_paths = ['/admin/', '/.env', '/backup/', '/password.txt', '/cgi-bin/', '/temp/', '/install.php', '/data/', '/files/']

            for _ in range(n_samples):
                is_fraud = np.random.random() < 0.4

                if is_fraud:
                    domain_base = np.random.choice(base_domains_fraud)
                    domain = domain_base.split('//')[-1]

                    keyword_part = np.random.choice(suspicious_keywords) if np.random.random() < 0.7 else ''
                    subdomain_part = f"{keyword_part}-{self._generate_random_string(4)}." if np.random.random() < 0.3 and keyword_part else ''

                    protocol = np.random.choice(['http://', 'https://'])
                    ip_address_part = f"@{self._generate_random_ip()}" if np.random.random() < 0.1 else ''
                    use_ip_as_host = np.random.random() < 0.15

                    host = self._generate_random_ip() if use_ip_as_host else (subdomain_part + domain)
                    url_prefix = f"{protocol}{host}{ip_address_part}"

                    path_segment = np.random.choice(suspicious_paths + [self._generate_random_path(min_len=5, max_len=30)]) if np.random.random() < 0.6 else ''
                    path_prefix = '//' if np.random.random() < 0.15 and path_segment else '/'
                    path = f"{path_prefix}{path_segment}" if path_segment else ''

                    query_params = f"?{self._generate_random_string(np.random.randint(3, 10))}={self._generate_random_string(np.random.randint(5, 15))}" if np.random.random() < 0.5 else ''
                    fragment = f"#{self._generate_random_string(np.random.randint(3, 8))}" if np.random.random() < 0.2 else ''

                    url = f"{url_prefix}{path}{query_params}{fragment}"
                    label = 1

                else:
                    domain_base = np.random.choice(base_domains_safe)
                    domain = domain_base.split('//')[-1]
                    protocol = 'https://'
                    host = domain
                    url_prefix = f"{protocol}{host}"

                    path_segment = np.random.choice(common_paths + [self._generate_random_path(min_len=3, max_len=20)]) if np.random.random() < 0.8 else '/'
                    path_prefix = '/'
                    path = f"{path_prefix}{path_segment}"

                    query_params = f"?id={np.random.randint(100, 9999)}" if np.random.random() < 0.2 else ''
                    fragment = f"#section-{np.random.randint(1, 10)}" if np.random.random() < 0.1 else ''

                    url = f"{url_prefix}{path}{query_params}{fragment}"
                    label = 0

                urls.append(url)
                labels.append(label)

        except Exception as e:
            logger.exception(f"Error generating synthetic data: {e}")
            return [], []

        logger.info(f"Generated {len(urls)} synthetic samples ({labels.count(1)} fraudulent, {labels.count(0)} safe).")
        return urls, labels

    def _generate_random_path(self, min_len=5, max_len=20):
        """Generates a random string suitable for a URL path segment."""
        characters = 'abcdefghijklmnopqrstuvwxyz0123456789-'
        return ''.join(np.random.choice(list(characters))
                         for _ in range(np.random.randint(min_len, max_len + 1)))

    def _generate_random_string(self, length):
         """Generates a random alphanumeric string of specified length."""
         characters = 'abcdefghijklmnopqrstuvwxyz0123456789'
         return ''.join(np.random.choice(list(characters)) for _ in range(length))

    def _generate_random_ip(self):
        """Generates a random fake IPv4 address string."""
        return f"{np.random.randint(1, 255)}.{np.random.randint(0, 255)}.{np.random.randint(0, 255)}.{np.random.randint(1, 254)}"


    def save_model(self):
        """Saves the trained link model and scaler to disk using joblib."""
        if not self.link_model or not self.link_scaler:
            logger.warning("Cannot save model or scaler: One or both objects are not trained/available.")
            return False

        try:
            joblib.dump(self.link_model, MODEL_FILE)
            joblib.dump(self.link_scaler, SCALER_FILE)
            logger.info(f"Model and scaler saved successfully to '{MODEL_DIR}'.")
            return True
        except Exception as e:
            logger.error(f"Error saving model or scaler to '{MODEL_DIR}': {e}", exc_info=True)
            return False


    def load_model(self):
        """Loads the trained link model and scaler from disk using joblib."""
        if not os.path.exists(MODEL_FILE) or not os.path.exists(SCALER_FILE):
            logger.info(f"Model file ('{os.path.basename(MODEL_FILE)}') or scaler file ('{os.path.basename(SCALER_FILE)}') not found at '{MODEL_DIR}'. Loading skipped.")
            return False

        try:
            self.link_model = joblib.load(MODEL_FILE)
            self.link_scaler = joblib.load(SCALER_FILE)
            logger.info(f"Model and scaler loaded successfully from '{MODEL_DIR}'.")

            if self.link_model is None or self.link_scaler is None or not hasattr(self.link_model, 'predict') or not hasattr(self.link_scaler, 'transform'):
                 logger.error("Loading failed: Loaded objects are None or missing expected attributes (predict/transform).")
                 self.link_model = None
                 self.link_scaler = None
                 return False

            if hasattr(self.link_scaler, 'n_features_in_') and self.link_scaler.n_features_in_ != EXPECTED_FEATURE_COUNT:
                 logger.warning(f"Loaded scaler expects {self.link_scaler.n_features_in_} features, but current feature extraction code expects {EXPECTED_FEATURE_COUNT}. This might cause errors. Consider retraining or checking code/model version.")

            logger.debug(f"Loaded model type: {type(self.link_model)}, Scaler type: {type(self.link_scaler)}")
            return True

        except Exception as e:
            logger.error(f"Error loading model or scaler from '{MODEL_DIR}': {e}", exc_info=True)
            self.link_model = None
            self.link_scaler = None
            return False


    def train_model(self, n_samples=10000, data_path=None):
        """
        Trains the fraud detection model.
        Can use synthetic data (default) or load from a file if data_path is provided.
        Args:
            n_samples (int): Number of synthetic samples if data_path is None.
            data_path (str, optional): Path to a real-world dataset file. If provided, n_samples is ignored.
                                       The file format must be handled by the load_real_data method.
        Returns:
            bool: True if training completed successfully, False if training failed.
        """
        logger.info("Starting model training process...")
        try:
            urls = []
            labels = []
            if data_path:
                 # Load data from file if path is provided
                 urls, labels = self.load_real_data(data_path)
            else:
                 # Otherwise, generate synthetic data
                 urls, labels = self.generate_synthetic_data(n_samples)


            if not urls or len(urls) != len(labels) or len(urls) < 2: # Need at least 2 samples for split
                logger.error("Training data (real or synthetic) generation failed or returned insufficient data.")
                self.link_model = None
                self.link_scaler = None
                return False

            logger.info("Extracting features for the training dataset...")
            # Use the _extract_link_features method for consistency. It handles its own errors and returns zeros on critical failure.
            X = np.array([self._extract_link_features(url) for url in urls])
            y = np.array(labels)

             # Check if the feature matrix has the expected number of columns/features
            if X.shape[1] != EXPECTED_FEATURE_COUNT:
                  logger.error(f"Error: Feature matrix shape mismatch after extraction. Expected {EXPECTED_FEATURE_COUNT} columns, but got {X.shape[1]}.")
                  self.link_model = None
                  self.link_scaler = None
                  return False

            if not np.isfinite(X).all():
                 logger.error("Training feature data contains non-finite values (NaN, Inf). Cannot train model. Investigate feature extraction.")
                 self.link_model = None
                 self.link_scaler = None
                 return False

            logger.info(f"Training data shape: X={X.shape}, y={y.shape}")

            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42, stratify=y)

            logger.info("Initializing and fitting StandardScaler on training data...")
            self.link_scaler = StandardScaler()
            X_train_scaled = self.link_scaler.fit_transform(X_train)
            X_test_scaled = self.link_scaler.transform(X_test)


            logger.info("Initializing and training RandomForestClassifier model...")
            self.link_model = RandomForestClassifier(
                 n_estimators=200,
                 random_state=42,
                 class_weight='balanced',
                 max_depth=25,
                 min_samples_leaf=5,
                 min_samples_split=10,
                 n_jobs=-1
             )
            self.link_model.fit(X_train_scaled, y_train)

            logger.info("Model Training Complete.")

            logger.info("Evaluating model performance on the test set...")
            if X_test_scaled.size > 0:
                y_pred = self.link_model.predict(X_test_scaled)

                accuracy = accuracy_score(y_test, y_pred)
                precision = precision_score(y_test, y_pred, zero_division=0)
                recall = recall_score(y_test, y_pred, zero_division=0)
                f1 = f1_score(y_test, y_pred, zero_division=0)


                logger.info("\nFraud Detection Metrics (on test set):")
                logger.info(f"Accuracy: {accuracy:.4f}")
                logger.info(f"Precision (Fraudulent): {precision:.4f}")
                logger.info(f"Recall (Fraudulent): {recall:.4f}")
                logger.info(f"F1-Score (Fraudulent): {f1:.4f}")

                logger.info("\nClassification Report (on test set):\n" + classification_report(y_test, y_pred, zero_division=0))
                logger.info("\nConfusion Matrix (on test set):\n" + str(confusion_matrix(y_test, y_pred)))

            else:
                logger.warning("Test set is empty (likely due to small n_samples). Skipping model evaluation metrics.")

            return True

        except Exception as e:
            logger.exception(f"Critical Error during model training: {e}")
            self.link_model = None
            self.link_scaler = None
            return False


    def analyze_url(self, url):
        """Analyzes a single URL string using the trained ML model."""
        try:
            if not self.link_model or not self.link_scaler:
                logger.error("Analysis failed: Model or scaler is not loaded/trained. Cannot proceed with analysis.")
                return {
                     'url': url,
                     'is_fraud': False,
                     'confidence': 0,
                     'risk_level': 'Error',
                     'risk_factors': ["Analysis model is not trained or loaded. Please ensure the backend started correctly."]
                 }

            features = np.array([self._extract_link_features(url)])

            if features.shape[1] != self.link_scaler.n_features_in_ or not np.isfinite(features).all():
                 if features.shape[1] != self.link_scaler.n_features_in_:
                     logger.error(f"Analysis failed: Feature count mismatch for URL '{url[:100]}...'. Scaler expects {self.link_scaler.n_features_in_} features, but extraction returned {features.shape[1]}. Check code/model-data sync.")
                 elif not np.isfinite(features).all():
                     logger.error(f"Analysis failed: Extracted features for URL '{url[:100]}...' contain non-finite values (NaN, Inf). Features: {features}")

                 return {
                      'url': url, 'is_fraud': False, 'confidence': 0, 'risk_level': 'Error',
                      'risk_factors': ["Analysis failed: Feature extraction issue detected. Please check backend logs."]
                   }

            features_scaled = self.link_scaler.transform(features)

            prediction = self.link_model.predict(features_scaled)[0]
            prediction_int = int(prediction)

            probabilities = self.link_model.predict_proba(features_scaled)[0]
            confidence = probabilities[prediction_int] * 100


            is_fraud_flag = bool(prediction_int)

            risk_level = 'Unknown'
            if is_fraud_flag:
                 if confidence >= 90:
                     risk_level = 'Critical'
                 elif confidence >= 75:
                     risk_level = 'High'
                 else:
                      risk_level = 'Medium'

            else:
                 if confidence >= 95:
                     risk_level = 'Safe'
                 elif confidence >= 80:
                     risk_level = 'Low'
                 else:
                      risk_level = 'Medium'


            risk_factors = []
            if features.shape[0] > 0 and features.shape[1] == EXPECTED_FEATURE_COUNT:
                extracted_features_dict = dict(zip(feature_names, features[0]))

                if extracted_features_dict.get("length", 0) > 100:
                    risk_factors.append("Unusually long URL (> 100 characters)")
                if extracted_features_dict.get("has_ip"):
                    risk_factors.append("URL contains IP address instead of a readable domain name")
                if extracted_features_dict.get("keyword_count", 0) > 0:
                    risk_factors.append(f"Contains suspicious keywords ({int(extracted_features_dict['keyword_count'])} found)")
                if extracted_features_dict.get("num_slashes", 0) > 7:
                    risk_factors.append("Excessive slashes in the URL path (> 7)")
                if extracted_features_dict.get("has_suspicious_tld"):
                    risk_factors.append("Uses a suspicious domain extension (TLD)")
                if extracted_features_dict.get("has_http", 0) and not extracted_features_dict.get("has_https", 0):
                    risk_factors.append("Uses non-secure HTTP protocol (HTTPS not used)")
                if extracted_features_dict.get("num_digits", 0) > 10:
                    risk_factors.append(f"Contains many digits in the URL ({int(extracted_features_dict['num_digits'])})")
                if extracted_features_dict.get("has_at_symbol"):
                     risk_factors.append("Contains '@' symbol (can be used for deception)")
                if extracted_features_dict.get("has_double_slash_after_protocol"):
                     risk_factors.append("Contains '//' immediately after protocol/netloc (suspicious structure)")

                domain_len = extracted_features_dict.get("domain_length", 0)
                entropy_val = extracted_features_dict.get("entropy", 0)
                if domain_len > 20 and entropy_val < 3.5:
                      risk_factors.append(f"Low domain entropy ({entropy_val:.2f}) for its length ({domain_len})")

                if extracted_features_dict.get("path_length", 0) > 60:
                     risk_factors.append(f"Long path segment ({int(extracted_features_dict['path_length'])} characters)")

                if extracted_features_dict.get("has_query", 0):
                    risk_factors.append("URL includes a query string")

            if is_fraud_flag and not any("Flagged as fraudulent by the model" in factor for factor in risk_factors):
                 risk_factors.append("Flagged as fraudulent by the machine learning model based on learned patterns")


            return {
                'url': url,
                'is_fraud': is_fraud_flag,
                'confidence': round(confidence, 2),
                'risk_level': risk_level,
                'risk_factors': risk_factors if risk_factors else ["No specific heuristic risk factors identified"]
            }
        except Exception as e:
            logger.exception(f"Critical Error during analyze_url for URL '{url[:100]}...'.")
            return {
                'url': url,
                'is_fraud': False,
                'confidence': 0,
                'risk_level': 'Error',
                'risk_factors': [f"An unexpected internal error occurred during analysis: {str(e)}"]
            }


    # TODO: Implement QR code specific feature extraction if needed, beyond decoding URL.
    # This typically requires image processing libraries like OpenCV.
    # def _extract_qr_features(self, image):
    #     """Placeholder: Extracts features from a QR code image itself."""
    #     pass

    # TODO: Implement a dedicated QR code analysis method if QR-specific features/model are used.
    # def analyze_qr_code(self, image):
    #     """Placeholder: Analyzes a QR code image using QR-specific features and model."""
    #     pass


# Example Usage Block - This runs only when this script is executed directly.
if __name__ == "__main__":
    print("\n--- Running Notebook/fraud_detection_model_.py for testing ---")

    # Configure logging for this standalone script run.
    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    logger = logging.getLogger(__name__)
    logger.info("Logging configured for standalone model testing.")

    detector = HybridFraudDetector()

    model_ready = False
    logger.info(f"Attempting to load the fraud detection model and scaler from '{MODEL_DIR}'.")
    if detector.load_model():
        logger.info("Successfully loaded existing model and scaler.")
        model_ready = True

    else:
        logger.warning("Existing model or scaler not found or loading failed. Proceeding to model training.")
        # --- Modified to train with a data file if available ---
        # Define the path to your real-world training data file (e.g., a CSV).
        # You MUST REPLACE 'your_real_data.csv' with the actual name/path of your file.
        # Place the file in the same directory as this script (Notebook) for this example path to work.
        real_data_file_path = os.path.join(os.path.dirname(__file__), 'your_real_data.csv')

        if os.path.exists(real_data_file_path):
             logger.info(f"Found real-world data file at '{real_data_file_path}'. Training using real data.")
             # Call train_model, passing the file path. train_model will call load_real_data.
             if detector.train_model(data_path=real_data_file_path):
                 logger.info("Model training with real data completed successfully.")
                 if detector.save_model():
                      logger.info("Trained model and scaler saved successfully.")
                      model_ready = True
                 else:
                      logger.error("Model training successful, but failed to save the trained model! Analysis may still work for this session.")
                      model_ready = True
             else:
                 logger.critical("Model training with real data failed. Cannot perform analysis tests.")
                 model_ready = False
        else:
             # If no real data file found at the specified path, fall back to synthetic data training.
             logger.warning(f"Real-world data file not found at '{real_data_file_path}'. Falling back to synthetic data training.")
             synthetic_samples_for_training = 10000
             logger.info(f"Starting synthetic data training with {synthetic_samples_for_training} samples.")
             if detector.train_model(n_samples=synthetic_samples_for_training): # Train with synthetic data
                 logger.info("Synthetic data training completed successfully.")
                 logger.info(f"Attempting to save the newly trained model and scaler to '{MODEL_DIR}'.")
                 if detector.save_model():
                      logger.info("Trained model and scaler saved successfully.")
                      model_ready = True
                 else:
                      logger.error("Model training successful, but failed to save the trained model! Analysis may still work for this session.")
                      model_ready = True
             else:
                 logger.critical("Synthetic data training failed. Cannot perform analysis tests.")
                 model_ready = False
        # --- End Modified Training Logic ---

    if model_ready:
        logger.info("\n--- Running Analysis Examples ---")
        # Define a list of test URLs.
        # Include some synthetic fraudulent examples and real legitimate examples.
        # These are used here just to demonstrate the analyze_url function output.
        test_urls = [
            "https://www.legitimate-bank.com/login/access?id=user123", # Safe synthetic
            "http://malicious-site.win/free-money.php?giveaway=now#promo", # Fraudulent synthetic
            "https://suspicious.click/promo-offer/.env", # Fraudulent synthetic
            "http://192.168.1.1//admin-login.html", # Fraudulent synthetic (IP address)
            "https://www.google.com/", # Real legitimate
            "https://www.youtube.com/", # Real legitimate
            "https://github.com/", # Real legitimate
            "https://www.paypal.com/", # Real legitimate (common phishing target)
            "https://pay.google.com/", # Real legitimate (example from user)
            "https://www.phonepe.com/", # Real legitimate (example from user)
             "http://fake-bank-login.xyz", # Fraudulent synthetic
        ]

        # Iterate through the test URLs and analyze each one.
        for url in test_urls:
            logger.info("-" * 50) # Separator in logs
            logger.info(f"Analyzing URL: {url}") # Log the URL being analyzed

            # Call the analyze_url method. It returns a dictionary result or an error dict.
            result = detector.analyze_url(url)

            # Print analysis result details to the console for testing.
            if isinstance(result, dict):
                is_fraud = result.get('is_fraud', False)
                risk_level = result.get('risk_level', 'Unknown')
                confidence = result.get('confidence', 0)
                risk_factors = result.get('risk_factors', [])

                print(f"URL: {url}")
                print(f"Status: {'Fraudulent' if is_fraud else 'Not Fraudulent'}")
                print(f"Risk Level: {risk_level}")
                print(f"Confidence: {confidence:.2f}%")
                print(f"Risk Factors: {', '.join(risk_factors)}") # Join factors for single line

            else:
                 logger.error(f"analyze_url function returned unexpected result type for {url[:100]}...: {type(result)}")

        logger.info("-" * 50)
        logger.info("--- Analysis Examples Complete ---")

    else:
         # If the model was not ready (loading or training failed), skip analysis examples.
         logger.error("Model was not ready. Analysis examples skipped.")

    print("\n--- Notebook/fraud_detection_model_.py Testing Complete ---")