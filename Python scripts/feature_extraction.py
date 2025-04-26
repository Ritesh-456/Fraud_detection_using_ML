# D:\Projects\Fraud Detection using ML\Fraud_detection_using_ML\Python scripts\feature_extraction.py

import re
import urllib.parse
from collections import Counter
import numpy as np
import math

def extract_features(url):
    """
    Extracts features from a URL.
    NOTE: This function is not currently used by app.py.
    The feature extraction logic is integrated into the HybridFraudDetector class.
    """
    features = []

    features.append(url_length(url))
    features.append(has_https(url))
    features.append(count_special_chars(url))
    features.append(check_ip_in_url(url))
    features.append(is_shortened_url(url))
    features.append(suspicious_keywords(url))
    features.append(domain_entropy(url))

    return np.array(features).reshape(1, -1)

def url_length(url):
    return len(url)

def has_https(url):
    return int("https" in url.lower())

def count_special_chars(url):
    return len(re.findall(r"[!@#$%^&*(),?\":{}|<>]", url))

def check_ip_in_url(url):
    return int(re.search(r"(\d{1,3}\.){3}\d{1,3}", url) is not None)

def is_shortened_url(url):
    shortened_domains = ["bit.ly", "tinyurl.com", "goo.gl", "t.co"]
    return int(any(short in url for short in shortened_domains))

def suspicious_keywords(url):
    keywords = ["login", "verify", "update", "bank", "secure"]
    return int(any(kw in url.lower() for kw in keywords))

def domain_entropy(url):
    domain = urllib.parse.urlparse(url).netloc
    probs = [n / len(domain) for n in Counter(domain).values()]
    entropy = -sum(p * math.log2(p) for p in probs) if probs else 0 # Added check for empty domain
    return round(entropy, 3)


if __name__ == "__main__":
    # Example usage of the functions in this file
    test_url = "https://www.example.com/path?query=test"
    features = extract_features(test_url)
    print(f"Features for {test_url}: {features}")

    test_url_fraud = "http://bad.site.xyz/login.php"
    features_fraud = extract_features(test_url_fraud)
    print(f"Features for {test_url_fraud}: {features_fraud}")