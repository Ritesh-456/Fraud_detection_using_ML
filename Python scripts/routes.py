import sys
import os

current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
sys.path.append(project_root)

from helpers.db import handler as db

def analyze_url(url):
    result = {"url": url, "status": "analyzed"}
    db.save_url_result(result)
    return result

if __name__ == "__main__":
    test_url = "http://example.com"
    analysis_result = analyze_url(test_url)
    print(analysis_result)