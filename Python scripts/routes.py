from helpers.db import handler as db 

def analyze_url(url):
    result = {"url": url, "status": "analyzed"}
    db.save_url_result(result)  
    return result
