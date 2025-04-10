import sys
import os

current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
sys.path.append(project_root)

from helpers.log import logger as log  

def predict_fraud(data):
    try:

        if not data:
            raise ValueError("Empty input")
        return "Prediction successful"
    except Exception as e:
        log.log_error(e)  
        return "Prediction failed"


if __name__ == "__main__":
    test_data = {"input": "some data"}
    prediction = predict_fraud(test_data)
    print(f"Prediction: {prediction}")