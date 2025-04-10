from helpers.log import logger as log  # ✅ Import your log helper

def predict_fraud(data):
    try:
        # dummy logic
        if not data:
            raise ValueError("Empty input")
        return "Prediction successful"
    except Exception as e:
        log.log_model_error(str(e))  # ✅ Log the error
        return "Prediction failed"
