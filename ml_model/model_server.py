from flask import Flask, request, jsonify
import numpy as np
import os
import joblib
from sklearn.ensemble import RandomForestClassifier

app = Flask(__name__)

# Feature names and their indices for the XGBoost model (in correct order)
FEATURE_NAMES = [
    'IAT',           # Index 0: The time difference with the previous packet
    'Tot sum',       # Index 1: Summation of packets lengths in flow
    'Rate',          # Index 2: Rate of packet transmission in a flow
    'flow_duration', # Index 3: Time between first and last packet received in flow
    'Duration',      # Index 4: Time-to-Live (ttl)
    'syn_count',     # Index 5: Number of packets with syn flag set in the same flow
    'urg_count',     # Index 6: Number of packets with urg flag set in the same flow
    'Number',        # Index 7: The number of packets in the flow
    'fin_count',     # Index 8: Number of packets with fin flag set in the same flow
    'ack_count',     # Index 9: Number of packets with ack flag set in the same flow
    'Protocol Type', # Index 10: Protocol numbers, as defined by the IANA (1-17, -1 for unknown)
    'ICMP',          # Index 11: Indicates if the network layer protocol is ICMP
    'TCP',           # Index 12: Indicates if the transport layer protocol is TCP
    'HTTP',          # Index 13: Indicates if the application layer protocol is HTTP
    'UDP'            # Index 14: Indicates if the transport layer protocol is UDP
]

# Load XGBoost model from joblib file
# Use absolute path based on script location
script_dir = os.path.dirname(os.path.abspath(__file__))
model_path = os.path.join(script_dir, 'xgboost_model_2.joblib')
if os.path.exists(model_path):
    try:
        model = joblib.load(model_path)
        print("Loaded XGBoost model from {0}".format(model_path))
    except Exception as e:
        print("Error loading XGBoost model: {0}".format(str(e)))
        # Fallback to pickle model if joblib fails
        import pickle
        fallback_model_path = os.path.join(script_dir, 'model.pkl')
        if os.path.exists(fallback_model_path):
            with open(fallback_model_path, 'rb') as f:
                model = pickle.load(f)
            print("Loaded fallback model from {0}".format(fallback_model_path))
        else:
            # Create a dummy model as last resort
            print("Creating a dummy RandomForestClassifier model for attack type detection")
            model = RandomForestClassifier(n_estimators=10, random_state=42)
            # Train with some dummy data (features, multi-class classification)
            num_samples = 100
            num_features = 15  # XGBoost model expects 15 features
            X_dummy = np.random.rand(num_samples, num_features)
            
            # Create labels: 0 for benign, 1-12 for different attack types
            y_dummy = np.random.randint(0, 13, size=num_samples)
            # Make 70% of samples benign (0)
            benign_indices = np.random.choice(num_samples, int(num_samples * 0.7), replace=False)
            y_dummy[benign_indices] = 0
            
            model.fit(X_dummy, y_dummy)
            
            # Save the model for future use
            with open(fallback_model_path, 'wb') as f:
                pickle.dump(model, f)
            print("Dummy model created and saved to {0}".format(fallback_model_path))
else:
    print("Model file {0} not found. Checking for fallback model.".format(model_path))
    # Fallback to pickle model
    import pickle
    fallback_model_path = os.path.join(script_dir, 'model.pkl')
    if os.path.exists(fallback_model_path):
        with open(fallback_model_path, 'rb') as f:
            model = pickle.load(f)
        print("Loaded fallback model from {0}".format(fallback_model_path))
    else:
        # Create a dummy model
        print("Creating a dummy RandomForestClassifier model for attack type detection")
        model = RandomForestClassifier(n_estimators=10, random_state=42)
        # Train with some dummy data
        num_samples = 100
        num_features = 15  # XGBoost model expects 15 features
        X_dummy = np.random.rand(num_samples, num_features)
        
        # Create labels: 0 for benign, 1-12 for different attack types
        y_dummy = np.random.randint(0, 13, size=num_samples)
        # Make 70% of samples benign (0)
        benign_indices = np.random.choice(num_samples, int(num_samples * 0.7), replace=False)
        y_dummy[benign_indices] = 0
        
        model.fit(X_dummy, y_dummy)
        
        # Save the model for future use
        with open(fallback_model_path, 'wb') as f:
            pickle.dump(model, f)
        print("Dummy model created and saved to {0}".format(fallback_model_path))

def validate_features(features):
    """
    Validate and clean the features from the Ryu controller.
    The features are already in the correct order for the XGBoost model.
    
    Expected feature order:
    0: IAT, 1: Tot sum, 2: Rate, 3: flow_duration, 4: Duration (TTL),
    5: syn_count, 6: urg_count, 7: Number, 8: fin_count, 9: ack_count,
    10: Protocol Type, 11: ICMP, 12: TCP, 13: HTTP, 14: UDP
    """
    # Ensure we have exactly 15 features
    if len(features) != 15:
        raise ValueError("Expected 15 features, got {0}".format(len(features)))
    
    # Convert to numpy array and ensure proper data types
    validated_features = np.array(features, dtype=float)
    
    # Validate Protocol Type (index 10) - should be 1-17 or -1
    if validated_features[10] < -1 or (validated_features[10] > 17 and validated_features[10] != -1):
        if validated_features[10] < 1 or validated_features[10] > 17:
            validated_features[10] = -1
    
    # Ensure binary indicators (ICMP, TCP, HTTP, UDP) are 0 or 1
    for idx in [11, 12, 13, 14]:  # ICMP, TCP, HTTP, UDP
        validated_features[idx] = 1 if validated_features[idx] > 0 else 0
    
    # Ensure counts are non-negative
    for idx in [5, 6, 7, 8, 9]:  # syn_count, urg_count, Number, fin_count, ack_count
        validated_features[idx] = max(0, validated_features[idx])
    
    return validated_features

@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.json
        raw_features = data['features']
        
        # Validate the features (they should already be in the correct order)
        validated_features = validate_features(raw_features)
        features_array = validated_features.reshape(1, -1)
        
        # Make prediction
        prediction = model.predict(features_array)
        attack_type = int(prediction[0])  # 0 for benign, 1-12 for attack types
        
        # Get prediction probabilities for all classes
        proba = model.predict_proba(features_array)[0]
        confidence = float(proba[attack_type]) if attack_type < len(proba) else 0.0
        print("Prediction:", attack_type, "Confidence:", confidence)
        
        return jsonify({
            'is_attack': bool(attack_type > 0),  # 0 is benign, 1-12 are attack types
            'attack_type': attack_type,
            'confidence': confidence,
            'features_count': len(raw_features),
            'protocol_type': int(validated_features[10]),
            'feature_names': FEATURE_NAMES
        })
    except Exception as e:
        print("Prediction error: {0}".format(str(e)))
        return jsonify({'error': str(e)}), 400

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint to verify if the model server is ready"""
    return jsonify({
        'status': 'ok',
        'model_type': type(model).__name__,
        'feature_count': len(FEATURE_NAMES)
    })

if __name__ == '__main__':
    print("ML model server starting up...")
    app.run(host='0.0.0.0', port=5000)
