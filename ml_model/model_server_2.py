from flask import Flask, request, jsonify
import numpy as np
import os
import joblib
from sklearn.ensemble import RandomForestClassifier

app = Flask(__name__)

# Feature names and their indices for the model (in correct order) - 33 features
FEATURE_NAMES = [
    'flow_duration',      # Index 0: Time between first and last packet in the flow
    'Protocol_Type',      # Index 1: Protocol type (TCP, UDP, ICMP, etc.)
    'Duration',           # Index 2: TTL value
    'Rate',               # Index 3: Packet transmission rate in the flow
    'Drate',              # Index 4: Inbound packet transmission rate
    'fin_flag_number',    # Index 5: FIN flag value (0/1)
    'syn_flag_number',    # Index 6: SYN flag value (0/1)
    'rst_flag_number',    # Index 7: RST flag value (0/1)
    'psh_flag_number',    # Index 8: PSH flag value (0/1)
    'ack_flag_number',    # Index 9: ACK flag value (0/1)
    'ece_flag_number',    # Index 10: ECE flag value (0/1)
    'cwr_flag_number',    # Index 11: CWR flag value (0/1)
    'ack_count',          # Index 12: Number of packets with ACK flag
    'syn_count',          # Index 13: Number of packets with SYN flag
    'fin_count',          # Index 14: Number of packets with FIN flag
    'urg_count',          # Index 15: Number of packets with URG flag
    'HTTP',               # Index 16: HTTP protocol indicator (0/1)
    'HTTPS',              # Index 17: HTTPS protocol indicator (0/1)
    'DNS',                # Index 18: DNS protocol indicator (0/1)
    'Telnet',             # Index 19: Telnet protocol indicator (0/1)
    'SMTP',               # Index 20: SMTP protocol indicator (0/1)
    'SSH',                # Index 21: SSH protocol indicator (0/1)
    'IRC',                # Index 22: IRC protocol indicator (0/1)
    'TCP',                # Index 23: TCP protocol indicator (0/1)
    'UDP',                # Index 24: UDP protocol indicator (0/1)
    'DHCP',               # Index 25: DHCP protocol indicator (0/1)
    'ARP',                # Index 26: ARP protocol indicator (0/1)
    'ICMP',               # Index 27: ICMP protocol indicator (0/1)
    'IPv',                # Index 28: IPv protocol indicator (0/1)
    'LLC',                # Index 29: LLC protocol indicator (0/1)
    'Tot_sum',            # Index 30: Sum of packet lengths in flow
    'IAT',                # Index 31: Inter-arrival time between packets
    'Number'              # Index 32: Number of packets in the flow
]

# Load model from joblib file
# Use absolute path based on script location
script_dir = os.path.dirname(os.path.abspath(__file__))
model_path = os.path.join(script_dir, 'xgboost_model_spearman.joblib')
if os.path.exists(model_path):
    try:
        model = joblib.load(model_path)
        print("Loaded XGBoost model from {0}".format(model_path))
    except Exception as e:
        print("Error loading XGBoost model: {0}".format(str(e)))
        # Fallback to pickle model if joblib fails
        import pickle
        fallback_model_path = os.path.join(script_dir, 'model_2.pkl')
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
            num_features = 33  # Model expects 33 features
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
    fallback_model_path = os.path.join(script_dir, 'model_2.pkl')
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
        num_features = 33  # Model expects 33 features
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
    The features are already in the correct order for the model.
    
    Expected feature order (33 features):
    0: flow_duration, 1: Protocol_Type, 2: Duration, 3: Rate, 4: Drate,
    5: fin_flag_number, 6: syn_flag_number, 7: rst_flag_number, 8: psh_flag_number, 9: ack_flag_number,
    10: ece_flag_number, 11: cwr_flag_number, 12: ack_count, 13: syn_count, 14: fin_count,
    15: urg_count, 16: HTTP, 17: HTTPS, 18: DNS, 19: Telnet,
    20: SMTP, 21: SSH, 22: IRC, 23: TCP, 24: UDP,
    25: DHCP, 26: ARP, 27: ICMP, 28: IPv, 29: LLC,
    30: Tot_sum, 31: IAT, 32: Number
    """
    # Ensure we have exactly 33 features
    if len(features) != 33:
        raise ValueError("Expected 33 features, got {0}".format(len(features)))
    
    # Convert to numpy array and ensure proper data types
    validated_features = np.array(features, dtype=float)
    
    # Validate Protocol Type (index 1) - should be 1-17 or -1
    if validated_features[1] < -1 or (validated_features[1] > 17 and validated_features[1] != -1):
        validated_features[1] = -1
    
    # Ensure binary indicators (flags and protocol indicators) are 0 or 1
    binary_indices = list(range(5, 12)) + list(range(16, 30))  # All flag values and protocol indicators
    for idx in binary_indices:
        validated_features[idx] = 1 if validated_features[idx] > 0 else 0
    
    # Ensure counts are non-negative
    count_indices = [12, 13, 14, 15, 32]  # ack_count, syn_count, fin_count, urg_count, Number
    for idx in count_indices:
        validated_features[idx] = max(0, validated_features[idx])
    
    # Ensure rate values are non-negative
    rate_indices = [3, 4]  # Rate, Drate
    for idx in rate_indices:
        validated_features[idx] = max(0, validated_features[idx])
    
    # Ensure time values are non-negative
    time_indices = [0, 31]  # flow_duration, IAT
    for idx in time_indices:
        validated_features[idx] = max(0, validated_features[idx])
    
    return validated_features

@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.json
        print("Received data for prediction:", data)
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
            'protocol_type': int(validated_features[1]),  # Protocol_Type is now at index 1
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
        'feature_count': len(FEATURE_NAMES),
        'model_name': 'xgboost_model_spearman'
    })

if __name__ == '__main__':
    print("ML model server starting up...")
    app.run(host='0.0.0.0', port=5000)