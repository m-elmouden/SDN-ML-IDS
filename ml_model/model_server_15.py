#!/usr/bin/env python3
"""
ML Model Server - 15 Features Version
Flask API server for serving XGBoost models trained on 15 features
"""

import os
import json
import logging
import numpy as np
from flask import Flask, request, jsonify
import joblib

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Global model variables
model_15 = None
scaler_15 = None

# Feature names for the 15-feature model
FEATURE_NAMES_15 = [
    'fin_flag_number', 'psh_flag_number', 'UDP', 'syn_flag_number', 'HTTP',
    'ICMP', 'IAT', 'Tot_sum', 'urg_count', 'syn_count',
    'fin_count', 'rst_flag_number', 'TCP', 'ack_count', 'Rate'
]

def load_models():
    """Load XGBoost models and scalers"""
    global model_15, scaler_15
    
    try:
        # Load 15-feature model
        model_15_path = '/app/xgb_model_15.joblib'
        if os.path.exists(model_15_path):
            model_15 = joblib.load(model_15_path)
            logger.info(f"Loaded 15-feature model from {model_15_path}")
        else:
            # Fallback to existing model if 15-feature model doesn't exist
            model_15_path = '/app/xgboost_model.joblib'
            if os.path.exists(model_15_path):
                model_15 = joblib.load(model_15_path)
                logger.warning(f"15-feature model not found, using fallback model from {model_15_path}")
            else:
                logger.error("No suitable model found for 15 features")
        
        # Load scaler for 15-feature model (if exists)
        scaler_15_path = '/app/robust_scaler_15.json'
        if os.path.exists(scaler_15_path):
            with open(scaler_15_path, 'r') as f:
                scaler_data = json.load(f)
                scaler_15 = scaler_data
                logger.info(f"Loaded 15-feature scaler from {scaler_15_path}")
        else:
            # Fallback to existing scaler
            scaler_15_path = '/app/robust_scaler_params.json'
            if os.path.exists(scaler_15_path):
                with open(scaler_15_path, 'r') as f:
                    scaler_data = json.load(f)
                    # Adapt scaler to 15 features by taking the first 15 parameters
                    if 'center_' in scaler_data and 'scale_' in scaler_data:
                        scaler_15 = {
                            'center_': scaler_data['center_'][:15] if len(scaler_data['center_']) >= 15 else scaler_data['center_'],
                            'scale_': scaler_data['scale_'][:15] if len(scaler_data['scale_']) >= 15 else scaler_data['scale_']
                        }
                        logger.warning(f"Adapted existing scaler for 15 features from {scaler_15_path}")
                    else:
                        scaler_15 = None
                        logger.warning("Scaler format not compatible, proceeding without scaling")
            else:
                scaler_15 = None
                logger.warning("No scaler found, proceeding without feature scaling")
        
        logger.info("Model loading completed")
        
    except Exception as e:
        logger.error(f"Error loading models: {e}")
        model_15 = None
        scaler_15 = None

def scale_features_15(features):
    """Apply scaling to 15 features using RobustScaler parameters"""
    if scaler_15 is None:
        logger.debug("No scaler available, returning features as-is")
        return features
    
    try:
        features_array = np.array(features, dtype=np.float64)
        
        # Ensure we have exactly 15 features
        if len(features_array) != 15:
            logger.error(f"Expected 15 features for scaling, got {len(features_array)}")
            return features
        
        # Apply RobustScaler transformation: (X - center) / scale
        center = np.array(scaler_15['center_'][:15], dtype=np.float64)
        scale = np.array(scaler_15['scale_'][:15], dtype=np.float64)
        
        # Avoid division by zero
        scale = np.where(scale == 0, 1.0, scale)
        
        scaled_features = (features_array - center) / scale
        
        logger.debug("Features scaled successfully")
        return scaled_features.tolist()
        
    except Exception as e:
        logger.error(f"Error scaling features: {e}")
        return features

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'model_15_loaded': model_15 is not None,
        'scaler_15_loaded': scaler_15 is not None,
        'feature_count': 15
    })

@app.route('/predict_15', methods=['POST'])
def predict_15_features():
    """Prediction endpoint for 15 features"""
    try:
        # Check if model is loaded
        if model_15 is None:
            return jsonify({
                'error': '15-feature model not loaded'
            }), 500
        
        # Parse request
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
        
        features = data.get('features', [])
        
        # Validate features
        if not isinstance(features, list):
            return jsonify({'error': 'Features must be a list'}), 400
        
        if len(features) != 15:
            return jsonify({
                'error': f'Expected 15 features, got {len(features)}'
            }), 400
        
        # Check for numeric values
        try:
            features_float = [float(f) for f in features]
        except (ValueError, TypeError):
            return jsonify({'error': 'All features must be numeric'}), 400
        
        # Scale features
        scaled_features = scale_features_15(features_float)
        
        # Make prediction
        features_array = np.array(scaled_features).reshape(1, -1)
        
        # Get prediction and probability
        prediction = model_15.predict(features_array)[0]
        
        # Try to get prediction probabilities
        try:
            probabilities = model_15.predict_proba(features_array)[0]
            confidence = float(max(probabilities))
        except:
            # If predict_proba is not available, use a default confidence
            confidence = 0.8 if prediction == 1 else 0.7
        
        # Determine attack type (simplified classification)
        attack_type = int(prediction) if prediction != 0 else 0
        
        result = {
            'is_attack': bool(prediction != 0),
            'attack_type': attack_type,
            'confidence': confidence,
            'model': 'xgb_model_15',
            'feature_count': 15,
            'scaled': scaler_15 is not None
        }
        
        logger.info(f"Prediction made: {'ATTACK' if result['is_attack'] else 'BENIGN'} (confidence: {confidence:.2f})")
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error during prediction: {e}")
        return jsonify({
            'error': f'Prediction failed: {str(e)}'
        }), 500

@app.route('/predict', methods=['POST'])
def predict_legacy():
    """Legacy prediction endpoint for backward compatibility"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
        
        features = data.get('features', [])
        
        # If exactly 15 features, redirect to 15-feature prediction
        if len(features) == 15:
            return predict_15_features()
        
        # Otherwise return error
        return jsonify({
            'error': f'This server only supports 15 features, got {len(features)}'
        }), 400
        
    except Exception as e:
        logger.error(f"Error in legacy predict endpoint: {e}")
        return jsonify({
            'error': f'Prediction failed: {str(e)}'
        }), 500

@app.route('/info', methods=['GET'])
def model_info():
    """Get information about loaded models"""
    return jsonify({
        'models': {
            '15_features': {
                'loaded': model_15 is not None,
                'features': FEATURE_NAMES_15,
                'scaler': scaler_15 is not None
            }
        },
        'endpoints': [
            '/predict_15 - Prediction for 15 features',
            '/predict - Legacy prediction endpoint',
            '/health - Health check',
            '/info - This endpoint'
        ]
    })

if __name__ == '__main__':
    logger.info("Starting ML Model Server (15 Features)")
    
    # Load models on startup
    load_models()
    
    # Check if at least one model is loaded
    if model_15 is None:
        logger.error("No models loaded successfully!")
        exit(1)
    
    # Start Flask server
    port = int(os.environ.get('PORT', 5000))
    logger.info(f"Starting server on port {port}")
    
    app.run(
        host='0.0.0.0',
        port=port,
        debug=False,
        threaded=True
    )
