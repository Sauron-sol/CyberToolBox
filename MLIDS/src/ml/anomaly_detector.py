import numpy as np
from sklearn.ensemble import IsolationForest
import joblib
import logging
from typing import Optional, List

class AnomalyDetector:
    def __init__(self, model_path: Optional[str] = None):
        """Initialize the anomaly detector."""
        self.logger = logging.getLogger(__name__)
        self.model = None
        
        # Enhanced parameters for Isolation Forest
        self.model_params = {
            'n_estimators': 200,  # More trees for better accuracy
            'max_samples': 'auto',
            'contamination': 0.1,  # 10% of data considered as anomalies
            'max_features': 1.0,
            'bootstrap': True,
            'n_jobs': -1,  # Use all available CPU cores
            'random_state': 42  # For reproducibility
        }
        
        if model_path:
            try:
                self.model = joblib.load(model_path)
                self.logger.info(f"Model loaded from {model_path}")
            except Exception as e:
                self.logger.error(f"Error loading model: {str(e)}")
    
    def train(self, X: np.ndarray):
        """
        Train the anomaly detection model.
        
        Args:
            X (np.ndarray): Training data
        """
        try:
            self.logger.info("Starting model training...")
            self.model = IsolationForest(**self.model_params)
            self.model.fit(X)
            self.logger.info("Training completed")
        except Exception as e:
            self.logger.error(f"Training error: {str(e)}")
            raise
    
    def predict(self, X: np.ndarray) -> Optional[List[int]]:
        """
        Predict anomalies in the data.
        
        Args:
            X (np.ndarray): Data to predict
            
        Returns:
            Optional[List[int]]: Predictions (-1 for anomalies, 1 for normal)
        """
        try:
            if self.model is None:
                self.logger.warning("Model not trained yet")
                return None
            
            # Get decision scores (-1 for anomaly, 1 for normal)
            predictions = self.model.predict(X)
            
            # Get confidence scores
            scores = self.model.score_samples(X)
            
            # Normalize scores between 0 and 1
            normalized_scores = (scores - scores.min()) / (scores.max() - scores.min())
            
            # Only consider as anomaly if the score is really low
            predictions[normalized_scores > 0.2] = 1  # Confidence threshold at 20%
            
            return predictions
            
        except Exception as e:
            self.logger.error(f"Prediction error: {str(e)}")
            return None
    
    def save_model(self, path: str):
        """
        Save the trained model.
        
        Args:
            path (str): Path to save the model
        """
        try:
            if self.model is not None:
                joblib.dump(self.model, path)
                self.logger.info(f"Model saved: {path}")
            else:
                self.logger.warning("No model to save")
        except Exception as e:
            self.logger.error(f"Error saving model: {str(e)}")
            raise 