"""
ML model trainer for the UTDRS core engine.
Handles training, saving, and evaluation of machine learning models for threat detection.
"""
from typing import Dict, Any, Optional, List, Tuple, Union
import os
import json
import pickle
import numpy as np
from datetime import datetime
from utils.logger import get_logger
from config import settings

logger = get_logger(__name__)

class ModelTrainer:
    """
    Trains and evaluates machine learning models for threat detection.
    """
    
    def __init__(self, models_directory: str = None):
        """
        Initialize the model trainer.
        
        Args:
            models_directory: Directory to save models to (defaults to config setting)
        """
        self.models_directory = models_directory or settings.MODEL_PATH
        
        # Ensure models directory exists
        if not os.path.exists(self.models_directory):
            os.makedirs(self.models_directory)
            logger.info(f"Created models directory: {self.models_directory}")
    
    async def train_phishing_model(self, training_data: List[Dict[str, Any]]) -> Tuple[Any, Dict[str, Any]]:
        """
        Train a phishing detection model.
        
        Args:
            training_data: List of labeled examples for training
            
        Returns:
            Tuple of (trained_model, performance_metrics)
        """
        try:
            logger.info(f"Training phishing detection model with {len(training_data)} examples")
            
            # In a real implementation, we would:
            # 1. Extract features from raw data
            # 2. Split into training and validation sets
            # 3. Train a model (e.g., RandomForest, Neural Network)
            # 4. Evaluate performance
            
            # For demonstration, we'll create a simple model
            from sklearn.ensemble import RandomForestClassifier
            from sklearn.feature_extraction.text import TfidfVectorizer
            from sklearn.pipeline import Pipeline
            from sklearn.model_selection import train_test_split
            from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
            
            # Extract features and labels
            texts = []
            labels = []
            
            for example in training_data:
                # Extract text content (e.g., email body or URL)
                text = example.get('content', '')
                if not text:
                    continue
                    
                texts.append(text)
                labels.append(1 if example.get('is_phishing', False) else 0)
                
            # Split into training and test sets
            X_train, X_test, y_train, y_test = train_test_split(texts, labels, test_size=0.2, random_state=42)
            
            # Create pipeline with vectorizer and classifier
            model = Pipeline([
                ('vectorizer', TfidfVectorizer(max_features=5000)),
                ('classifier', RandomForestClassifier(n_estimators=100, random_state=42))
            ])
            
            # Train model
            model.fit(X_train, y_train)
            
            # Evaluate performance
            y_pred = model.predict(X_test)
            
            # Calculate metrics
            metrics = {
                'accuracy': accuracy_score(y_test, y_pred),
                'precision': precision_score(y_test, y_pred),
                'recall': recall_score(y_test, y_pred),
                'f1_score': f1_score(y_test, y_pred),
                'test_samples': len(X_test),
                'training_samples': len(X_train)
            }
            
            logger.info(f"Phishing model trained with accuracy: {metrics['accuracy']:.4f}, F1: {metrics['f1_score']:.4f}")
            
            return model, metrics
            
        except Exception as e:
            logger.error(f"Error training phishing model: {str(e)}")
            raise
    
    async def train_malware_model(self, training_data: List[Dict[str, Any]]) -> Tuple[Any, Dict[str, Any]]:
        """
        Train a malware detection model.
        
        Args:
            training_data: List of labeled examples for training
            
        Returns:
            Tuple of (trained_model, performance_metrics)
        """
        try:
            logger.info(f"Training malware detection model with {len(training_data)} examples")
            
            # In a real implementation, we would:
            # 1. Extract features from file samples or process behaviors
            # 2. Split into training and validation sets
            # 3. Train a model (e.g., Gradient Boosting, Neural Network)
            # 4. Evaluate performance
            
            # For demonstration, we'll create a simple model
            from sklearn.ensemble import GradientBoostingClassifier
            from sklearn.model_selection import train_test_split
            from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
            
            # Extract features and labels
            features_list = []
            labels = []
            
            for example in training_data:
                # Extract numerical features
                features = example.get('features', [])
                if not features:
                    continue
                    
                features_list.append(features)
                labels.append(1 if example.get('is_threat', False) else 0)
                
            # Convert to numpy arrays
            X = np.array(features_list)
            y = np.array(labels)
            
            # Split into training and test sets
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
            
            # Train model
            model = RandomForestClassifier(n_estimators=100, random_state=42)
            model.fit(X_train, y_train)
            
            # Evaluate performance
            y_pred = model.predict(X_test)
            
            # Calculate metrics
            metrics = {
                'accuracy': accuracy_score(y_test, y_pred),
                'precision': precision_score(y_test, y_pred),
                'recall': recall_score(y_test, y_pred),
                'f1_score': f1_score(y_test, y_pred),
                'test_samples': len(X_test),
                'training_samples': len(X_train)
            }
            
            logger.info(f"Network threat model trained with accuracy: {metrics['accuracy']:.4f}, F1: {metrics['f1_score']:.4f}")
            
            return model, metrics
            
        except Exception as e:
            logger.error(f"Error training network threat model: {str(e)}")
            raise
    
    async def train_user_behavior_model(self, training_data: List[Dict[str, Any]]) -> Tuple[Any, Dict[str, Any]]:
        """
        Train a user behavior anomaly detection model.
        
        Args:
            training_data: List of examples for training
            
        Returns:
            Tuple of (trained_model, performance_metrics)
        """
        try:
            logger.info(f"Training user behavior model with {len(training_data)} examples")
            
            # In a real implementation, we would:
            # 1. Extract features from user activity data
            # 2. Split into training and validation sets
            # 3. Train an anomaly detection model (e.g., Isolation Forest, One-Class SVM)
            # 4. Evaluate performance
            
            # For demonstration, we'll create a simple model
            from sklearn.ensemble import IsolationForest
            from sklearn.model_selection import train_test_split
            from sklearn.metrics import precision_score, recall_score, f1_score
            
            # Extract features
            features_list = []
            
            for example in training_data:
                # Extract numerical features
                features = example.get('features', [])
                if not features:
                    continue
                    
                features_list.append(features)
                
            # Convert to numpy array
            X = np.array(features_list)
            
            # Train model (unsupervised)
            model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
            model.fit(X)
            
            # For evaluation, we'll use a subset of the data labeled as anomalies
            # In a real implementation, we would have a separate validation set
            test_data = [example for example in training_data if 'is_anomaly' in example]
            
            if test_data:
                X_test = np.array([example.get('features', []) for example in test_data])
                y_test = np.array([1 if example.get('is_anomaly', False) else -1 for example in test_data])
                
                # Predict
                y_pred = model.predict(X_test)
                
                # Convert predictions to match labels (-1 for anomaly, 1 for normal in Isolation Forest)
                y_pred_binary = [1 if pred == -1 else 0 for pred in y_pred]
                y_test_binary = [1 if label == 1 else 0 for label in y_test]
                
                # Calculate metrics
                metrics = {
                    'precision': precision_score(y_test_binary, y_pred_binary),
                    'recall': recall_score(y_test_binary, y_pred_binary),
                    'f1_score': f1_score(y_test_binary, y_pred_binary),
                    'test_samples': len(X_test),
                    'training_samples': len(X)
                }
            else:
                # No labeled test data, return placeholder metrics
                metrics = {
                    'precision': 0.0,
                    'recall': 0.0,
                    'f1_score': 0.0,
                    'test_samples': 0,
                    'training_samples': len(X)
                }
            
            logger.info(f"User behavior model trained with {len(X)} samples")
            
            return model, metrics
            
        except Exception as e:
            logger.error(f"Error training user behavior model: {str(e)}")
            raise
    
    async def save_model(self, model_type: str, model: Any, metrics: Dict[str, Any], 
                        version: str = None) -> str:
        """
        Save a trained model and its metadata.
        
        Args:
            model_type: Type of model (phishing, malware, network, user_behavior)
            model: The trained model object
            metrics: Performance metrics
            version: Optional version string (defaults to timestamp)
            
        Returns:
            Path to the saved model
        """
        # Create model directory
        model_dir = os.path.join(self.models_directory, model_type)
        if not os.path.exists(model_dir):
            os.makedirs(model_dir)
            
        # Generate version if not provided
        if not version:
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            version = f"{model_type}_{timestamp}"
            
        # Save model
        model_file = os.path.join(model_dir, 'model.pkl')
        with open(model_file, 'wb') as f:
            pickle.dump(model, f)
            
        # Create metadata
        metadata = {
            "name": f"{model_type}_model",
            "version": version,
            "created_at": datetime.utcnow().isoformat(),
            "description": f"{model_type.capitalize()} detection model",
            "metrics": metrics,
            "threshold": 0.7,  # Default confidence threshold
        }
        
        # Save metadata
        metadata_file = os.path.join(model_dir, 'metadata.json')
        with open(metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2)
            
        logger.info(f"Saved {model_type} model version {version}")
        
        return model_file
    
    async def load_model(self, model_type: str) -> Tuple[Optional[Any], Optional[Dict[str, Any]]]:
        """
        Load a trained model and its metadata.
        
        Args:
            model_type: Type of model to load
            
        Returns:
            Tuple of (model, metadata) or (None, None) if not found
        """
        model_dir = os.path.join(self.models_directory, model_type)
        model_file = os.path.join(model_dir, 'model.pkl')
        metadata_file = os.path.join(model_dir, 'metadata.json')
        
        if not os.path.exists(model_file) or not os.path.exists(metadata_file):
            logger.warning(f"Model or metadata not found for {model_type}")
            return None, None
            
        try:
            # Load model
            with open(model_file, 'rb') as f:
                model = pickle.load(f)
                
            # Load metadata
            with open(metadata_file, 'r') as f:
                metadata = json.load(f)
                
            logger.info(f"Loaded {model_type} model version {metadata.get('version', 'unknown')}")
            
            return model, metadata
            
        except Exception as e:
            logger.error(f"Error loading {model_type} model: {str(e)}")
            return None, None
    
    async def evaluate_model(self, model_type: str, model: Any, test_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Evaluate a model on test data.
        
        Args:
            model_type: Type of model to evaluate
            model: The model to evaluate
            test_data: List of labeled examples for testing
            
        Returns:
            Dictionary of performance metrics
        """
        try:
            logger.info(f"Evaluating {model_type} model with {len(test_data)} examples")
            
            # Different evaluation logic based on model type
            if model_type == 'phishing':
                return await self._evaluate_phishing_model(model, test_data)
            elif model_type == 'malware':
                return await self._evaluate_malware_model(model, test_data)
            elif model_type == 'network':
                return await self._evaluate_network_model(model, test_data)
            elif model_type == 'user_behavior':
                return await self._evaluate_user_behavior_model(model, test_data)
            else:
                raise ValueError(f"Unknown model type: {model_type}")
                
        except Exception as e:
            logger.error(f"Error evaluating model: {str(e)}")
            return {
                'error': str(e),
                'accuracy': 0.0,
                'precision': 0.0,
                'recall': 0.0,
                'f1_score': 0.0
            }
    
    async def _evaluate_phishing_model(self, model: Any, test_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Evaluate a phishing detection model."""
        from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
        
        # Extract texts and labels
        texts = []
        labels = []
        
        for example in test_data:
            text = example.get('content', '')
            if not text:
                continue
                
            texts.append(text)
            labels.append(1 if example.get('is_phishing', False) else 0)
            
        # Make predictions
        y_pred = model.predict(texts)
        y_proba = model.predict_proba(texts)[:, 1]  # Probability of positive class
        
        # Calculate metrics
        metrics = {
            'accuracy': accuracy_score(labels, y_pred),
            'precision': precision_score(labels, y_pred),
            'recall': recall_score(labels, y_pred),
            'f1_score': f1_score(labels, y_pred),
            'test_samples': len(texts)
        }
        
        # Calculate AUC if possible
        try:
            from sklearn.metrics import roc_auc_score
            metrics['auc'] = roc_auc_score(labels, y_proba)
        except:
            metrics['auc'] = 0.0
            
        return metrics
    
    async def _evaluate_malware_model(self, model: Any, test_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Evaluate a malware detection model."""
        from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
        
        # Extract features and labels
        features_list = []
        labels = []
        
        for example in test_data:
            features = example.get('features', [])
            if not features:
                continue
                
            features_list.append(features)
            labels.append(1 if example.get('is_malware', False) else 0)
            
        # Convert to numpy arrays
        X = np.array(features_list)
        y = np.array(labels)
        
        # Make predictions
        y_pred = model.predict(X)
        y_proba = model.predict_proba(X)[:, 1]  # Probability of positive class
        
        # Calculate metrics
        metrics = {
            'accuracy': accuracy_score(y, y_pred),
            'precision': precision_score(y, y_pred),
            'recall': recall_score(y, y_pred),
            'f1_score': f1_score(y, y_pred),
            'test_samples': len(X)
        }
        
        # Calculate AUC if possible
        try:
            from sklearn.metrics import roc_auc_score
            metrics['auc'] = roc_auc_score(y, y_proba)
        except:
            metrics['auc'] = 0.0
            
        return metrics
    
    async def _evaluate_network_model(self, model: Any, test_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Evaluate a network threat detection model."""
        from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
        
        # Extract features and labels
        features_list = []
        labels = []
        
        for example in test_data:
            features = example.get('features', [])
            if not features:
                continue
                
            features_list.append(features)
            labels.append(1 if example.get('is_threat', False) else 0)
            
        # Convert to numpy arrays
        X = np.array(features_list)
        y = np.array(labels)
        
        # Make predictions
        y_pred = model.predict(X)
        y_proba = model.predict_proba(X)[:, 1]  # Probability of positive class
        
        # Calculate metrics
        metrics = {
            'accuracy': accuracy_score(y, y_pred),
            'precision': precision_score(y, y_pred),
            'recall': recall_score(y, y_pred),
            'f1_score': f1_score(y, y_pred),
            'test_samples': len(X)
        }
        
        # Calculate AUC if possible
        try:
            from sklearn.metrics import roc_auc_score
            metrics['auc'] = roc_auc_score(y, y_proba)
        except:
            metrics['auc'] = 0.0
            
        return metrics
    
    async def _evaluate_user_behavior_model(self, model: Any, test_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Evaluate a user behavior anomaly detection model."""
        from sklearn.metrics import precision_score, recall_score, f1_score
        
        # Extract features and anomaly labels
        features_list = []
        labels = []
        
        for example in test_data:
            features = example.get('features', [])
            if not features or 'is_anomaly' not in example:
                continue
                
            features_list.append(features)
            labels.append(1 if example.get('is_anomaly', False) else 0)
            
        # Convert to numpy arrays
        X = np.array(features_list)
        y = np.array(labels)
        
        if len(X) == 0:
            return {
                'precision': 0.0,
                'recall': 0.0,
                'f1_score': 0.0,
                'test_samples': 0
            }
        
        # Make predictions
        y_pred = model.predict(X)
        
        # Convert predictions (-1 for anomaly, 1 for normal in Isolation Forest)
        y_pred_binary = [1 if pred == -1 else 0 for pred in y_pred]
        
        # Calculate metrics
        metrics = {
            'precision': precision_score(y, y_pred_binary),
            'recall': recall_score(y, y_pred_binary),
            'f1_score': f1_score(y, y_pred_binary),
            'test_samples': len(X)
        }
        
        return metrics []
            
            for example in training_data:
                # Extract numerical features
                features = example.get('features', [])
                if not features:
                    continue
                    
                features_list.append(features)
                labels.append(1 if example.get('is_malware', False) else 0)
                
            # Convert to numpy arrays
            X = np.array(features_list)
            y = np.array(labels)
            
            # Split into training and test sets
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
            
            # Train model
            model = GradientBoostingClassifier(n_estimators=100, random_state=42)
            model.fit(X_train, y_train)
            
            # Evaluate performance
            y_pred = model.predict(X_test)
            
            # Calculate metrics
            metrics = {
                'accuracy': accuracy_score(y_test, y_pred),
                'precision': precision_score(y_test, y_pred),
                'recall': recall_score(y_test, y_pred),
                'f1_score': f1_score(y_test, y_pred),
                'test_samples': len(X_test),
                'training_samples': len(X_train)
            }
            
            logger.info(f"Malware model trained with accuracy: {metrics['accuracy']:.4f}, F1: {metrics['f1_score']:.4f}")
            
            return model, metrics
            
        except Exception as e:
            logger.error(f"Error training malware model: {str(e)}")
            raise
    
    async def train_network_threat_model(self, training_data: List[Dict[str, Any]]) -> Tuple[Any, Dict[str, Any]]:
        """
        Train a network threat detection model.
        
        Args:
            training_data: List of labeled examples for training
            
        Returns:
            Tuple of (trained_model, performance_metrics)
        """
        try:
            logger.info(f"Training network threat model with {len(training_data)} examples")
            
            # In a real implementation, we would:
            # 1. Extract features from network traffic data
            # 2. Split into training and validation sets
            # 3. Train a model (e.g., Random Forest, XGBoost)
            # 4. Evaluate performance
            
            # For demonstration, we'll create a simple model
            from sklearn.ensemble import RandomForestClassifier
            from sklearn.model_selection import train_test_split
            from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
            
            # Extract features and labels
            features_list = []
            labels =