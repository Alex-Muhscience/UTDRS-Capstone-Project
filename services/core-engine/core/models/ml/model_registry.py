import os
import pickle
import json
from typing import Dict, Any, Optional, List, Union
from utils.logger import get_logger
import numpy as np

logger = get_logger(__name__)

class ModelRegistry:
    """
    Registry for machine learning models used by the ML detector.
    Handles model loading, versioning, and metadata management.
    """
    
    def __init__(self, models_directory: str):
        """
        Initialize the model registry.
        
        Args:
            models_directory: Path to the directory containing ML models
        """
        self.models_directory = models_directory
        self.models = {}
        self.model_metadata = {}
        self.ensure_directory_exists()
        self.load_models()
        
    def ensure_directory_exists(self):
        """Ensure that the models directory and essential subdirectories exist."""
        if not os.path.exists(self.models_directory):
            os.makedirs(self.models_directory)
            logger.info(f"Created models directory: {self.models_directory}")
            
        # Create standard subdirectories for different model types
        subdirs = ['phishing', 'malware', 'network', 'user_behavior']
        for subdir in subdirs:
            subdir_path = os.path.join(self.models_directory, subdir)
            if not os.path.exists(subdir_path):
                os.makedirs(subdir_path)
                logger.info(f"Created model subdirectory: {subdir_path}")
                
                # Create empty model placeholder
                self._create_placeholder_model(subdir)
        
    def _create_placeholder_model(self, model_type: str):
        """
        Create placeholder model files for development when no real models exist.
        
        Args:
            model_type: Type of model to create placeholder for
        """
        model_dir = os.path.join(self.models_directory, model_type)
        
        # Create a simple placeholder model using sklearn dummy classifier
        try:
            from sklearn.dummy import DummyClassifier
            model = DummyClassifier(strategy="constant", constant=0)  # Always predict benign
        except ImportError:
            # Fallback to a simple dict-based model if sklearn is not available
            model = {
                "type": "dummy",
                "predict_proba": lambda X: np.array([[0.9, 0.1]] * len(X))
            }
        
        # Save model
        with open(os.path.join(model_dir, 'model.pkl'), 'wb') as f:
            pickle.dump(model, f)
            
        # Create model metadata
        metadata = {
            "name": f"{model_type}_model",
            "version": "0.1.0",
            "created_at": "2022-01-01T00:00:00Z",
            "description": f"Placeholder {model_type} detection model",
            "input_features": ["feature1", "feature2"],
            "output_classes": ["benign", "malicious"],
            "threshold": 0.7,
            "accuracy": 0.5,  # Random guessing
            "placeholder": True
        }
        
        # Save metadata
        with open(os.path.join(model_dir, 'metadata.json'), 'w') as f:
            json.dump(metadata, f, indent=2)
            
        logger.info(f"Created placeholder {model_type} model")
        
    def load_models(self):
        """
        Load all available ML models from the models directory.
        """
        logger.info(f"Loading ML models from {self.models_directory}")
        
        # Check if models directory exists
        if not os.path.exists(self.models_directory):
            logger.warning(f"Models directory {self.models_directory} does not exist")
            return
            
        # Scan for model directories
        for model_dir in [d for d in os.listdir(self.models_directory) 
                         if os.path.isdir(os.path.join(self.models_directory, d))]:
            model_path = os.path.join(self.models_directory, model_dir)
            
            # Check for model file
            model_file = os.path.join(model_path, 'model.pkl')
            if not os.path.exists(model_file):
                logger.warning(f"No model.pkl found in {model_path}")
                continue
                
            # Check for metadata file
            metadata_file = os.path.join(model_path, 'metadata.json')
            if os.path.exists(metadata_file):
                try:
                    with open(metadata_file, 'r') as f:
                        metadata = json.load(f)
                    self.model_metadata[model_dir] = metadata
                except Exception as e:
                    logger.error(f"Error loading metadata for {model_dir}: {str(e)}")
                    self.model_metadata[model_dir] = {"name": model_dir, "placeholder": True}
            else:
                logger.warning(f"No metadata.json found in {model_path}")
                self.model_metadata[model_dir] = {"name": model_dir, "placeholder": True}
                
            logger.info(f"Found model: {model_dir} (will load on demand)")
            
    def get_model(self, model_name: str) -> Optional[Any]:
        """
        Get a model by name, loading it from disk if not already loaded.
        
        Args:
            model_name: Name of the model to get
            
        Returns:
            The loaded model or None if not found
        """
        # If model is already loaded, return it
        if model_name in self.models:
            return self.models[model_name]
            
        # If model directory exists, try to load the model
        model_dir = os.path.join(self.models_directory, model_name)
        model_file = os.path.join(model_dir, 'model.pkl')
        
        if os.path.exists(model_file):
            try:
                with open(model_file, 'rb') as f:
                    model = pickle.load(f)
                self.models[model_name] = model
                logger.info(f"Loaded model {model_name}")
                return model
            except Exception as e:
                logger.error(f"Error loading model {model_name}: {str(e)}")
                return None
        else:
            logger.warning(f"Model file for {model_name} not found at {model_file}")
            return None
            
    def get_model_metadata(self, model_name: str) -> Dict[str, Any]:
        """
        Get metadata for a model.
        
        Args:
            model_name: Name of the model to get metadata for
            
        Returns:
            Model metadata dictionary
        """
        return self.model_metadata.get(model_name, {})
        
    def list_models(self) -> List[Dict[str, Any]]:
        """
        List all available models with their metadata.
        
        Returns:
            List of model metadata dictionaries
        """
        return [
            {
                "name": model_name,
                "loaded": model_name in self.models,
                **self.model_metadata.get(model_name, {})
            }
            for model_name in self.model_metadata.keys()
        ]
        
    def save_model(self, model_name: str, model: Any, metadata: Dict[str, Any]) -> bool:
        """
        Save a model to the registry.
        
        Args:
            model_name: Name to save the model under
            model: The model object to save
            metadata: Metadata for the model
            
        Returns:
            True if the model was saved successfully, False otherwise
        """
        model_dir = os.path.join(self.models_directory, model_name)
        
        # Create model directory if it doesn't exist
        if not os.path.exists(model_dir):
            os.makedirs(model_dir)
            
        # Save model file
        model_file = os.path.join(model_dir, 'model.pkl')
        try:
            with open(model_file, 'wb') as f:
                pickle.dump(model, f)
        except Exception as e:
            logger.error(f"Error saving model {model_name}: {str(e)}")
            return False
            
        # Save metadata file
        metadata_file = os.path.join(model_dir, 'metadata.json')
        try:
            with open(metadata_file, 'w') as f:
                json.dump(metadata, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving metadata for {model_name}: {str(e)}")
            return False
            
        # Update in-memory records
        self.models[model_name] = model
        self.model_metadata[model_name] = metadata
        
        logger.info(f"Successfully saved model {model_name}")
        return True