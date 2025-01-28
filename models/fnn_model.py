import kagglehub
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from tensorflow import keras
from tensorflow.keras import layers


class FFNNModel:
    def _init_(self, input_shape, output_shape):
        self.model = self.build_model(input_shape, output_shape)

    def build_model(self, input_shape, output_shape):
        model = keras.Sequential([
            layers.Dense(64, activation='relu', input_shape=(input_shape,)),
            layers.Dense(64, activation='relu'),
            layers.Dense(output_shape, activation='softmax')  # Change activation depending on your task
        ])
        model.compile(optimizer='adam', loss='sparse_categorical_crossentropy', metrics=['accuracy'])
        return model

    def train_model(self, X, y, validation_split=0.2, epochs=50, batch_size=32):
        try:
            assert X.shape[0] == y.shape[0], "Mismatch between features and labels"
            self.model.fit(X, y, epochs=epochs, batch_size=batch_size, validation_split=validation_split)
        except Exception as e:
            print(f"Error during training: {e}")

    def evaluate_model(self, X, y):
        try:
            results = self.model.evaluate(X, y)
            print(f"Test Loss: {results[0]}, Test Accuracy: {results[1]}")
        except Exception as e:
            print(f"Error during evaluation: {e}")

    def predict(self, X):
        try:
            predictions = self.model.predict(X)
            return np.argmax(predictions, axis=1)
        except Exception as e:
            print(f"Error during prediction: {e}")
            return None


# Download latest version
path = kagglehub.dataset_download("naserabdullahalam/phishing-email-dataset")

print("Path to dataset files:", path)
def load_data(file_path):
    try:
        data = pd.read_csv.path
        # Assume the last column is the label
        X = data.iloc[:, :-1].values
        y = data.iloc[:, -1].values
        return X, y
    except Exception as e:
        print(f"Error loading data: {e}")
        return None, None


if __name__ == "_main_":
    # Sample usage
    file_path = path  # Replace with your dataset path
    X, y = load_data(file_path)

    if X is not None and y is not None:
        input_shape = X.shape[1]
        output_shape = len(np.unique(y))  # Number of unique labels
        model = FFNNModel(input_shape, output_shape)

        # Splitting the data into training and testing
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

        model.train_model(X_train, y_train)
        model.evaluate_model(X_test, y_test)