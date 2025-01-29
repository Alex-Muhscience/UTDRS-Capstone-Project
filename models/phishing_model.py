# Import necessary libraries
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.utils import shuffle
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import os
from flask import Flask, request, jsonify

# 1. Data Loading and Preprocessing
def load_data(file_path):
    try:
        df = pd.read_csv(file_path)
        print(f"Dataset loaded from {file_path}.")
        print(f"Initial dataset shape: {df.shape}")

        df = df.dropna().drop_duplicates()
        print(f"Dataset shape after cleaning: {df.shape}")

        phishing_emails = df[df['label'] == 1]
        non_phishing_emails = df[df['label'] == 0]
        sample_size = min(len(phishing_emails), len(non_phishing_emails))

        df_balanced = pd.concat([
            phishing_emails.sample(n=sample_size, random_state=42),
            non_phishing_emails.sample(n=sample_size, random_state=42)
        ]).reset_index(drop=True)
        df_balanced = shuffle(df_balanced, random_state=42)
        print(f"Balanced dataset shape: {df_balanced.shape}")

        cleaned_path = os.path.join(os.path.dirname(file_path), "cleaned_phishing_dataset.csv")
        df_balanced.to_csv(cleaned_path, index=False)
        print(f"Cleaned dataset saved to {cleaned_path}.")

        return df_balanced
    except Exception as e:
        print(f"Error loading data: {e}")
        return None

def preprocess_data(df):
    X = df['text_combined']
    y = df['label']

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y
    )

    tfidf = TfidfVectorizer(max_features=5000)
    X_train_tfidf = tfidf.fit_transform(X_train)
    X_test_tfidf = tfidf.transform(X_test)

    X_train_tfidf = X_train_tfidf.toarray()
    X_test_tfidf = X_test_tfidf.toarray()

    print("TF-IDF vectorization completed.")
    print(f"Training set shape: {X_train_tfidf.shape}")
    print(f"Testing set shape: {X_test_tfidf.shape}")

    return X_train_tfidf, X_test_tfidf, y_train.values, y_test.values, tfidf

# 2. Neural Network Model Class
class FFNNModel:
    def __init__(self, input_shape):
        self.model = self.build_model(input_shape)

    def build_model(self, input_shape):
        model = keras.Sequential([
            layers.Dense(256, activation='relu', input_shape=(input_shape,)),
            layers.BatchNormalization(),
            layers.Dropout(0.4),
            layers.Dense(128, activation='relu'),
            layers.BatchNormalization(),
            layers.Dropout(0.4),
            layers.Dense(64, activation='relu'),
            layers.BatchNormalization(),
            layers.Dropout(0.3),
            layers.Dense(1, activation='sigmoid')
        ])
        model.compile(
            optimizer=keras.optimizers.Adam(learning_rate=0.0005),
            loss='binary_crossentropy',
            metrics=['accuracy', keras.metrics.Precision(), keras.metrics.Recall()]
        )
        return model

    def train_model(self, X_train, y_train, X_val, y_val, epochs=50, batch_size=128):
        early_stopping = keras.callbacks.EarlyStopping(
            monitor='val_loss', patience=5, restore_best_weights=True
        )
        history = self.model.fit(
            X_train, y_train,
            validation_data=(X_val, y_val),
            epochs=epochs,
            batch_size=batch_size,
            verbose=2,
            callbacks=[early_stopping]
        )
        return history

    def evaluate_model(self, X_test, y_test):
        results = self.model.evaluate(X_test, y_test, verbose=2)
        print(f"Test Loss: {results[0]}, Test Accuracy: {results[1]}")
        print(f"Precision: {results[2]}, Recall: {results[3]}")

    def predict(self, X):
        predictions = self.model.predict(X)
        return (predictions > 0.5).astype(int)

    def save_model(self, path):
        self.model.save(path)
        print(f"Model saved to {path}.")

    @staticmethod
    def load_model(path):
        model = keras.models.load_model(path)
        print(f"Model loaded from {path}.")
        return model

# 3. Visualization
def plot_training_history(history):
    plt.figure(figsize=(14, 6))

    # Accuracy
    plt.subplot(1, 2, 1)
    plt.plot(history.history['accuracy'], label='Train Accuracy')
    plt.plot(history.history['val_accuracy'], label='Validation Accuracy')
    plt.xlabel('Epochs')
    plt.ylabel('Accuracy')
    plt.title('Training and Validation Accuracy')
    plt.legend()

    # Loss
    plt.subplot(1, 2, 2)
    plt.plot(history.history['loss'], label='Train Loss')
    plt.plot(history.history['val_loss'], label='Validation Loss')
    plt.xlabel('Epochs')
    plt.ylabel('Loss')
    plt.title('Training and Validation Loss')
    plt.legend()

    plt.tight_layout()
    plt.show()

# 4. Flask REST API Integration
app = Flask(__name__)
model_path = "phishing_model.h5"
tfidf_path = "tfidf_vectorizer.pkl"

@app.route('/predict', methods=['POST'])
def predict():
    data = request.json
    email_content = data.get('email_content')

    if not email_content:
        return jsonify({"error": "Email content is required."}), 400

    # Load the model and TF-IDF vectorizer
    model = FFNNModel.load_model(model_path)
    tfidf = pd.read_pickle(tfidf_path)

    # Transform input and predict
    email_vectorized = tfidf.transform([email_content]).toarray()
    prediction = model.predict(email_vectorized)[0][0]
    result = "Phishing" if prediction == 1 else "Not Phishing"

    return jsonify({"prediction": result})

# 5. Main Execution
def main():
    file_path = "datasets/phishing_email.csv"

    df = load_data(file_path)
    if df is not None:
        X_train, X_test, y_train, y_test, tfidf = preprocess_data(df)

        input_shape = X_train.shape[1]

        model = FFNNModel(input_shape)
        history = model.train_model(
            X_train, y_train, X_test, y_test,
            epochs=50, batch_size=128
        )

        model.evaluate_model(X_test, y_test)
        plot_training_history(history)

        # Save model and vectorizer
        model.save_model(model_path)
        pd.to_pickle(tfidf, tfidf_path)

        # Start Flask app
        app.run(port=5000, debug=True)

if __name__ == "__main__":
    main()
