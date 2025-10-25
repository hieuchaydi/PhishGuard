import joblib
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, VotingClassifier
from sklearn.metrics import accuracy_score, confusion_matrix
import seaborn as sns
import matplotlib.pyplot as plt

class EnsembleClassifier:
    def __init__(self, model_path='ensemble_model.pkl', scaler_path='scaler.pkl', data_path='preprocessed_data.pkl'):
        """
        Initialize the EnsembleClassifier.

        Parameters:
        - model_path (str): Path to save/load the trained model.
        - scaler_path (str): Path to save/load the scaler.
        - data_path (str): Path to the preprocessed data.
        """
        self.model_path = model_path
        self.scaler_path = scaler_path
        self.data_path = data_path
        self.ensemble = None
        self.scaler = None
        self.features = None
        self.X_train = None
        self.X_val = None
        self.X_test = None
        self.y_train = None
        self.y_val = None
        self.y_test = None

    def load_data(self):
        """
        Load preprocessed data from a pickle file.
        """
        try:
            (self.X_train, self.X_val, self.X_test, self.y_train, self.y_val, 
             self.y_test, self.scaler, self.features) = joblib.load(self.data_path)
            print("Preprocessed data loaded successfully.")
        except Exception as e:
            print(f"Error loading data: {e}")
            raise

    def initialize_model(self):
        """
        Initialize the ensemble classifier with logistic regression, random forest, and gradient boosting.
        """
        lr = LogisticRegression(max_iter=1000)
        rf = RandomForestClassifier(n_estimators=200, random_state=42)
        gb = GradientBoostingClassifier()
        self.ensemble = VotingClassifier(estimators=[('lr', lr), ('rf', rf), ('gb', gb)], voting='soft')

    def train_model(self):
        """
        Train the ensemble model on the training data.
        """
        if self.X_train is None or self.y_train is None:
            raise ValueError("Training data not loaded. Call load_data() first.")
        self.ensemble.fit(self.X_train, self.y_train)
        print("Model training completed.")

    def evaluate_model(self):
        """
        Evaluate the model on validation and test sets, and display confusion matrix.
        """
        if self.ensemble is None:
            raise ValueError("Model not trained. Call train_model() first.")
        
        # Validation accuracy
        val_pred = self.ensemble.predict(self.X_val)
        val_acc = accuracy_score(self.y_val, val_pred)
        print(f"Validation accuracy: {val_acc:.4f}")

        # Test accuracy
        test_pred = self.ensemble.predict(self.X_test)
        test_acc = accuracy_score(self.y_test, test_pred)
        print(f"Test accuracy: {test_acc:.4f}")

        # Confusion matrix
        cm = confusion_matrix(self.y_test, test_pred)
        plt.figure(figsize=(8, 6))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues')
        plt.xlabel('Predicted')
        plt.ylabel('Actual')
        plt.title('Confusion Matrix')
        plt.show()

    def save_model(self):
        """
        Save the trained model and scaler to disk.
        """
        if self.ensemble is None:
            raise ValueError("Model not trained. Call train_model() first.")
        try:
            joblib.dump(self.ensemble, self.model_path)
            joblib.dump(self.scaler, self.scaler_path)
            print(f"Model and scaler saved to {self.model_path} and {self.scaler_path}")
        except Exception as e:
            print(f"Error saving model or scaler: {e}")
            raise

    def run_training_pipeline(self):
        """
        Run the complete training pipeline: load data, initialize, train, evaluate, and save.
        """
        self.load_data()
        self.initialize_model()
        self.train_model()
        self.evaluate_model()
        self.save_model()

if __name__ == "__main__":
    classifier = EnsembleClassifier()
    classifier.run_training_pipeline()