import joblib
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, VotingClassifier
from sklearn.metrics import accuracy_score, confusion_matrix
import seaborn as sns
import matplotlib.pyplot as plt
import pandas as pd

class EnsembleClassifier:
    def __init__(self, model_path='ensemble_model.pkl', scaler_path='scaler.pkl', data_path='preprocessed_data.pkl', info_path='model_info.pkl'):
        """
        Khởi tạo EnsembleClassifier.

        Parameters:
        - model_path (str): Đường dẫn để lưu/tải mô hình.
        - scaler_path (str): Đường dẫn để lưu/tải scaler.
        - data_path (str): Đường dẫn đến dữ liệu đã xử lý.
        - info_path (str): Đường dẫn để lưu thông tin mô hình (accuracy, confusion matrix).
        """
        self.model_path = model_path
        self.scaler_path = scaler_path
        self.data_path = data_path
        self.info_path = info_path
        self.ensemble = None
        self.scaler = None
        self.features = None
        self.X_train = None
        self.X_val = None
        self.X_test = None
        self.y_train = None
        self.y_val = None
        self.y_test = None
        self.model_info = None

    def load_data(self):
        """
        Tải dữ liệu đã xử lý từ file pickle.
        """
        try:
            (self.X_train, self.X_val, self.X_test, self.y_train, self.y_val, 
             self.y_test, self.scaler, self.features) = joblib.load(self.data_path)
            print("Tải dữ liệu đã xử lý thành công.")
            print(f"Features used: {self.features}")
        except Exception as e:
            print(f"Lỗi khi tải dữ liệu: {e}")
            raise

    def initialize_model(self):
        """
        Khởi tạo mô hình ensemble với Logistic Regression, Random Forest, và Gradient Boosting.
        """
        lr = LogisticRegression(max_iter=1000, random_state=42)
        rf = RandomForestClassifier(n_estimators=200, max_depth=20, random_state=42)
        gb = GradientBoostingClassifier(n_estimators=100, random_state=42)
        # Increase weight for Random Forest to emphasize feature importance
        self.ensemble = VotingClassifier(
            estimators=[('lr', lr), ('rf', rf), ('gb', gb)],
            voting='soft',
            weights=[1, 2, 1]  # Higher weight for Random Forest
        )

    def train_model(self):
        """
        Huấn luyện mô hình ensemble trên tập train.
        """
        if self.X_train is None or self.y_train is None:
            raise ValueError("Dữ liệu train chưa được tải. Gọi load_data() trước.")
        self.ensemble.fit(self.X_train, self.y_train)
        print("Huấn luyện mô hình hoàn tất.")

    def evaluate_model(self):
        """
        Đánh giá mô hình trên tập validation và test, lưu thông tin mô hình.
        """
        if self.ensemble is None:
            raise ValueError("Mô hình chưa được huấn luyện. Gọi train_model() trước.")
        
        # Độ chính xác validation
        val_pred = self.ensemble.predict(self.X_val)
        val_acc = accuracy_score(self.y_val, val_pred)
        
        # Độ chính xác test
        test_pred = self.ensemble.predict(self.X_test)
        test_acc = accuracy_score(self.y_test, test_pred)
        
        # Ma trận nhầm lẫn
        cm = confusion_matrix(self.y_test, test_pred)
        
        # Feature importance từ Random Forest
        rf = self.ensemble.named_estimators_['rf']
        feature_importance = pd.DataFrame({
            'feature': self.features,
            'importance': rf.feature_importances_
        }).sort_values('importance', ascending=False)
        
        # Lưu thông tin mô hình
        self.model_info = {
            'val_accuracy': val_acc,
            'test_accuracy': test_acc,
            'confusion_matrix': cm.tolist(),
            'features': self.features,
            'feature_importance': feature_importance.to_dict('records')
        }
        
        print(f"Độ chính xác validation: {val_acc:.4f}")
        print(f"Độ chính xác test: {test_acc:.4f}")
        print("\nFeature Importance:")
        print(feature_importance)
        
        # Vẽ ma trận nhầm lẫn
        plt.figure(figsize=(8, 6))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                    xticklabels=['Legitimate', 'Phishing'], 
                    yticklabels=['Legitimate', 'Phishing'])
        plt.xlabel('Dự đoán')
        plt.ylabel('Thực tế')
        plt.title('Ma Trận Nhầm Lẫn (Test Set)')
        plt.show()

    def save_model(self):
        """
        Lưu mô hình, scaler và thông tin mô hình vào đĩa.
        """
        if self.ensemble is None:
            raise ValueError("Mô hình chưa được huấn luyện. Gọi train_model() trước.")
        try:
            joblib.dump(self.ensemble, self.model_path)
            joblib.dump(self.scaler, self.scaler_path)
            joblib.dump(self.model_info, self.info_path)
            print(f"Mô hình, scaler và thông tin mô hình được lưu tại {self.model_path}, {self.scaler_path}, {self.info_path}")
        except Exception as e:
            print(f"Lỗi khi lưu mô hình, scaler hoặc thông tin: {e}")
            raise

    def run_training_pipeline(self):
        """
        Chạy toàn bộ pipeline huấn luyện: tải dữ liệu, khởi tạo, huấn luyện, đánh giá, lưu mô hình.
        """
        self.load_data()
        self.initialize_model()
        self.train_model()
        self.evaluate_model()
        self.save_model()

if __name__ == "__main__":
    classifier = EnsembleClassifier()
    classifier.run_training_pipeline()