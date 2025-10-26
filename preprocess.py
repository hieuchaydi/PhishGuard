import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import joblib

class PhishingDataPreprocessor:
    def __init__(self, data_path='dataset_phishing.csv', output_path='preprocessed_data.pkl'):
        """
        Khởi tạo PhishingDataPreprocessor.

        Parameters:
        - data_path (str): Đường dẫn đến file CSV đầu vào.
        - output_path (str): Đường dẫn để lưu dữ liệu đã xử lý.
        """
        self.data_path = data_path
        self.output_path = output_path
        self.selected_features = [
            'length_url', 'length_hostname', 'ip', 'nb_dots', 'nb_hyphens', 'nb_at',
            'nb_qm', 'nb_and', 'nb_eq', 'nb_slash', 'nb_underscore', 'prefix_suffix',
            'tld_in_subdomain', 'nb_subdomains', 'random_domain', 'shortening_service',
            'https_token', 'ratio_digits_url', 'ratio_digits_host', 'char_repeat',
            'ratio_intHyperlinks', 'ratio_extHyperlinks', 'login_form', 'submit_email',
            'iframe', 'popup_window', 'safe_anchor', 'external_favicon', 'empty_title',
            'domain_in_title'
        ]
        self.scaler = StandardScaler()
        self.X_train = None
        self.X_val = None
        self.X_test = None
        self.y_train = None
        self.y_val = None
        self.y_test = None

    def load_data(self):
        """
        Đọc và xử lý sơ bộ dataset từ CSV.
        """
        try:
            df = pd.read_csv(self.data_path)
            df['status'] = df['status'].map({'legitimate': 0, 'phishing': 1})
            return df
        except Exception as e:
            print(f"Lỗi khi đọc dữ liệu: {e}")
            raise

    def preprocess(self):
        """
        Xử lý dữ liệu: chọn đặc trưng, chuẩn hóa, chia tập train/val/test.
        """
        df = self.load_data()
        X = df[self.selected_features]
        y = df['status']
        
        # Chuẩn hóa đặc trưng
        X_scaled = self.scaler.fit_transform(X)
        
        # Chia dữ liệu
        X_train_val, self.X_test, y_train_val, self.y_test = train_test_split(
            X_scaled, y, test_size=0.15, random_state=42, stratify=y)
        self.X_train, self.X_val, self.y_train, self.y_val = train_test_split(
            X_train_val, y_train_val, test_size=0.1765, random_state=42, stratify=y_train_val)
        
        # Lưu dữ liệu đã xử lý
        joblib.dump((self.X_train, self.X_val, self.X_test, self.y_train, self.y_val, 
                     self.y_test, self.scaler, self.selected_features), self.output_path)
        print(f"Xử lý dữ liệu hoàn tất. Dữ liệu được lưu tại {self.output_path}")

if __name__ == "__main__":
    preprocessor = PhishingDataPreprocessor()
    preprocessor.preprocess()