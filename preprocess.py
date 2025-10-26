import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import joblib


class PhishingDataPreprocessor:
    """
    Tiền xử lý dữ liệu cho bài toán phát hiện phishing:
    - Chọn các đặc trưng cần thiết
    - Chuẩn hóa dữ liệu
    - Chia dữ liệu thành train/val/test
    - Lưu output dưới dạng pickle
    """

    def __init__(self, data_path='dataset_phishing.csv', output_path='preprocessed_data.pkl'):
        self.data_path = data_path
        self.output_path = output_path

        self.selected_features = [
            # 🔹 Đặc trưng URL (cấu trúc)
            "length_url", "length_hostname", "ip", "nb_dots", "nb_hyphens",
            "nb_at", "nb_qm", "nb_and", "nb_eq", "nb_slash", "nb_underscore",
            "prefix_suffix", "tld_in_subdomain", "nb_subdomains",
            "random_domain", "shortening_service", "https_token",

            # 🔹 Đặc trưng thống kê ký tự
            "ratio_digits_url", "ratio_digits_host", "char_repeat",

            # 🔹 Đặc trưng liên kết
            "ratio_intHyperlinks", "ratio_extHyperlinks",

            # 🔹 HTML / Nội dung trang
            "login_form", "submit_email", "iframe", "popup_window",
            "safe_anchor", "external_favicon", "empty_title", "domain_in_title",
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
        Đọc dataset và chuyển đổi label sang số.
        """
        try:
            df = pd.read_csv(self.data_path)
            df['status'] = df['status'].map({'legitimate': 0, 'phishing': 1})
            print(f"Tải dữ liệu thành công: {df.shape[0]} samples.")
            return df
        except Exception as e:
            raise Exception(f"Lỗi khi đọc dữ liệu từ {self.data_path}: {e}")

    def preprocess(self):
        """
        Tiền xử lý dữ liệu và lưu vào file.
        """
        df = self.load_data()

        # Chọn feature và label
        X = df[self.selected_features]
        y = df['status']

        # Chuẩn hóa
        X_scaled = self.scaler.fit_transform(X)

        # Chia dữ liệu theo tỷ lệ: 70% train, 15% val, 15% test
        X_train_val, self.X_test, y_train_val, self.y_test = train_test_split(
            X_scaled, y, test_size=0.15, random_state=42, stratify=y
        )
        self.X_train, self.X_val, self.y_train, self.y_val = train_test_split(
            X_train_val, y_train_val, test_size=0.1765, random_state=42, stratify=y_train_val
        )

        # Lưu tiền xử lý
        joblib.dump(
            (
                self.X_train, self.X_val, self.X_test,
                self.y_train, self.y_val, self.y_test,
                self.scaler, self.selected_features
            ),
            self.output_path
        )

        print(f"""
✅ Hoàn tất tiền xử lý!
📁 Train: {self.X_train.shape[0]} samples
📁 Val:   {self.X_val.shape[0]} samples
📁 Test:  {self.X_test.shape[0]} samples
📌 File đã lưu tại: {self.output_path}
        """)


if __name__ == "__main__":
    preprocessor = PhishingDataPreprocessor()
    preprocessor.preprocess()
