import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import joblib
from math import log2
from urllib.parse import urlparse
import idna
import numpy as np

class PhishingDataPreprocessor:
    def __init__(self, data_path='dataset_phishing.csv', output_path='preprocessed_data.pkl'):
        self.data_path = data_path
        self.output_path = output_path
        self.selected_features = [
            "length_url", "length_hostname", "nb_dots", "nb_hyphens", "nb_at", "nb_qm",
            "nb_and", "nb_or", "nb_eq", "nb_percent", "nb_colon", "nb_comma", "nb_space",
            "nb_slash", "nb_www", "nb_com", "http_in_path", "https_token", "prefix_suffix",
            "longest_words_raw", "tld_in_subdomain", "shortening_service", "ratio_digits_url",
            "ratio_digits_host", "login_form", "submit_email", "iframe", "popup_window",
            "empty_title", "domain_in_title", "domain_age", "domain_registration_length",
            "dns_record", "google_index", "entropy_host"
        ]
        self.scaler = StandardScaler()
        self.X_train = None
        self.X_val = None
        self.X_test = None
        self.y_train = None
        self.y_val = None
        self.y_test = None

    @staticmethod
    def entropy(s):
        if not s or len(s) < 2:  # Handle empty or very short strings
            return 0.0
        p, l = {}, len(s)
        for c in s:
            p[c] = p.get(c, 0) + 1
        return -sum((c / l) * log2(c / l) for c in p.values() if c > 0)

    def load_data(self):
        try:
            df = pd.read_csv(self.data_path)
            df['status'] = df['status'].map({'legitimate': 0, 'phishing': 1})

            def compute_entropy_host(url):
                host = urlparse(url).hostname or ""
                if not host:
                    return 0.0
                try:
                    host_puny = idna.encode(host).decode("ascii")
                    return self.entropy(host_puny)
                except idna.core.IDNAError as e:
                    print(f"Invalid hostname '{host}' in URL '{url}': {e}")
                    return self.entropy(host)  # Fallback to raw hostname

            df['entropy_host'] = df['url'].apply(compute_entropy_host)

            # Log entropy statistics
            print(f"Entropy statistics:\n{df.groupby('status')['entropy_host'].describe()}")
            print(f"Tải dữ liệu thành công: {df.shape[0]} samples.")
            return df
        except Exception as e:
            raise Exception(f"Lỗi khi đọc dữ liệu từ {self.data_path}: {e}")

    def preprocess(self):
        df = self.load_data()
        X = df[self.selected_features]
        y = df['status']
        X_scaled = self.scaler.fit_transform(X)
        X_train_val, self.X_test, y_train_val, self.y_test = train_test_split(
            X_scaled, y, test_size=0.15, random_state=42, stratify=y
        )
        self.X_train, self.X_val, self.y_train, self.y_val = train_test_split(
            X_train_val, y_train_val, test_size=0.1765, random_state=42, stratify=y_train_val
        )
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