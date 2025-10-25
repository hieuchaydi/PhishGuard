import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import joblib

class PhishingDataPreprocessor:
    def __init__(self, data_path='dataset_phishing.csv', output_path='preprocessed_data.pkl'):
        """
        Initialize the PhishingDataPreprocessor.

        Parameters:
        - data_path (str): Path to the input CSV file.
        - output_path (str): Path to save the preprocessed data.
        """
        self.data_path = data_path
        self.output_path = output_path
        self.selected_features = [
            'length_url', 'length_hostname', 'nb_dots', 'nb_hyphens', 'nb_at', 'nb_qm',
            'nb_and', 'nb_eq', 'nb_underscore', 'nb_tilde', 'nb_percent', 'nb_slash',
            'nb_star', 'nb_colon', 'nb_comma', 'nb_semicolumn', 'nb_dollar', 'nb_space',
            'nb_www', 'nb_com', 'nb_dslash', 'http_in_path', 'https_token',
            'ratio_digits_url', 'ratio_digits_host', 'punycode', 'port', 'tld_in_path',
            'tld_in_subdomain', 'abnormal_subdomain', 'nb_subdomains', 'prefix_suffix',
            'random_domain', 'shortening_service', 'path_extension', 'ip',
            'nb_forms_no_pwd', 'has_hidden_iframe', 'nb_external_scripts', 'nb_external_imgs'
        ]
        self.html_cols = ['nb_forms_no_pwd', 'has_hidden_iframe', 'nb_external_scripts', 'nb_external_imgs']
        self.scaler = StandardScaler()
        self.X_train = None
        self.X_val = None
        self.X_test = None
        self.y_train = None
        self.y_val = None
        self.y_test = None

    def load_data(self):
        """
        Load and preprocess the dataset from CSV.
        """
        try:
            df = pd.read_csv(self.data_path)
            df['status'] = df['status'].map({'legitimate': 0, 'phishing': 1})
            
            # Add HTML columns with default value 0 if not present
            for col in self.html_cols:
                if col not in df.columns:
                    df[col] = 0
            
            return df
        except Exception as e:
            print(f"Error loading data: {e}")
            raise

    def preprocess(self):
        """
        Preprocess the data: select features, scale, and split into train/val/test sets.
        """
        df = self.load_data()
        X = df[self.selected_features]
        y = df['status']
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        # Split data
        X_train_val, self.X_test, y_train_val, self.y_test = train_test_split(
            X_scaled, y, test_size=0.15, random_state=42, stratify=y)
        self.X_train, self.X_val, self.y_train, self.y_val = train_test_split(
            X_train_val, y_train_val, test_size=0.1765, random_state=42, stratify=y_train_val)
        
        # Save preprocessed data
        joblib.dump((self.X_train, self.X_val, self.X_test, self.y_train, self.y_val, 
                     self.y_test, self.scaler, self.selected_features), self.output_path)
        print(f"Preprocessing completed. Data saved to {self.output_path}")

if __name__ == "__main__":
    preprocessor = PhishingDataPreprocessor()
    preprocessor.preprocess()