import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import joblib

df = pd.read_csv("dataset_phishing.csv")
df['status'] = df['status'].map({'legitimate': 0, 'phishing': 1})

# Chỉ thêm HTML cols = 0
html_cols = ['nb_forms_no_pwd', 'has_hidden_iframe', 'nb_external_scripts', 'nb_external_imgs']
for col in html_cols:
    if col not in df.columns:
        df[col] = 0

selected_features = [
    'length_url', 'length_hostname', 'nb_dots', 'nb_hyphens', 'nb_at', 'nb_qm',
    'nb_and', 'nb_eq', 'nb_underscore', 'nb_tilde', 'nb_percent', 'nb_slash',
    'nb_star', 'nb_colon', 'nb_comma', 'nb_semicolumn', 'nb_dollar', 'nb_space',
    'nb_www', 'nb_com', 'nb_dslash', 'http_in_path', 'https_token',
    'ratio_digits_url', 'ratio_digits_host', 'punycode', 'port', 'tld_in_path',
    'tld_in_subdomain', 'abnormal_subdomain', 'nb_subdomains', 'prefix_suffix',
    'random_domain', 'shortening_service', 'path_extension', 'ip'
] + html_cols

X = df[selected_features]
y = df['status']

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

X_train_val, X_test, y_train_val, y_test = train_test_split(
    X_scaled, y, test_size=0.15, random_state=42, stratify=y)
X_train, X_val, y_train, y_val = train_test_split(
    X_train_val, y_train_val, test_size=0.1765, random_state=42, stratify=y_train_val)

joblib.dump((X_train, X_val, X_test, y_train, y_val, y_test, scaler, selected_features),
            'preprocessed_data.pkl')
print("Preprocess done (HTML only).")