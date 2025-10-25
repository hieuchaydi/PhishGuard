import tkinter as tk
from tkinter import ttk, messagebox
import joblib
import requests
import re
import pandas as pd
from urllib.parse import urlparse
from math import log2
from bs4 import BeautifulSoup
import threading

class PhishingDetectorGUI:
    def __init__(self, model_path='ensemble_model.pkl', scaler_path='scaler.pkl', data_path='preprocessed_data.pkl'):
        """
        Initialize the PhishingDetectorGUI.

        Parameters:
        - model_path (str): Path to the trained model.
        - scaler_path (str): Path to the scaler.
        - data_path (str): Path to the preprocessed data for features list.
        """
        self.model_path = model_path
        self.scaler_path = scaler_path
        self.data_path = data_path
        self.ensemble = None
        self.scaler = None
        self.features = None
        self.root = None
        self.entry = None
        self.btn = None
        self.result_label = None

    def load_model(self):
        """
        Load the trained model, scaler, and features.
        """
        try:
            self.ensemble = joblib.load(self.model_path)
            self.scaler = joblib.load(self.scaler_path)
            _, _, _, _, _, _, _, self.features = joblib.load(self.data_path)
            print("Model, scaler, and features loaded successfully.")
        except Exception as e:
            print(f"Error loading model or scaler: {e}")
            raise

    @staticmethod
    def entropy(s):
        """
        Calculate the entropy of a string.
        """
        p, l = {}, len(s)
        for c in s:
            p[c] = p.get(c, 0) + 1
        return -sum((c / l) * log2(c / l) for c in p.values()) if l > 0 else 0

    @staticmethod
    def get_html_features(url):
        """
        Extract HTML-based features from a URL.
        """
        try:
            r = requests.get(url, timeout=5, verify=False)
            s = BeautifulSoup(r.text, 'html.parser')
            forms = s.find_all('form')
            pwd = any(i.get('type') == 'password' for f in forms for i in f.find_all('input'))
            iframes = s.find_all('iframe')
            scripts = [sc for sc in s.find_all('script') if sc.get('src')]
            imgs = [img.get('src') for img in s.find_all('img') if img.get('src') and urlparse(img.get('src')).netloc != urlparse(url).netloc]
            return {
                'nb_forms_no_pwd': len(forms) - pwd,
                'has_hidden_iframe': any('hidden' in str(i).lower() for i in iframes),
                'nb_external_scripts': len(scripts),
                'nb_external_imgs': len(imgs)
            }
        except:
            return {'nb_forms_no_pwd': 0, 'has_hidden_iframe': 0, 'nb_external_scripts': 0, 'nb_external_imgs': 0}

    def extract_features(self, url):
        """
        Extract features from a URL for prediction.
        """
        p = urlparse(url)
        host, path = p.hostname or '', p.path
        parts = host.split('.') if host else []
        domain = '.'.join(parts[-2:]) if len(parts) >= 2 else host
        subdomain = '.'.join(parts[:-2]) if len(parts) > 2 else ''

        feats = {
            'length_url': len(url),
            'length_hostname': len(host),
            'nb_dots': url.count('.'),
            'nb_hyphens': url.count('-'),
            'nb_at': url.count('@'),
            'nb_qm': url.count('?'),
            'nb_and': url.count('&'),
            'nb_eq': url.count('='),
            'nb_underscore': url.count('_'),
            'nb_tilde': url.count('~'),
            'nb_percent': url.count('%'),
            'nb_slash': url.count('/'),
            'nb_star': url.count('*'),
            'nb_colon': url.count(':'),
            'nb_comma': url.count(','),
            'nb_semicolumn': url.count(';'),
            'nb_dollar': url.count('$'),
            'nb_space': url.count(' '),
            'nb_www': 1 if 'www' in host else 0,
            'nb_com': 1 if '.com' in host else 0,
            'nb_dslash': url.count('//'),
            'http_in_path': 1 if 'http' in path.lower() else 0,
            'https_token': 1 if 'https' in url.lower() else 0,
            'ratio_digits_url': sum(c.isdigit() for c in url) / len(url) if url else 0,
            'ratio_digits_host': sum(c.isdigit() for c in host) / len(host) if host else 0,
            'punycode': 1 if host.startswith('xn--') else 0,
            'port': 1 if p.port else 0,
            'tld_in_path': 1 if (parts[-1] if parts else '') in path else 0,
            'tld_in_subdomain': 1 if (parts[-1] if parts else '') in subdomain else 0,
            'abnormal_subdomain': 1 if re.search(r'\.{2,}', subdomain) or len(subdomain) > 30 else 0,
            'nb_subdomains': len(parts),
            'prefix_suffix': 1 if '-' in domain else 0,
            'random_domain': 1 if self.entropy(domain) > 4 else 0,
            'shortening_service': 1 if any(s in host for s in ['bit.ly', 't.co', 'goo.gl', 'tinyurl.com', 'ow.ly', 'is.gd', 'buff.ly', 'adf.ly', 'bit.do', 'mcaf.ee']) else 0,
            'path_extension': 1 if path.endswith(('.exe', '.zip', '.rar', '.php', '.html')) else 0,
            'ip': 1 if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', host) or re.match(r'^[0-9a-fA-F:]+$', host) else 0
        }
        feats.update(self.get_html_features(url))
        return feats

    def predict(self):
        """
        Predict whether a URL is phishing or legitimate.
        """
        url = self.entry.get().strip()
        if not url:
            return
        self.btn.config(state='disabled')
        self.result_label.config(text="Đang kiểm tra...", foreground="orange")

        def run():
            try:
                f = self.extract_features(url)
                X = pd.DataFrame([f])[self.features]
                X_scaled = self.scaler.transform(X)
                pred = self.ensemble.predict(X_scaled)[0]
                txt = "PHISHING (Giả mạo)" if pred else "LEGITIMATE (An toàn)"
                color = "red" if pred else "green"
                self.result_label.config(text=txt, foreground=color)
            except Exception as e:
                messagebox.showerror("Lỗi", str(e))
            finally:
                self.btn.config(state='normal')

        threading.Thread(target=run, daemon=True).start()

    def setup_gui(self):
        """
        Set up the Tkinter GUI for the phishing detector.
        """
        self.root = tk.Tk()
        self.root.title("Phishing Detector")
        self.root.geometry("520x220")
        self.root.resizable(False, False)

        tk.Label(self.root, text="Nhập URL để kiểm tra:", font=("Arial", 12)).pack(pady=10)
        self.entry = ttk.Entry(self.root, width=65, font=("Arial", 10))
        self.entry.pack(pady=5)

        self.btn = ttk.Button(self.root, text="Kiểm tra", command=self.predict)
        self.btn.pack(pady=10)

        self.result_label = tk.Label(self.root, text="", font=("Arial", 14, "bold"))
        self.result_label.pack(pady=10)

    def run(self):
        """
        Load model and run the GUI application.
        """
        self.load_model()
        self.setup_gui()
        self.root.mainloop()

if __name__ == "__main__":
    gui = PhishingDetectorGUI()
    gui.run()