from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
import joblib
import requests
import re
import pandas as pd
from urllib.parse import urlparse
from math import log2
from bs4 import BeautifulSoup
import uvicorn
import warnings
import logging
import os

# Thiết lập logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Tắt cảnh báo SSL từ requests
warnings.filterwarnings("ignore", category=requests.packages.urllib3.exceptions.InsecureRequestWarning)

app = FastAPI(title="Phishing Detector API")

# Mount thư mục static để phục vụ file HTML, CSS, JS
app.mount("/static", StaticFiles(directory="static"), name="static")

class URLRequest(BaseModel):
    url: str

class PhishingDetector:
    def __init__(self, model_path='ensemble_model.pkl', scaler_path='scaler.pkl', data_path='preprocessed_data.pkl', info_path='model_info.pkl'):
        self.model_path = model_path
        self.scaler_path = scaler_path
        self.data_path = data_path
        self.info_path = info_path
        self.ensemble = None
        self.scaler = None
        self.features = None
        self.model_info = None
        self.load_model()

    def load_model(self):
        try:
            if not os.path.exists(self.model_path):
                raise FileNotFoundError(f"Mô hình không tìm thấy tại {self.model_path}")
            if not os.path.exists(self.scaler_path):
                raise FileNotFoundError(f"Scaler không tìm thấy tại {self.scaler_path}")
            if not os.path.exists(self.data_path):
                raise FileNotFoundError(f"Dữ liệu đã xử lý không tìm thấy tại {self.data_path}")
            
            self.ensemble = joblib.load(self.model_path)
            self.scaler = joblib.load(self.scaler_path)
            _, _, _, _, _, _, _, self.features = joblib.load(self.data_path)
            
            if os.path.exists(self.info_path):
                self.model_info = joblib.load(self.info_path)
            else:
                logger.warning(f"Tệp model_info.pkl không tồn tại tại {self.info_path}. Sử dụng thông tin mặc định.")
                self.model_info = {
                    'val_accuracy': 0.0,
                    'test_accuracy': 0.0,
                    'confusion_matrix': [[0, 0], [0, 0]],
                    'features': self.features
                }
            logger.info("Tải mô hình, scaler, thông tin mô hình và danh sách đặc trưng thành công.")
        except Exception as e:
            logger.error(f"Lỗi khi tải mô hình, scaler hoặc thông tin: {e}")
            raise

    @staticmethod
    def entropy(s):
        p, l = {}, len(s)
        for c in s:
            p[c] = p.get(c, 0) + 1
        return -sum((c / l) * log2(c / l) for c in p.values()) if l > 0 else 0

    @staticmethod
    def char_repeat(url):
        count = 0
        prev_char = None
        for char in url:
            if char == prev_char:
                count += 1
            prev_char = char
        return count

    def extract_features(self, url):
        # Thêm giao thức https:// nếu thiếu
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        p = urlparse(url)
        host, path = p.hostname or '', p.path
        parts = host.split('.') if host else []
        domain = '.'.join(parts[-2:]) if len(parts) >= 2 else host
        subdomain = '.'.join(parts[:-2]) if len(parts) > 2 else ''
        tld = parts[-1] if parts else ''

        feats = {
            'length_url': len(url),
            'length_hostname': len(host),
            'ip': 1 if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', host) or re.match(r'^[0-9a-fA-F:]+$', host) else 0,
            'nb_dots': url.count('.'),
            'nb_hyphens': url.count('-'),
            'nb_at': url.count('@'),
            'nb_qm': url.count('?'),
            'nb_and': url.count('&'),
            'nb_eq': url.count('='),
            'nb_slash': url.count('/'),
            'nb_underscore': url.count('_'),
            'prefix_suffix': 1 if '-' in domain else 0,
            'tld_in_subdomain': 1 if tld in subdomain else 0,
            'nb_subdomains': len(parts),
            'random_domain': 1 if self.entropy(domain) > 4 else 0,
            'shortening_service': 1 if any(s in host for s in ['bit.ly', 't.co', 'goo.gl', 'tinyurl.com', 'ow.ly', 'is.gd', 'buff.ly', 'adf.ly', 'bit.do', 'mcaf.ee']) else 0,
            'https_token': 1 if 'https' in url.lower() and not url.lower().startswith('https://') else 0,
            'ratio_digits_url': sum(c.isdigit() for c in url) / len(url) if url else 0,
            'ratio_digits_host': sum(c.isdigit() for c in host) / len(host) if host else 0,
            'char_repeat': self.char_repeat(url),
            'ratio_intHyperlinks': 0,
            'ratio_extHyperlinks': 0,
            'login_form': 0,
            'submit_email': 0,
            'iframe': 0,
            'popup_window': 0,
            'safe_anchor': 0,
            'external_favicon': 0,
            'empty_title': 0,
            'domain_in_title': 0
        }

        html_analysis = {
            'num_links': 0,
            'num_forms': 0,
            'num_iframes': 0,
            'title': '',
            'external_links': []
        }

        try:
            r = requests.get(url, timeout=5, verify=False)
            s = BeautifulSoup(r.text, 'html.parser')
            feats['login_form'] = 1 if any(i.get('type') == 'password' for f in s.find_all('form') for i in f.find_all('input')) else 0
            feats['submit_email'] = 1 if any(i.get('type') == 'email' for f in s.find_all('form') for i in f.find_all('input')) else 0
            feats['iframe'] = 1 if s.find_all('iframe') else 0
            feats['popup_window'] = 1 if 'window.open' in r.text.lower() else 0
            links = s.find_all('a', href=True)
            total_links = len(links)
            int_links = len([l for l in links if not urlparse(l['href']).netloc or urlparse(l['href']).netloc == urlparse(url).netloc])
            ext_links = [l['href'] for l in links if urlparse(l['href']).netloc and urlparse(l['href']).netloc != urlparse(url).netloc]
            feats['ratio_intHyperlinks'] = int_links / total_links if total_links > 0 else 0
            feats['ratio_extHyperlinks'] = len(ext_links) / total_links if total_links > 0 else 0
            feats['safe_anchor'] = len([l for l in links if l['href'].startswith('#') or l['href'] == '']) / total_links if total_links > 0 else 0
            favicon = s.find('link', rel='icon') or s.find('link', rel='shortcut icon')
            feats['external_favicon'] = 1 if favicon and urlparse(favicon.get('href', '')).netloc and urlparse(favicon.get('href', '')).netloc != urlparse(url).netloc else 0
            title = s.find('title')
            feats['empty_title'] = 1 if not title or not title.text.strip() else 0
            feats['domain_in_title'] = 1 if title and domain in title.text.lower() else 0
            html_analysis['num_links'] = total_links
            html_analysis['num_forms'] = len(s.find_all('form'))
            html_analysis['num_iframes'] = len(s.find_all('iframe'))
            html_analysis['title'] = title.text.strip() if title else ''
            html_analysis['external_links'] = ext_links[:10]
        except Exception as e:
            logger.warning(f"Lỗi khi cào HTML từ {url}: {e}")

        return feats, html_analysis

    def predict(self, url: str):
        try:
            # Thêm giao thức https:// nếu thiếu
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            feats, html_analysis = self.extract_features(url)
            X = pd.DataFrame([feats])[self.features]
            X_scaled = self.scaler.transform(X)
            pred = self.ensemble.predict(X_scaled)[0]
            prob = self.ensemble.predict_proba(X_scaled)[0][1]  # Xác suất lớp phishing (1)
            return {
                "url": url,
                "result": "Phishing ⚠️" if pred else "Legitimate ✅",
                "probability": round(prob, 2),
                "html_analysis": html_analysis,
                "features": feats
            }
        except Exception as e:
            logger.error(f"Lỗi khi dự đoán URL {url}: {e}")
            raise HTTPException(status_code=500, detail=str(e))

# Khởi tạo detector
try:
    detector = PhishingDetector()
except Exception as e:
    logger.error(f"Không thể khởi tạo PhishingDetector: {e}")
    raise

# Route để phục vụ trang HTML
@app.get("/")
async def serve_home():
    return FileResponse("static/index.html")

# Endpoint API để dự đoán phishing
@app.post("/predict")
async def predict_phishing(request: URLRequest):
    if not request.url:
        raise HTTPException(status_code=400, detail="URL không được để trống")
    logger.info(f"Nhận yêu cầu dự đoán cho URL: {request.url}")
    return detector.predict(request.url)

# Endpoint API để lấy thông tin mô hình
@app.get("/model_info")
async def get_model_info():
    try:
        logger.info("Truy cập endpoint /model_info")
        if detector.model_info is None:
            raise ValueError("Thông tin mô hình không khả dụng")
        return detector.model_info
    except Exception as e:
        logger.error(f"Lỗi khi truy xuất thông tin mô hình: {e}")
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)