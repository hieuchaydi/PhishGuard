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
import idna
import socket
import whois
import time

current_time = "01:45 AM +07, Tuesday, October 28, 2025"
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
logger.info(f"Server started at {current_time}")

warnings.filterwarnings("ignore", category=requests.packages.urllib3.exceptions.InsecureRequestWarning)

app = FastAPI(title="Phishing Detector API")
app.mount("/static", StaticFiles(directory="static"), name="static")

class URLRequest(BaseModel):
    url: str

class PhishingDetector:
    def __init__(self, model_path='ensemble_model.pkl', data_path='preprocessed_data.pkl', info_path='model_info.pkl'):
        self.model_path = model_path
        self.data_path = data_path
        self.info_path = info_path
        self.ensemble = None
        self.scaler = None
        self.features = None
        self.model_info = None
        self.load_model()

    def load_model(self):
        try:
            self.ensemble = joblib.load(self.model_path)
            _, _, _, _, _, _, self.scaler, self.features = joblib.load(self.data_path)
            self.model_info = joblib.load(self.info_path)
            logger.info("✅ Mô hình, scaler và thông tin mô hình đã tải xong.")
        except Exception as e:
            logger.error(f"❌ Không thể tải model, scaler hoặc thông tin: {e}")
            raise

    @staticmethod
    def entropy(s):
        if not s or len(s) < 2:
            return 0.0
        p, l = {}, len(s)
        for c in s:
            p[c] = p.get(c, 0) + 1
        return -sum((c / l) * log2(c / l) for c in p.values() if c > 0)

    def longest_word(self, text):
        words = re.findall(r'[A-Za-z0-9]+', text)
        return max((len(w) for w in words), default=0)

    def get_domain_info(self, domain):
        try:
            w = whois.whois(domain)
            creation_date = w.creation_date
            expiration_date = w.expiration_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0]
            if creation_date and expiration_date:
                domain_age = (expiration_date - creation_date).days
                domain_registration_length = (expiration_date - creation_date).days
            else:
                domain_age = 0
                domain_registration_length = 0
            return {
                "domain_age": domain_age,
                "domain_registration_length": domain_registration_length,
                "dns_record": 1,  # Gán đúng khi DNS thành công
                "google_index": 1 if self.check_google_index(domain) else 0
            }
        except Exception as e:
            logger.warning(f"Lỗi khi lấy thông tin WHOIS cho {domain}: {e}")
            return {
                "domain_age": -1,  # Giá trị mặc định khi lỗi
                "domain_registration_length": -1,
                "dns_record": 1,  # Gán đúng khi DNS thành công
                "google_index": 0
            }

    def check_google_index(self, domain):
        max_attempts = 3
        for attempt in range(max_attempts):
            try:
                search_url = f"https://www.google.com/search?q=site:{domain}"
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    'Accept-Language': 'en-US,en;q=0.9'
                }
                response = requests.get(search_url, headers=headers, timeout=10)  # Tăng timeout
                response.raise_for_status()
                if "did not match any documents" in response.text.lower():
                    logger.info(f"Domain {domain} không được Google lập chỉ mục (attempt {attempt + 1}/{max_attempts}).")
                    return 0
                logger.info(f"Domain {domain} được Google lập chỉ mục (attempt {attempt + 1}/{max_attempts}).")
                return 1
            except requests.exceptions.RequestException as e:
                logger.warning(f"Lỗi khi kiểm tra chỉ mục Google cho {domain} (attempt {attempt + 1}/{max_attempts}): {e}")
                if attempt < max_attempts - 1:
                    time.sleep(2)
                else:
                    logger.error(f"Không thể kiểm tra chỉ mục Google cho {domain} sau {max_attempts} lần thử.")
                    return 0

    def extract_features(self, url):
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        p = urlparse(url)
        host = p.hostname or ""
        try:
            host_puny = idna.encode(host).decode("ascii")
        except idna.core.IDNAError as e:
            logger.warning(f"Invalid hostname '{host}' in URL '{url}': {e}")
            host_puny = host

        dns_record = 1  # Gán đúng khi DNS thành công, dựa trên log
        try:
            socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
            logger.info(f"DNS resolution succeeded for {host} with addresses: {socket.getaddrinfo(host, 443)}")
        except socket.gaierror as e:
            dns_record = 0
            logger.warning(f"DNS resolution failed for {host}: {e}")

        feats = {
            "length_url": len(url),
            "length_hostname": len(host),
            "nb_dots": url.count("."),
            "nb_hyphens": url.count("-"),
            "nb_at": url.count("@"),
            "nb_qm": url.count("?"),
            "nb_and": url.count("&"),
            "nb_or": url.lower().count("or"),
            "nb_eq": url.count("="),
            "nb_percent": url.count("%"),
            "nb_colon": url.count(":"),
            "nb_comma": url.count(","),
            "nb_space": url.count(" "),
            "nb_slash": url.count("/"),
            "nb_www": url.lower().count("www"),
            "nb_com": url.lower().count(".com"),
            "http_in_path": 1 if "http" in p.path.lower() else 0,
            "https_token": 1 if "https" in host.lower() and not url.startswith("https://") else 0,
            "prefix_suffix": 1 if "-" in host else 0,
            "longest_words_raw": self.longest_word(url),
            "tld_in_subdomain": 1 if len(host.split(".")) > 2 and host.split(".")[-1] in host.split(".")[0] else 0,
            "shortening_service": 1 if any(s in host for s in ['bit.ly', 't.co', 'goo.gl', 'tinyurl.com']) else 0,
            "ratio_digits_url": sum(c.isdigit() for c in url) / len(url),
            "ratio_digits_host": sum(c.isdigit() for c in host) / len(host) if len(host) > 0 else 0,
            "login_form": 0,
            "submit_email": 0,
            "iframe": 0,
            "popup_window": 0,
            "empty_title": 0,
            "domain_in_title": 0,
            "domain_age": 0,
            "domain_registration_length": 0,
            "dns_record": dns_record,
            "google_index": 0,
            "entropy_host": self.entropy(host_puny)
        }

        html_analysis = {
            "num_links": 0,
            "num_forms": 0,
            "num_iframes": 0,
            "title": "Không có",
            "external_links": []
        }

        if dns_record == 1:
            try:
                r = requests.get(url, timeout=10, verify=False)  # Tăng timeout
                r.raise_for_status()
                s = BeautifulSoup(r.text, "html.parser")
                feats["login_form"] = 1 if s.find("input", {"type": "password"}) and s.find("form") else 0
                feats["submit_email"] = 1 if s.find("input", {"type": "email"}) and s.find("form") else 0
                feats["iframe"] = 1 if s.find("iframe") else 0
                feats["popup_window"] = 1 if "window.open" in r.text.lower() else 0
                title = s.find("title")
                feats["empty_title"] = 1 if not title or not title.text.strip() else 0
                feats["domain_in_title"] = 1 if title and host.split(".")[0] in title.text.lower() else 0
                html_analysis["num_links"] = len(s.find_all("a", href=True))
                html_analysis["num_forms"] = len(s.find_all("form"))
                html_analysis["num_iframes"] = len(s.find_all("iframe"))
                html_analysis["title"] = title.text.strip() if title and title.text.strip() else "Không có"
                html_analysis["external_links"] = [
                    a.get("href") for a in s.find_all("a", href=True)
                    if urlparse(a.get("href")).hostname and urlparse(a.get("href")).hostname != host
                ]
            except requests.exceptions.RequestException as e:
                logger.warning(f"Không thể truy cập {url} để cào HTML: {e}")

        domain_info = self.get_domain_info(host)
        feats.update(domain_info)

        logger.info(f"Features for {url}: {feats}")  # Log đầy đủ tất cả đặc trưng
        return feats, html_analysis

    def predict(self, url):
        feats, html_analysis = self.extract_features(url)
        X = pd.DataFrame([feats])[self.features]
        X_scaled = self.scaler.transform(X)
        pred = self.ensemble.predict(X_scaled)[0]
        prob = self.ensemble.predict_proba(X_scaled)[0][1]
        return {
            "url": url,
            "result": "Phishing ⚠️" if prob >= 0.5 else "Legitimate ✅",
            "probability": round(prob, 2),
            "features": feats,
            "html_analysis": html_analysis
        }

detector = PhishingDetector()

@app.get("/")
async def home():
    return FileResponse("static/index.html")

@app.post("/predict")
async def predict_phishing(req: URLRequest):
    url = req.url.strip()
    url_regex = re.compile(
        r'^(http|https)://(?:[\w.-]+|[^\x00-\x7F]+)\.[a-zA-Z]{2,}.*'
    )
    if not url_regex.match(url):
        logger.warning(f"❌ URL không hợp lệ: {url}")
        raise HTTPException(
            status_code=400,
            detail="URL không hợp lệ. Vui lòng nhập đúng định dạng (e.g., http://example.com)!"
        )
    try:
        logger.info(f"Nhận yêu cầu dự đoán cho URL: {url}")
        result = detector.predict(url)
        return result
    except Exception as e:
        logger.error(f"Lỗi khi dự đoán: {e}")
        raise HTTPException(status_code=500, detail="Không thể phân tích URL!")

@app.get("/model_info")
async def get_model_info():
    try:
        return detector.model_info
    except Exception as e:
        logger.error(f"Lỗi khi lấy thông tin mô hình: {e}")
        raise HTTPException(status_code=500, detail="Không thể lấy thông tin mô hình!")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)