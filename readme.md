# Phishing URL Detector (URL + HTML Features)

**Dự án:** Phát hiện website lừa đảo (phishing) sử dụng đặc trưng từ **URL** và **nội dung HTML**.  
Kết hợp **Ensemble Learning** (Logistic Regression + Random Forest + Gradient Boosting) và giao diện **Tkinter** để kiểm tra real-time.

---

## Mục lục
1. [Tổng quan](#tổng-quan)  
2. [Tính năng chính](#tính-năng-chính)  
3. [Cấu trúc thư mục](#cấu-trúc-thư-mục)  
4. [Yêu cầu hệ thống](#yêu-cầu-hệ-thống)  
5. [Cài đặt nhanh](#cài-đặt-nhanh)  
6. [Chuẩn bị dữ liệu & huấn luyện](#chuẩn-bị-dữ-liệu--huấn-luyện)  
7. [Đặc trưng (Features)](#đặc-trưng-features)  
8. [Mô hình & Ensemble](#mô-hình--ensemble)  
9. [Sử dụng GUI (app.py)](#sử-dụng-gui-apppy)  
10. [Ví dụ đầu ra](#ví-dụ-đầu-ra)  
11. [Ghi chú bảo mật & đạo đức](#ghi-chú-bảo-mật--đạo-đức)  
12. [Góp ý / Báo lỗi](#góp-ý--báo-lỗi)  
13. [License](#license)

---

## Tổng quan
Dự án này nhằm xây dựng một công cụ kiểm tra URL để xác định **có phải phishing hay không** bằng cách kết hợp:
- Phân tích đặc trưng từ **URL** (độ dài, token, presence of IP, shortening, v.v.)
- Phân tích **HTML** của trang (form action, input types, iframe ẩn, script ngoại, ảnh ngoại, meta tags)
- Áp dụng pipeline tiền xử lý → huấn luyện → lưu model → GUI để kiểm thử real-time.

Mục tiêu: cân bằng giữa tốc độ (phù hợp kiểm tra real-time) và độ chính xác.

---

## Tính năng chính
- Kiểm tra URL real-time: trả về **LEGITIMATE** (xanh) hoặc **PHISHING** (đỏ).
- Phân tích chi tiết URL: IP trong domain, sử dụng shortening service, số lượng subdomain, presence of suspicious tokens (login, secure, update...).
- Phân tích HTML: form không có password, form action trỏ tới domain khác, iframe ẩn (width/height 0 hoặc CSS hidden), script/img loading từ domain bên ngoài.
- Ensemble model: kết hợp Logistic Regression, Random Forest, Gradient Boosting để tăng độ ổn định.
- Giao diện Tkinter đơn giản — nhập URL, bấm kiểm tra, hiển thị kết quả và log các feature quan trọng.
- Hỗ trợ chạy offline (sau khi đã huấn luyện và lưu mô hình).

---

## Cấu trúc thư mục
```
phishing_project/
│
├─ dataset_phishing.csv       # (Tùy chọn) dữ liệu gốc chứa URL + label
├─ requirements.txt           # gói cần thiết
├─ data_preprocess.py         # chuẩn bị dữ liệu, feature extraction
├─ model_train.py             # huấn luyện mô hình, lưu file model.pkl
├─ app.py                     # GUI (Tkinter) để kiểm tra real-time
├─ models/                    # thư mục lưu model đã huấn luyện (model.pkl)
└─ README.md                  # tài liệu này
```

---

## Yêu cầu hệ thống
- Python 3.8+
- Bộ thư viện (các gói chính):
  - scikit-learn
  - pandas
  - numpy
  - requests
  - beautifulsoup4
  - lxml
  - joblib (hoặc pickle)
  - tkinter (thường có sẵn trên hệ thống)
  - optionally: xgboost hoặc lightgbm nếu muốn thay GradientBoosting bằng XGBoost/LightGBM

Ví dụ `requirements.txt`:
```
pandas
numpy
scikit-learn
requests
beautifulsoup4
lxml
joblib
```

---

## Cài đặt nhanh

```bash
# 1. Tạo virtual environment (khuyến nghị)
python -m venv venv
# Windows
venv\Scripts\activate
# macOS / Linux
# source venv/bin/activate

# 2. Cài đặt dependencies
pip install -r requirements.txt
```

---

## Chuẩn bị dữ liệu & huấn luyện

**1) Tiền xử lý (chạy 1 lần)**  
`data_preprocess.py` chịu trách nhiệm:
- Đọc `dataset_phishing.csv` (cột bắt buộc: `url`, `label` với label = 0 (legit) hoặc 1 (phish))
- Làm sạch URL, chuẩn hóa
- Extract features từ URL (length, token count, số dấu `-`, presence of IP, shortening)
- Lấy HTML (sử dụng requests + bs4) để extract HTML features (form action, nếu có `<input type="password">`, iframe attributes, external scripts/images)
- Lưu feature matrix dưới dạng CSV (ví dụ `features.csv`) hoặc pickle.

**Lưu ý:** Khi crawl HTML, respect robots.txt và tránh gửi quá nhiều request — dùng delay.

**2) Huấn luyện & lưu model**  
`model_train.py`:
- Đọc `features.csv`
- Chia train/test, chuẩn hóa/scale nếu cần
- Huấn luyện LogisticRegression, RandomForestClassifier, GradientBoostingClassifier
- Tạo ensemble (ví dụ VotingClassifier hoặc stacking) — cân nhắc cân trọng số nếu model có performance khác nhau
- Lưu model đã huấn luyện (ví dụ `models/ensemble_model.pkl`) và lưu bộ scaler / encoder nếu có.

Chạy lần đầu:
```bash
python data_preprocess.py
python model_train.py
```

---

## Đặc trưng (Features) — chi tiết

### URL-based features
- `url_length`: tổng số ký tự URL
- `num_dots`: số dấu chấm
- `num_hyphens`: số dấu `-`
- `has_ip`: boolean nếu domain là IP (ví dụ `http://192.168.1.1/...`)
- `uses_shortening`: boolean nếu sử dụng goo.gl, bit.ly, tinyurl, v.v.
- `num_subdomains`: số subdomain (ví dụ `a.b.c.example.com`)
- `suspicious_tokens`: presence của token như `login`, `update`, `confirm`, `secure`, `bank`, `verify`
- `special_char_ratio`: tỷ lệ ký tự không phải chữ/số
- `path_depth`: chiều sâu path (số `/` sau domain)

### HTML-based features
- `has_form`: có `<form>` hay không
- `form_has_password_input`: có `<input type="password">` hay không
- `form_action_external`: form action trỏ sang domain khác (hoặc ip)
- `num_iframes`: số iframe
- `hidden_iframe`: iframe với width/height 0 hoặc style display:none
- `external_scripts_ratio`: tỉ lệ script tag load từ domain khác
- `external_images_ratio`: tỉ lệ img src từ domain khác
- `meta_redirect`: presence của meta refresh redirect
- `suspicious_js`: các pattern JS thường dùng trong phishing (obfuscation, document.write with external src...)

Các feature HTML trên cần xử lý carefully khi trang không load được — fallback values nên là `NaN` hoặc `0` tùy cách xử lý.

---

## Mô hình & Ensemble
- Mô hình cơ bản:
  - Logistic Regression — nhanh, dễ giải thích
  - Random Forest — bắt pattern phi tuyến, robust với outliers
  - Gradient Boosting (GBM) — thường có độ chính xác cao
- Kỹ thuật ensemble:
  - `VotingClassifier` (soft/hard voting) hoặc `StackingClassifier` với meta-learner (Logistic/LightGBM)
- Metrics để đánh giá: Accuracy, Precision, Recall, F1-score, ROC-AUC. Phishing detection nên ưu tiên Recall (bắt nhiều phishing) nếu chấp nhận false positives thấp.

---

## Sử dụng GUI (app.py)
- Mở terminal và chạy:
```bash
python app.py
```
- Giao diện gồm:
  - Input box: nhập URL đầy đủ (bao gồm http/https)
  - Button `Check`: phân tích URL + nếu có thể fetch HTML thì kết hợp feature HTML
  - Kết quả: hiển thị **LEGITIMATE** (màu xanh) hoặc **PHISHING** (màu đỏ)
  - Chi tiết: danh sách các feature quan trọng và giá trị, log request/response (nếu bật debug)

**Lưu ý bảo mật:** app.py có thể thực hiện request tới URL do người dùng nhập — cẩn thận với URL độc hại. Tốt nhất chạy trong môi trường an toàn hoặc sandbox.

---

## Ví dụ đầu ra
| URL | Kết quả |
|---|---|
| https://google.com | 🟢 LEGITIMATE |
| http://bit.ly/phish123 | 🔴 PHISHING |

(Giao diện GUI sẽ hiển thị màu sắc rõ ràng và thông tin chi tiết về lý do dự đoán)

---

## Ghi chú bảo mật & đạo đức
- Công cụ này chỉ hỗ trợ nhận diện sơ bộ, không đảm bảo 100% chính xác.
- Không dùng công cụ này để tấn công hoặc tạo phishing.
- Khi crawl / fetch HTML, hãy tuân thủ robots.txt và luật pháp địa phương.
- Không lưu thông tin người dùng nhạy cảm trên server công khai.

---

## Góp ý / Báo lỗi
Mở issue hoặc gửi pull request trên repository. Vui lòng kèm:
- Mô tả lỗi/feature
- Môi trường (OS, Python version)
- Log hoặc ảnh chụp màn hình

---

## License
MIT License — tuỳ chỉnh nếu cần.

---

## Tác giả
- Hiếu + Tú — Code gốc + cải tiến


---

### Ghi chú cuối
Bạn có thể:
- Thay thế placeholder ảnh GUI bằng ảnh chụp thực tế `assets/gui_preview.png`
- Thêm script tự động build model Docker nếu muốn triển khai
- Thêm test suite (pytest) để đảm bảo feature extraction hoạt động đúng

