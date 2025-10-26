async function checkURL() {
    const urlInput = document.getElementById('url-input').value;
    const resultDiv = document.getElementById('result');
    const htmlAnalysisDiv = document.getElementById('html-analysis');
    const featuresAnalysisDiv = document.getElementById('features-analysis');
    const modelInfoDiv = document.getElementById('model-info');

    if (!urlInput) {
        resultDiv.textContent = 'Vui lòng nhập URL!';
        resultDiv.className = 'result';
        htmlAnalysisDiv.innerHTML = '';
        featuresAnalysisDiv.innerHTML = '';
        return;
    }

    resultDiv.textContent = 'Đang kiểm tra...';
    resultDiv.className = 'result checking';
    htmlAnalysisDiv.innerHTML = '';
    featuresAnalysisDiv.innerHTML = '';
    modelInfoDiv.innerHTML = '';

    try {
        const response = await fetch('/predict', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ url: urlInput })
        });

        if (!response.ok) {
            throw new Error(await response.text());
        }

        const data = await response.json();
        resultDiv.innerHTML = `
            <p>🔍 URL: ${data.url}</p>
            <p>👉 Kết quả dự đoán: ${data.result}</p>
            <p>🔢 Xác suất phishing: ${data.probability}</p>
        `;
        resultDiv.className = 'result ' + (data.result.includes('Phishing') ? 'phishing' : 'legitimate');

        const analysis = data.html_analysis;
        htmlAnalysisDiv.innerHTML = `
            <h3>Phân Tích HTML</h3>
            <p><strong>Số lượng liên kết (&lt;a&gt;):</strong> ${analysis.num_links}</p>
            <p><strong>Số lượng biểu mẫu (&lt;form&gt;):</strong> ${analysis.num_forms}</p>
            <p><strong>Số lượng iframe (&lt;iframe&gt;):</strong> ${analysis.num_iframes}</p>
            <p><strong>Tiêu đề trang (&lt;title&gt;):</strong> ${analysis.title || 'Không có'}</p>
            <p><strong>Liên kết ngoài:</strong></p>
            <ul>
                ${analysis.external_links.length > 0 ? analysis.external_links.map(link => `<li>${link}</li>`).join('') : '<li>Không có</li>'}
            </ul>
        `;

        const features = data.features;
        featuresAnalysisDiv.innerHTML = `
            <h3>Phân Tích Đặc Trưng</h3>
            <ul>
                ${Object.keys(features).map(key => `<li>${key}: ${features[key]}</li>`).join('')}
            </ul>
        `;
    } catch (error) {
        resultDiv.textContent = 'Lỗi: ' + error.message;
        resultDiv.className = 'result';
        htmlAnalysisDiv.innerHTML = '';
        featuresAnalysisDiv.innerHTML = '';
    }
}

async function showModelInfo() {
    const modelInfoDiv = document.getElementById('model-info');
    modelInfoDiv.innerHTML = 'Đang tải thông tin mô hình...';

    try {
        const response = await fetch('/model_info');
        if (!response.ok) {
            throw new Error(await response.text());
        }

        const data = await response.json();
        const valAcc = (data.val_accuracy * 100).toFixed(2);
        const testAcc = (data.test_accuracy * 100).toFixed(2);
        const cm = data.confusion_matrix;
        const features = data.features;

        modelInfoDiv.innerHTML = `
            <h3>Thông Tin Mô Hình</h3>
            <p><strong>Độ chính xác validation:</strong> ${valAcc}%</p>
            <p><strong>Độ chính xác test:</strong> ${testAcc}%</p>
            <p><strong>Ma trận nhầm lẫn:</strong></p>
            <table>
                <tr>
                    <th></th>
                    <th>Dự đoán: An toàn</th>
                    <th>Dự đoán: Giả mạo</th>
                </tr>
                <tr>
                    <td><strong>Thực tế: An toàn</strong></td>
                    <td>${cm[0][0]}</td>
                    <td>${cm[0][1]}</td>
                </tr>
                <tr>
                    <td><strong>Thực tế: Giả mạo</strong></td>
                    <td>${cm[1][0]}</td>
                    <td>${cm[1][1]}</td>
                </tr>
            </table>
            <p><strong>Đặc trưng được sử dụng:</strong></p>
            <ul>
                ${features.map(f => `<li>${f}</li>`).join('')}
            </ul>
        `;
    } catch (error) {
        modelInfoDiv.innerHTML = 'Lỗi: ' + error.message;
    }
}