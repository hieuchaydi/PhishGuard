async function checkURL() {
    const urlInput = document.getElementById('url-input').value;
    const resultDiv = document.getElementById('result');
    const htmlAnalysisDiv = document.getElementById('html-analysis');
    const featuresAnalysisDiv = document.getElementById('features-analysis');
    const modelInfoDiv = document.getElementById('model-info');
    const loadingDiv = document.getElementById('loading');

    if (!urlInput) {
        resultDiv.textContent = 'Vui lòng nhập URL!';
        resultDiv.className = 'result-box';
        htmlAnalysisDiv.innerHTML = '';
        htmlAnalysisDiv.className = 'analysis-box hidden';
        featuresAnalysisDiv.innerHTML = '';
        featuresAnalysisDiv.className = 'analysis-box hidden';
        modelInfoDiv.innerHTML = '';
        modelInfoDiv.className = 'analysis-box hidden';
        loadingDiv.className = 'loading hidden';
        return;
    }

    resultDiv.textContent = '';
    resultDiv.className = 'result-box hidden';
    htmlAnalysisDiv.innerHTML = '';
    htmlAnalysisDiv.className = 'analysis-box hidden';
    featuresAnalysisDiv.innerHTML = '';
    featuresAnalysisDiv.className = 'analysis-box hidden';
    modelInfoDiv.innerHTML = '';
    modelInfoDiv.className = 'analysis-box hidden';
    loadingDiv.className = 'loading';

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
        console.log('Response:', data);

        resultDiv.innerHTML = `
            <p>🔍 URL: ${data.url}</p>
            <p>👉 Kết quả dự đoán: ${data.result}</p>
            <p>🔢 Xác suất phishing: ${data.probability}</p>
        `;
        resultDiv.className = 'result-box ' + (
            data.result.includes('Phishing') ? 'phishing' :
            data.result.includes('ngờ') ? 'suspicious' : 'legitimate'
        );

        const analysis = data.html_analysis || {
            num_links: 0,
            num_forms: 0,
            num_iframes: 0,
            title: "Không có",
            external_links: []
        };
        htmlAnalysisDiv.innerHTML = `
            <h3>Phân Tích HTML</h3>
            <p><strong>Số lượng liên kết (&lt;a&gt;):</strong> ${analysis.num_links}</p>
            <p><strong>Số lượng biểu mẫu (&lt;form&gt;):</strong> ${analysis.num_forms}</p>
            <p><strong>Số lượng iframe (&lt;iframe&gt;):</strong> ${analysis.num_iframes}</p>
            <p><strong>Tiêu đề trang (&lt;title&gt;):</strong> ${analysis.title}</p>
            <p><strong>Liên kết ngoài:</strong></p>
            <ul>
                ${analysis.external_links.length > 0 ? analysis.external_links.map(link => `<li>${link}</li>`).join('') : '<li>Không có</li>'}
            </ul>
        `;
        htmlAnalysisDiv.className = 'analysis-box';

        const features = data.features || {};
        featuresAnalysisDiv.innerHTML = `
            <h3>Phân Tích Đặc Trưng</h3>
            <ul>
                ${Object.keys(features).map(key => `<li>${key}: ${features[key]}</li>`).join('')}
            </ul>
        `;
        featuresAnalysisDiv.className = 'analysis-box';

        loadingDiv.className = 'loading hidden';
    } catch (error) {
        console.error('Error:', error);
        resultDiv.textContent = 'Lỗi: ' + (error.message.includes('URL không hợp lệ') ? error.message.replace('{"detail":"', '').replace('"}', '') : error.message);
        resultDiv.className = 'result-box error';
        htmlAnalysisDiv.innerHTML = '';
        htmlAnalysisDiv.className = 'analysis-box hidden';
        featuresAnalysisDiv.innerHTML = '';
        featuresAnalysisDiv.className = 'analysis-box hidden';
        loadingDiv.className = 'loading hidden';
    }
}

async function showModelInfo() {
    const modelInfoDiv = document.getElementById('model-info');
    const loadingDiv = document.getElementById('loading');
    modelInfoDiv.innerHTML = '';
    modelInfoDiv.className = 'analysis-box hidden';
    loadingDiv.className = 'loading';

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
        modelInfoDiv.className = 'analysis-box';
        loadingDiv.className = 'loading hidden';
    } catch (error) {
        console.error('Error:', error);
        modelInfoDiv.innerHTML = 'Lỗi: ' + error.message;
        modelInfoDiv.className = 'analysis-box';
        loadingDiv.className = 'loading hidden';
    }
}