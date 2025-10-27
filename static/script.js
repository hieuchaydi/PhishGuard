let latestResult = null;

async function checkURL() {
    const urlInput = document.getElementById('url-input').value.trim();
    const loading = document.getElementById('loading');
    const resultDiv = document.getElementById('result');
    const htmlAnalysisDiv = document.getElementById('html-analysis');
    const featuresAnalysisDiv = document.getElementById('features-analysis');
    
    if (!urlInput) {
        alert('Vui lòng nhập URL!');
        return;
    }

    loading.classList.remove('hidden');
    resultDiv.classList.add('hidden');
    htmlAnalysisDiv.classList.add('hidden');
    featuresAnalysisDiv.classList.add('hidden');
    
    try {
        const response = await fetch('/predict', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: urlInput })
        });

        if (!response.ok) {
            throw new Error(`HTTP error! Status: ${response.status}`);
        }

        const data = await response.json();
        latestResult = data; // Lưu kết quả để sử dụng cho saveResultsToCSV
        
        loading.classList.add('hidden');
        
        resultDiv.classList.remove('hidden');
        resultDiv.innerHTML = `
            <h2 class="font-bold text-lg">Kết quả kiểm tra</h2>
            <p><strong>URL:</strong> ${data.url}</p>
            <p><strong>Kết quả:</strong> ${data.result}</p>
            <p><strong>Xác suất phishing:</strong> ${(data.probability * 100).toFixed(2)}%</p>
            <canvas id="probabilityChart"></canvas>
        `;
        showProbabilityChart(data.probability);
        
        htmlAnalysisDiv.classList.remove('hidden');
        htmlAnalysisDiv.innerHTML = `
            <h2 class="font-bold text-lg">Phân tích HTML</h2>
            <p><strong>Số liên kết:</strong> ${data.html_analysis.num_links}</p>
            <p><strong>Số form:</strong> ${data.html_analysis.num_forms}</p>
            <p><strong>Số iframe:</strong> ${data.html_analysis.num_iframes}</p>
            <p><strong>Tiêu đề trang:</strong> ${data.html_analysis.title}</p>
            <p><strong>Liên kết ngoài:</strong> ${data.html_analysis.external_links.length > 0 ? data.html_analysis.external_links.join(', ') : 'Không có'}</p>
        `;
        
        featuresAnalysisDiv.classList.remove('hidden');
        featuresAnalysisDiv.innerHTML = `
            <h2 class="font-bold text-lg">Phân tích đặc trưng</h2>
            <ul>${Object.keys(data.features).map(f => `<li><strong>${f}:</strong> ${data.features[f]}</li>`).join('')}</ul>
        `;
        
    } catch (error) {
        loading.classList.add('hidden');
        resultDiv.classList.remove('hidden');
        resultDiv.innerHTML = `<p class="text-red-500">Lỗi: ${error.message}</p>`;
    }
}

async function showModelInfo() {
    const modelInfoDiv = document.getElementById('model-info');
    modelInfoDiv.classList.remove('hidden');
    
    try {
        const response = await fetch('/model_info');
        const data = await response.json();
        
        modelInfoDiv.innerHTML = `
            <h2 class="font-bold text-lg">Thông tin mô hình</h2>
            <p><strong>Độ chính xác validation:</strong> ${(data.val_accuracy * 100).toFixed(2)}%</p>
            <p><strong>Độ chính xác test:</strong> ${(data.test_accuracy * 100).toFixed(2)}%</p>
            <h3 class="font-bold">Tầm quan trọng đặc trưng:</h3>
            <ul>${data.feature_importance.map(f => `<li>${f.feature}: ${(f.importance * 100).toFixed(2)}%</li>`).join('')}</ul>
        `;
    } catch (error) {
        modelInfoDiv.innerHTML = `<p class="text-red-500">Lỗi: ${error.message}</p>`;
    }
}

function showProbabilityChart(probability) {
    const ctx = document.getElementById('probabilityChart').getContext('2d');
    if (window.myChart) window.myChart.destroy();
    window.myChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: ['Phishing', 'Legitimate'],
            datasets: [{
                label: 'Xác suất',
                data: [probability, 1 - probability],
                backgroundColor: ['#ff0000', '#00ff00']
            }]
        },
        options: {
            scales: { y: { beginAtZero: true, max: 1 } }
        }
    });
}

async function saveResultsToCSV() {
    if (!latestResult) {
        alert('Vui lòng kiểm tra URL trước khi lưu kết quả!');
        return;
    }

    const data = latestResult;
    const csvContent = [
        'URL,Result,Probability,' + Object.keys(data.features).join(','),
        `${data.url},${data.result},${data.probability},${Object.values(data.features).join(',')}`
    ].join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'phishing_results.csv';
    a.click();
    window.URL.revokeObjectURL(url);
}