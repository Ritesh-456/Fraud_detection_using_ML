function analyzeUrl() {
    const url = document.getElementById('url-input').value;
    if (!url) return;

    fetch('http://127.0.0.1:5000/analyze-url', {  
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url: url })
    })
        .then(response => response.json())
        .then(result => {
            updateUrlResult(result);  
            addToHistory(url, result);  
        })
        .catch(error => {
            console.error('Error:', error);
        });
}

function updateUrlResult(result) {
    const resultCard = document.getElementById('url-result');
    resultCard.style.display = 'block';
    resultCard.className = `result-card ${result.is_fraud ? 'fraud' : 'safe'}`;

    document.getElementById('confidence-value').textContent = `${result.confidence}%`;
    document.getElementById('confidence-bar').style.width = `${result.confidence}%`;
    document.getElementById('risk-level').textContent = result.risk_level;

    const riskList = document.getElementById('risk-factors-list');
    riskList.innerHTML = result.risk_factors.map(factor => `<li>${factor}</li>`).join('');
}

function simulateUrlAnalysis(url) {
    const confidence = Math.random() * 100;
    return {
        is_fraud: confidence > 70,
        confidence: confidence.toFixed(2),
        risk_level: confidence > 80 ? 'High' : confidence > 50 ? 'Medium' : 'Low',
        risk_factors: [
            'Suspicious domain',
            'Contains unusual characters',
            'Recently registered domain'
        ]
    };
}

function analyzeQR(input) {
    if (input.files && input.files[0]) {
        const reader = new FileReader();
        reader.onload = function (e) {
            const result = simulateQRAnalysis();
            updateQRResult(result);
            addToHistory('QR Code Analysis', result);
        };
        reader.readAsDataURL(input.files[0]);
    }
}

function simulateQRAnalysis() {
    const confidence = Math.random() * 100;
    return {
        is_fraud: confidence > 70,
        confidence: confidence.toFixed(2),
        risk_level: confidence > 80 ? 'High' : confidence > 50 ? 'Medium' : 'Low'
    };
}

function updateQRResult(result) {
    const resultCard = document.getElementById('qr-result');
    resultCard.style.display = 'block';
    resultCard.className = `result-card ${result.is_fraud ? 'fraud' : 'safe'}`;
    resultCard.innerHTML = `
<h3>Analysis Results</h3>
<div class="result-details">
    <p>Confidence: ${result.confidence}%</p>
    <p>Risk Level: ${result.risk_level}</p>
</div>
`;
}

function addToHistory(item, result) {
    const historyList = document.getElementById('history-list');
    const listItem = document.createElement('li');
    listItem.className = 'history-item';
    listItem.innerHTML = `
<span>${item}</span>
<span class="status-badge ${result.is_fraud ? 'fraud' : 'safe'}">
    ${result.is_fraud ? 'Fraudulent' : 'Safe'}
</span>
`;
    historyList.insertBefore(listItem, historyList.firstChild);
}
