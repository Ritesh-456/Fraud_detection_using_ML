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
    document.getElementById('confidence-bar').style.width = `${Math.min(100, result.confidence)}%`;

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
        const file = input.files[0];
        const formData = new FormData();
        formData.append('file', file);

        fetch('http://127.0.0.1:5000/analyze-qr', {
            method: 'POST',
            body: formData,
        })
            .then(response => response.json())
            .then(result => {
                updateQRResult(result);
                const reader = new FileReader();
                reader.onload = function (e) {
                    const qrImage = document.getElementById('qr-image');
                    qrImage.src = e.target.result;
                    document.getElementById('qr-image-container').style.display = 'block';

                   
                    fetch('/generate-qr', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify({ url: result.url }),
                    })
                        .then(response => response.json())
                        .then(qrResult => {
                            addToHistory(result.url, result, qrResult.data);
                        })
                        .catch(error => {
                            console.error('Error generating QR code:', error);
                            addToHistory(result.url, result); 
                        });
                };
                reader.readAsDataURL(file);
                document.getElementById('clearQR').disabled = false;
            })
            .catch(error => {
                console.error('Error:', error);
            });
    }
}

function clearQR() {
    const qrImageContainer = document.getElementById('qr-image-container');
    qrImageContainer.style.display = 'none';

    const qrInput = document.getElementById('qr-input');
    qrInput.value = '';

    document.getElementById('qr-result').style.display = 'none';
    document.getElementById('clearQR').disabled = true;
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

function addToHistory(item, result, qrDataUrl = null) {
    const historyList = document.getElementById('history-list');
    const listItem = document.createElement('li');
    listItem.className = 'history-item';

    const statusBadge = document.createElement('span');
    statusBadge.className = `status-badge ${result.is_fraud ? 'fraud' : 'safe'}`;
    statusBadge.textContent = result.is_fraud ? 'Fraudulent' : 'Safe';

    const deleteButton = document.createElement('button');
    deleteButton.className = 'delete-history-item';
    deleteButton.innerHTML = '&#10060;';
    deleteButton.style.background = 'none';
    deleteButton.style.border = 'none';
    deleteButton.style.color = 'gray';
    deleteButton.style.fontSize = '12px';
    deleteButton.style.cursor = 'pointer';
    deleteButton.style.transition = 'color 0.3s ease, transform 0.2s ease, box-shadow 0.2s ease';
    deleteButton.style.marginLeft = '5px';
    deleteButton.onmouseover = function () {
        deleteButton.style.color = '#808080';
        deleteButton.style.transform = 'scale(1.1)';
        deleteButton.style.boxShadow = '0 4px 8px rgba(0, 0, 0, 0.2)';
    };
    deleteButton.onmouseout = function () {
        deleteButton.style.color = 'gray';
        deleteButton.style.transform = 'scale(1)';
        deleteButton.style.boxShadow = 'none';
    };
    deleteButton.onclick = function () {
        historyList.removeChild(listItem);
        updateLocalStorage();
    };

    let itemContent = `<span>${item}</span>`;

    if (qrDataUrl) {
        itemContent += `<img src="${qrDataUrl}" alt="QR Code" style="width: 30px; height: 30px; vertical-align: middle; margin-left: 5px;">`;
    }

    listItem.innerHTML = itemContent;
    listItem.appendChild(statusBadge);
    listItem.appendChild(deleteButton);

    historyList.insertBefore(listItem, historyList.firstChild);
    updateLocalStorage();
}

function updateLocalStorage() {
    const historyList = document.getElementById('history-list');
    const historyItems = [];
    historyList.querySelectorAll('.history-item').forEach(item => {
        historyItems.push({
            text: item.querySelector('span').textContent,
            isFreud: item.querySelector('.status-badge').classList.contains('fraud')
        });
    });
    localStorage.setItem('analysisHistory', JSON.stringify(historyItems));
}

function loadHistory() {
    const savedHistory = localStorage.getItem('analysisHistory');
    if (savedHistory) {
        JSON.parse(savedHistory).forEach(entry => {
            addToHistory(entry.text, { isFreud: entry.isFreud });
        });
    }
}
document.addEventListener('DOMContentLoaded', function () {
    const historySection = document.getElementById('history-section');
    historySection.style.width = '350px';

    const clearButton = document.createElement('button');
    clearButton.textContent = 'Clear History';
    clearButton.className = 'clear-history';
    clearButton.style.padding = '8px 12px';
    clearButton.style.border = 'none';
    clearButton.style.backgroundColor = 'gray';
    clearButton.style.color = 'white';
    clearButton.style.cursor = 'pointer';
    clearButton.style.borderRadius = '5px';
    clearButton.style.fontWeight = 'bold';
    clearButton.style.transition = 'background-color 0.3s ease';
    clearButton.onmouseover = function () {
        clearButton.style.backgroundColor = '#808080';
    };
    clearButton.onmouseout = function () {
        clearButton.style.backgroundColor = 'gray';
    };
    clearButton.onclick = clearHistory;

    historySection.appendChild(clearButton);

    loadHistory();
    document.getElementById('clearQR').disabled = true; 
});
