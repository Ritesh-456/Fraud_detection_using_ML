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
            const qrImage = document.getElementById('qr-image');
            qrImage.src = e.target.result; 
            document.getElementById('qr-image-container').style.display = 'block'; 
        };
        reader.readAsDataURL(input.files[0]);
    }
}

function clearQR() {
    const qrImageContainer = document.getElementById('qr-image-container');
    qrImageContainer.style.display = 'none'; // Hide the image container

    const qrInput = document.getElementById('qr-input');
    qrInput.value = ''; // Clear the file input

    document.getElementById('qr-result').style.display = 'none'; // Hide analysis result if any
}

function simulateQRAnalysis() {
    const confidence = Math.random() * 100; // Randomly generate confidence between 0 and 100
    return {
        is_fraud: confidence > 70, // If confidence is above 70%, mark as fraudulent
        confidence: confidence.toFixed(2), // Round the confidence to 2 decimal places
        risk_level: confidence > 80 ? 'High' : confidence > 50 ? 'Medium' : 'Low' // Assign risk level based on confidence
    };
}

function updateQRResult(result) {
    const resultCard = document.getElementById('qr-result');
    resultCard.style.display = 'block'; // Ensure the result card is visible

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
    const listItem = document.createElement('li'); // Create a new list item for history
    listItem.className = 'history-item'; // Add class for styling

    const statusBadge = document.createElement('span');
    statusBadge.className = `status-badge ${result.isFreud ? 'fraud' : 'safe'}`;
    statusBadge.textContent = result.isFreud ? 'Fraudulent' : 'Safe';

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

    listItem.innerHTML = `<span>${item}</span>`; 
    listItem.appendChild(statusBadge); 
    listItem.appendChild(deleteButton); 

    historyList.insertBefore(listItem, historyList.firstChild);
    updateLocalStorage(); 
}

function clearHistory() {
    const historyList = document.getElementById('history-list');
    historyList.innerHTML = '';
    localStorage.removeItem('analysisHistory'); 
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
});
