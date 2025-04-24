// --- DOM Element References ---
const loginForm = document.getElementById('login-form');
const registerForm = document.getElementById('register-form');
const mainAppContent = document.getElementById('main-app-content');
const authSection = document.getElementById('auth-section');
const userStatus = document.getElementById('user-status');
const userIdentifierSpan = document.getElementById('user-identifier'); // Use the new ID
const authFormsDiv = document.getElementById('auth-forms');

const urlInput = document.getElementById('url-input');
const urlResultCard = document.getElementById('url-result');
const confidenceValueSpan = document.getElementById('confidence-value');
const confidenceBarFill = document.getElementById('confidence-bar');
const riskLevelSpan = document.getElementById('risk-level');
const riskFactorsList = document.getElementById('risk-factors-list');
const qrInput = document.getElementById('qr-input');
const qrImageContainer = document.getElementById('qr-image-container');
const qrImage = document.getElementById('qr-image');
const clearQRButton = document.getElementById('clearQR');
const qrResultCard = document.getElementById('qr-result');
const historyList = document.getElementById('history-list');
const clearHistoryButton = document.getElementById('clear-history-button'); // Use the unique ID


document.addEventListener('DOMContentLoaded', function() {
    const modeToggle = document.getElementById('mode-toggle');
    const body = document.body;

    // Load saved mode from localStorage
    let currentMode = localStorage.getItem('mode') || 'light'; // Default to light
    body.classList.add(currentMode + '-mode'); // Apply initial mode

    // Toggle Mode
    modeToggle.addEventListener('click', function() {
        if (currentMode === 'light') {
            currentMode = 'dark';
        } else {
            currentMode = 'light';
        }

        // Toggle the class on the body
        body.classList.remove('light-mode', 'dark-mode'); // Remove both classes
        body.classList.add(currentMode + '-mode');        // Add the current mode's class

        // Save mode to localStorage
        localStorage.setItem('mode', currentMode);
    });
});

// --- View State Management ---
function showLoginForm() {
    loginForm.style.display = 'block';
    registerForm.style.display = 'none';
    mainAppContent.style.display = 'none';
    authFormsDiv.style.display = 'none';
    userStatus.style.display = 'none';
    // Clear forms when switching
    document.getElementById('login-email').value = '';
    document.getElementById('login-password').value = '';
}

function showRegisterForm() {
    loginForm.style.display = 'none';
    registerForm.style.display = 'block';
    mainAppContent.style.display = 'none';
    authFormsDiv.style.display = 'none';
    userStatus.style.display = 'none';
    // Clear forms when switching
    document.getElementById('register-email').value = '';
    document.getElementById('register-password').value = '';
    document.getElementById('confirm-password').value = '';
    // Also clear username field if added
    const registerUsernameInput = document.getElementById('register-username');
    if (registerUsernameInput) {
        registerUsernameInput.value = '';
    }
}

// Update showMainApp function - displays user identifier (username)
function showMainApp(userIdentifier) {
    loginForm.style.display = 'none';
    registerForm.style.display = 'none';
    mainAppContent.style.display = 'grid';
    authFormsDiv.style.display = 'none';
    userStatus.style.display = 'flex';
    userIdentifierSpan.textContent = userIdentifier; // Set the username
}

function showAuthButtons() {
    loginForm.style.display = 'none';
    registerForm.style.display = 'none';
    mainAppContent.style.display = 'none';
    authFormsDiv.style.display = 'flex';
    userStatus.style.display = 'none';
    userIdentifierSpan.textContent = ''; // Clear display

    // Clear analysis results and history
    urlResultCard.style.display = 'none';
    qrResultCard.style.display = 'none';
    historyList.innerHTML = ''; // Clear history UI list
    clearQR();
}

// --- Authentication Functions (Backend API Calls) ---

async function register() {
    const email = document.getElementById('register-email').value;
    const username = document.getElementById('register-username').value; // Get username value
    const password = document.getElementById('register-password').value;
    const confirmPassword = document.getElementById('confirm-password').value;

    if (!email || !username || !password || !confirmPassword) { // Check for username input
        alert('Please fill in all fields.');
        return;
    }
    if (password !== confirmPassword) {
        alert('Passwords do not match.');
        return;
    }

    console.log('Attempting to register:', email, username);

    try {
        const response = await fetch('http://127.0.0.1:5000/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            // Include username in the body
            body: JSON.stringify({ email, username, password })
        });
        const result = await response.json();

        if (response.ok) {
            alert('Registration successful! You can now log in.');
            showLoginForm(); // Show login form after successful registration
        } else {
            alert('Registration failed: ' + (result.error || response.statusText));
            console.error('Registration error:', response.status, result);
        }
    } catch (error) {
        console.error('Network error during registration:', error);
        alert('An error occurred during registration. Please try again.');
    }
}


async function login() {
    const email = document.getElementById('login-email').value;
    const password = document.getElementById('login-password').value;

    if (!email || !password) {
        alert('Please enter email and password.');
        return;
    }

    console.log('Attempting to login:', email);

    try {
        const response = await fetch('http://127.0.0.1:5000/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password })
        });
        const result = await response.json();

        // Check for success and if username is available in the response
        if (response.ok && result.success && result.username) { // Ensure username is in the response
            console.log('Login successful. Reloading page...');
            // MODIFIED: Instead of showing main app directly, reload the page
            window.location.reload(); // This triggers checkLoginStatus on the reloaded page

        } else {
            // Handle login failure response from backend
            alert('Login failed: ' + (result.error || 'Invalid email or password'));
            console.error('Login error:', response.status, result);
        }
    } catch (error) {
        // Handle network errors or issues before response
        console.error('Network error during login:', error);
        alert('An error occurred during login. Please try again.');
    }
}

async function logout() {
    console.log('Attempting to logout');

    try {
        const response = await fetch('http://127.0.0.1:5000/logout', {
            method: 'POST'
             // Browser handles session cookies for authentication
        });

        if (response.ok && (await response.json()).success) {
            console.log('Logout successful');
            // MODIFIED: Reload page after logout to reset frontend state via checkLoginStatus
             window.location.reload(); // This triggers checkLoginStatus on the reloaded page
        } else {
             // Even if backend reports error, try to clear frontend state
             console.error('Logout failed:', response.status);
             window.location.reload(); // Still reload to reset state
             alert('Logout failed, but frontend state cleared.');
        }
    } catch (error) {
        console.error('Network error during logout:', error);
        alert('An error occurred during logout.');
        window.location.reload(); // Still reload to reset state
    }
}

// --- Initial Check for Login Status ---
async function checkLoginStatus() {
    console.log('Checking login status...');
    try {
        const response = await fetch('http://127.0.0.1:5000/status', {
            method: 'GET',
            headers: {
                // Browser handles session cookies for authentication
            }
        });
         const result = await response.json();

        // Check if logged in and username is available in the response
        if (response.ok && result.is_logged_in && result.username) { // Ensure username is in the response
            console.log('User is logged in:', result.email, 'Username:', result.username);
            showMainApp(result.username); // Pass username to showMainApp
            // Load history for the logged-in user (no delay needed here, it's on page load)
            loadHistory();
        } else {
            console.log('User is not logged in.');
            showAuthButtons(); // Show authentication options
        }
    } catch (error) {
        // Handle network errors or issues before response
        console.error('Network error checking login status:', error);
         // Assume not logged in or backend is down
        showAuthButtons();
        // Optionally, display a message indicating backend connection issue
        // alert('Could not connect to the backend. Please try again later.');
    }
}


// --- Analysis Functions (Backend API Calls handled by app.py save) ---
// These functions now just trigger the analysis on the backend.
// The backend handles saving the history for the logged-in user.

async function analyzeUrl() {
    const url = urlInput.value;
    if (!url) {
        alert('Please enter a URL.');
        return;
    }

    // Analysis routes on backend are protected by @login_required.
    // If the user is not logged in, the backend will return 302 (redirect to login),
    // which the browser follows. The subsequent GET to /login results in 405.
    // We need to handle the response status from the FINAL request after redirects.

    console.log('Analyzing URL:', url);
    // Clear previous results while analyzing
    urlResultCard.style.display = 'none';


    try {
        const response = await fetch('http://127.0.0.1:5000/analyze-url', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                 // Browser handles session cookies for authentication
            },
            body: JSON.stringify({ url: url })
        });

        // Fetch API follows 302 redirects. We need to check the status of the final response.
        // If Flask-Login redirected, the final response might be from GET /login (405) or the login page itself.

        if (response.ok) { // Status 200-299 from the FINAL response (should be from /analyze-url)
            const result = await response.json();
            console.log('URL Analysis Result:', result);
            updateUrlResult(result);
            // History saving is handled by the backend /analyze-url route
            // After a successful analysis that is saved, reload the history section.
             loadHistory(); // Reload history immediately

        } else if (response.status === 401) { // If Flask-Login was configured to return 401 instead of 302
            alert('Please log in to analyze URLs.');
            showAuthButtons(); // Redirect or show login form
        }
         else if (response.status === 405) { // Handle the 405 Method Not Allowed from the redirect to GET /login
             alert('Analysis failed. Please ensure you are logged in.');
             console.error('URL Analysis Error: Redirected to Login (405)', response.status, response.statusText);
             // The user was likely redirected because they weren't logged in or session expired.
             showAuthButtons(); // Show auth buttons as they are likely not logged in
        }
        else { // Handle other error statuses (e.g., 500 from /analyze-url itself)
             const errorResult = await response.json().catch(() => ({ error: 'Could not parse error response from backend' }));
             alert('Analysis failed: ' + (errorResult.error || response.statusText));
             console.error('URL Analysis Error:', response.status, errorResult);
        }

    } catch (error) {
        console.error('Network error during URL analysis:', error);
        alert('An error occurred during URL analysis.');
    }
}

async function analyzeQR(input) {
     // Analysis routes on backend are protected by @login_required.
     // Handle redirect/405 like analyzeUrl.

    if (input.files && input.files[0]) {
        const file = input.files[0];
        const formData = new FormData();
        formData.append('file', file);

        console.log('Analyzing QR code file:', file.name);
        // Clear previous results while analyzing
         qrResultCard.style.display = 'none';


        // Display the uploaded image first for immediate feedback
        const reader = new FileReader();
        reader.onload = function (e) {
            qrImage.src = e.target.result;
            qrImageContainer.style.display = 'block';
        };
        reader.readAsDataURL(file);
        clearQRButton.disabled = false;


        try {
            const response = await fetch('http://127.0.0.1:5000/analyze-qr', {
                method: 'POST',
                body: formData,
                 // Browser handles session cookies for authentication
            });

            // Handle 302 redirect -> 405 GET /login like analyzeUrl
             if (response.ok) { // Status 200-299 from the FINAL response (/analyze-qr)
                const result = await response.json();
                console.log('QR Analysis Result:', result);
                updateQRResult(result);
                // History saving is handled by the backend /analyze-qr route
                // After a successful analysis that is saved, reload history
                 loadHistory(); // Reload history immediately


             } else if (response.status === 401) { // If Flask-Login was configured to return 401
                 alert('Please log in to analyze QR codes.');
                 showAuthButtons(); // Redirect or show login form
                 clearQR(); // Clear the displayed QR image on auth error

            } else if (response.status === 405) { // Handle the 405 Method Not Allowed from the redirect to GET /login
                 alert('QR analysis failed. Please ensure you are logged in.');
                 console.error('QR Analysis Error: Redirected to Login (405)', response.status, response.statusText);
                 showAuthButtons(); // Show auth buttons as they are likely not logged in
                 clearQR(); // Clear the displayed QR image on redirect/auth error
            }
             else { // Handle other error statuses (e.g., 500 from /analyze-qr itself)
                 const errorResult = await response.json().catch(() => ({ error: 'Could not parse error response from backend' }));
                 alert('QR analysis failed: ' + (errorResult.error || response.statusText));
                 console.error('QR Analysis Error:', response.status, errorResult);
                // Optionally clear the displayed QR image and disable clear button
                // clearQR();
            }

        } catch (error) {
            console.error('Network error during QR analysis:', error);
            alert('An error occurred during QR analysis.');
            // Optionally clear the displayed QR image and disable clear button
            // clearQR();
        }
    }
}

function updateUrlResult(result) {
    urlResultCard.style.display = 'block';
    // Use risk level for warning class if not fraud and not low risk
    urlResultCard.className = `result-card ${result.is_fraud ? 'fraud' : (result.risk_level !== 'Low' ? 'warning' : 'safe')}`;

    confidenceValueSpan.textContent = `${parseFloat(result.confidence).toFixed(2)}`; // Ensure 2 decimal places
    // Ensure confidence bar doesn't exceed 100%
    confidenceBarFill.style.width = `${Math.min(100, parseFloat(result.confidence))}%;`;

    riskLevelSpan.textContent = result.risk_level;

    riskFactorsList.innerHTML = result.risk_factors.map(factor => `<li>${factor}</li>`).join('');
}

function updateQRResult(result) {
     qrResultCard.style.display = 'block';
     // Use risk level for warning class if not fraud and not low risk
    qrResultCard.className = `result-card ${result.is_fraud ? 'fraud' : (result.risk_level !== 'Low' ? 'warning' : 'safe')}`;

    qrResultCard.innerHTML = `
        <h3>Analysis Results</h3>
        <div class="result-details">
            <p>Confidence: ${parseFloat(result.confidence).toFixed(2)}%</p>
            <p>Risk Level: ${result.risk_level}</p>
            ${result.url ? `<p>Decoded URL: <span style="word-break: break-all;">${result.url}</span></p>` : ''} </div>
    `;
}


function clearQR() {
    qrImageContainer.style.display = 'none';
    qrImage.src = ''; // Clear the image source

    qrInput.value = ''; // Clear the file input value

    qrResultCard.style.display = 'none'; // Hide the result card
    clearQRButton.disabled = true; // Disable clear button again
}

// --- History Management Functions (Backend API Calls) ---

// saveAnalysisHistory is no longer needed as saving is done by backend analysis routes

// Updated loadHistory function with better error messages and no delay needed on initial load
async function loadHistory() {
    console.log('Attempting to load history from backend...');
    historyList.innerHTML = '<li class="history-item">Loading history...</li>'; // Show loading indicator

    try {
        const response = await fetch('http://127.0.0.1:5000/history', {
            method: 'GET',
            headers: {
                 // Browser handles session cookies for authentication
            }
        });

        if (response.ok) { // Status 200-299 means success
            const history = await response.json(); // Assuming backend returns a list of history items
            console.log('History loaded:', history);

            historyList.innerHTML = ''; // Clear loading indicator/previous content

            if (history && history.length > 0) {
                 history.forEach(item => {
                    // Format item from backend response to match expected structure for addHistoryItemToUI
                    // Backend structure: { id, user_id, item_type, item_data, analysis_result, analyzed_at }
                    const formattedItem = {
                         db_id: item.id, // Store the database ID for deletion
                         type: item.item_type,
                         data: item.item_data,
                         // If your backend returns qrDataUrl, use it here:
                         // qrDataUrl: item.analysis_result?.qrDataUrl || null,
                         qrDataUrl: null, // Assuming not returned currently

                         result: item.analysis_result // Use the parsed JSON result directly
                    };
                    addHistoryItemToUI(formattedItem);
                 });
            } else {
                console.log('No history found for this user.');
                historyList.innerHTML = '<li class="history-item">No history yet. Analyze something!</li>'; // Display "No history yet"
            }

        } else if (response.status === 401) {
             // This case might be hit if Flask-Login returns 401 instead of 302 redirect
             console.warn('Attempted to load history while not logged in (401).');
             historyList.innerHTML = '<li class="history-item">Please log in to view history.</li>';
             // showAuthButtons(); // Showing auth buttons is handled by checkLoginStatus on reload
        } else if (response.status === 405) {
             // This case is hit after the 302 redirect to GET /login
              console.error('Failed to load history: Redirected to Login (405). User session may have expired.');
              historyList.innerHTML = '<li class="history-item">Failed to load history. Please log in again.</li>';
              // showAuthButtons(); // Showing auth buttons is handled by checkLoginStatus on reload
        }
         else { // Handle other error statuses (e.g., 500 Internal Server Error from /history itself)
            // Try parsing JSON, fallback if not JSON - This is more robust error handling
            const errorResult = await response.json().catch(() => ({ error: 'Could not parse error response from backend' }));
            console.error('Failed to load history:', response.status, errorResult);
            historyList.innerHTML = `<li class="history-item">Error loading history: ${errorResult.error || `Status ${response.status}`}</li>`; // Display specific error message
        }
    } catch (error) { // Handle network errors or issues before response
        console.error('Network error loading history:', error);
        historyList.innerHTML = '<li class="history-item">Network error while loading history.</li>'; // More specific network error
    }
}

// Helper function to add a history item to the UI list
function addHistoryItemToUI(item) {
    const listItem = document.createElement('li');
    listItem.className = 'history-item';
    // Store the database ID on the list item element itself for easy access during deletion
    if (item.db_id) {
        listItem.dataset.historyId = item.db_id;
    }


    const statusBadge = document.createElement('span');
    // Ensure item.result exists before accessing its properties
    const isFraud = item.result ? item.result.is_fraud : false;
    statusBadge.className = `status-badge ${isFraud ? 'fraud' : 'safe'}`;
    statusBadge.textContent = isFraud ? 'Fraudulent' : 'Safe';

    const deleteButton = document.createElement('button');
    deleteButton.className = 'delete-history-item';
    deleteButton.innerHTML = '&#10060;'; // Unicode cross character
    deleteButton.title = 'Remove from history';

    // Attach the delete logic
    deleteButton.onclick = async function () {
        const historyId = listItem.dataset.historyId;
        if (historyId && confirm('Are you sure you want to remove this item from history?')) {
            const deleted = await deleteHistoryItem(historyId);
            if (deleted) {
                // Remove the item from the UI list only on backend success
                historyList.removeChild(listItem);
                console.log(`Removed history item ${historyId} from UI.`);
            } else {
                // Error message is shown by deleteHistoryItem, no extra alert here
            }
        } else if (!historyId) {
            console.error('History item missing database ID, cannot delete.');
            alert('Cannot delete this history item (ID not found).');
        }
    };


    let itemContentHtml = `<span>${item.data}</span>`;

    // Add QR image preview if available and you want to display it in history list
    // This requires the backend /history endpoint to return the QR image data URL,
    // or you need another endpoint to generate it from item.item_data.
    // For now, assuming qrDataUrl might not be directly available in the history list fetch.
    // if (item.type === 'qr' && item.qrDataUrl) {
    //     itemContentHtml += `<img src="${item.qrDataUrl}" alt="QR Code Preview" style="width: 30px; height: 30px; vertical-align: middle; margin-left: 10px; cursor: pointer;" onclick="showQrPreview('${item.qrDataUrl}')" title="View QR Code">`;
    // }

    listItem.innerHTML = itemContentHtml; // Set the content first
    listItem.appendChild(statusBadge); // Append badge
    // Only add delete button if the item has a database ID
    if (item.db_id) {
        listItem.appendChild(deleteButton);
    }


    // Add the new item to the top of the list
    historyList.insertBefore(listItem, historyList.firstChild);
}

async function deleteHistoryItem(item_id) {
    console.log('Attempting to delete history item with ID:', item_id);
    // Delete route is protected by @login_required. Handle 302 redirect -> 405 like analyzeUrl

    try {
        const response = await fetch(`http://127.0.0.1:5000/delete-history-item/${item_id}`, {
            method: 'DELETE',
            headers: {
                 // Browser handles session cookies for authentication
            }
        });

        if (response.ok) { // Status 200-299 means success from the FINAL response (/delete-history-item)
            const result = await response.json();
             if (result.success) {
                console.log('History item deleted successfully from backend.');
                // After successful deletion, reload history
                 loadHistory(); // Reload history immediately
                return true; // Indicate success
             } else {
                 // Backend returned 200 but success was false (e.g., item not found or not owned by user)
                 console.error('Failed to delete history item:', result.error || 'Unknown reason');
                 alert('Failed to delete history item: ' + (result.error || 'Unknown reason'));
                 return false;
             }

        } else if (response.status === 401) { // If Flask-Login returned 401
            alert('Please log in to delete history.');
            showAuthButtons(); // Redirect or show login form
            return false;
        } else if (response.status === 404) { // Backend explicitly returned 404
            const errorResult = await response.json().catch(() => ({ error: 'Not Found' }));
            console.error('Failed to delete history item:', response.status, errorResult);
            alert(`Failed to delete history item: ${errorResult.error || `Status ${response.status}`}`);
            return false;
        }
        else if (response.status === 405) { // Handle the 405 Method Not Allowed from the redirect to GET /login
             alert('Failed to delete history item. Please log in again.');
             console.error('Delete History Error: Redirected to Login (405)', response.status, response.statusText);
             showAuthButtons(); // Show auth buttons as they are likely not logged in
             return false;
        }
        else { // Handle other error statuses (e.g., 500 from /delete-history-item itself)
            const errorResult = await response.json().catch(() => ({ error: 'Could not parse error response from backend' }));
            console.error('Failed to delete history item:', response.status, errorResult);
            alert(`Failed to delete history item: ${errorResult.error || `Status ${response.status}`}`);
            return false;
        }
    } catch (error) { // Handle network errors or issues before response
        console.error('Network error deleting history item:', error);
        alert('A network error occurred while deleting history item.');
        return false; // Indicate failure
    }
}


async function clearHistory() {
    console.log('Attempting to clear history from backend...');
    // Clear history route is protected by @login_required. Handle 302 redirect -> 405 like analyzeUrl

    if (confirm('Are you sure you want to clear all your analysis history?')) {
        try {
            const response = await fetch('http://127.0.0.1:5000/clear-history', {
                method: 'POST',
                headers: {
                     // Browser handles session cookies for authentication
                }
            });

            if (response.ok) { // Status 200-299 means success from the FINAL response (/clear-history)
                const result = await response.json();
                if (result.success) {
                    console.log('History cleared successfully from backend.');
                    historyList.innerHTML = ''; // Clear the UI list on success
                } else {
                    // Backend returned 200 but success was false
                    console.error('Failed to clear history:', result.error || 'Unknown reason');
                    alert('Failed to clear history: ' + (result.error || 'Unknown reason'));
                }
            } else if (response.status === 401) { // If Flask-Login returned 401
                alert('Please log in to clear history.');
                showAuthButtons(); // Redirect or show login form
            } else if (response.status === 405) { // Handle the 405 Method Not Allowed from the redirect to GET /login
                 alert('Failed to clear history. Please log in again.');
                 console.error('Clear History Error: Redirected to Login (405)', response.status, response.statusText);
                 showAuthButtons(); // Show auth buttons as they are likely not logged in
            }
            else { // Handle other error statuses (e.g., 500 from /clear-history itself)
                 const errorResult = await response.json().catch(() => ({ error: 'Could not parse error response from backend' }));
                 console.error('Failed to clear history:', response.status, errorResult);
                 alert(`Failed to clear history: ${errorResult.error || `Status ${response.status}`}`);
            }
        } catch (error) { // Handle network errors or issues before response
            console.error('Network error clearing history:', error);
            alert('A network error occurred while clearing history.');
        }
    }
}


// --- Event Listeners ---
document.addEventListener('DOMContentLoaded', function () {
    // On load, check if the user is already logged in
    checkLoginStatus();

    // Ensure clear QR is disabled initially
    clearQRButton.disabled = true;

    // Add event listeners to the login/register toggle spans within auth cards
    document.querySelector('#login-form .toggle-form span').onclick = showRegisterForm;
    document.querySelector('#register-form .toggle-form span').onclick = showLoginForm;

    // Ensure buttons in header also call show functions
    document.getElementById('show-login').onclick = showLoginForm;
    document.getElementById('show-register').onclick = showRegisterForm;

    // Note: Login/Register button clicks call the login/register functions directly via onclick in HTML

    // Add event listener for the clear history button
    // We already selected it by ID at the top: const clearHistoryButton = document.getElementById('clear-history-button');
    if (clearHistoryButton) {
        clearHistoryButton.onclick = clearHistory;
    } else {
        console.error('Clear History button not found!');
    }
});

// Ensure QR input change still triggers analyzeQR
if (qrInput) {
    qrInput.onchange = function () { analyzeQR(this); };
} else {
    console.error('QR Input element not found!');
}


// Attach functions to global window object so they can be called from HTML onclick attributes
window.register = register;
window.login = login;
window.logout = logout;
window.analyzeUrl = analyzeUrl;
window.clearQR = clearQR;
// No need to expose deleteHistoryItem or clearHistory directly as they are called by handlers
// window.clearHistory = clearHistory;