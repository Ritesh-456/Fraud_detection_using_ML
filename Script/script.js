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
// Corrected typo on this line:
const qrInput = document.getElementById('qr-input');
const qrImageContainer = document.getElementById('qr-image-container');
const qrImage = document.getElementById('qr-image');
const clearQRButton = document.getElementById('clearQR');
const qrResultCard = document.getElementById('qr-result');
const historyList = document.getElementById('history-list');
const clearHistoryButton = document.getElementById('clear-history-button'); // Use the unique ID

// Message display area (ensure this element exists in index.html)
const messageArea = document.getElementById('message-area');

// History Filter UI Elements
const historyControlsDiv = document.getElementById('history-controls'); // Container for controls
const filterTypeSelect = document.getElementById('filter-type');
const filterRiskSelect = document.getElementById('filter-risk');
const applyFiltersButton = document.getElementById('apply-filters-button');
const exportHistoryButton = document.getElementById('export-history-button'); // Export button


// --- Functions for Filtering and Export ---

function applyHistoryFilters() {
    console.log('Applying history filters...');
    // displayMessage('Applying filters...', 'info'); // Avoid spamming this message

    // Get filter values from UI elements
    const typeFilter = filterTypeSelect ? filterTypeSelect.value : '';
    const riskFilterValue = filterRiskSelect ? filterRiskSelect.value : ''; // Get the VALUE attribute


    // Construct filters object based on the VALUE
    const filters = {};

    // Add type filter if selected (and not the default empty/all option)
    if (typeFilter !== '' && typeFilter.toLowerCase() !== 'all') {
        filters.type = typeFilter;
    }

    // Correctly map the new riskFilterValue to backend filter keys
    if (riskFilterValue === 'is_fraud_true') {
        filters.is_fraud = 'true'; // Backend expects 'true' or 'false' string for this filter
    } else if (riskFilterValue === 'is_fraud_false') {
        filters.is_fraud = 'false';
    } else if (riskFilterValue.startsWith('risk_')) {
        // Extract the risk level string from the value (e.g., 'Critical' from 'risk_Critical')
        filters.risk_level = riskFilterValue.substring(5); // Remove 'risk_' prefix
    }
    // If riskFilterValue is '', no risk/is_fraud filter is added (handled by backend)

    // Add other filters here as you add UI elements (e.g., search input, date pickers)
    // const searchTermInput = document.getElementById('search-input');
    // const searchTerm = searchTermInput ? searchTermInput.value.trim() : '';
    // if (searchTerm !== '') {
    //    filters.search_term = searchTerm;
    // }


    // Reload history with filters
    loadHistory(filters);
}

async function exportHistory() {
    console.log('Attempting to export history...');
    displayMessage('Preparing history for export...', 'info');

    // Get the currently applied filters so the export is filtered as well
    const filters = {};

    if (filterTypeSelect && filterTypeSelect.value !== '' && filterTypeSelect.value.toLowerCase() !== 'all') {
        filters.type = filterTypeSelect.value;
    }

    if (filterRiskSelect) {
        const riskFilterValue = filterRiskSelect.value;
        if (riskFilterValue === 'is_fraud_true') {
            filters.is_fraud = 'true';
        } else if (riskFilterValue === 'is_fraud_false') {
            filters.is_fraud = 'false';
        } else if (riskFilterValue.startsWith('risk_')) {
            filters.risk_level = riskFilterValue.substring(5);
        }
    }
    // ... other filters (search, date range) for export


    const queryParams = new URLSearchParams();
    for (const key in filters) {
        if (filters[key] !== '' && filters[key] !== null && filters[key] !== undefined) {
            queryParams.append(encodeURIComponent(key), encodeURIComponent(filters[key]));
        }
    }

    const fetchUrl = `http://127.0.0.1:5000/export-history?${queryParams.toString()}`;
    console.log("Fetching history for export from:", fetchUrl);


    try {
        // Use a standard fetch, let the browser handle the download dialog
        const response = await fetch(fetchUrl, {
            method: 'GET',
            headers: {
                // Browser handles session cookies for authentication
            }
        });

        // Check for specific errors first
        if (response.status === 401 || response.status === 405) {
            displayMessage('Please log in to export history.', 'error');
            showAuthButtons();
            return; // Stop execution
        }

        if (response.status === 204) { // Backend might return 204 No Content if no history found
            displayMessage('No history found to export with current filters.', 'info');
            return; // Stop execution
        }

        if (response.ok) { // Status 200-299
            // Get the filename from the Content-Disposition header if possible, fallback to default
            const contentDisposition = response.headers.get('Content-Disposition');
            let filename = 'history_export.csv';
            if (contentDisposition) {
                const filenameMatch = contentDisposition.match(/filename="(.+)"/);
                if (filenameMatch && filenameMatch.length > 1) {
                    filename = filenameMatch[1];
                }
            }

            // Get the Blob data
            const blob = await response.blob();

            // Create a link element
            const a = document.createElement('a');

            // Create a download link URL
            const url = window.URL.createObjectURL(blob);
            a.href = url;
            a.download = filename; // Set the desired filename

            // Append the link to the body and trigger the download
            document.body.appendChild(a);
            a.click();

            // Clean up by revoking the object URL and removing the link
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);

            displayMessage('History exported successfully.', 'success');

        } else { // Handle other error statuses
            const errorText = await response.text(); // Get raw text for potential error message
            let errorMsg = `Failed to export history: Status ${response.status}`;
            try {
                const errorResult = JSON.parse(errorText);
                errorMsg = 'Failed to export history: ' + (errorResult.error || errorText);
            } catch (e) {
                errorMsg = 'Failed to export history: ' + errorText;
            }
            displayMessage(errorMsg, 'error');
            console.error('Failed to export history:', response.status, errorText);
        }

    } catch (error) {
        console.error('Network error during history export:', error);
        displayMessage('An error occurred during export.', 'error');
    }
}


// --- Message Display Function ---
function displayMessage(message, type = 'info') {
    const messageAreaElement = document.getElementById('message-area');

    if (!messageAreaElement) {
        console.warn("Message area element not found. Falling back to console log.", message, type);
        if (type === 'error') console.error(message);
        else if (type === 'success') console.log(message);
        else console.info(message);
        return;
    }

    // Clear previous messages before appending a new one (adjust if you want multiple messages)
    messageAreaElement.innerHTML = '';


    const messageElement = document.createElement('div');
    messageElement.textContent = message;
    messageElement.className = `message ${type}`; // Add class like 'message info', 'message success', etc.


    messageAreaElement.appendChild(messageElement);

    // Auto-remove non-error, non-warning messages after a few seconds
    if (type !== 'error' && type !== 'warning') {
        setTimeout(() => {
            if (messageAreaElement.contains(messageElement)) {
                messageAreaElement.removeChild(messageElement);
            }
        }, 2000); // 2 seconds
    }
}


// --- View State Management ---
function showLoginForm() {
    if (loginForm) loginForm.style.display = 'block';
    if (registerForm) registerForm.style.display = 'none';
    if (mainAppContent) mainAppContent.style.display = 'none';
    if (authFormsDiv) authFormsDiv.style.display = 'none'; // Hide auth buttons div
    if (userStatus) userStatus.style.display = 'none'; // Hide user status
    // Clear forms when switching
    const loginEmailInput = document.getElementById('login-email');
    if (loginEmailInput) loginEmailInput.value = '';
    const loginPasswordInput = document.getElementById('login-password');
    if (loginPasswordInput) loginPasswordInput.value = '';

    // Keep messages visible when switching between login/register forms
    // displayMessage(''); // Clear messages
}

function showRegisterForm() {
    if (loginForm) loginForm.style.display = 'none';
    if (registerForm) registerForm.style.display = 'block';
    if (mainAppContent) mainAppContent.style.display = 'none';
    if (authFormsDiv) authFormsDiv.style.display = 'none'; // Hide auth buttons div
    if (userStatus) userStatus.style.display = 'none'; // Hide user status
    // Clear forms when switching
    const registerEmailInput = document.getElementById('register-email');
    if (registerEmailInput) registerEmailInput.value = '';
    const registerPasswordInput = document.getElementById('register-password');
    if (registerPasswordInput) registerPasswordInput.value = '';
    const confirmPasswordInput = document.getElementById('confirm-password');
    if (confirmPasswordInput) confirmPasswordInput.value = '';

    // Also clear username field
    const registerUsernameInput = document.getElementById('register-username');
    if (registerUsernameInput) {
        registerUsernameInput.value = '';
    }
    // Keep messages visible when switching between login/register forms
    // displayMessage(''); // Clear messages
}

// Update showMainApp function - displays user identifier (username)
function showMainApp(userIdentifier) {
    if (loginForm) loginForm.style.display = 'none';
    if (registerForm) registerForm.style.display = 'none';
    if (mainAppContent) mainAppContent.style.display = 'grid';
    if (authFormsDiv) authFormsDiv.style.display = 'none'; // Hide auth buttons div
    if (userStatus) userStatus.style.display = 'flex'; // Show user status
    if (userIdentifierSpan) userIdentifierSpan.textContent = userIdentifier; // Set the username
    // displayMessage(''); // Keep login success message temporarily

    // Show history controls when main app is shown
    if (historyControlsDiv) {
        historyControlsDiv.style.display = 'flex'; // Or 'block' or 'grid' depending on CSS
    }
}

function showAuthButtons() {
    if (loginForm) loginForm.style.display = 'none';
    if (registerForm) registerForm.style.display = 'none';
    if (mainAppContent) mainAppContent.style.display = 'none';
    if (authFormsDiv) authFormsDiv.style.display = 'flex'; // Show auth buttons div
    if (userStatus) userStatus.style.display = 'none'; // Hide user status
    if (userIdentifierSpan) userIdentifierSpan.textContent = ''; // Clear display

    // Clear analysis results and history UI
    if (urlResultCard) urlResultCard.style.display = 'none';
    if (qrResultCard) qrResultCard.style.display = 'none';
    if (historyList) historyList.innerHTML = ''; // Clear history UI list
    clearQR();
    displayMessage(''); // Clear messages

    // Hide history controls when auth buttons are shown
    if (historyControlsDiv) {
        historyControlsDiv.style.display = 'none';
    }
}

// --- Authentication Functions (Backend API Calls) ---

async function register() {
    const emailInput = document.getElementById('register-email');
    const usernameInput = document.getElementById('register-username');
    const passwordInput = document.getElementById('register-password');
    const confirmPasswordInput = document.getElementById('confirm-password');

    if (!emailInput || !usernameInput || !passwordInput || !confirmPasswordInput) {
        console.error('Required registration input elements not found.');
        displayMessage('Error: Registration form elements missing.', 'error');
        return;
    }

    const email = emailInput.value.trim(); // Trim whitespace
    const username = usernameInput.value.trim(); // Trim whitespace
    const password = passwordInput.value;
    const confirmPassword = confirmPasswordInput.value;


    if (!email || !username || !password || !confirmPassword) {
        displayMessage('Please fill in all fields.', 'warning');
        return;
    }
    if (!/\S+@\S+\.\S+/.test(email)) { // Basic email format check
        displayMessage('Please enter a valid email address.', 'warning');
        return;
    }
    if (password !== confirmPassword) {
        displayMessage('Passwords do not match.', 'warning');
        return;
    }
    // Optional: Add password strength validation here


    console.log('Attempting to register:', email, username);
    displayMessage('Registering...', 'info');


    try {
        // Disable register button while fetching (Optional UI improvement)
        // const registerButton = registerForm.querySelector('button');
        // if (registerButton) registerButton.disabled = true;

        const response = await fetch('http://127.0.0.1:5000/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, username, password })
        });
        const result = await response.json();

        if (response.ok) {
            displayMessage('Registration successful! You can now log in.', 'success');
            showLoginForm(); // Show login form after successful registration
        } else {
            const errorMsg = result.error || response.statusText || 'Unknown error';
            displayMessage('Registration failed: ' + errorMsg, 'error');
            console.error('Registration error:', response.status, result);
        }
    } catch (error) {
        console.error('Network error during registration:', error);
        displayMessage('An error occurred during registration. Please try again.', 'error');
    } finally {
        // Re-enable register button (Optional UI improvement)
        // const registerButton = registerForm.querySelector('button');
        // if (registerButton) registerButton.disabled = false;
    }
}


async function login() {
    const emailInput = document.getElementById('login-email');
    const passwordInput = document.getElementById('login-password');

    if (!emailInput || !passwordInput) {
        console.error('Required login input elements not found.');
        displayMessage('Error: Login form elements missing.', 'error');
        return;
    }

    const email = emailInput.value.trim(); // Trim whitespace
    const password = passwordInput.value;


    if (!email || !password) {
        displayMessage('Please enter email and password.', 'warning');
        return;
    }
    if (!/\S+@\S+\.\S+/.test(email)) { // Basic email format check
        displayMessage('Please enter a valid email address.', 'warning');
        return;
    }

    console.log('Attempting to login:', email);
    displayMessage('Logging in...', 'info');


    try {
        // Disable login button while fetching (Optional UI improvement)
        // const loginButton = loginForm.querySelector('button');
        // if (loginButton) loginButton.disabled = true;

        const response = await fetch('http://127.0.0.1:5000/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password })
        });
        const result = await response.json();

        // Check for success and if username is available in the response
        if (response.ok && result.success && result.username) { // Ensure username is in the response
            console.log('Login successful.'); // Reloading handles the rest
            displayMessage('Login successful!', 'success');
            // Reloading is needed because Flask-Login sets the session cookie
            // which the *browser* needs to pick up on the next full page load.
            // Delay reload slightly to show success message? Or just reload immediately.
            // window.location.reload(); // Immediate reload
            setTimeout(() => window.location.reload(), 500); // Delay for 0.5 seconds

        } else {
            // Handle login failure response from backend
            const errorMsg = result.error || 'Invalid email or password';
            displayMessage('Login failed: ' + errorMsg, 'error');
            console.error('Login error:', response.status, result);
        }
    } catch (error) {
        console.error('Network error during login:', error);
        displayMessage('An error occurred during login. Please try again.', 'error');
    } finally {
        // Re-enable login button (Optional UI improvement)
        // const loginButton = loginForm.querySelector('button');
        // if (loginButton) loginButton.disabled = false;
    }
}

async function logout() {
    console.log('Attempting to logout');
    displayMessage('Logging out...', 'info');

    try {
        // Disable logout button while fetching (Optional UI improvement)
        // const logoutButton = userStatus.querySelector('button');
        // if (logoutButton) logoutButton.disabled = true;

        const response = await fetch('http://127.0.0.1:5000/logout', {
            method: 'POST'
            // Browser handles session cookies for authentication
        });

        if (response.ok && (await response.json()).success) {
            console.log('Logout successful');
            displayMessage('Logged out successfully.', 'success');
            // Reload page after logout to reset frontend state via checkLoginStatus
            setTimeout(() => window.location.reload(), 500); // Delay for 0.5 seconds
        } else {
            // Even if backend reports error, try to clear frontend state
            console.error('Logout failed:', response.status);
            displayMessage('Logout failed, but frontend state cleared.', 'error');
            // Still reload to reset state, even on backend error
            setTimeout(() => window.location.reload(), 500); // Delay for 0.5 seconds
        }
    } catch (error) {
        console.error('Network error during logout:', error);
        displayMessage('An error occurred during logout.', 'error');
        // Still reload to reset state on network error
        setTimeout(() => window.location.reload(), 500); // Delay for 0.5 seconds
    } finally {
        // Re-enable logout button (Optional UI improvement)
        // const logoutButton = userStatus.querySelector('button');
        // if (logoutButton) logoutButton.disabled = false;
    }
}

// --- Initial Check for Login Status ---
async function checkLoginStatus() {
    console.log('Checking login status...');
    // displayMessage('Checking login status...', 'info'); // Avoid showing this on every page load

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
            // Load history for the logged-in user with initial filters (which will be empty)
            applyHistoryFilters(); // Use this function to load with initial filters
        } else {
            console.log('User is not logged in.');
            showAuthButtons(); // Show authentication options
            // Display message only if not already showing a login/registration form
            if (loginForm.style.display === 'none' && registerForm.style.display === 'none') {
                displayMessage('Please log in or register to use the fraud detection system.', 'info');
            }
        }
    } catch (error) {
        console.error('Network error checking login status:', error);
        // Assume not logged in or backend is down on network error
        showAuthButtons();
        displayMessage('Could not connect to the backend. Please ensure the backend server is running.', 'error');
    }
}


// --- Analysis Functions (Backend API Calls handled by app.py save) ---

async function analyzeUrl() {
    if (!urlInput) {
        console.error('URL Input element not found!');
        displayMessage('Error: URL input field missing.', 'error');
        return;
    }
    const url = urlInput.value.trim(); // Trim whitespace
    if (!url) {
        displayMessage('Please enter a URL.', 'warning');
        return;
    }

    console.log('Analyzing URL:', url);
    displayMessage('Analyzing URL...', 'info');
    // Disable analyze button while processing?
    // const analyzeUrlButton = urlInput.nextElementSibling; // Assuming button is next sibling
    // if (analyzeUrlButton && analyzeUrlButton.tagName === 'BUTTON') analyzeUrlButton.disabled = true;


    // Clear previous results while analyzing
    if (urlResultCard) urlResultCard.style.display = 'none';


    try {
        const response = await fetch('http://127.0.0.1:5000/analyze-url', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                // Browser handles session cookies for authentication
            },
            body: JSON.stringify({ url: url })
        });

        // Handle specific non-OK statuses first (like auth issues from Flask-Login redirect)
        if (response.status === 401) {
            displayMessage('Please log in to analyze URLs.', 'error');
            showAuthButtons();
            return; // Stop execution
        }
        if (response.status === 405) {
            // This can happen if Flask-Login redirects a POST to a GET login route
            displayMessage('Analysis failed due to login issue. Please log in again.', 'error');
            console.error('URL Analysis Error: Likely Flask-Login redirect (405)');
            showAuthButtons();
            return; // Stop execution
        }


        if (response.ok) { // Status 200-299 means success
            const result = await response.json();
            console.log('URL Analysis Result:', result);
            updateUrlResult(result); // <--- This displays the result in the card

            // --- Check for save error flag from backend ---
            if (result.save_error) {
                displayMessage('URL analysis complete, but results could not be saved to history.', 'warning');
                console.warn('Backend reported save error for URL:', url, result);
                // Do NOT reload history if saving failed, as the new item isn't there
            } else {
                displayMessage('URL analysis complete and saved to history.', 'success');
                console.log('URL analysis and save successful for URL:', url);
                // Reload history only if saving was successful
                applyHistoryFilters();
            }

        } else { // Handle other error statuses (e.g., 400, 500 from analyze-url itself)
            const errorText = await response.text(); // Get raw text for potential error message
            let errorMsg = `URL Analysis failed: Status ${response.status}`;
            try {
                const errorResult = JSON.parse(errorText);
                errorMsg = 'URL Analysis failed: ' + (errorResult.error || errorText);
            } catch (e) {
                errorMsg = 'URL Analysis failed: ' + errorText;
            }
            displayMessage(errorMsg, 'error');
            console.error('URL Analysis Error:', response.status, errorText);
        }

    } catch (error) {
        console.error('Network error during URL analysis:', error);
        displayMessage('An error occurred during URL analysis. Please check backend connection.', 'error');
    } finally {
        // Re-enable analyze button (Optional UI improvement)
        // const analyzeUrlButton = urlInput.nextElementSibling;
        // if (analyzeUrlButton && analyzeUrlButton.tagName === 'BUTTON') analyzeUrlButton.disabled = false;
    }
}

async function analyzeQR(input) {
    if (!qrInput) {
        console.error('QR Input element not found!');
        displayMessage('Error: QR input field missing.', 'error');
        return;
    }

    if (input.files && input.files[0]) {
        const file = input.files[0];
        const formData = new FormData();
        formData.append('file', file);

        console.log('Analyzing QR code file:', file.name);
        displayMessage('Analyzing QR code...', 'info');
        // Disable relevant UI elements?


        // Clear previous results while analyzing
        if (qrResultCard) qrResultCard.style.display = 'none';


        // Display the uploaded image first for immediate feedback
        const reader = new FileReader();
        reader.onload = function (e) {
            if (qrImageContainer) qrImageContainer.style.display = 'block';
            if (qrImage) qrImage.src = e.target.result;
        };
        reader.readAsDataURL(file);
        if (clearQRButton) clearQRButton.disabled = false;


        try {
            const response = await fetch('http://127.0.0.1:5000/analyze-qr', {
                method: 'POST',
                body: formData,
                // Browser handles session cookies for authentication
            });

            // Handle specific non-OK statuses first
            if (response.status === 401) {
                displayMessage('Please log in to analyze QR codes.', 'error');
                showAuthButtons();
                clearQR(); // Clear the displayed QR image on auth error
                return; // Stop execution
            }
            if (response.status === 405) {
                displayMessage('QR analysis failed due to login issue. Please log in again.', 'error');
                console.error('QR Analysis Error: Likely Flask-Login redirect (405)');
                showAuthButtons();
                clearQR(); // Clear the displayed QR image on auth error
                return; // Stop execution
            }

            if (response.ok) { // Status 200-299
                const result = await response.json();
                console.log('QR Analysis Result:', result);
                updateQRResult(result); // <--- This displays the result in the card


                // --- Check for save error flag from backend ---
                if (result.save_error) {
                    displayMessage('QR analysis complete, but results could not be saved to history.', 'warning');
                    console.warn('Backend reported save error for QR:', file.name, result);
                    // Do NOT reload history if saving failed
                } else {
                    displayMessage('QR analysis complete and saved to history.', 'success');
                    console.log('QR analysis and save successful for QR:', file.name);
                    // Reload history only if saving was successful
                    applyHistoryFilters();
                }

            } else { // Handle other error statuses
                const errorText = await response.text(); // Get raw text for potential error message
                let errorMsg = `QR Analysis failed: Status ${response.status}`;
                try {
                    const errorResult = JSON.parse(errorText);
                    errorMsg = 'QR Analysis failed: ' + (errorResult.error || errorText);
                } catch (e) {
                    errorMsg = 'QR Analysis failed: ' + errorText;
                }
                displayMessage(errorMsg, 'error');
                console.error('QR Analysis Error:', response.status, errorText);
                // Keep displayed image/clear button as is for now? Or clear?
            }

        } catch (error) {
            console.error('Network error during QR analysis:', error);
            displayMessage('An error occurred during QR analysis. Please check backend connection.', 'error');
            // Keep displayed image/clear button as is for now? Or clear?
        } finally {
            // Re-enable relevant UI elements?
        }
    } else {
        // Handle case where file input change event fired but no file was selected/available
        console.log('QR input changed, but no file selected.');
        clearQR(); // Clear any previously displayed image/result
    }
}

function updateUrlResult(result) {
    if (!urlResultCard || !confidenceValueSpan || !confidenceBarFill || !riskLevelSpan || !riskFactorsList) {
        console.error('URL result elements not found! Cannot update result card.');
        // Optionally hide the card container if elements are missing
        if (urlResultCard) urlResultCard.style.display = 'none';
        return;
    }
    urlResultCard.style.display = 'block';
    // Use risk level for warning class if not fraud and not low/safe risk
    // Check result.is_fraud carefully as it might be null/undefined if result JSON was malformed
    const isFraud = result.is_fraud === true; // Explicitly check against true
    const riskLevel = result.risk_level || 'Unknown';

    let cardClass = 'safe'; // Default to safe styling
    if (isFraud) {
        cardClass = 'fraud'; // Red for fraudulent
    } else if (riskLevel === 'Critical' || riskLevel === 'High' || riskLevel === 'Medium') {
        cardClass = 'warning'; // Orange/Yellow for higher non-fraud risk
    }
    // No change for 'Low' or 'Safe' - they keep the 'safe' styling

    urlResultCard.className = `result-card ${cardClass}`;


    confidenceValueSpan.textContent = `${parseFloat(result.confidence || 0).toFixed(2)}`; // Default to 0 if confidence is missing
    // Ensure confidence bar doesn't exceed 100%
    confidenceBarFill.style.width = `${Math.min(100, parseFloat(result.confidence || 0))}%;`;

    riskLevelSpan.textContent = riskLevel;

    // Ensure risk_factors is an array before mapping
    const riskFactors = Array.isArray(result.risk_factors) ? result.risk_factors : [];
    if (riskFactors.length > 0) {
        riskFactorsList.innerHTML = riskFactors.map(factor => `<li>${factor}</li>`).join('');
    } else {
        riskFactorsList.innerHTML = '<li>No specific risk factors identified</li>'; // Provide a default if empty
    }
}

function updateQRResult(result) {
    if (!qrResultCard) {
        console.error('QR result card element not found! Cannot update QR result.');
        return;
    }
    qrResultCard.style.display = 'block';

    // Determine card class based on result, similar to updateUrlResult
    const isFraud = result.is_fraud === true; // Explicitly check against true
    const riskLevel = result.risk_level || 'Unknown';
    let cardClass = 'safe';
    if (isFraud) {
        cardClass = 'fraud';
    } else if (riskLevel === 'Critical' || riskLevel === 'High' || riskLevel === 'Medium') {
        cardClass = 'warning';
    }
    qrResultCard.className = `result-card ${cardClass}`;


    // Ensure all necessary result properties exist before displaying
    const confidence = result.confidence !== undefined ? parseFloat(result.confidence || 0).toFixed(2) + '%' : 'N/A';
    const decodedUrl = result.url ? `<p>Decoded URL: <span style="word-break: break-all;">${result.url}</span></p>` : '';
    // For QR, we might just show the basic details
    qrResultCard.innerHTML = `
         <h3>Analysis Results</h3>
         <div class="result-details">
             <p>Confidence: ${confidence}</p>
             <p>Risk Level: ${riskLevel}</p>
             ${decodedUrl}
         </div>
         <!-- Risk factors for QR can be added here if backend provides them in QR analysis result -->
         <!-- <h4>Risk Factors:</h4>
         <ul class="risk-factors">${Array.isArray(result.risk_factors) ? result.risk_factors.map(factor => `<li>${factor}</li>`).join('') : '<li>No specific risk factors identified</li>'}</ul>
         -->
     `;
}


function clearQR() {
    if (qrImageContainer) qrImageContainer.style.display = 'none';
    if (qrImage) qrImage.src = ''; // Clear the image source

    if (qrInput) qrInput.value = ''; // Clear the file input value

    if (qrResultCard) qrResultCard.style.display = 'none'; // Hide the result card
    if (clearQRButton) clearQRButton.disabled = true; // Disable clear button again
    // Keep messages related to analysis results, don't clear here
}

// --- History Management Functions (Backend API Calls) ---

async function loadHistory(filters = {}) {
    console.log('Attempting to load history from backend with filters:', filters);

    if (!historyList) {
        console.error('History List element not found for loading!');
        displayMessage('Error: History list area missing.', 'error');
        return;
    }

    // Clear previous history and show loading indicator
    historyList.innerHTML = '<li class="history-item loading">Loading history...</li>';
    // displayMessage('Loading history...', 'info'); // Optional: show loading message


    // Construct query parameters from the filters object
    const queryParams = new URLSearchParams();
    for (const key in filters) {
        // This check ensures that filters with empty string, null, or undefined values are not appended.
        // Also skip if the filter value is 'all' explicitly for robustness
        if (filters[key] !== '' && filters[key] !== null && filters[key] !== undefined && filters[key].toLowerCase() !== 'all') {
            // Ensure key and value are properly encoded
            queryParams.append(encodeURIComponent(key), encodeURIComponent(filters[key]));
        }
    }

    const fetchUrl = `http://127.0.0.1:5000/history?${queryParams.toString()}`;
    console.log("Fetching history from:", fetchUrl); // Debugging fetch URL


    try {
        const response = await fetch(fetchUrl, {
            method: 'GET',
            headers: {
                // Browser handles session cookies for authentication
            }
        });

        // Handle specific non-OK statuses first
        if (response.status === 401) {
            console.warn('Attempted to load history while not logged in (401).');
            historyList.innerHTML = '<li class="history-item">Please log in to view history.</li>';
            // displayMessage('Please log in to view history.', 'warning'); // Optional: warning message
            showAuthButtons(); // Show auth buttons as user is not logged in
            return; // Stop execution
        }
        if (response.status === 405) {
            console.error('Failed to load history: Redirected to Login (405). User session may have expired.');
            historyList.innerHTML = '<li class="history-item error">Failed to load history. Please log in again.</li>'; // Use an error class
            displayMessage('Failed to load history. Please log in again.', 'error');
            showAuthButtons(); // Show auth buttons as user is likely not logged in
            return; // Stop execution
        }


        if (response.ok) { // Status 200-299 means success
            const history = await response.json(); // Assuming backend returns a list of history items
            console.log('History loaded:', history);

            historyList.innerHTML = ''; // Clear loading indicator/previous content

            if (history && history.length > 0) {
                history.forEach(item => {
                    // Backend structure: { id, user_id, item_type, item_data, analysis_result, analyzed_at }
                    // Use the structure directly as passed from backend
                    const formattedItem = {
                        db_id: item.id,
                        type: item.item_type,
                        data: item.item_data,
                        result: item.analysis_result, // Use the parsed JSON result directly
                        analyzed_at: item.analyzed_at // This should be the timestamp string from the backend
                    };
                    addHistoryItemToUI(formattedItem);
                });
                // displayMessage('History loaded successfully.', 'success'); // Avoid spamming
            } else {
                console.log('No history found for this user with applied filters.');
                historyList.innerHTML = '<li class="history-item">No history found matching the filters.</li>'; // Display "No history yet"
                // displayMessage('No history found.', 'info'); // Avoid spamming
            }

        } else { // Handle other error statuses (e.g., 500 from /history itself)
            const errorText = await response.text(); // Get raw text for potential error message
            let errorMsg = `Error loading history: Status ${response.status}`;
            try {
                const errorResult = JSON.parse(errorText);
                errorMsg = 'Error loading history: ' + (errorResult.error || errorText);
            } catch (e) {
                errorMsg = 'Error loading history: ' + errorText;
            }
            console.error('Failed to load history:', response.status, errorText);
            historyList.innerHTML = `<li class="history-item error">${errorMsg}</li>`; // Display specific error message with error styling
            displayMessage(errorMsg, 'error');
        }
    } catch (error) { // Handle network errors or issues before response
        console.error('Network error loading history:', error);
        historyList.innerHTML = '<li class="history-item error">Network error while loading history. Please check backend connection.</li>'; // More specific network error
        displayMessage('Network error while loading history.', 'error');
    }
}

// Helper function to add a history item to the UI list
function addHistoryItemToUI(item) {
    if (!historyList) {
        console.error('History List element not found for adding item!');
        return;
    }

    const listItem = document.createElement('li');
    listItem.className = 'history-item';
    // Store the database ID on the list item element itself
    if (item.db_id) {
        listItem.dataset.historyId = item.db_id;
    }

    // Get analysis result details safely
    const analysisResult = item.result || {};
    // Use riskLevel string for badge text and class determination
    const riskLevel = analysisResult.risk_level || 'Unknown';


    const statusBadge = document.createElement('span');
    let badgeClass = 'info'; // Default to 'info'
    let badgeText = riskLevel; // Badge text is the riskLevel string


    // --- MODIFIED BADGE LOGIC: Rely only on riskLevel string for badge appearance ---
    switch (riskLevel) {
        case 'Critical':
        case 'High':
            badgeClass = 'warning'; // Use warning class for High/Critical
            badgeText = riskLevel; // Text is Critical or High
            break;
        case 'Medium':
            badgeClass = 'warning'; // Use warning class for Medium
            badgeText = riskLevel; // Text is Medium
            break;
        case 'Low':
        case 'Safe':
            badgeClass = 'safe'; // Green
            badgeText = riskLevel; // Text is Low or Safe
            break;
        case 'Fraudulent': // Handle "Fraudulent" if backend explicitly sends this as risk_level
             badgeClass = 'fraud'; // Red
             badgeText = 'Fraudulent'; // Text is Fraudulent
             break;
        default: // Handles 'Unknown', 'Error', or any other unexpected value
            // Fallback: If riskLevel is unknown/error, *then* check the is_fraud flag as a secondary indicator
            const isFraudFallback = analysisResult.is_fraud === true;
            if (isFraudFallback) {
                 badgeClass = 'fraud'; // If marked is_fraud:true but risk_level is strange, show fraud
                 badgeText = 'Fraudulent (Unknown Level)'; // Indicate the ambiguity
            } else {
                 badgeClass = 'info'; // Default for truly unknown/error
                 badgeText = riskLevel; // Text is Unknown, Error, etc.
            }
            break;
    }
     // --- END MODIFIED BADGE LOGIC ---


    statusBadge.className = `status-badge ${badgeClass}`;
    statusBadge.textContent = badgeText;

    const deleteButton = document.createElement('button');
    deleteButton.className = 'delete-history-item';
    deleteButton.innerHTML = '❌'; // Unicode cross character
    deleteButton.title = 'Remove from history';

    deleteButton.onclick = async function () {
        const historyId = listItem.dataset.historyId;
        if (historyId && confirm('Are you sure you want to remove this item from history?')) {
            const deleted = await deleteHistoryItem(historyId);
            if (deleted) {
                // Remove the item from the UI list only on backend success
                if (historyList.contains(listItem)) {
                    historyList.removeChild(listItem);
                    console.log(`Removed history item ${historyId} from UI.`);
                    displayMessage('History item deleted.', 'success');
                }
            } else {
                // Error message is shown by deleteHistoryItem
            }
        } else if (!historyId) {
            console.error('History item missing database ID, cannot delete.');
            displayMessage('Cannot delete this history item (ID not found).', 'error');
        }
    };

    // --- MODIFIED: Include item data and timestamp in a flex container ---
    // Create a span to hold the item data and timestamp
    const itemInfo = document.createElement('span');
    itemInfo.style.flexGrow = '1'; // Allow this part to take up space
    itemInfo.style.marginRight = '10px'; // Add spacing before badge/delete button
    itemInfo.style.wordBreak = 'break-word'; // Allow wrapping within this span
    itemInfo.style.overflowWrap = 'break-word'; // Also allow wrapping (modern browsers)

    // Create spans for item data and timestamp within itemInfo
    const dataSpan = document.createElement('span');
    dataSpan.textContent = item.data;
    dataSpan.style.display = 'block'; // Make it a block element so timestamp appears below or wraps properly
    dataSpan.style.wordBreak = 'break-word'; // Ensure long words break
    dataSpan.style.overflowWrap = 'break-word'; // Ensure long words break

    itemInfo.appendChild(dataSpan);

    // Check if analyzed_at exists and is valid
    if (item.analyzed_at) {
        try {
            // Create a Date object from the timestamp string
            const date = new Date(item.analyzed_at);
            // Check if Date object is valid (handle potential parsing issues)
            if (!isNaN(date.getTime())) {
                // Format the date/time nicely
                const formattedDate = date.toLocaleString();

                const timestampSpan = document.createElement('span');
                timestampSpan.className = 'history-timestamp'; // Apply timestamp class
                timestampSpan.textContent = formattedDate;
                 timestampSpan.style.display = 'block'; // Make timestamp a block
                 timestampSpan.style.marginTop = '3px'; // Space above timestamp

                itemInfo.appendChild(timestampSpan); // Append timestamp span to itemInfo
            } else {
                console.warn(`Could not parse date for history item ${item.db_id}: ${item.analyzed_at}`);
                const timestampSpan = document.createElement('span');
                timestampSpan.className = 'history-timestamp';
                timestampSpan.textContent = 'Invalid Date';
                 timestampSpan.style.display = 'block';
                 timestampSpan.style.marginTop = '3px';
                itemInfo.appendChild(timestampSpan);
            }
        } catch (e) {
            console.error(`Error processing date for history item ${item.db_id}: ${e}`, item.analyzed_at);
            const timestampSpan = document.createElement('span');
            timestampSpan.className = 'history-timestamp';
            timestampSpan.textContent = 'Error';
            timestampSpan.style.display = 'block';
            timestampSpan.style.marginTop = '3px';
            itemInfo.appendChild(timestampSpan);
        }
    }
    // --- END MODIFIED ---


    // Append the item info span, badge, and delete button to the list item
    listItem.appendChild(itemInfo); // Append the new container span
    listItem.appendChild(statusBadge);
    if (item.db_id) {
        listItem.appendChild(deleteButton);
    }

    // Add the new item to the top of the list
    historyList.insertBefore(listItem, historyList.firstChild);
}
async function deleteHistoryItem(item_id) {
    console.log('Attempting to delete history item with ID:', item_id);
    displayMessage('Deleting history item...', 'info');

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
                console.log('History item deleted successfully:', item_id);
                // UI removal is handled in addHistoryItemToUI's deleteButton onclick
                return true; // Indicate success
            } else {
                const errorMsg = result.error || 'Unknown error';
                console.error('Backend reported failed deletion:', errorMsg);
                displayMessage('Failed to delete history item: ' + errorMsg, 'error');
                return false; // Indicate failure
            }

        } else if (response.status === 401) {
            displayMessage('Please log in to delete history items.', 'error');
            showAuthButtons(); // Redirect or show login form
            return false;
        }
        else if (response.status === 404) {
            console.error('History item not found on backend:', item_id);
            displayMessage('Failed to delete: Item not found.', 'error');
            return false;
        }
        else if (response.status === 405) {
            console.error('Delete History Error: Redirected to Login (405).', response.status, response.statusText);
            displayMessage('Failed to delete. Please log in again.', 'error');
            showAuthButtons();
            return false;
        }
        else { // Handle other error statuses
            const errorText = await response.text();
            let errorMsg = `Failed to delete history item: Status ${response.status}`;
            try {
                const errorResult = JSON.parse(errorText);
                errorMsg = 'Failed to delete history item: ' + (errorResult.error || errorText);
            } catch (e) {
                errorMsg = 'Failed to delete history item: ' + errorText;
            }
            console.error('Failed to delete history item:', response.status, errorText);
            displayMessage(errorMsg, 'error');
            return false; // Indicate failure
        }
    } catch (error) {
        console.error('Network error during deletion:', error);
        displayMessage('An error occurred during deletion. Please check backend connection.', 'error');
        return false; // Indicate failure
    }
}


async function clearHistory() {
    if (!historyList) {
        console.error('History List element not found for clearing!');
        displayMessage('Error: History list area missing.', 'error');
        return;
    }

    if (!confirm('Are you sure you want to clear all your history? This cannot be undone.')) {
        return; // User cancelled
    }

    console.log('Attempting to clear all history...');
    displayMessage('Clearing history...', 'info');

    try {
        // Disable clear history button? (Optional UI improvement)
        // if (clearHistoryButton) clearHistoryButton.disabled = true;

        const response = await fetch('http://127.0.0.1:5000/clear-history', {
            method: 'POST', // Or DELETE, depending on your backend design
            headers: {
                'Content-Type': 'application/json',
                // Browser handles session cookies for authentication
            },
            // Body might be empty or contain user confirmation, depends on backend
            body: JSON.stringify({})
        });

        // Handle specific non-OK statuses first
        if (response.status === 401) {
            displayMessage('Please log in to clear history.', 'error');
            showAuthButtons();
            return; // Stop execution
        }
        if (response.status === 405) {
            displayMessage('Clear history failed due to login issue. Please log in again.', 'error');
            console.error('Clear History Error: Likely Flask-Login redirect (405)');
            showAuthButtons();
            return; // Stop execution
        }


        if (response.ok) { // Status 200-299
            const result = await response.json();
            if (result.success) {
                console.log('History cleared successfully');
                displayMessage('All history cleared.', 'success');
                historyList.innerHTML = '<li class="history-item">History cleared.</li>'; // Clear UI list immediately
                // No need to reload history after clearing, the list is intentionally empty
            } else {
                const errorMsg = result.error || 'Unknown error';
                console.error('Backend reported failed clearing:', errorMsg);
                displayMessage('Failed to clear history: ' + errorMsg, 'error');
                // Leave existing history visible if clearing failed? Or show error message in list?
                historyList.innerHTML = `<li class="history-item error">${errorMsg}</li>`;
            }
        } else { // Handle other error statuses
            const errorText = await response.text();
            let errorMsg = `Failed to clear history: Status ${response.status}`;
            try {
                const errorResult = JSON.parse(errorText);
                errorMsg = 'Failed to clear history: ' + (errorResult.error || errorText);
            } catch (e) {
                errorMsg = 'Failed to clear history: ' + errorText;
            }
            console.error('Failed to clear history:', response.status, errorText);
            historyList.innerHTML = `<li class="history-item error">${errorMsg}</li>`;
            displayMessage(errorMsg, 'error');
        }
    } catch (error) {
        console.error('Network error during history clearing:', error);
        displayMessage('An error occurred while clearing history. Please check backend connection.', 'error');
        historyList.innerHTML = '<li class="history-item error">Network error while clearing history. Please check backend connection.</li>';
    } finally {
        // Re-enable clear history button?
        // if (clearHistoryButton) clearHistoryButton.disabled = false;
    }
}


// --- Initial Setup and Event Listeners ---
document.addEventListener('DOMContentLoaded', function () {
    const modeToggle = document.getElementById('mode-toggle');
    const body = document.body;

    // Load saved mode from localStorage
    let currentMode = localStorage.getItem('mode') || 'light'; // Default to light
    body.classList.add(currentMode + '-mode'); // Apply initial mode

    // Toggle Mode
    modeToggle.addEventListener('click', function () {
        if (body.classList.contains('light-mode')) { // Check current state based on class
            currentMode = 'dark';
        } else {
            currentMode = 'light';
        }

        // Toggle the class on the body
        body.classList.remove('light-mode', 'dark-mode'); // Remove both classes
        body.classList.add(currentMode + '-mode'); // Add the current mode's class

        // Save mode to localStorage
        localStorage.setItem('mode', currentMode);
    });

    // On load, check if the user is already logged in
    checkLoginStatus();

    // Ensure clear QR is disabled initially
    if (clearQRButton) {
        clearQRButton.disabled = true;
    } else {
        console.error('Clear QR button not found!');
    }


    // Add event listeners to the login/register toggle spans within auth cards
    const loginToggleSpan = document.querySelector('#login-form .toggle-form span');
    if (loginToggleSpan) {
        loginToggleSpan.onclick = showRegisterForm;
    } else {
        console.error('Login toggle span not found!');
    }

    const registerToggleSpan = document.querySelector('#register-form .toggle-form span');
    if (registerToggleSpan) {
        registerToggleSpan.onclick = showLoginForm;
    } else {
        console.error('Register toggle span not found!');
    }


    // Ensure buttons in header also call show functions
    const showLoginButton = document.getElementById('show-login');
    if (showLoginButton) {
        showLoginButton.onclick = showLoginForm;
    } else {
        console.error('Show Login button not found!');
    }

    const showRegisterButton = document.getElementById('show-register');
    if (showRegisterButton) {
        showRegisterButton.onclick = showRegisterForm;
    } else {
        console.error('Show Register button not found!');
    }


    // Note: Login/Register button clicks call the login/register functions directly via onclick in HTML

    // Add event listener for the clear history button
    if (clearHistoryButton) {
        clearHistoryButton.onclick = clearHistory;
    } else {
        console.error('Clear History button not found!');
    }

    // Ensure QR input change still triggers analyzeQR
    if (qrInput) {
        qrInput.onchange = function () { analyzeQR(this); };
    } else {
        console.error('QR Input element not found!');
    }

    // --- Event Listeners for History Filtering and Export ---
    if (applyFiltersButton) {
        applyFiltersButton.addEventListener('click', applyHistoryFilters);
    } else {
        console.error('Apply Filters button not found!');
    }

    if (exportHistoryButton) {
        exportHistoryButton.addEventListener('click', exportHistory);
        // Check if already logged in to enable export on load
        // This check needs to be done after checkLoginStatus resolves
        // For now, ensure it's enabled by default if button exists.
        exportHistoryButton.disabled = false;
        exportHistoryButton.title = "Export filtered history to CSV";
    } else {
        console.error('Export History button not found!');
    }

    // Optional: Apply filters automatically when filter values change
    // if (filterTypeSelect) filterTypeSelect.addEventListener('change', applyHistoryFilters);
    // if (filterRiskSelect) filterRiskSelect.addEventListener('change', applyHistoryFilters);

});


// Attach functions to global window object so they can be called from HTML onclick attributes
// Functions called directly from HTML onclick MUST be attached to window or defined globally
window.register = register;
window.login = login;
window.logout = logout;
window.analyzeUrl = analyzeUrl;
window.analyzeQR = analyzeQR;
window.clearQR = clearQR;
window.applyHistoryFilters = applyHistoryFilters;
window.exportHistory = exportHistory;

// REMOVED the manual fetch block that was at the end