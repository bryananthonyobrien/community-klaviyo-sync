import { makeRequestWithTokenRefresh, API_URL, fetchWithTimeout, refreshAccessToken, createAuthorizedHeaders, clearDataFromLocalStorage, logError } from './helpers.js';

export let selectedFileLocation = null;

export function setSelectedFileLocation(location) {
    selectedFileLocation = location;
    console.log("selectedFileLocation updated to:", selectedFileLocation);
}

export function getSelectedFileLocation() {
    return selectedFileLocation;
}

// Function to hide dropdown
function hideDropdown() {
    const dropdown = document.getElementById('dropdown');
    if (dropdown) {
        dropdown.style.display = 'none';
    }
}

// Event listener for clicks outside the dropdown
document.addEventListener('click', function(event) {
    const dropdown = document.getElementById('dropdown');
    const selectedRow = document.getElementById('discoveries-table');

    // Check if the dropdown and selectedRow exist before checking `contains`
    if (dropdown && !dropdown.contains(event.target)) {
        if (selectedRow && !selectedRow.contains(event.target)) {
            hideDropdown();
        }
    }
});

// Define the function to decode JWT
function decodeJWT(token) {
    const base64Url = token.split('.')[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const jsonPayload = decodeURIComponent(atob(base64).split('').map(function(c) {
        return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
    }).join(''));
    return JSON.parse(jsonPayload);
}

function debounce(func, delay) {
    let timeoutId;
    return function(...args) {
        if (timeoutId) {
            clearTimeout(timeoutId);
        }
        timeoutId = setTimeout(() => {
            func.apply(this, args);
        }, delay);
    };
}

function updateTotals() {
    // Get all individual counts
    const falsePhone = parseInt(document.getElementById('false-phone').textContent) || 0;
    const falseNoPhone = parseInt(document.getElementById('false-no-phone').textContent) || 0;
    const truePhone = parseInt(document.getElementById('true-phone').textContent) || 0;
    const trueNoPhone = parseInt(document.getElementById('true-no-phone').textContent) || 0;
    const unspecifiedPhone = parseInt(document.getElementById('unspecified-phone').textContent) || 0;
    const unspecifiedNoPhone = parseInt(document.getElementById('unspecified-no-phone').textContent) || 0;

    // Calculate row totals
    const falseTotal = falsePhone + falseNoPhone;
    const trueTotal = truePhone + trueNoPhone;
    const unspecifiedTotal = unspecifiedPhone + unspecifiedNoPhone;

    // Update row totals
    document.getElementById('false-total').textContent = falseTotal;
    document.getElementById('true-total').textContent = trueTotal;
    document.getElementById('unspecified-total').textContent = unspecifiedTotal;

    // Calculate column totals
    const totalWithPhone = falsePhone + truePhone + unspecifiedPhone;
    const totalWithoutPhone = falseNoPhone + trueNoPhone + unspecifiedNoPhone;

    // Update column totals
    document.getElementById('total-with-phone').textContent = totalWithPhone;
    document.getElementById('total-without-phone').textContent = totalWithoutPhone;

    // Calculate grand total
    const grandTotal = totalWithPhone + totalWithoutPhone;

    // Update grand total
    document.getElementById('grand-total').textContent = grandTotal;
}

function addCheckoutEventListener() {
    const checkoutButton = document.getElementById('checkout-button');
    if (checkoutButton) {
        checkoutButton.addEventListener('click', async function () {
            const creditsInput = document.getElementById('credits-input');
            const credits = parseInt(creditsInput.value);

            if (isNaN(credits) || credits < 1000) { // Assuming 1000 is the minimum number of credits
                alert('Minimum number of credits is 1000');
                return;
            }

            const payload = { credits };

            const response = await makeRequestWithTokenRefresh(async (token) => {
                return fetch(`${API_URL}/create-checkout-session`, {
                    method: 'POST',
                    headers: createAuthorizedHeaders(token),
                    body: JSON.stringify(payload)
                });
            });

            if (response && response.ok) {
                const session = await response.json();
                console.log('Received session:', session);

                if (session.error) {
                    console.error(session.error);
                    alert('Error during checkout: ' + session.error);
                } else {
                    console.log('Redirecting to Stripe checkout with session ID:', session.id);
                    const result = await stripe.redirectToCheckout({ sessionId: session.id });

                    if (result && result.error) {
                        console.error(result.error.message);
                        alert('Checkout error: ' + result.error.message);
                    } else {
                        console.log('Checkout successful, fetching updated token');
                        await refreshAccessToken(); // Refresh token after successful checkout
                        // TODO UPDATE CREDITS IN BACK END
                    }
                }
            } else {
                alert('Checkout process failed. Please try again.');
                logError('Checkout process failed', response);
            }
        });
        console.log('Checkout Button enabled');
    }
}

function checkSessionAndRedirect() {
    const accessToken = localStorage.getItem('access_token');
    if (!accessToken) {
        alert('Session expired. Please login again.');
        window.location.href = '/';
    } else {
        window.location.href = '/dashboard';  // Redirect to the user dashboard or appropriate page
    }
}

async function fetchCredits() {
    let accessToken = localStorage.getItem('access_token');
    if (!accessToken) {
        console.error('No access token available');
        return;
    }

    try {
        const response = await fetchWithTimeout(`${API_URL}/credits`, {
            method: 'GET',
            headers: createAuthorizedHeaders(accessToken),
            timeout: 20000
        });

        if (response.ok) {
            const data = await response.json();
            updateCredits(data.credits);
        } else if (response.status === 401) {
            console.log('Access token expired, attempting to refresh...');
            accessToken = await refreshAccessToken();
            if (accessToken) {
                const retryResponse = await fetchWithTimeout(`${API_URL}/credits`, {
                    method: 'GET',
                    headers: createAuthorizedHeaders(accessToken),
                    timeout: 20000
                });

                if (retryResponse.ok) {
                    const data = await retryResponse.json();
                    updateCredits(data.credits);
                } else {
                    logError('Fetch credits after refresh', await retryResponse.json());
                }
            } else {
                alert('Failed to refresh access token. Please login again.');
            }
        } else if (response.status === 429) {
            const retryAfter = response.headers.get('Retry-After') || 60;
            console.error(`Rate limit exceeded. Retry after ${retryAfter} seconds.`);
            setTimeout(fetchCredits, retryAfter * 1000); // Retry after the specified time
        } else {
            logError('Fetch credits', await response.json());
        }
    } catch (error) {
        logError('Fetch credits', error);
    }
}

function updateCredits(credits) {
    const creditsDisplayElement = document.getElementById('credits-display');
    if (creditsDisplayElement) {
        creditsDisplayElement.innerText = `Credits: ${credits}`;
    }
}

// Add this function to decode the JWT and get the username
export function getUsernameFromJWT() {
    const token = localStorage.getItem('access_token');
    if (!token) return null;

    const payload = JSON.parse(atob(token.split('.')[1])); // Decode JWT
    console.log('payload:', payload);  // Debugging: log the payload to check structure
    return payload.sub; // Adjusted to match your JWT structure
}

// Function to select a row and save its contents to local storage
function updateSelectedProfile_DELME(row) {

    console.error('Entered updateSelectedProfile with :', row);
    const selectedProfile = {
        email: row.cells[0].textContent,
        phoneNumber: row.cells[1].textContent,
        firstName: row.cells[2].textContent,
        lastName: row.cells[3].textContent,
        city: row.cells[4].textContent,
        country: row.cells[5].textContent,
        region: row.cells[6].textContent,
        zip: row.cells[7].textContent,
        latitude: row.cells[8].textContent,
        longitude: row.cells[9].textContent,
        birthday: row.cells[10].textContent, // Add Birthday here
        gender: row.cells[11].textContent, // Add Birthday here
        created: row.cells[12].textContent,
        dummyEmail: row.cells[13].textContent // Adjust index if necessary
    };

    // Save the selected profile to local storage
    localStorage.setItem('selected-sms-profile-eligible-to-import-into-community', JSON.stringify(selectedProfile));

    // Enable the Import Selected Profile button
    document.getElementById('import-selected-profile-button').disabled = false;
}

// Check Server Status Button
const checkServerStatusButton = document.getElementById('check-server-status-button');
let statusCheckInterval = null; // To keep track of the interval

if (checkServerStatusButton) {
    checkServerStatusButton.addEventListener('click', async function () {
        checkServerStatusButton.disabled = true; // Disable the button during the check

        try {
            const response = await makeRequestWithTokenRefresh(async (token) => {
                return fetchWithTimeout(`${API_URL}/klaviyo_status`, {
                    method: 'GET',
                    headers: createAuthorizedHeaders(token),
                    timeout: 10000 // Set a timeout of 10 seconds for the request
                });
            });

            if (response && response.ok) {
                const statusData = await response.json();
                console.log('Server status:', statusData);

                // Update the UI with the server data
                document.getElementById('credits-value').textContent = statusData.credits;
                document.getElementById('service-count-value').textContent = statusData.service_count;
                document.getElementById('user-status-value').textContent = statusData.user_status;
                document.getElementById('profile-count-value').textContent = statusData.profile_count;

                // Update UI based on the `klaviyo_status`
                if (statusData.klaviyo_status === 'not started') {
                    document.getElementById('server-status-title').textContent = 'Klaviyo discovery not started';
                } else if (statusData.klaviyo_status === 'running') {
                    document.getElementById('server-status-title').textContent = 'Klaviyo discovery in progress';
                } else if (statusData.klaviyo_status === 'complete') {
                    document.getElementById('server-status-title').textContent = 'Klaviyo discovery complete';
                } else if (statusData.klaviyo_status === 'failed') {
                    document.getElementById('server-status-title').textContent = 'Klaviyo discovery failed';
                }
            } else {
                console.error('Server status check failed:', await response.json());
                alert('Server status check failed.');
            }
        } catch (error) {
            console.error('Error checking server status:', error);
            alert('An error occurred while checking the server status.');
        } finally {
            checkServerStatusButton.disabled = false; // Re-enable the button after the check
        }
    });
} else {
    console.log('Check Server Status button is not available on this page.');
}


document.querySelectorAll('#community-events-table th').forEach(header => {
    header.addEventListener('contextmenu', (e) => {
        e.preventDefault();

        // Remove any existing context menus
        document.querySelectorAll('.context-menu').forEach(menu => menu.remove());

        // Create a new context menu
        const contextMenu = document.createElement('div');
        contextMenu.classList.add('context-menu');
        contextMenu.style.position = 'absolute';
        contextMenu.style.top = `${e.pageY}px`;
        contextMenu.style.left = `${e.pageX}px`;
        contextMenu.innerHTML = `
            <div onclick="sortColumn('${header.textContent}', 'asc')">Sort A-Z</div>
            <div onclick="sortColumn('${header.textContent}', 'desc')">Sort Z-A</div>
            <div onclick="quickFilter('${header.textContent}')">Quick Filter</div>
        `;

        document.body.appendChild(contextMenu);

        // Hide the menu when clicking outside
        document.addEventListener('click', () => contextMenu.remove(), { once: true });
    });
});

function sortColumn(columnName, order) {
    const tableBody = document.getElementById('community-events-table-body');
    const rows = Array.from(tableBody.querySelectorAll('tr'));

    rows.sort((a, b) => {
        const cellA = a.querySelector(`td:nth-child(${getColumnIndex(columnName)})`).textContent.trim();
        const cellB = b.querySelector(`td:nth-child(${getColumnIndex(columnName)})`).textContent.trim();

        if (order === 'asc') {
            return cellA.localeCompare(cellB);
        } else {
            return cellB.localeCompare(cellA);
        }
    });

    // Re-populate sorted rows
    tableBody.innerHTML = '';
    rows.forEach(row => tableBody.appendChild(row));
}

function getColumnIndex(columnName) {
    const headers = Array.from(document.querySelectorAll('#community-events-table th'));
    return headers.findIndex(header => header.textContent.trim() === columnName) + 1;
}

function quickFilter(columnName) {
    const tableBody = document.getElementById('community-events-table-body');
    const rows = Array.from(tableBody.querySelectorAll('tr'));
    const uniqueValues = new Set();

    // Collect unique values for the selected column
    rows.forEach(row => {
        const cellValue = row.querySelector(`td:nth-child(${getColumnIndex(columnName)})`).textContent.trim();
        if (cellValue) uniqueValues.add(cellValue);
    });

    // Show quick filter panel with unique values
    showQuickFilterPanel(Array.from(uniqueValues), columnName);
}

function showQuickFilterPanel(values, columnName) {
    // Remove any existing filter panels
    document.querySelectorAll('.filter-panel').forEach(panel => panel.remove());

    const filterPanel = document.createElement('div');
    filterPanel.classList.add('filter-panel');
    filterPanel.innerHTML = `
        <h3>Quick Filter “${columnName}”</h3>
        <input type="text" placeholder="Search..." oninput="filterValues(this.value)">
        <div class="filter-controls">
            <a href="#" onclick="deselectAll()">Deselect All</a>
        </div>
        <div class="filter-actions">
            <button onclick="applyFilter('${columnName}')">Apply Filter</button>
            <button onclick="closeFilterPanel()">Close</button>
        </div>
        <div class="filter-values">
            ${values.map(value => `<label><input type="checkbox" checked> ${value}</label>`).join('')}
        </div>
    `;

    document.body.appendChild(filterPanel);
}

function closeFilterPanel() {
    document.querySelectorAll('.filter-panel').forEach(panel => panel.remove());
}

function deselectAll() {
    const checkboxes = document.querySelectorAll('.filter-values input[type="checkbox"]');
    checkboxes.forEach(checkbox => checkbox.checked = false);
}

function filterValues(searchTerm) {
    const checkboxes = document.querySelectorAll('.filter-values label');
    checkboxes.forEach(label => {
        const text = label.textContent.toLowerCase();
        label.style.display = text.includes(searchTerm.toLowerCase()) ? '' : 'none';
    });
}

function applyFilter(columnName) {
    const tableBody = document.getElementById('community-events-table-body');
    const checkboxes = document.querySelectorAll('.filter-values input[type="checkbox"]');
    const selectedValues = Array.from(checkboxes)
        .filter(checkbox => checkbox.checked)
        .map(checkbox => checkbox.parentElement.textContent.trim());

    Array.from(tableBody.querySelectorAll('tr')).forEach(row => {
        const cellValue = row.querySelector(`td:nth-child(${getColumnIndex(columnName)})`).textContent.trim();
        row.style.display = selectedValues.includes(cellValue) ? '' : 'none';
    });

    document.querySelector('.filter-panel').remove();
}


export function updateSpinnerStatus(result) {
    const totalProfiles = result.total_profiles || 0;
    const processedProfiles = result.processed_profiles || 0;
    const progressBar = document.getElementById('progress-bar');
    const progressPercent = document.getElementById('progress-percent');

    // Only proceed if both progress bar elements exist in the DOM
    if (progressBar && progressPercent && totalProfiles > 0) {
        const percentComplete = (processedProfiles / totalProfiles) * 100;

        // Update the progress bar width and display percentage
        progressBar.style.width = percentComplete;
        progressPercent.innerText = Math.floor(percentComplete); // Display integer percentage
    } else {
        console.error("Progress bar or percentage display element is missing.");
    }
}

export function updateProgress(processedProfiles, totalProfiles) {
    const progressBar = document.getElementById('progress-bar');
    const progressPercent = document.getElementById('progress-percent');

    // Calculate percentage
    const percentage = totalProfiles > 0 ? Math.round((processedProfiles / totalProfiles) * 100) : 0;

    // Update progress bar width and percentage text, if elements are found
    if (progressBar) {
        progressBar.style.width = `${percentage}%`;
    } else {
        console.error("Progress bar element not found.");
    }
    if (progressPercent) {
        progressPercent.textContent = `${percentage}`; // Adds % symbol for clarity
    } else {
        console.error("Progress percentage element not found.");
    }
}

// Function to handle errors and alert the user
function handleError(errorMessage, error = null) {
    // Regular expression to extract the error code
    const errorCodeMatch = errorMessage.match(/Error code: ([\w-]+)/);
    let extractedErrorCode = errorCodeMatch ? errorCodeMatch[1] : null;

    // Determine the custom error message based on the extracted error code
    if (extractedErrorCode === "504-loadbalancer") {
        errorMessage = "The Import took too long. You need to increase the number of max workers and retry. [504-loadbalancer]";
    } else if (extractedErrorCode === "504-backend") {
        errorMessage = "The Import took too long. You need to increase the number of max workers and retry. [504-backend]";
    }

    // Log the error and alert the user
    console.error(errorMessage, error);
    alert(errorMessage);
}

async function revokeTokens() {
    const username = prompt('Enter username to revoke tokens for:');
    let accessToken = localStorage.getItem('access_token');
    if (!accessToken) {
        console.error('No access token available');
        alert('No access token available. Please login first.');
        return;
    }

    try {
        const response = await fetchWithTimeout(`${API_URL}/revoke`, {
            method: 'POST',
            headers: createAuthorizedHeaders(accessToken),
            body: JSON.stringify({ username }),
            timeout: 20000
        });

        if (response.ok) {
            console.log('Tokens revoked successfully');
            alert('Tokens revoked successfully');
            // Remove the tokens from local storage
            localStorage.removeItem('access_token');
            localStorage.removeItem('refresh_token');
        } else {
            logError('Revoke tokens', await response.json());
            alert('Failed to revoke tokens');
        }
    } catch (error) {
        logError('Revoke tokens', error);
        alert('Error during token revocation');
    }
}

// Function to load community_modals.html into client.html
export async function loadCommunityModals() {

    try {
        const response = await fetch('/static/community_modals.html');
        const html = await response.text();
        const modalContainer = document.getElementById('community-members-container');

        if (modalContainer) {
            modalContainer.innerHTML = html;

            // Enable the Members button after modals are loaded
            const membersButton = document.getElementById('load-community-members-button');
            if (membersButton) {
                membersButton.disabled = false;
                membersButton.style.backgroundColor = ''; // Reset to default background color
                membersButton.style.cursor = 'pointer'; // Set cursor to pointer for active button
                console.log("Members button enabled after modals loaded");
            } else {
                console.error("Members button not found or modals not loaded");
            }

            // Enable the Communities button after modals are loaded
            const communitiesButton = document.getElementById('load-communities-button');
            if (communitiesButton) {
                communitiesButton.disabled = false;
                communitiesButton.style.backgroundColor = ''; // Reset to default background color
                communitiesButton.style.cursor = 'pointer'; // Set cursor to pointer for active button
                console.log("Communities button enabled after modals loaded");
            } else {
                console.error("Communities button not found or modals not loaded");
            }

        } else {
            console.error('community-members-container not found');
        }
    } catch (error) {
        console.error('Error loading modals:', error);
    }
}

