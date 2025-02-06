import { makeRequestWithTokenRefresh } from '/static/helpers.js';
import { API_URL } from '/static/helpers.js';
import { createAuthorizedHeaders } from '/static/helpers.js';
import { updateProgress } from '/static/scripts.js';
import { updateSpinnerStatus } from '/static/scripts.js';

// Select the "Import Selected Profile" button
const importSelectedProfileButton = document.getElementById('import-selected-profile-button');

// Event listener for the "Import Selected Profile" button
if (importSelectedProfileButton) {
    importSelectedProfileButton.addEventListener('click', async function () {
        // Retrieve the selected profile from local storage
        const selectedProfile = localStorage.getItem('selected-sms-profile-eligible-to-import-into-community');

        if (!selectedProfile) {
            alert('No profile selected for import.');
            return;
        }

        // Trigger the import function
        await triggerCommunityImport(JSON.parse(selectedProfile));
    });
}

function updateImportSummary(data) {
    const importSummarySection = document.getElementById('import-summary-section');

    // Helper function to format epoch time to "YYYY-MM-DD HH:mm:ss"
    function formatEpochToDate(epoch) {
        if (!epoch || isNaN(epoch)) {
            return 'N/A'; // Return 'N/A' if epoch is invalid or missing
        }
        const date = new Date(epoch * 1000);  // Convert seconds to milliseconds
        const year = date.getFullYear();
        const month = String(date.getMonth() + 1).padStart(2, '0');
        const day = String(date.getDate()).padStart(2, '0');
        const hours = String(date.getHours()).padStart(2, '0');
        const minutes = String(date.getMinutes()).padStart(2, '0');
        const seconds = String(date.getSeconds()).padStart(2, '0');
        return `${year}-${month}-${day} ${hours}:${minutes}:${seconds}`;
    }

    // Helper function to check if a string is a valid date
    function isDateString(dateStr) {
        return !isNaN(Date.parse(dateStr));
    }

    // Update summary details with fallbacks for missing elements
    const totalProfilesElement = document.getElementById('total-profiles');
    if (totalProfilesElement) {
        totalProfilesElement.innerText = data.total_profiles || 'N/A';
    } else {
        console.error("Element for total profiles not found.");
    }

    const importStartedElement = document.getElementById('import-started');
    if (importStartedElement) {
        importStartedElement.innerText = isDateString(data.import_started_at)
            ? data.import_started_at
            : formatEpochToDate(data.import_started_at);
    } else {
        console.error("Element for import started date not found.");
    }

    const importEndedElement = document.getElementById('import-ended');
    if (importEndedElement) {
        importEndedElement.innerText = isDateString(data.import_ended_at)
            ? data.import_ended_at
            : formatEpochToDate(data.import_ended_at);
    } else {
        console.error("Element for import ended date not found.");
    }

    // Update total time with a fallback if total_time_taken is invalid
    const totalTimeElement = document.getElementById('total-time');
    if (totalTimeElement) {
        totalTimeElement.innerText = (data.total_time_taken && !isNaN(data.total_time_taken))
            ? `${data.total_time_taken.toFixed(0)} seconds`
            : 'N/A';
    } else {
        console.error("Element for total time not found.");
    }

    // Update test mode and max workers fields
    const testModeElement = document.getElementById('test-mode');
    if (testModeElement) {
        testModeElement.innerText = data.test_mode_enabled ? "Enabled" : "Disabled";
    } else {
        console.error("Element for test mode not found.");
    }

    const maxWorkersElement = document.getElementById('max-workers');
    if (maxWorkersElement) {
        maxWorkersElement.innerText = data.max_workers || 'N/A';
    } else {
        console.error("Element for max workers not found.");
    }

    // Update the Imported Count with the successful_imports value
    const importedCountElement = document.getElementById('imported-count');
    if (importedCountElement) {
        importedCountElement.innerText = data.successful_imports || '0';  // Default to 0 if not present
    } else {
        console.error("Element for imported count not found.");
    }

    // Show the summary section if it exists
    if (importSummarySection) {
        importSummarySection.style.display = 'block';
    } else {
        console.error("Import summary section element not found.");
    }
}

export async function triggerCommunityImport(profileData) {
    const importSelectedProfileButton = document.getElementById('import-selected-profile-button');

    if (!importSelectedProfileButton) {
        console.error('Import Selected Profile button not found.');
        return;
    }
    console.log('triggerCommunityImport entered with :',profileData);

    // Disable the button and change its appearance
    importSelectedProfileButton.style.backgroundColor = 'grey';
    importSelectedProfileButton.disabled = true;

    try {
        // Make the request to the backend API
        const response = await makeRequestWithTokenRefresh(async (token) => {
            return fetch(`${API_URL}/preopt_into_community`, {
                method: 'POST',
                headers: createAuthorizedHeaders(token),
                body: JSON.stringify(profileData) // Send the selected profile as JSON
            });
        });

        // Log the raw response object for debugging
        console.log('Community Import Response:', response);

        // Check if the response is successful
        if (response && response.ok) {
            const data = await response.json();
            console.log('Community Import Data:', data);

            // Display the msg field dynamically from the response JSON
            const message = data.msg || 'Unknown error';

            if (data.success) {
                alert(`Profile imported successfully: ${message}`);
                importSelectedProfileButton.style.backgroundColor = 'green';
            } else if (data.status === 'partial_success') {
                alert(`Profile imported, but failed to add to sub-community: ${message}`);
                importSelectedProfileButton.style.backgroundColor = 'orange'; // Different color for partial success
            } else if (data.status === 'duplicate') {
                alert(`This profile was already imported: ${message}`);
                importSelectedProfileButton.style.backgroundColor = 'blue'; // Different color for duplicates
            } else {
                alert(`Failed to import profile: ${message}`);
                importSelectedProfileButton.style.backgroundColor = 'red';
            }
        } else {
            // Handle specific error responses
            alert('Bad Request: Please check if your Community API keys are correct.');
            importSelectedProfileButton.style.backgroundColor = 'red';
        }
    } catch (error) {
        // Handle any unexpected errors
        console.error('Error during community import:', error);
        alert('An unexpected error occurred.');
        importSelectedProfileButton.style.backgroundColor = 'red';
    } finally {
        // Re-enable the button after the request is completed
        importSelectedProfileButton.disabled = false;
    }
}

export async function triggerCommunityImportAll() {
    const accessToken = localStorage.getItem('access_token');

    if (!accessToken) {
        console.error('No access token available');
        alert('No access token available. Please login first.');
        return;
    }

    // Show the spinner and progress bar
    const successCountSpinner = document.getElementById('successful-imports-count-spinner');
    if (successCountSpinner) {
        successCountSpinner.style.display = 'block';
    } else {
        console.error('Spinner element not found.');
    }

    // Reset progress bar and spinner
    const progressBar = document.getElementById('progress-bar');
    if (progressBar) {
        progressBar.style.width = '0%';
    } else {
        console.error('progressBar element not found.');
    }

    const progressPercent = document.getElementById('progress-percent');
    if (progressPercent) {
        progressPercent.textContent = '0';
    } else {
        console.error('progressPercent element not found.');
    }

    // Disable the import button to prevent additional clicks
    const importAllProfilesButton = document.getElementById('import-all-profiles-button');
    if (importAllProfilesButton) {
        importAllProfilesButton.style.backgroundColor = 'grey';
        importAllProfilesButton.disabled = true;
    }

    const checkImportStatusRequest = async (token) => {
        return fetchWithTimeout(`${API_URL}/check_import_status`, {
            method: 'GET',
            headers: createAuthorizedHeaders(token),
            timeout: 60000
        });
    };

    const signalGatewayTimeoutRequest = async (token) => {
        return fetchWithTimeout(`${API_URL}/signal_gateway_timeout`, {
            method: 'POST',
            headers: createAuthorizedHeaders(token),
            timeout: 60000
        });
    };

    let chunkNumber = 1;
    let moreChunks = true;

    // Interval to fetch and update the final status every 5 seconds
    const finalStatusInterval = setInterval(async () => {
        try {
            const finalStatusResponse = await makeRequestWithTokenRefresh(checkImportStatusRequest);
            const finalData = await finalStatusResponse.json();
            console.log('Final status response:', JSON.stringify(finalData, null, 4));

            if (finalStatusResponse.ok) {
                const result = finalData.result;
                updateImportSummary(result);

                if (result.processed_profiles !== undefined && result.total_profiles !== undefined) {
                    updateProgress(result.processed_profiles, result.total_profiles);
                    updateSpinnerStatus(result);
                }

                if (result.status === 'completed' || result.status === '504 (Gateway Time-out)' || !result.more_chunks) {
                    clearInterval(finalStatusInterval);
                    importAllProfilesButton.style.backgroundColor = result.status === '504 (Gateway Time-out)' ? 'red' : 'green';
                    console.log('result.status:', result.status);
                }
            } else {
                handleError('Error fetching final import status.');
                importAllProfilesButton.style.backgroundColor = 'red';
            }
        } catch (error) {
            console.error('Error fetching final import status:', error);
            clearInterval(finalStatusInterval);
        }
    }, 5000);

    try {
        while (moreChunks) {
            console.log(`Processing chunk number ${chunkNumber}`);

            const importResponse = await makeRequestWithTokenRefresh((token) => {
                return fetchWithTimeout(`${API_URL}/import_all_profiles`, {
                    method: 'POST',
                    headers: createAuthorizedHeaders(token),
                    timeout: 900000,
                    body: JSON.stringify({ chunk_number: chunkNumber })
                });
            });

            if (importResponse.ok) {
                const contentType = importResponse.headers.get("content-type");

                if (contentType && contentType.includes("application/json")) {
                    const responseData = await importResponse.json();
                    console.log('Import response data:', JSON.stringify(responseData, null, 4));

                    const { status, processed_profiles, total_profiles, successful_imports, number_of_chunks, number_of_chunks_processed, message } = responseData;
                    console.log(`Status: ${status}, Message: ${message}`);
                    console.log(`Processed profiles: ${processed_profiles}/${total_profiles}, Successful imports: ${successful_imports}`);
                    console.log(`Chunk ${chunkNumber} of ${number_of_chunks} (${number_of_chunks_processed} completed)`);

                    moreChunks = responseData.more_chunks;
                    chunkNumber = responseData.chunk_number + 1;

                    updateSpinnerStatus(responseData);
                    updateProgress(processed_profiles, total_profiles);
                } else {
                    const responseText = await importResponse.text();
                    console.error("Response is not in JSON format. Likely a server error or timeout.");
                    console.error("Received response text:", responseText);

                    const signalTimeoutResponse = await makeRequestWithTokenRefresh(signalGatewayTimeoutRequest);
                    if (signalTimeoutResponse.ok) {
                        console.log('Signaled gateway timeout status to backend.');
                    } else {
                        console.error('Failed to signal gateway timeout to backend.');
                    }

                    handleError('Received non-JSON response. Possible server error.');
                    break;
                }
            } else {
                const errorResponse = await importResponse.text();
                console.error("Non-OK response received:", errorResponse);
                handleError(`Error processing chunk ${chunkNumber}: ${errorResponse || 'Unknown error'}`);

                const signalTimeoutResponse = await makeRequestWithTokenRefresh(signalGatewayTimeoutRequest);
                if (signalTimeoutResponse.ok) {
                    console.log('Signaled gateway timeout status to backend.');
                } else {
                    console.error('Failed to signal gateway timeout to backend.');
                }
                break;
            }
        }

        console.log("All chunks processed. Import complete.");

        const finalStatusResponse = await makeRequestWithTokenRefresh(checkImportStatusRequest);
        const finalData = await finalStatusResponse.json();
        console.log('Final status response:', JSON.stringify(finalData, null, 4));

        if (finalStatusResponse.ok) {
            updateImportSummary(finalData.result);
            importAllProfilesButton.style.backgroundColor = 'green';
        } else {
            handleError('Error fetching final import status.');
            importAllProfilesButton.style.backgroundColor = 'red';
        }

    } catch (error) {
        if (error.name === 'AbortError') {
            console.error('Import request timed out');
            handleError('Import request took too long and timed out');

            const signalTimeoutResponse = await makeRequestWithTokenRefresh(signalGatewayTimeoutRequest);
            if (signalTimeoutResponse.ok) {
                console.log('Signaled gateway timeout status to backend.');
            } else {
                console.error('Failed to signal gateway timeout to backend.');
            }

            importAllProfilesButton.style.backgroundColor = 'red';
        } else {
            handleError(`Error during community import for all profiles: ${error}`);
            importAllProfilesButton.style.backgroundColor = 'red';
        }
    } finally {
        if (successCountSpinner) {
            successCountSpinner.style.display = 'none';
        }
        if (importAllProfilesButton) {
            importAllProfilesButton.disabled = false;
        }
        clearInterval(finalStatusInterval);
    }
}


