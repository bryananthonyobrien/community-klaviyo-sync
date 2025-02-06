import { makeRequestWithTokenRefresh } from '/static/helpers.js';
import { API_URL } from '/static/helpers.js';
import { createAuthorizedHeaders } from '/static/helpers.js';
import { logError } from '/static/helpers.js';
import { setSelectedFileLocation } from '/static/scripts.js';
import { loadProfiles } from '/static/profiles.js';
import { getSelectedFileLocation } from '/static/scripts.js';

// Define the stripe variable in a broader scope
export let isDownloadInProgress = false; // Flag to track if a download is already in progress

export function downloadAllFiles(fileLocation) {
    return new Promise((resolve, reject) => {
        // Validate the file location
        if (!fileLocation) {
            alert('No file location selected.');
            reject(new Error('No file location selected.'));
            return;
        }

        // Get required elements
        const downloadButton = document.getElementById('download-all-files');
        const spinner = document.getElementById('loading-spinner');

        // Disable the download button and show spinner to prevent duplicate actions
        downloadButton.disabled = true;
        spinner.style.display = 'block';

        console.log(`Initiating download for directory: ${fileLocation}`);

        // Initiate fetch request to download files
        fetch(`/download_directory?directory=${encodeURIComponent(fileLocation)}`, {
            method: 'GET',
            headers: createAuthorizedHeaders(localStorage.getItem('access_token'))
        })
        .then(response => {
            if (!response.ok) {
                console.error('Response not OK:', response);
                throw new Error('Failed to download files');
            }
            return response.blob();
        })
        .then(blob => {
            // Create a temporary download link and trigger the download
            const downloadLink = document.createElement('a');
            downloadLink.href = window.URL.createObjectURL(blob);
            downloadLink.download = 'files.zip';
            document.body.appendChild(downloadLink);
            downloadLink.click();
            document.body.removeChild(downloadLink);
            console.log('Download completed successfully.');
            resolve(); // Resolve the Promise on successful download
        })
        .catch(error => {
            console.error('Error during the fetch or download process:', error);
            alert('Error downloading files.');
            reject(error); // Reject the Promise on error
        })
        .finally(() => {
            // Always re-enable the button and hide the spinner
            console.log('Re-enabling the download button and hiding spinner.');
            downloadButton.disabled = false;
            spinner.style.display = 'none';
        });
    });
}


function onDownloadClick(fileLocation) {
    if (isDownloadInProgress) {
        console.log('Download already in progress.');
        return;
    }

    isDownloadInProgress = true;
    downloadAllFiles(fileLocation)
        .finally(() => {
            isDownloadInProgress = false;
        });

    const dropdown = document.getElementById('dropdown');
    dropdown.style.display = 'none';
}

export async function deleteKlaviyoDiscovery() {

    const fileLocation = getSelectedFileLocation()
    if (!fileLocation) {
        alert('No file location selected.');
        return;
    }

    // Log the payload to be sent to the server
    console.log(`Payload for delete request: { file_location: ${fileLocation} }`);

    // Disable the delete button to prevent multiple clicks
    const deleteButton = document.getElementById('delete-klaviyo-discovery');
    const spinner = document.getElementById('loading-spinner');

    deleteButton.disabled = true;
    spinner.style.display = 'block'; // Show the spinner

    console.log(`Initiating delete for discovery at location: ${fileLocation}`);

    // Create the request function to send a DELETE request
    const requestFn = async (token) => {
        return fetch(`${API_URL}/delete_klaviyo_discovery`, {
            method: 'DELETE',
            headers: {
                ...createAuthorizedHeaders(token),
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ file_location: fileLocation })
        });
    };

    // Use the token refresh logic wrapped inside makeRequestWithTokenRefresh
    try {
        const response = await makeRequestWithTokenRefresh(requestFn);

        if (response.ok) {
            console.log('Delete operation completed successfully');

            // Call fetchKlaviyoDiscoveries to refresh the list after deletion
            fetchKlaviyoDiscoveries();
        } else {
            const errorData = await response.json();
            console.error('Failed to delete discovery:', errorData);
            alert('Failed to delete discovery');
        }
    } catch (error) {
        console.error('Error during the delete process:', error);
        alert('Error deleting discovery');
    } finally {
        // Re-enable the button and hide the spinner
        deleteButton.disabled = false;
        spinner.style.display = 'none';
    }
}


export function selectRow(index, fileLocation) {
    let table = document.getElementById('discoveries-table');
    let rows = table.getElementsByTagName('tr');

    // Remove 'selected' class from all rows and highlight the clicked one
    for (let i = 1; i < rows.length; i++) {
        rows[i].classList.remove('selected');
    }
    rows[index + 1].classList.add('selected');

    // Update the selected file location
    setSelectedFileLocation(fileLocation);

    console.log(`Selected Row: ${index}, File Location: ${fileLocation}`);

    // Position and show the dropdown
    let dropdown = document.getElementById('dropdown');
    let rowRect = rows[index + 1].getBoundingClientRect();
    dropdown.style.display = 'block';
    dropdown.style.position = 'absolute';
    dropdown.style.left = `${rowRect.left}px`;
    dropdown.style.top = `${rowRect.bottom}px`;

    // Add download functionality
    const downloadButton = document.getElementById('download-all-files');
    if (downloadButton) {
        // Use the getter to retrieve the file location dynamically
        downloadButton.onclick = () => onDownloadClick(getSelectedFileLocation());
    } else {
        console.error('Download button not found');
    }
}
export function displayDiscoveriesTable(discoveries) {
    console.log('displayDiscoveriesTable entered');
    let table = document.getElementById('discoveries-table');
    table.innerHTML = '';  // Clear the table

    let header = `
        <tr>
            <th>Start Time</th>
            <th>End Time</th>
            <th>Profiles Retrieved</th>
            <th>Directory Exists</th>
        </tr>
    `;
    table.innerHTML = header;

    discoveries.forEach((discovery, index) => {
        let row = document.createElement('tr');
        row.setAttribute('data-index', index);
        row.setAttribute('data-file-location', discovery.file_location);

        row.innerHTML = `
            <td>${discovery.start_time}</td>
            <td>${discovery.end_time}</td>
            <td>${discovery.profile_count}</td>
            <td>${discovery.directory_exists ? 'Yes' : 'No'}</td>
        `;

        row.addEventListener('click', () => {
            selectRow(index, discovery.file_location);
        });

        table.appendChild(row);
    });
}


export async function fetchKlaviyoDiscoveries() {
    const accessToken = localStorage.getItem('access_token');

    if (!accessToken) {
        console.error('No access token available');
        alert('No access token available. Please login first.');
        return;
    }

    const requestFn = async (token) => {
        return fetch(`${API_URL}/klaviyo_discoveries`, {
            method: 'GET',
            headers: createAuthorizedHeaders(token)
        });
    };

    try {
        const response = await makeRequestWithTokenRefresh(requestFn);

        if (response && response.ok) {
            const data = await response.json(); // Directly parse JSON
            console.log('Klaviyo Discoveries Response:', data);

            if (Array.isArray(data) && data.length > 0) {
                displayDiscoveriesTable(data);

                let mostRecentDiscovery = null;
                let mostRecentEpoch = 0;

                data.forEach(discovery => {
                    console.log('Evaluating discovery:', discovery);

                    const rawEndTime = discovery.end_time;
                    if (rawEndTime) {
                        const discoveryEpoch = Date.parse(rawEndTime);
                        if (!isNaN(discoveryEpoch) && discovery.file_location) {
                            if (discoveryEpoch > mostRecentEpoch) {
                                mostRecentEpoch = discoveryEpoch;
                                mostRecentDiscovery = discovery;
                            }
                        } else {
                            console.warn('Skipping invalid discovery:', discovery);
                        }
                    }
                });

                if (mostRecentDiscovery) {
                    const fileLocation = mostRecentDiscovery.file_location;

                    const titleElement = document.getElementById('discover-klaviyo-profiles-title');
                    titleElement.textContent = "Select or Kick off a New Discovery";

                    setSelectedFileLocation(fileLocation);

                    if (fileLocation) {
                        loadProfiles(false);
                    } else {
                        console.error('Failed to retrieve file location for loading profiles');
                    }
                } else {
                    console.warn('No valid discoveries found.');
                }
            } else {
                console.info('No Klaviyo discoveries found');
                const titleElement = document.getElementById('discover-klaviyo-profiles-title');
                if (titleElement) {
                    titleElement.textContent = "Click Discover Klaviyo button below to discover Profiles";
                }
                document.getElementById('discoveries-container').innerHTML = 'No discoveries found.';
            }
        } else if (response && response.status === 401) {
            console.error('Unauthorized: Token information not found');
            alert('Session expired. Please log in again.');
        } else {
            const errorMsg = await response.text();
            console.error('Error fetching Klaviyo discoveries:', errorMsg);
            alert(`Failed to fetch Klaviyo discoveries: ${errorMsg}`);
        }
    } catch (error) {
        console.error('Error in fetchKlaviyoDiscoveries:', error);
        logError('Fetch Klaviyo Discoveries', error);
    }
}



export async function discoverKlaviyoProfiles() {
    const discoverButton = document.getElementById('discover-klaviyo-button');
    const spinner = document.getElementById('loading-spinner');
    const titleElement = document.getElementById('discover-klaviyo-profiles-title');
    let pollingInterval = null; // For managing the polling interval

    console.log("Starting Klaviyo profile discovery...");

    // Disable the discover button and show the loading spinner
    discoverButton.classList.add('busy-button');
    discoverButton.disabled = true;
    spinner.style.display = 'block';
    titleElement.textContent = "Klaviyo Discovery running...";

    try {
        // Start polling for status updates immediately
        pollingInterval = setInterval(async () => {
            try {
                const statusResponse = await makeRequestWithTokenRefresh(async (token) => {
                    return fetch(`${API_URL}/klaviyo_status`, {
                        method: 'GET',
                        headers: createAuthorizedHeaders(token)
                    });
                });

                if (statusResponse && statusResponse.ok) {
                    const statusData = await statusResponse.json();
                    console.log("Polling status data:", statusData);

                    // Update the title with the profile count
                    titleElement.textContent =
                        `Klaviyo Discovery running ... ${statusData.profile_count} profiles retrieved`;

                    // Stop polling if discovery is complete or failed
                    if (statusData.klaviyo_status === 'complete') {
                        titleElement.textContent =
                            `Discovery Complete - successfully retrieved ${statusData.profile_count} Profiles`;
                        clearInterval(pollingInterval);
                    } else if (statusData.klaviyo_status === 'failed') {
                        titleElement.textContent = "Klaviyo Discovery failed.";
                        clearInterval(pollingInterval);
                    }
                } else {
                    console.error("Polling failed:", await statusResponse.json());
                }
            } catch (pollingError) {
                console.error("Error during polling:", pollingError);
            }
        }, 5000); // Poll every 5 seconds

        // Perform the synchronous call to start discovery using makeRequestWithTokenRefresh
        console.log("Performing synchronous discovery call...");
        const response = await makeRequestWithTokenRefresh(async (token) => {
            return fetch(`${API_URL}/discover_klaviyo_profiles`, {
                method: 'POST',
                headers: createAuthorizedHeaders(token)
            });
        });

        if (response && response.ok) {
            console.log("Synchronous discovery call completed.");
        } else {
            console.error("Failed to initiate discovery:", await response.json());
            alert("Failed to initiate discovery.");
        }
    } catch (error) {
        logError("Error in Klaviyo profile discovery", error);
        alert("An error occurred while discovering Klaviyo profiles");
    } finally {
        // Ensure polling is stopped after synchronous call ends
        if (pollingInterval) {
            clearInterval(pollingInterval);
        }

        // Hide the loading spinner and re-enable the discover button
        spinner.style.display = 'none';
        discoverButton.classList.remove('busy-button');
        discoverButton.disabled = false;
        titleElement.textContent = `Select or Kick off a New Discovery`;
    }
}



