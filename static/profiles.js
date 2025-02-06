import { makeRequestWithTokenRefresh } from '/static/helpers.js';
import { API_URL } from '/static/helpers.js';
import { createAuthorizedHeaders } from '/static/helpers.js';
import { selectedFileLocation } from '/static/scripts.js';
import { createStagingFiles } from '/static/staging.js';
import { getUsernameFromJWT } from '/static/scripts.js';

// Function to update the profiles table in the UI with sorting by Created date
function updateProfilesTable(profiles) {

    console.log('updateProfilesTable entered');

    const profilesTable = document.getElementById('profiles-table-body');
    profilesTable.innerHTML = ''; // Clear existing table rows

    // Convert the profiles object to an array for sorting
    const profilesArray = Object.entries(profiles).map(([phoneNumber, profile]) => {
        return { phoneNumber, ...profile };
    });

    // Sort the profiles by the 'created' field in descending order (most recent first)
    profilesArray.sort((a, b) => {
        const dateA = a.created ? new Date(a.created) : new Date(0);
        const dateB = b.created ? new Date(b.created) : new Date(0);
        return dateB - dateA;
    });

    // Iterate over the sorted profiles array and update the table
    for (const profile of profilesArray) {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${profile.email || ''}</td>
            <td>${profile.phoneNumber}</td>
            <td>${profile.first_name || ''}</td>
            <td>${profile.last_name || ''}</td>
            <td>${profile.city || ''}</td>
            <td>${profile.country || ''}</td>
            <td>${profile.region || ''}</td>
            <td>${profile.zip || ''}</td>
            <td>${profile.latitude || ''}</td>
            <td>${profile.longitude || ''}</td>
            <td>${profile.birthday || ''}</td> <!-- Add Birthday Field -->
            <td>${profile.gender || ''}</td> <!-- Add Gender Field -->
            <td>${profile.created || ''}</td>
            <td>${profile.dummy_email ? 'Yes' : 'No'}</td>
        `;

        // Add click event listener for row selection
        row.addEventListener('click', function() {
             const selectedProfile = {
                first_name: profile.first_name || "",
                last_name: profile.last_name || "",
                email: profile.email || "",
                phoneNumber: profile.phoneNumber || "",
                phone_number:profile.phone_number || "",
                birthday: profile.birthday || "",
                gender: profile.gender || "",
                city: profile.city || "",
                state_name: profile.region || "",
                zip: profile.zip || "",
                country_name: profile.country || "",
                longitude: profile.longitude || "",
                latitude: profile.latitude || "",
                channel: profile.channel || "",
                created: profile.created || "",
                updated: profile.updated || "",
                last_event_date: profile.last_event_date || "",
                ip: profile.ip || "",
            };

            console.log('Profile selected:', selectedProfile);
            localStorage.setItem('selected-sms-profile-eligible-to-import-into-community', JSON.stringify(selectedProfile));


            // Remove 'selected' class from all rows
            const rows = profilesTable.getElementsByTagName('tr');
            for (let r of rows) {
                r.classList.remove('selected');
            }

            // Highlight the selected row
            row.classList.add('selected');

            // Enable the import button
            const importSelectedProfileButton = document.getElementById('import-selected-profile-button');
            importSelectedProfileButton.disabled = false; // Enable button when a row is selected
            importSelectedProfileButton.style.backgroundColor = 'green'; // Set button color to green
        });

        profilesTable.appendChild(row);
    }
}

// Example function to handle chunk loading
async function loadChunk(selectedChunk) {
    console.log('loadChunk : ',selectedChunk);
    const username = getUsernameFromJWT();

    const chunkKey = `sms_profiles_eligible_to_import_to_community_${username}_${selectedChunk}`;

    // Define request function for fetching the specific chunk
    const requestFn = async (token) => {
        console.info(`Creating fetch request for chunk ${selectedChunk}.`); // Debug: log request creation
        return fetch(`${API_URL}/get_chunk_data`, {
            method: 'POST',
            headers: createAuthorizedHeaders(token),
            body: JSON.stringify({ chunk_key: chunkKey })
        });
    };

    try {
        const response = await makeRequestWithTokenRefresh(requestFn);

        if (!response.ok) {
            throw new Error(`Failed to fetch chunk data for chunk ${selectedChunk}`);
        }

        const chunkData = await response.json();
        console.log(`Data for chunk ${selectedChunk} retieved`);
        updateProfilesTable(chunkData);

    } catch (error) {
        console.info(`Error loading chunk ${selectedChunk}:`, error);
    }
}

export async function downloadEligibleProfiles() {
    const accessToken = localStorage.getItem('access_token');

    // Retrieve the stage1Path from local storage
    const stage1Path = localStorage.getItem('stage1Path');

    // Check if the path exists
    if (!stage1Path) {
        alert('Failed to retrieve the file path for the eligible profiles.');
        return;
    }

    // Show the loading spinner
    const spinner = document.getElementById('loading-spinner');
    if (spinner) {
        spinner.style.display = 'block'; // Show the spinner
    }

    // Construct the download URL
    const csvFilePath = encodeURIComponent(stage1Path); // Encode the path for safety
    const downloadUrl = `${API_URL}/download_csv?file_path=${csvFilePath}`; // Use the retrieved file path

    // Create a request function to download the CSV file
    const requestFn = async (token) => {
        return fetch(downloadUrl, {
            method: 'GET',
            headers: createAuthorizedHeaders(token) // Include the authorization header
        });
    };

    try {
        const response = await makeRequestWithTokenRefresh(requestFn);

        if (response && response.ok) {
            const blob = await response.blob(); // Get the file as a Blob
            const downloadLink = document.createElement('a');
            downloadLink.href = window.URL.createObjectURL(blob);
            downloadLink.download = 'eligible_profiles.csv'; // Set the download filename
            document.body.appendChild(downloadLink);
            downloadLink.click();
            document.body.removeChild(downloadLink);
            console.log('Eligible profiles CSV file downloaded successfully from ',csvFilePath);
        } else {
            throw new Error('Failed to download the CSV file');
        }
    } catch (error) {
        console.error('Error downloading the CSV file:', error);
        alert('Error downloading the eligible profiles CSV file: ' + error.message);
    } finally {
        // Hide the loading spinner after the request is complete
        if (spinner) {
            spinner.style.display = 'none'; // Hide the spinner
        }
    }
}

export async function downloadFailedProfiles() {
    const accessToken = localStorage.getItem('access_token');

    // Retrieve the stage1DroppedPath from local storage
    const stage1DroppedPath = localStorage.getItem('stage1DroppedPath');

    // Check if the path exists
    if (!stage1DroppedPath) {
        alert('Failed to retrieve the file path for the failed profiles.');
        return;
    }

    // Show the loading spinner
    const spinner = document.getElementById('loading-spinner');
    if (spinner) {
        spinner.style.display = 'block'; // Show the spinner
    }

    // Construct the download URL
    const csvFilePath = encodeURIComponent(stage1DroppedPath); // Encode the path for safety
    const downloadUrl = `${API_URL}/download_csv?file_path=${csvFilePath}`; // Use the retrieved file path

    // Create a request function to download the CSV file
    const requestFn = async (token) => {
        return fetch(downloadUrl, {
            method: 'GET',
            headers: createAuthorizedHeaders(token) // Include the authorization header
        });
    };

    try {
        const response = await makeRequestWithTokenRefresh(requestFn);

        if (response && response.ok) {
            const blob = await response.blob(); // Get the file as a Blob
            const downloadLink = document.createElement('a');
            downloadLink.href = window.URL.createObjectURL(blob);
            downloadLink.download = 'failed_profiles.csv'; // Set the download filename
            document.body.appendChild(downloadLink);
            downloadLink.click();
            document.body.removeChild(downloadLink);
            console.log('Failed profiles CSV file downloaded successfully');
        } else {
            throw new Error('Failed to download the CSV file');
        }
    } catch (error) {
        console.error('Error downloading the CSV file:', error);
        alert('Error downloading the failed profiles CSV file: ' + error.message);
    } finally {
        // Hide the loading spinner after the request is complete
        if (spinner) {
            spinner.style.display = 'none'; // Hide the spinner
        }
    }
}

export function loadProfiles() {
    const directory = selectedFileLocation; // Get the selected directory from the previously selected row
    const accessToken = localStorage.getItem('access_token');

    // Get the state of the download CSV checkbox
    const downloadCsvChecked = document.getElementById('download-csv-checkbox').checked;
    const clashButton = document.getElementById('clashButton');

    // Show the loading spinner
    const spinner = document.getElementById('loading-spinner');
    spinner.style.display = 'block'; // Show the spinner

    // Create the request function to load profiles
    const requestFn = async (token) => {
        return fetch(`${API_URL}/load_profiles`, {
            method: 'POST',
            headers: createAuthorizedHeaders(token),
            body: JSON.stringify({ directory })
        });
    };

    makeRequestWithTokenRefresh(requestFn)
    .then(response => {
        if (!response.ok) {
            throw new Error('Failed to load profiles');
        }
        return response.json();
    })
    .then(data => {
        if (data.success) {
            console.log('Profiles loaded successfully:', data.total_profiles);

            populate_pagination_for_SMS_Profiles_Eligible_to_Import_into_Community();

            // Only download the CSV if the checkbox is checked
            if (downloadCsvChecked) {
                console.log('Downloading CSV file as checkbox is selected.');

                // Construct the CSV download URL
                const csvFilePath = encodeURIComponent(data.csv_file_path); // Encode the path for safety
                const downloadUrl = `${API_URL}/download_csv?file_path=${csvFilePath}`; // Use the returned CSV file path

                // Trigger download of the CSV file
                const csvRequestFn = async (token) => {
                    return fetch(downloadUrl, {
                        method: 'GET',
                        headers: createAuthorizedHeaders(token)
                    });
                };

                makeRequestWithTokenRefresh(csvRequestFn)
                .then(downloadResponse => {
                    if (!downloadResponse.ok) {
                        throw new Error('Failed to download CSV file');
                    }
                    return downloadResponse.blob(); // Get the file as a Blob
                })
                .then(blob => {
                    const downloadLink = document.createElement('a');
                    downloadLink.href = window.URL.createObjectURL(blob);
                    downloadLink.download = `${data.username}_profiles.csv`; // Set the download filename
                    document.body.appendChild(downloadLink);
                    downloadLink.click();
                    document.body.removeChild(downloadLink);
                    console.log('CSV file downloaded successfully');
                })
                .catch(error => {
                    console.error('Error downloading the CSV file:', error);
                });
            } else {
                console.log('CSV download skipped as checkbox is not selected.');
            }

            // Update the profile count table with counts for "With Phone", "Without Phone", and "Duplicates"
            document.getElementById('total-with-phone').textContent = data.counts["with_phone"];
            document.getElementById('total-without-phone').textContent = data.counts["without_phone"];
            document.getElementById('total-duplicate-emails-discarded').textContent = data.duplicate_emails; // New line for duplicates

            let total_zip_count, increased_count, initial_zip_count, percentage_increase;
            total_zip_count = data.counts["actual_location_data_from_ip_address"] + data.counts["number_zip_sourced_from_location"] + data.counts["number_zip_sourced_from_properties"];
            increased_count = data.counts["number_zip_sourced_from_properties_only_option"] + data.counts["actual_location_data_from_ip_address"];
            initial_zip_count = total_zip_count - increased_count

            if (initial_zip_count > 0) {
                percentage_increase = ((total_zip_count - initial_zip_count) / initial_zip_count) * 100;
                percentage_increase = percentage_increase.toFixed(2); // Format to two decimal places
            } else {
                percentage_increase = "0"; // Handle edge case
            }

            document.getElementById('total-zip-from-ip-address').textContent = data.counts["actual_location_data_from_ip_address"];
            document.getElementById('total-zip-from-location-attribute').textContent = data.counts["number_zip_sourced_from_location"];
            document.getElementById('total-zip-from-property-attribute').textContent = data.counts["number_zip_sourced_from_properties"];
            document.getElementById('total-zip').textContent = total_zip_count;
            document.getElementById('total-percentage-increased-zip').textContent = percentage_increase;
            document.getElementById('total-increased-zip').textContent = increased_count;


            // Calculate and update the grand total
            const grandTotal = data.counts["with_phone"] + data.counts["without_phone"] + data.duplicate_emails;
            document.getElementById('grand-total').textContent = grandTotal;

            // Extract the timestamp from selectedFileLocation and format it
            const timestampRegex = /(\d{4})(\d{2})(\d{2})_(\d{2})(\d{2})(\d{2})/;
            const match = directory.match(timestampRegex);

            if (match) {
                const formattedTime = `${match[1]}-${match[2]}-${match[3]} ${match[4]}:${match[5]}:${match[6]}`;
                const tableTitle = `Profiles discovered at ${formattedTime}`;

                // Set the table title
                const tableTitleElement = document.getElementById('profile-table-title');
                tableTitleElement.textContent = tableTitle;
            }
            createStagingFiles()
            // Enable the button after successful profile load
            clashButton.style.display = 'inline-block'; // Show the button
            clashButton.disabled = false;        // Enable the button
        } else {
            throw new Error(data.msg);
        }
    })
    .catch(error => {
        console.error('Error loading profiles:', error);
    })
    .finally(() => {
        // Hide the loading spinner after the request is complete
        spinner.style.display = 'none'; // Hide the spinner
    });
}

async function populate_pagination_for_SMS_Profiles_Eligible_to_Import_into_Community() {
    console.log('Populate pagination for SMS Profiles Eligible to Import into Community');
    const accessToken = localStorage.getItem('access_token');

    if (!accessToken) {
        console.info('No access token available');
        alert('No access token available. Please login first.');
        return;
    }

    // Define request function to fetch import status
    const requestFn = async (token) => {
        console.info('Creating fetch request to get import status.');
        return fetch(`${API_URL}/import_status`, {
            method: 'GET',
            headers: createAuthorizedHeaders(token)
        });
    };

    try {
        const response = await makeRequestWithTokenRefresh(requestFn);

        if (!response.ok) {
            throw new Error('Failed to fetch import status');
        }

        const data = await response.json();

        // Extract total profiles and number of chunks
        const totalProfiles = data.total_profiles || 0;
        const numberOfChunks = data.number_of_chunks || 1;
        const resultsPerPage = 1000; // Fixed at 1000 results per page
        let currentPage = 1; // Initialize current page

        if (numberOfChunks < 1) {
            console.info('No chunks available for pagination.');
            return;
        }

        // Clear existing pagination
        const paginationContainer = document.getElementById('sms-profiles-eligible-to-import-into-community-pagination-container');
        paginationContainer.innerHTML = '';

        // Create Previous button
        const prevButton = document.createElement('button');
        prevButton.textContent = '‹ Back';
        prevButton.disabled = currentPage === 1;
        prevButton.onclick = () => changePage(currentPage - 1);
        paginationContainer.appendChild(prevButton);

        // Page numbers container
        const pageNumbersContainer = document.createElement('div');
        paginationContainer.appendChild(pageNumbersContainer);

        // Function to change page
        function changePage(page) {
            if (page < 1 || page > numberOfChunks) return;
            currentPage = page;
            updatePagination();
            loadChunk(currentPage); // Load data for the selected page
        }

        // Create pagination buttons
        function updatePagination() {
            pageNumbersContainer.innerHTML = ''; // Clear page numbers

            // Display up to 7 page numbers at a time
            const maxPageButtons = 7;
            let startPage = Math.max(1, currentPage - Math.floor(maxPageButtons / 2));
            let endPage = Math.min(numberOfChunks, startPage + maxPageButtons - 1);

            if (endPage - startPage < maxPageButtons - 1) {
                startPage = Math.max(1, endPage - maxPageButtons + 1);
            }

            for (let i = startPage; i <= endPage; i++) {
                const pageButton = document.createElement('button');
                pageButton.textContent = i;
                pageButton.className = 'pagination-button';
                if (i === currentPage) {
                    pageButton.classList.add('active'); // Highlight active page in black
                }
                pageButton.onclick = () => changePage(i);
                pageNumbersContainer.appendChild(pageButton);
            }

            // Update Previous and Next button states
            prevButton.disabled = currentPage === 1;
            nextButton.disabled = currentPage === numberOfChunks;

            // Display result range
            const startResult = (currentPage - 1) * resultsPerPage + 1;
            const endResult = Math.min(currentPage * resultsPerPage, totalProfiles);
            resultsInfo.textContent = `${startResult}-${endResult} of ${totalProfiles}`;
        }

        // Create Next button
        const nextButton = document.createElement('button');
        nextButton.textContent = 'Next ›';
        nextButton.disabled = currentPage === numberOfChunks;
        nextButton.onclick = () => changePage(currentPage + 1);
        paginationContainer.appendChild(nextButton);

        // Results info (e.g., "1-1000 of 1250")
        const resultsInfo = document.createElement('div');
        resultsInfo.classList.add('results-info');
        paginationContainer.appendChild(resultsInfo);

        // Initialize pagination display
        updatePagination();

        console.log('Pagination buttons created successfully');
    } catch (error) {
        console.info('Error populating pagination for SMS Profiles Eligible to Import into Community:', error);
        alert('Failed to populate pagination.');
    }
}

