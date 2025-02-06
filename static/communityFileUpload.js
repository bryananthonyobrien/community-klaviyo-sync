import { makeRequestWithTokenRefresh } from '/static/helpers.js';
import { API_URL } from '/static/helpers.js';
import { createAuthorizedHeaders } from '/static/helpers.js';
import { createStagingFiles } from '/static/staging.js';
import { getUsernameFromJWT } from '/static/scripts.js';

let selectedCommunityRowData = null; // Variable to store selected community row details
let selectedMemberRowData = {};

// Function to handle community row selection and syncing to Klaviyo
export function enableCommunityRowSelection() {
    const syncButton = document.getElementById('sync-communities-to-klaviyo-button');
    const viewButton = document.getElementById('view-communities-button');
    const communitiesTableBody = document.getElementById('communities-count-table').querySelector('tbody');

    // Helper function to disable a button
    function disableButton(button) {
        button.disabled = true;
        button.style.backgroundColor = 'grey';
        button.style.cursor = 'not-allowed';
    }

    // Helper function to enable a button
    function enableButton(button) {
        button.disabled = false;
        button.style.backgroundColor = '';
        button.style.cursor = 'pointer';
    }

    // Initially disable both buttons
    if (syncButton) disableButton(syncButton);
    if (viewButton) disableButton(viewButton);

    // Add event listener for row selection in the Communities table
    communitiesTableBody.addEventListener('click', (event) => {
        const row = event.target.closest('tr');
        if (row) {
            // Remove 'selected' class from any previously selected row
            communitiesTableBody.querySelectorAll('tr').forEach(r => r.classList.remove('selected'));

            // Add 'selected' class to the clicked row to highlight it
            row.classList.add('selected');

            // Capture the row details
            const cells = row.querySelectorAll('td');
            selectedCommunityRowData = {
                id: cells[0].innerText,
                name: cells[1].innerText,
                count: cells[2].innerText
            };

            // Enable buttons after row selection
            if (syncButton) enableButton(syncButton);
            if (viewButton) enableButton(viewButton);

            console.log('Selected Community Row Data:', selectedCommunityRowData);
        }
    });

    // Add click event to "Sync to Klaviyo" button once
    if (syncButton) {
        syncButton.addEventListener('click', () => {
            if (selectedCommunityRowData) {
                createCommunityList({ name: selectedCommunityRowData.name });
            }
        });
    }

    // Add click event to "View" button once
    if (viewButton) {
        viewButton.addEventListener('click', () => {
            if (selectedCommunityRowData) {
                alert(`TODO: View "${selectedCommunityRowData.name}"`);
            }
        });
    }
}

// Function to create a new community list in Klaviyo
async function createCommunityList(options = {}) {
    const syncButton = document.getElementById('sync-communities-to-klaviyo-button');
    const spinner = document.getElementById('loading-spinner'); // Assume there’s a spinner element for loading

    console.log(`Attempting to create community list with name: ${options.name}`);

    // Disable sync button and show the spinner
    syncButton.classList.add('busy-button');
    syncButton.disabled = true;
    spinner.style.display = 'block';

    try {
        const requestFn = async (token) => {
            const requestOptions = {
                method: 'POST',
                headers: createAuthorizedHeaders(token),
                body: JSON.stringify({
                    data: {
                        type: "list",
                        attributes: {
                            name: options.name
                        }
                    }
                })
            };
            return fetch('/create_community_list', requestOptions);
        };

        // Execute the request with token refresh logic
        const response = await makeRequestWithTokenRefresh(requestFn);

        if (response && response.ok) {
            const data = await response.json();
            console.log('Community list created successfully:', data);
            alert(`Community list "${options.name}" created successfully!`);
        } else if (response && response.status === 409) {
            // Handle 409 Conflict: List already exists
            const data = await response.json();
            console.log('Community list ${options.name} already exists:', data);
            alert(`Community list "${options.name}" already exists.`);
        } else if (response && response.status === 402) {
            const errorData = await response.json();
            logError('Insufficient credits', errorData);
            alert('Insufficient credits to create a community list');
        } else if (response && response.status === 429) {
            const responseData = await response.json();
            if (responseData.detail) {
                console.warn(`API call returned busy status: ${responseData.detail}`);
                alert(responseData.detail);
            } else {
                const retryAfter = response.headers.get('Retry-After') || 60;
                console.warn(`Rate limit exceeded. Retry after ${retryAfter} seconds.`);
                alert(`Rate limit exceeded. Retry after ${retryAfter} seconds.`);
                setTimeout(() => createCommunityList(options), retryAfter * 1000); // Retry after specified time
            }
        } else if (response && response.status === 403) {
            const data = await response.json();
            logError('User is suspended', data.msg);
            alert('User is suspended and cannot create a community list');
        } else {
            logError('Failed to create community list', await response.json());
            alert('Failed to create community list');
        }
    } catch (error) {
        logError('Error creating community list', error);
        alert('Error creating community list');
    } finally {
        // Hide the spinner and re-enable the button
        spinner.style.display = 'none';
        syncButton.classList.remove('busy-button');
        syncButton.disabled = false;
    }
}

export async function fetchMembersData() {
    const accessToken = localStorage.getItem('access_token');
    const addCommunityMemberToKlayvioListButton = document.getElementById('add-community-member-to-klaviyo-list-button');
    const unloadMembersButton = document.getElementById('flush-community-members-from-redis-button');
    const loadButton = document.getElementById('load-community-members-button');

    if (!accessToken) {
        console.error('No access token available');
        alert('No access token available. Please login first.');
        return;
    }

    // Define the request function to fetch member data
    const requestFn = async (token) => {
        return fetch(`${API_URL}/get_members_data`, {
            method: 'GET',
            headers: createAuthorizedHeaders(token),
        });
    };

    // Use the token refresh logic wrapped inside makeRequestWithTokenRefresh
    try {
        const response = await makeRequestWithTokenRefresh(requestFn);

        if (response && response.ok) {
            const data = await response.json();
            console.log('get_members_data returned :', data);

            if (data && typeof data === 'object' && data.members_total !== 'N/A') {
                // Update the members table with the data received
                updateMembersTable({
                    members_deleted: data.members_deleted,
                    members_live: data.members_live,
                    members_opt_out: data.members_opt_out,
                    members_total: data.members_total,
                    file_name: data.file_name
                });

                // Create and store data structures on the window object
                createWindowDataStructures(data.members_data);

                // Enable the View and Unload buttons if Redis key exists and data is loaded
                if (data.members_loaded_in_redis) {
                    console.log("fetchMembersData: Enable the View and Unload buttons");
                    addCommunityMemberToKlayvioListButton.disabled = false;
                    addCommunityMemberToKlayvioListButton.style.backgroundColor = ''; // Reset to default color
                    addCommunityMemberToKlayvioListButton.style.cursor = 'pointer';
                    unloadMembersButton.disabled = false;
                    unloadMembersButton.style.backgroundColor = '';
                    unloadMembersButton.style.cursor = 'pointer';
                } else {
                    console.log("fetchMembersData: Disable the View and Unload buttons");
                    addCommunityMemberToKlayvioListButton.disabled = true;
                    addCommunityMemberToKlayvioListButton.style.backgroundColor = 'grey';
                    addCommunityMemberToKlayvioListButton.style.cursor = 'not-allowed';
                    unloadMembersButton.disabled = true;
                    unloadMembersButton.style.backgroundColor = 'grey';
                    unloadMembersButton.style.cursor = 'not-allowed';
                }

                // Set the table title to show the file name
                document.getElementById('members-table-title').textContent = `Members in ${data.file_name} - Total: ${data.total_members}`;
                populateCommunityMemberViewTable(1000);
            } else {
                // Disable View and Unload buttons
                addCommunityMemberToKlayvioListButton.disabled = true;
                unloadMembersButton.disabled = true;
                addCommunityMemberToKlayvioListButton.style.backgroundColor = 'grey';
                unloadMembersButton.style.backgroundColor = 'grey';
                addCommunityMemberToKlayvioListButton.style.cursor = 'not-allowed';
                unloadMembersButton.style.cursor = 'not-allowed';

                console.log("No members data available.");
            }
        } else if (response && response.status === 401) {
            console.log('Unauthorized: Token information not found');
            alert('Session expired. Please log in again.');
        } else {
            const errorMsg = await response.text();
            console.log('Error fetching members data:', errorMsg);
            alert('Failed to fetch members data');
        }
    } catch (error) {
        console.log('Error in fetchMembersData:', error);
        alert('An error occurred while fetching members data');
    }
}

// Function to create or update window data structures based on members data
function createWindowDataStructures(membersData) {
    const membersById = {};
    const membersByName = {};

    Object.entries(membersData).forEach(([memberId, member]) => {
        // Store by member ID
        membersById[memberId] = member;

        // Store by member name (combination of first and last name)
        const fullName = `${member.FIRST_NAME} ${member.LAST_NAME}`;
        membersByName[fullName] = memberId;

    });

    // Store the organized data in the window object for future access
    window.membersData = {
        membersById,
        membersByName
    };

    console.log("Members data structures created in window.membersData:", window.membersData);
}

// Function to update the members table when a file is uploaded
function updateMembersTable(data) {
    const deleted = data.members_deleted || 0;
    const live = data.members_live || 0;
    const optOut = data.members_opt_out || 0;
    const total = data.members_total || (deleted + live + optOut);
    const file_name = data.file_name;

    document.getElementById('members-deleted').textContent = deleted;
    document.getElementById('members-live').textContent = live;
    document.getElementById('members-opt-out').textContent = optOut;
    document.getElementById('members-total').textContent = total;

    const tableTitleElement = document.getElementById('members-table-title');
    tableTitleElement.textContent = `Members in ${file_name} - Total: ${total}`;
}

  // Function to show the spinner near the Members button
function showSpinnerNearButton() {
      const membersButton = document.getElementById('load-community-members-button');
      const spinner = document.getElementById('community-file-upload-spinner');

      if (membersButton && spinner) {
          const buttonRect = membersButton.getBoundingClientRect();

          spinner.style.display = 'block';
          spinner.style.position = 'absolute';
          spinner.style.top = `${buttonRect.top + window.scrollY}px`;
          spinner.style.left = `${buttonRect.left + window.scrollX}px`;
          console.log("Debug: Spinner shown at position", spinner.style.top, spinner.style.left);
      } else {
          console.error("Debug: Either the Members button or Spinner is not found.");
      }
  }

  // Hide the spinner after file upload
function hideSpinner() {
      const spinner = document.getElementById('community-file-upload-spinner');
      if (spinner) {
          spinner.style.display = 'none';
          console.log("Debug: Spinner hidden.");
      }
  }

async function populateCommunityMemberViewTable(maxRows = null) {
    console.log("populateCommunityMemberViewTable");

    // Log the maxRows value if it is supplied
    if (maxRows) {
        console.log(`Rendering up to ${maxRows} rows.`);
    } else {
        console.log("Rendering all rows.");
    }

    const tableBody = document.getElementById('community-member-view-table-body');
    if (!tableBody) {
        console.log("Missing element: community-member-view-table-body");
        return;
    }

    const addCommunityMemberToKlayvioListButton = document.getElementById('add-community-member-to-klaviyo-list-button');
    if (!addCommunityMemberToKlayvioListButton) {
        console.log("Missing element: add-community-member-to-klaviyo-list-button");
        return;
    }

    // Disable the View button and show a loading cursor
    addCommunityMemberToKlayvioListButton.disabled = true;
    addCommunityMemberToKlayvioListButton.style.backgroundColor = 'grey';
    addCommunityMemberToKlayvioListButton.style.cursor = 'not-allowed';

    try {
        const response = await makeRequestWithTokenRefresh(async (token) => {
            return fetch(`${API_URL}/get_members_data`, {
                method: 'GET',
                headers: createAuthorizedHeaders(token),
            });
        });

        if (response.ok) {
            const responseData = await response.json();
            const members = responseData.members_data || {};

            // Clear existing rows in the table
            tableBody.innerHTML = '';

            // Use a single HTML string for all rows to improve performance
            let rowsHTML = '';
            const columns = [
                "MEMBER_ID", "LEADER_ID", "CHANNEL", "PHONE_NUMBER", "SUBSCRIPTION_STATE",
                "FIRST_NAME", "LAST_NAME", "EMAIL", "DATE_OF_BIRTH", "GENDER",
                "CITY", "ZIP_CODE", "STATE", "STATE_CODE", "COUNTRY", "COUNTRY_CODE",
                "DEVICE_TYPE", "FIRST_ACTIVATED_AT"
            ];

            // Convert members to an array and apply maxRows limit if specified
            const memberEntries = Object.values(members);
            const limitedMembers = maxRows ? memberEntries.slice(0, maxRows) : memberEntries;

            // Populate rowsHTML with table rows, limited by maxRows if provided
            limitedMembers.forEach(member => {
                if (member && typeof member === 'object') {
                    rowsHTML += '<tr>';
                    columns.forEach(col => {
                        rowsHTML += `<td>${member[col] || 'N/A'}</td>`; // Handle missing data
                    });
                    rowsHTML += '</tr>';
                } else {
                    console.warn("Skipped an invalid member entry:", member);
                }
            });

            // Insert all rows at once into the table body
            tableBody.innerHTML = rowsHTML;

            console.log("Community members loaded into the view table successfully.");
        } else {
            console.error('Failed to load community members:', response.statusText);
            alert("Failed to load community members. Please try again.");
        }
    } catch (error) {
        console.error('Error fetching community members:', error);
        alert("An error occurred while loading community members.");
    } finally {
        // Re-enable the View button
        addCommunityMemberToKlayvioListButton.disabled = false;
        addCommunityMemberToKlayvioListButton.style.backgroundColor = ''; // Reset color
        addCommunityMemberToKlayvioListButton.style.cursor = 'pointer';
        enableCommunityMemberRowSelection();
    }
}

export async function uploadCommunityMembersFile() {
    const fileInput = document.getElementById('community-file-input');
    const button = document.getElementById('load-community-members-button');
    const buttonText = document.getElementById('load-community-members-button-text');
    const spinner = document.getElementById('community-members-file-upload-spinner');
    const statusMessage = document.getElementById('upload-status-message');

    // References for View and Unload buttons
    const addCommunityMemberToKlayvioListButton = document.getElementById('add-community-member-to-klaviyo-list-button');
    const unloadMembersButton = document.getElementById('flush-community-members-from-redis-button');

    console.log('uploadCommunityMembersFile: Disable View and Unload buttons during loading');
    // Disable View and Unload buttons during loading
    addCommunityMemberToKlayvioListButton.disabled = true;
    unloadMembersButton.disabled = true;
    addCommunityMemberToKlayvioListButton.style.backgroundColor = 'grey';
    unloadMembersButton.style.backgroundColor = 'grey';
    addCommunityMemberToKlayvioListButton.style.cursor = 'not-allowed';
    unloadMembersButton.style.cursor = 'not-allowed';

    // Reset file input value to ensure onchange is triggered even if the same file is selected
    fileInput.value = '';

    fileInput.click();

    // Reattach the onchange listener every time the function is called
    fileInput.onchange = async () => {
        const file = fileInput.files[0];

        if (!file) {
            alert('No file selected. Please try again.');
            console.log("Debug: No file selected, exiting function.");
            return;
        }

        const filenamePattern = /^members\.\d{4}_\d{1,2}_\d{1,2}\.csv$/;
        if (!filenamePattern.test(file.name)) {
            alert('Invalid file format. Please upload a file named like members.2024_10_1.csv');
            console.log(`Debug: File name ${file.name} does not match pattern, exiting function.`);
            return;
        }

        // Show the spinner, disable button, and update text
        button.disabled = true;
        buttonText.textContent = "Loading";
        spinner.style.display = 'block';
        button.style.backgroundColor = '';

        // Set table values to "Computing..." while uploading
        document.getElementById('members-deleted').textContent = "Computing...";
        document.getElementById('members-live').textContent = "Computing...";
        document.getElementById('members-opt-out').textContent = "Computing...";
        document.getElementById('members-total').textContent = "Computing...";

        const formData = new FormData();
        formData.append('file', file);

        const username = getUsernameFromJWT();
        const directoryPath = `/home/bryananthonyobrien/mysite/data/community/members/${username}`;
        formData.append('directoryPath', directoryPath);

        try {
            console.log("Starting file upload ...", file.name);
            const response = await makeRequestWithTokenRefresh(async (token) => {
                return fetch(`${API_URL}/upload_community_members_file`, {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${token}`,
                    },
                    body: formData,
                });
            });

            const responseData = await response.json();
            console.log("upload_community_members_file returned:", responseData);

            if (response.ok) {
                // If upload is successful, process and store the members data
                if (statusMessage) {
                    statusMessage.textContent = "Upload complete.";
                    statusMessage.style.color = "green";
                }

                createStagingFiles()

                processAndStoreMembersData(responseData); // Update table with uploaded file data
                button.style.backgroundColor = '';

                // Enable "View" and "Unload" buttons upon successful upload
                console.log('uploadCommunityMembersFile: Enable "View" and "Unload" buttons upon successful upload');
                addCommunityMemberToKlayvioListButton.disabled = false;
                unloadMembersButton.disabled = false;
                addCommunityMemberToKlayvioListButton.style.backgroundColor = '';
                unloadMembersButton.style.backgroundColor = '';
                addCommunityMemberToKlayvioListButton.style.cursor = 'pointer';
                unloadMembersButton.style.cursor = 'pointer';
            } else {
                // If there's an error in the response, show an error message and set button color to red
                if (statusMessage) {
                    statusMessage.textContent = `Failed to upload file: ${responseData.msg}`;
                    statusMessage.style.color = "red";
                }
                button.style.backgroundColor = 'red';
                console.log(`Debug: File upload failed with message: ${responseData.msg}`);
            }
        } catch (error) {
            console.log('Error uploading file:', error);
            if (statusMessage) {
                statusMessage.textContent = "An error occurred while uploading the file.";
                statusMessage.style.color = "red";
            }
            button.style.backgroundColor = 'red';
        } finally {
            // Hide the spinner, enable button, and reset text
            spinner.style.display = 'none';
            button.disabled = false;
            buttonText.textContent = "Load";

            // Clear the status message after a few seconds
            if (statusMessage) {
                setTimeout(() => { statusMessage.textContent = ""; }, 5000);
            }
        }
    };
}

// Function to process and store members data
function processAndStoreMembersData(responseData) {
    const { members_data, file_name, total_members } = responseData;

    const membersById = {};
    const membersByName = {};

    // Process each member in the members_data
    Object.entries(members_data).forEach(([memberId, member]) => {
        // Store by member ID
        membersById[memberId] = {
            MEMBER_ID: member.MEMBER_ID,
            LEADER_ID: member.LEADER_ID,
            CHANNEL: member.CHANNEL,
            PHONE_NUMBER: member.PHONE_NUMBER,
            SUBSCRIPTION_STATE: member.SUBSCRIPTION_STATE,
            FIRST_NAME: member.FIRST_NAME,
            LAST_NAME: member.LAST_NAME,
            EMAIL: member.EMAIL,
            DATE_OF_BIRTH: member.DATE_OF_BIRTH,
            GENDER: member.GENDER,
            CITY: member.CITY,
            ZIP_CODE: member.ZIP_CODE,
            STATE: member.STATE,
            STATE_CODE: member.STATE_CODE,
            COUNTRY: member.COUNTRY,
            COUNTRY_CODE: member.COUNTRY_CODE,
            DEVICE_TYPE: member.DEVICE_TYPE,
            FIRST_ACTIVATED_AT: member.FIRST_ACTIVATED_AT,
        };

        // Store by member name (combination of first and last name)
        const fullName = `${member.FIRST_NAME} ${member.LAST_NAME}`;
        membersByName[fullName] = memberId;

    });

    // Store the organized data in the window object for future access
    window.membersData = {
        membersById,
        membersByName
    };


    // Update the UI with specific counts if needed
    updateMembersTable({
        members_deleted: responseData.members_deleted,
        members_live: responseData.members_live,
        members_opt_out: responseData.members_opt_out,
        members_total: total_members,
        file_name: responseData.file_name
    });

    console.log("Processed members data stored in window.membersData:", window.membersData);
}

function enableCommunityMemberRowSelection() {

    console.log('enableCommunityMemberRowSelection called');

    const addCommunityMemberToKlayvioListButton = document.getElementById('add-community-member-to-klaviyo-list-button');
    const syncCommunityMemberToKlaviyoButton = document.getElementById('sync-community-member-to-klaviyo-button');
    const membersTableBody = document.getElementById('community-member-view-table-body');

    // Helper functions to enable/disable buttons
    function disableButton(button) {
        if (button) {
            button.disabled = true;
            button.style.backgroundColor = 'grey';
            button.style.cursor = 'not-allowed';
        }
    }

    function enableButton(button) {
        if (button) {
            button.disabled = false;
            button.style.backgroundColor = '';
            button.style.cursor = 'pointer';
        }
    }

    // Initially disable both buttons
    disableButton(addCommunityMemberToKlayvioListButton);
    console.log('enableCommunityMemberRowSelection: Initially disable syncCommunityMemberToKlaviyoButton');
    disableButton(syncCommunityMemberToKlaviyoButton);

    // Clear existing event listeners by cloning each row
    const rows = Array.from(membersTableBody.querySelectorAll('tr'));
    rows.forEach((row) => {
        const newRow = row.cloneNode(true);  // Clone the row to remove all listeners
        membersTableBody.replaceChild(newRow, row); // Replace row with the clone
    });

    // Add click event listener to each row
    const updatedRows = membersTableBody.querySelectorAll('tr');
    updatedRows.forEach((row) => {
        row.addEventListener('click', () => {
            // Remove 'selected' class from any previously selected row
            updatedRows.forEach((r) => r.classList.remove('selected'));

            // Add 'selected' class to the clicked row
            row.classList.add('selected');

            // Capture the row details
            const cells = row.querySelectorAll('td');
            selectedMemberRowData = {
                memberId: cells[0]?.innerText || '',
                leaderId: cells[1]?.innerText || '',
                channel: cells[2]?.innerText || '',
                phoneNumber: cells[3]?.innerText || '',
                subscriptionState: cells[4]?.innerText || '',
                firstName: cells[5]?.innerText || '',
                lastName: cells[6]?.innerText || '',
                email: cells[7]?.innerText || '',
                dateOfBirth: cells[8]?.innerText || '',
                gender: cells[9]?.innerText || '',
                city: cells[10]?.innerText || '',
                zipCode: cells[11]?.innerText || '',
                state: cells[12]?.innerText || '',
                stateCode: cells[13]?.innerText || '',
                country: cells[14]?.innerText || '',
                countryCode: cells[15]?.innerText || '',
                deviceType: cells[16]?.innerText || '',
                firstActivatedAt: cells[17]?.innerText || '',
            };

            // Enable buttons after row selection
            enableButton(addCommunityMemberToKlayvioListButton);
            console.log('enableCommunityMemberRowSelection: Enable syncCommunityMemberToKlaviyoButton after row selection');
            enableButton(syncCommunityMemberToKlaviyoButton);

            console.log('Selected Member Row Data:', selectedMemberRowData);
        });
    });

    // Add click event to "View" button once, with a flag to prevent multiple listeners
    if (addCommunityMemberToKlayvioListButton && !addCommunityMemberToKlayvioListButton.hasEventListener) {
        addCommunityMemberToKlayvioListButton.addEventListener('click', () => {
            if (selectedMemberRowData) {
                alert(`Viewing details for member "${selectedMemberRowData.memberId}"`);
                // Implement your view logic here
            } else {
                alert('No member selected.');
            }
        });
        addCommunityMemberToKlayvioListButton.hasEventListener = true;  // Custom flag to avoid duplicate listeners
    }

    // Add click event to "Unload" button once, with a similar flag
    if (syncCommunityMemberToKlaviyoButton && !syncCommunityMemberToKlaviyoButton.hasEventListener) {
        syncCommunityMemberToKlaviyoButton.addEventListener('click', () => {
            if (selectedMemberRowData) {
                console.log(`Unloading data for member "${selectedMemberRowData.memberId}"`);
                // Implement your unload logic here
            } else {
                alert('No member selected.');
            }
        });
        syncCommunityMemberToKlaviyoButton.hasEventListener = true;  // Custom flag to avoid duplicate listeners
    }
}

function checkResponseDataType(responseData) {
    if (Array.isArray(responseData)) {
        console.log("responseData is an array");
    } else if (typeof responseData === 'object' && responseData !== null) {
        console.log("responseData is an object");
    } else {
        console.log("responseData is not an object or array");
    }
}

// Function to process memberships data
function processMembershipData(membershipsData) {
    const communitiesById = {};
    const communitiesByName = {};
    const memberCommunities = {};

    // Iterate over each community in the memberships data
    Object.entries(membershipsData).forEach(([communityId, community]) => {
        // Store by community ID
        communitiesById[communityId] = {
            COMMUNITY_NAME: community.COMMUNITY_NAME,
            members: community.members.map(member => member.MEMBER_ID),
        };

        // Store by community name
        communitiesByName[community.COMMUNITY_NAME] = communityId;

        // Map each member ID to the communities they belong to
        community.members.forEach(member => {
            const memberId = member.MEMBER_ID;
            if (!memberCommunities[memberId]) {
                memberCommunities[memberId] = [];
            }
            memberCommunities[memberId].push({
                COMMUNITY_NAME: community.COMMUNITY_NAME,
                communityId: communityId,
            });
        });
    });

    // Return all structures for later access
    return { communitiesById, communitiesByName, memberCommunities };
}

export async function repopulateCommunityTable() {
    const accessToken = localStorage.getItem('access_token');
    const communitiesTitleElement = document.getElementById('communities-table-title');
    const membershipsTitleElement = document.getElementById('community-membership-table-title');

    const unloadCommunitiesButton = document.getElementById('flush-communities-from-redis-button');
    const syncButton = document.getElementById('sync-communities-to-klaviyo-button');
    const viewButton = document.getElementById('view-communities-button');

    // Disable buttons for visual feedback during fetch
    if (viewButton) {
        viewButton.disabled = true;
        viewButton.style.backgroundColor = 'grey';
        viewButton.style.cursor = 'not-allowed';
    }
    if (syncButton) {
        syncButton.disabled = true;
        syncButton.style.backgroundColor = 'grey';
        syncButton.style.cursor = 'not-allowed';
    }

    if (!unloadCommunitiesButton) {
        console.error("unloadCommunitiesButton button is missing.");
        return;
    }

    // Check if table titles are loaded
    if (!communitiesTitleElement || !membershipsTitleElement) {
        console.log("Table titles not loaded; skipping data fetch.");
        return;
    }

    // Verify access token is available
    if (!accessToken) {
        console.error('No access token available');
        alert('No access token available. Please login first.');
        return;
    }

    // Function to make an authenticated request to fetch data
    const fetchData = async (dataType) => {
        return makeRequestWithTokenRefresh(async (token) => {
            const response = await fetch(`${API_URL}/get_community_data?data=${dataType}`, {
                method: 'GET',
                headers: createAuthorizedHeaders(token),
            });
            if (response.ok) {
                return response.json();
            } else {
                throw new Error(`Failed to fetch ${dataType} data`);
            }
        });
    };

    try {
        // Fetch communities data
        const communitiesResponse = await fetchData('communities');

        if (communitiesResponse && communitiesResponse.communities_data && communitiesResponse.communities_data.community_data) {
            const communitiesDataObject = communitiesResponse.communities_data.community_data;

            const communitiesDataArray = Object.values(communitiesDataObject).map(item => ({
                id: item.COMMUNITY_ID || 'N/A',
                name: item.COMMUNITY_NAME || 'Unnamed Community',
                count: item.MEMBER_COUNT || 0
            }));

            updateCommunitiesTable({
                file_name: communitiesResponse.communities_data.file_name,
                total_community_count: communitiesResponse.communities_data.total_community_count,
                communities_data: communitiesDataArray
            });

            communitiesTitleElement.textContent = `Communities in ${communitiesResponse.communities_data.file_name || 'Unknown File'} - Total: ${communitiesResponse.communities_data.total_community_count || 0}`;
            unloadCommunitiesButton.disabled = false;
            unloadCommunitiesButton.style.backgroundColor = '';
            unloadCommunitiesButton.style.cursor = 'pointer';
        } else {
            communitiesTitleElement.textContent = "No Communities Data Available";
        }
    } catch (error) {
        console.error("Error in repopulateCommunityTable (communities):", error);
        alert("An error occurred while fetching data.");
    }

    try {
        // Fetch memberships data
        const membershipsResponse = await fetchData('memberships');
        // console.log("Fetched memberships data:", JSON.stringify(membershipsResponse, null, 2));

        if (membershipsResponse && membershipsResponse.memberships_data && membershipsResponse.memberships_data.membership_data) {
            // Process and store membership data in the desired format
            const { communitiesById, communitiesByName, memberCommunities } = processMembershipData(membershipsResponse.memberships_data.membership_data);

            // Store processed data for future access
            window.membershipsData = { communitiesById, communitiesByName, memberCommunities };

            membershipsTitleElement.textContent = `Memberships in ${membershipsResponse.memberships_data.file_name || 'Unknown File'} - Total: ${membershipsResponse.memberships_data.total_membership_count || 0}`;
        } else {
            membershipsTitleElement.textContent = "No Memberships Data Available";
        }
    } catch (error) {
        console.error("Error in repopulateCommunityTable (memberships):", error);
        alert("An error occurred while fetching data.");
    }
}

function updateCommunitiesTable(responseData) {
    const communitiesCountTableBody = document.getElementById('communities-count-table').querySelector('tbody');

    // Build the new communities title part
    const communitiesTitle = `Communities in ${responseData.file_name || 'Unknown File'} - Total: ${responseData.total_community_count || 0}`;
    const communitiesTitleElement = document.getElementById('communities-table-title');

    if (communitiesTitleElement) {
        communitiesTitleElement.textContent = `${communitiesTitle}`;
    }

    // Clear existing rows in the table body
    communitiesCountTableBody.innerHTML = '';

    // Check if communities_data is an array; if so, convert it to an object
    let communitiesDataObject = {};
    if (Array.isArray(responseData.communities_data)) {
        communitiesDataObject = responseData.communities_data.reduce((acc, community) => {
            acc[community.id] = {
                COMMUNITY_ID: community.id || 'N/A',
                COMMUNITY_NAME: community.name || 'Unnamed Community',
                MEMBER_COUNT: community.count || 0
            };
            return acc;
        }, {});
    } else {
        // If it's already an object, use it as is
        communitiesDataObject = responseData.communities_data;
    }

    // Populate the table with the community data from the object
    const communityArray = Object.values(communitiesDataObject);
    if (communityArray.length > 0) {
        communityArray.forEach((community) => {
            const row = document.createElement('tr');

            const idCell = document.createElement('td');
            idCell.textContent = community.COMMUNITY_ID || 'N/A';

            const nameCell = document.createElement('td');
            nameCell.textContent = community.COMMUNITY_NAME || 'Unnamed Community';

            const countCell = document.createElement('td');
            countCell.textContent = community.MEMBER_COUNT || '0';

            row.appendChild(idCell);
            row.appendChild(nameCell);
            row.appendChild(countCell);

            communitiesCountTableBody.appendChild(row);
        });
    } else {
        // Display a message if no community data is available
        const row = document.createElement('tr');
        const noDataCell = document.createElement('td');
        noDataCell.colSpan = 3;
        noDataCell.textContent = 'No community data available';
        noDataCell.style.textAlign = 'center';
        row.appendChild(noDataCell);
        communitiesCountTableBody.appendChild(row);
    }
}

export async function uploadCommunityMembershipsFile() {
    const fileInput = document.createElement('input');
    fileInput.type = 'file';
    fileInput.accept = '.csv';
    const spinner = document.getElementById('community-memberships-file-upload-spinner');
    const buttonText = document.getElementById('load-community-memberships-button-text');
    const button = document.getElementById('load-community-memberships-button');

    fileInput.onchange = async () => {
        const file = fileInput.files[0];

        if (!file) {
            alert('No file selected. Please try again.');
            spinner.style.display = 'none';
            return;
        }

        const filenamePattern = /^member_communities\.\d{4}_\d{1,2}_\d{1,2}\.csv$/;
        if (!filenamePattern.test(file.name)) {
            alert('Invalid file format. Please upload a file named like member_communities.2024_11_1.csv');
            spinner.style.display = 'none';
            return;
        }

        const formData = new FormData();
        formData.append('file', file);

        const username = getUsernameFromJWT();
        if (!username) {
            alert("Error: Username not found in JWT.");
            spinner.style.display = 'none'; // Hide spinner if username is not found
            return;
        }

        const directoryPath = `/home/bryananthonyobrien/mysite/data/community/member_communities/${username}`;
        formData.append('directoryPath', directoryPath);

        button.disabled = true;
        buttonText.textContent = "Loading";
        spinner.style.display = 'block';
        button.style.backgroundColor = ''; // Reset background color in case of previous errors

        try {
            console.log("Uploading memberships file...");
            const response = await makeRequestWithTokenRefresh(async (token) => {
                return fetch(`${API_URL}/upload_memberships_file`, {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${token}`,
                    },
                    body: formData,
                });
            });

            const responseData = await response.json();

            if (response.ok) {
                console.log("Memberships file uploaded successfully:", responseData);
                alert(`File "${file.name}" uploaded successfully!`);

                // Log the full response data for detailed inspection
                // console.log("Full response data:", JSON.stringify(responseData, null, 2));
                    console.log("Full response data:");
                    checkResponseDataType(responseData);

                // Update the memberships title in the HTML
                const membershipsTitleElement = document.getElementById('community-membership-table-title');
                const membershipsTitle = `Memberships in ${responseData.file_name} - Total: ${responseData.total_membership_count}`;
                membershipsTitleElement.textContent = membershipsTitle;

            } else {
                alert(`Failed to upload file: ${responseData.msg}`);
                console.error("Upload error:", responseData.msg);
            }
        } catch (error) {
            console.error("Error during upload:", error);
            alert("An error occurred during the file upload.");
        } finally {
            spinner.style.display = 'none';
            button.disabled = false;
            buttonText.textContent = "Load";
            button.style.backgroundColor = '';
        }

    };

    fileInput.click();
}

export async function uploadCommunitysubCommunitiesFile() {
    const fileInput = document.getElementById('community-file-input');
    const button = document.getElementById('load-communities-button');
    const buttonText = document.getElementById('load-communities-button-text');
    const spinner = document.getElementById('community-communities-file-upload-spinner');
    const statusMessage = document.getElementById('upload-status-message');

    const viewButton = document.getElementById('view-communities-button');
    const unloadCommunitiesButton = document.getElementById('flush-communities-from-redis-button');

    viewButton.disabled = true;
    unloadCommunitiesButton.disabled = true;
    viewButton.style.backgroundColor = 'grey';
    unloadCommunitiesButton.style.backgroundColor = 'grey';
    viewButton.style.cursor = 'not-allowed';
    unloadCommunitiesButton.style.cursor = 'not-allowed';

    fileInput.value = '';
    fileInput.click();

    fileInput.onchange = async () => {
        const file = fileInput.files[0];

        if (!file) {
            alert('No file selected. Please try again.');
            console.log("Debug: No file selected, exiting function.");
            return;
        }

        const filenamePattern = /^communities\.\d{4}_\d{1,2}_\d{1,2}\.csv$/;
        if (!filenamePattern.test(file.name)) {
            alert('Invalid file format. Please upload a file named like communities.2024_10_1.csv');
            console.log(`Debug: File name ${file.name} does not match pattern, exiting function.`);
            return;
        }

        button.disabled = true;
        buttonText.textContent = "Loading";
        spinner.style.display = 'block';
        button.style.backgroundColor = '';

        const formData = new FormData();
        formData.append('file', file);

        const username = getUsernameFromJWT();
        const directoryPath = `/home/bryananthonyobrien/mysite/data/community/communities/${username}`;
        formData.append('directoryPath', directoryPath);

        try {
            console.log("Starting file upload ...", file.name);

            // Log the FormData payload
            console.log("FormData payload:");
            for (let [key, value] of formData.entries()) {
                console.log(`  ${key}: ${value}`);
            }  // <-- Added missing closing brace for the for loop here

            const response = await makeRequestWithTokenRefresh(async (token) => {
                return fetch(`${API_URL}/upload_community_communities_file`, {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${token}`,
                    },
                    body: formData,
                });
            });

            const responseData = await response.json();
            console.log("upload_community_communities_file returned:", responseData);

            if (response.ok) {
                if (statusMessage) {
                    statusMessage.textContent = "Upload complete.";
                    statusMessage.style.color = "green";
                }

                if (responseData.community_data) {
                    console.log(`uploadCommunitysubCommunitiesFile`);

                    // Transform `community_data` array into an object format for `updateCommunitiesTable`
                    const communitiesDataObject = responseData.community_data.reduce((acc, community) => {
                        acc[community.ID] = {
                            COMMUNITY_ID: community.ID,
                            COMMUNITY_NAME: community.Name,
                            MEMBER_COUNT: community.Count
                        };
                        return acc;
                    }, {});

                    // Create a formatted object that `updateCommunitiesTable` expects
                    const formattedData = {
                        file_name: responseData.file_name,
                        total_community_count: responseData.total_community_count,
                        communities_data: communitiesDataObject
                    };

                    // Update the table with the formatted data
                    updateCommunitiesTable(formattedData);
                } else {
                    console.warn("No community data in response to populate the table.");
                }

                button.style.backgroundColor = '';

                viewButton.disabled = false;
                unloadCommunitiesButton.disabled = false;
                viewButton.style.backgroundColor = '';
                unloadCommunitiesButton.style.backgroundColor = '';
                viewButton.style.cursor = 'pointer';
                unloadCommunitiesButton.style.cursor = 'pointer';
            } else {
                if (statusMessage) {
                    statusMessage.textContent = `Failed to upload file: ${responseData.msg}`;
                    statusMessage.style.color = "red";
                }
                button.style.backgroundColor = 'red';
                console.error(`Debug: File upload failed with message: ${responseData.msg}`);
            }
        } catch (error) {
            console.error('Error uploading file:', error);
            if (statusMessage) {
                statusMessage.textContent = "An error occurred while uploading the file.";
                statusMessage.style.color = "red";
            }
            button.style.backgroundColor = 'red';
        } finally {
            spinner.style.display = 'none';
            button.disabled = false;
            buttonText.textContent = "Load";
            button.style.backgroundColor = '';

            if (statusMessage) {
                setTimeout(() => { statusMessage.textContent = ""; }, 5000);
            }
        }
    };
}

export async function unloadCommunityMembersData() {
    const unloadMembersButton = document.getElementById('flush-community-members-from-redis-button');
    const addCommunityMemberToKlayvioListButton = document.getElementById('add-community-member-to-klaviyo-list-button');
    const loadButton = document.getElementById('load-community-members-button');

    // Disable all buttons during unloading
    unloadMembersButton.disabled = true;
    addCommunityMemberToKlayvioListButton.disabled = true;
    loadButton.disabled = true;

    unloadMembersButton.textContent = "Unloading...";
    unloadMembersButton.style.backgroundColor = 'grey';
    unloadMembersButton.style.cursor = 'not-allowed';
    addCommunityMemberToKlayvioListButton.style.backgroundColor = 'grey';
    addCommunityMemberToKlayvioListButton.style.cursor = 'not-allowed';
    loadButton.style.backgroundColor = 'grey';
    loadButton.style.cursor = 'not-allowed';

    try {
        console.log("unload_community_data");
        const response = await makeRequestWithTokenRefresh(async (token) => {
            return fetch(`${API_URL}/unload_community_data`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ data: "members" }) // Add "members" to the request body
            });
        });

        if (response.ok) {
            console.log("Community Members data unloaded successfully.");
            unloadMembersButton.disabled = true; // Keep Unload button disabled after successful unload
            unloadMembersButton.style.backgroundColor = 'grey';
            unloadMembersButton.textContent = "Unload";
        } else {
            const responseData = await response.json();
            console.log(`Failed to unload data: ${responseData.msg}`);
            unloadMembersButton.style.backgroundColor = 'red'; // Set button color to red on error
            unloadMembersButton.disabled = false; // Re-enable Unload button on error
            unloadMembersButton.textContent = "Try again";
        }
    } catch (error) {
        console.log("Error unloading community data:", error);
        unloadMembersButton.style.backgroundColor = 'red'; // Set button color to red on error
        unloadMembersButton.disabled = false;
        unloadMembersButton.textContent = "Try again";
    } finally {
        // Enable the Load button only after unloading completes
        loadButton.disabled = false;
        loadButton.style.backgroundColor = ''; // Reset to original color
        loadButton.style.cursor = 'pointer';
    }
}

async function unload_subCommunities_Data(dataType) {
    const unloadCommunitiesButton = document.getElementById('flush-communities-from-redis-button');
    const viewButton = document.getElementById('view-communities-button');
    const loadButton = document.getElementById('load-communities-button');

    // Disable all buttons during unloading
    unloadCommunitiesButton.disabled = true;
    viewButton.disabled = true;
    loadButton.disabled = true;

    unloadCommunitiesButton.textContent = "Unloading...";
    unloadCommunitiesButton.style.backgroundColor = 'grey';
    unloadCommunitiesButton.style.cursor = 'not-allowed';
    viewButton.style.backgroundColor = 'grey';
    viewButton.style.cursor = 'not-allowed';
    loadButton.style.backgroundColor = 'grey';
    loadButton.style.cursor = 'not-allowed';

    try {
        console.log(`Debug: Starting ${dataType} data unload...`);
        const response = await makeRequestWithTokenRefresh(async (token) => {
            return fetch(`${API_URL}/unload_community_data`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ data: dataType }) // Use dataType in request body
            });
        });

        if (response.ok) {
            console.log(`Debug: ${dataType} data unloaded successfully.`);
            unloadCommunitiesButton.disabled = true; // Keep Unload button disabled after successful unload
            unloadCommunitiesButton.style.backgroundColor = 'grey';
            unloadCommunitiesButton.textContent = "Unload";
        } else {
            const responseData = await response.json();
            console.log(`Debug: Failed to unload ${dataType} data: ${responseData.msg}`);
            unloadCommunitiesButton.style.backgroundColor = 'red'; // Set button color to red on error
            unloadCommunitiesButton.disabled = false; // Re-enable Unload button on error
            unloadCommunitiesButton.textContent = "Try again";
        }
    } catch (error) {
        console.log(`Error unloading ${dataType} data:`, error);
        unloadCommunitiesButton.style.backgroundColor = 'red'; // Set button color to red on error
        unloadCommunitiesButton.disabled = false;
        unloadCommunitiesButton.textContent = "Try again";
    } finally {
        // Enable the Load button only after unloading completes
        loadButton.disabled = false;
        loadButton.style.backgroundColor = ''; // Reset to original color
        loadButton.style.cursor = 'pointer';
    }
}

export async function unload_Community_subCommunities_and_Memberships_Data() {
    await unload_subCommunities_Data('memberships');
    await unload_subCommunities_Data('communities');
}


