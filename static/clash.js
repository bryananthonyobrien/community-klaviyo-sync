import { makeRequestWithTokenRefresh } from '/static/helpers.js';
import { showTab } from '/static/client.js';
import { triggerCommunityImport } from '/static/communityImport.js';
import { API_URL } from '/static/helpers.js';
import { createAuthorizedHeaders } from '/static/helpers.js';

let selectedPassedRowData = null; // Declare the variable at the top-level scope

export async function downloadMembersNotInKlaviyo() {
    const accessToken = localStorage.getItem('access_token');

    // Retrieve the stage2Path from local storage
    const stage2Path = localStorage.getItem('stage2Path');

    // Check if the path exists
    if (!stage2Path) {
        console.log("Failed to retrieve the file path for members not in Klayvio.");
        return;
    }

    // Show the loading spinner
    const spinner = document.getElementById('loading-spinner');
    if (spinner) {
        spinner.style.display = 'block'; // Show the spinner
    }

    // Construct the download URL
    const csvFilePath = encodeURIComponent(stage2Path); // Encode the path for safety
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
            downloadLink.download = 'members_not_in_klayvio.csv'; // Set the download filename
            document.body.appendChild(downloadLink);
            downloadLink.click();
            document.body.removeChild(downloadLink);
            console.log('Members Not in Klayvio CSV file downloaded successfully');
        } else {
            throw new Error('Failed to download the CSV file');
        }
    } catch (error) {
        console.error('Error downloading the CSV file:', error);
        alert('Error downloading the members not in Klayvio CSV file: ' + error.message);
    } finally {
        // Hide the loading spinner after the request is complete
        if (spinner) {
            spinner.style.display = 'none'; // Hide the spinner
        }
    }
}

export async function clashMembersProfiles() {
    const accessToken = localStorage.getItem('access_token');

    if (!accessToken) {
        console.error('No access token available');
        alert('No access token available. Please login first.');
        return;
    }

    // Show the spinner
    const spinner = document.getElementById('clash-loading-spinner');
    if (spinner) {
        spinner.style.display = 'block';  // Show the spinner
    } else {
        console.error('Spinner element not found.');
    }

    // Get the button element and disable it
    const clashButton = document.getElementById('clash-members-profiles-button');
    if (clashButton) {
        clashButton.classList.add('busy-button'); // Add busy-button class for grey color
        clashButton.disabled = true; // Disable the button
    }

    // Create a request function to clash members and profiles
    const requestFn = async (token) => {
        return fetch(`${API_URL}/clash_members_profiles`, {
            method: 'POST',
            headers: {
                ...createAuthorizedHeaders(token),
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ message: "test" }) // Sending a simple non-empty JSON object
        });
    };

    try {
        const response = await makeRequestWithTokenRefresh(requestFn);
        console.log("Response:", response);

        if (response && response.ok) {
            const data = await response.json();
            console.log("Response JSON:", data);

            // Ensure we have a success response
            if (data.success) {
                const counts = data.counts;
                const metadata = data.metadata;

                // Save member IDs by state globally
                storeMemberIdsByState(data.member_ids_by_state);

                // Row 1: Matched Members
                document.getElementById('matched-live').textContent = counts.live;
                document.getElementById('matched-opted-out').textContent = counts.opted_out;
                document.getElementById('matched-deleted').textContent = "Unknown";
                document.getElementById('matched-total').textContent = counts.matched_members;

                // Row 2: Non-Matched Members
                document.getElementById('non-matched-live').textContent = counts.non_matched_live;
                document.getElementById('non-matched-opted-out').textContent = counts.non_matched_opted_out;
                document.getElementById('non-matched-deleted').textContent = "Unknown";
                document.getElementById('non-matched-total').textContent = counts.non_matched_members;

                // Row 3: Totals (Sum of matched and non-matched)
                const totalLive = counts.live + counts.non_matched_live;
                const totalOptedOut = counts.opted_out + counts.non_matched_opted_out;
                const totalDeleted = counts.deleted; // Only non-matched members can be deleted
                const grandTotal = counts.matched_members + counts.non_matched_members; // Fixed total calculation

                // Updating the totals in the table
                document.getElementById('total-live').textContent = totalLive;
                document.getElementById('total-opted-out').textContent = totalOptedOut;
                document.getElementById('total-deleted').textContent = totalDeleted;
                document.getElementById('grand-total-of-members').textContent = grandTotal; // Set the correct grand total

                // Update title with file name if available
                if (metadata && metadata.file_name) {
                    document.getElementById('members-clash-title').textContent = `Clashed Members (${metadata.file_name}) and Profiles`;
                }
            } else {
                console.error('Clash Members and Profiles request failed:', data);
                alert('Failed to clash members and profiles');
            }
        } else if (response && response.status === 401) {
            console.error('Unauthorized: Token information not found');
            alert('Session expired. Please log in again.');
        } else if (response && response.status === 422) {
            // Handle missing profiles or members data
            const data = await response.json();
            if (data.profiles_missing) {
                console.info('Profiles data is missing:', data);
                alert(data.msg); // Alert user about missing profiles
                showTab(3);
            } else if (data.members_missing) {
                console.info('Members data is missing:', data);
                alert(data.msg); // Alert user about missing members
                showTab(6); // Navigate to the "Load Community Data" tab directly
            } else {
                alert('Failed to clash members and profiles');
            }
        } else {
            const errorResponse = await response.json();
            console.error('Error fetching clash members and profiles:', errorResponse);
            alert('Failed to clash members and profiles');
        }
    } catch (error) {
        console.error('Error in clashMembersProfiles:', error);
        logError('Clash Members and Profiles', error); // Log the error for further analysis
    } finally {
        // Hide the spinner and re-enable the button when request is done
        if (spinner) {
            spinner.style.display = 'none'; // Hide spinner
        }
        if (clashButton) {
            clashButton.classList.remove('busy-button'); // Remove busy-button class
            clashButton.disabled = false; // Re-enable the button
        }
    }
}

document.addEventListener('DOMContentLoaded', () => {
    // Set up initial table configuration or styling if needed
    const clashTable = document.getElementById('members-clash-table');

    // Highlight cells on click without triggering data population
    clashTable.addEventListener('click', (event) => {
        const target = event.target;
        if (target.tagName === 'TD') {
            // Remove previous highlights
            document.querySelectorAll('#members-clash-table td').forEach(cell => cell.classList.remove('selected-cell'));
            target.classList.add('selected-cell');
        }
    });
});

// Function to toggle buttons based on row selection
function toggleClashedButtons(enable) {
    const addButton = document.getElementById('add-clashed-member-to-klaviyo-list-button');
    const syncButton = document.getElementById('sync-clashed-member-to-klaviyo-button');

    if (enable) {
        addButton.disabled = false;
        addButton.style.backgroundColor = '#4CAF50'; // Green background
        addButton.style.cursor = 'pointer';

        syncButton.disabled = false;
        syncButton.style.backgroundColor = '#4CAF50'; // Green background
        syncButton.style.cursor = 'pointer';
    } else {
        addButton.disabled = true;
        addButton.style.backgroundColor = 'grey';
        addButton.style.cursor = 'not-allowed';

        syncButton.disabled = true;
        syncButton.style.backgroundColor = 'grey';
        syncButton.style.cursor = 'not-allowed';
    }
}

// Add click event listeners to each row in the clashed-members-view-table
document.getElementById('clashed-members-view-table').addEventListener('click', function(event) {
    // Check if a row is clicked
    const target = event.target;
    if (target.tagName === 'TD') {
        // Highlight the selected row
        const selectedRow = target.parentNode;
        document.querySelectorAll('#clashed-members-view-table tr').forEach(row => {
            row.classList.remove('selected'); // Remove selection from all rows
        });
        selectedRow.classList.add('selected'); // Add selection to clicked row

        // Enable the buttons when a row is selected
        toggleClashedButtons(true);
    }
});

// Check if table is empty and disable buttons if true
function checkTableIsEmpty() {
    const tableBody = document.getElementById('clashed-members-view-table-body');
    const rows = tableBody.getElementsByTagName('tr');
    toggleClashedButtons(rows.length > 0);
}

// Run the checkTableIsEmpty function after populating the table
document.addEventListener('DOMContentLoaded', function() {
    checkTableIsEmpty(); // Run once when the page loads
});

// Disable buttons when no row is selected (outside click)
document.addEventListener('click', function(event) {
    const isClickInsideTable = document.getElementById('clashed-members-view-table').contains(event.target);
    if (!isClickInsideTable) {
        toggleClashedButtons(false); // Disable buttons if clicking outside the table
    }
});

document.querySelectorAll('#members-clash-table td').forEach(cell => {
    cell.addEventListener('click', async function () {
        // Clear any existing highlights on all cells
        document.querySelectorAll('#members-clash-table td').forEach(cell => {
            cell.style.backgroundColor = ''; // Reset cell background color
        });

        if (!window.memberIdsByState) {
            console.log("window.memberIdsByState missing. Attempting to trigger the Clash button.");

            const clashButton = document.getElementById('clash-members-profiles-button');
            if (clashButton) {
                clashButton.click(); // Simulate button click
                console.log("Clash Members and Profiles button clicked.");
            } else {
                console.log("Clash Members and Profiles button not found.");
            }
            return;
        }
        // Determine the selected row and column
        const row = cell.parentElement.rowIndex;
        const col = cell.cellIndex;

        // Show the progress pill container
        const progressContainer = document.getElementById('clash-members-progress-pill-container');
        const progressBar = document.getElementById('clash-members-progress-pill-bar');
        const progressText = document.getElementById('clash-members-progress-pill-text');

        if (progressContainer) {
            console.log("Show the progress pill");
            progressContainer.style.display = 'block'; // Show the progress pill
            progressBar.style.width = '0%'; // Reset progress bar width
            progressText.textContent = '0%'; // Reset progress text
        } else {
            console.log("Progress container is missing");
        }

        // Handle "Unknown" cells (Row 1 Column 3 and Row 2 Column 3)
        if ((row === 1 && col === 3) || (row === 2 && col === 3)) {
            cell.style.backgroundColor = 'grey'; // Highlight the cell with grey
            document.getElementById('clashed-members-view-table-body').innerHTML = ''; // Clear the lower table
            console.log("Unknown cell selected. Clearing table.");

            // Clear the dynamic table title
            const tableTitle = document.getElementById('dynamic-clashed-members-table-title');
            if (tableTitle) {
                tableTitle.textContent = 'No data to display';
            }

            // Hide progress pill for "Unknown" cells
            if (progressContainer) {
                progressContainer.style.display = 'none';
            }

            return; // Exit since "unknown" cells don't trigger any further actions
        }

        // Handle "Deleted" cell (Row 3, Column 3)
        if (row === 3 && col === 3) {
            const deletedMembers = window.memberIdsByState.deleted || []; // Get the "deleted" member IDs
            cell.style.backgroundColor = '#b3d1ff'; // Highlight the cell in light blue

            if (deletedMembers.length > 0) {
                await populateClashedMembersViewTableWithProgress(deletedMembers, progressContainer, progressBar, progressText); // Populate the lower table with progress

                // Update the dynamic table title
                const tableTitle = document.getElementById('dynamic-clashed-members-table-title');
                if (tableTitle) {
                    tableTitle.textContent = "Deleted Members (All)";
                }
            } else {
                // If no deleted members exist, clear the table and show a message
                document.getElementById('clashed-members-view-table-body').innerHTML = ''; // Clear the lower table
                const tableTitle = document.getElementById('dynamic-clashed-members-table-title');
                if (tableTitle) {
                    tableTitle.textContent = 'No Deleted Members';
                }
                console.log("No deleted members found.");
            }

            // Hide progress pill after handling
            if (progressContainer) {
                progressContainer.style.display = 'none';
                console.log("Hide progress pill after handling");
            }

            return; // Exit since "Deleted" cells are now handled
        }

        // Highlight the selected cell
        cell.style.backgroundColor = '#b3d1ff'; // Light blue for active cells

        let memberIds = [];
        let titleText = '';

        // Logic for fetching memberIds based on row and column
        if (row === 1 && col === 4) {
            // Row 1 Total - combine live and optedOut
            memberIds = [...(window.memberIdsByState.live || []), ...(window.memberIdsByState.optedOut || [])];
            titleText = "Live and Opted-out Members Already In Klaviyo";
        } else if (row === 2 && col === 4) {
            // Row 2 Total - combine nonMatchedLive and nonMatchedOptedOut
            memberIds = [...(window.memberIdsByState.nonMatchedLive || []), ...(window.memberIdsByState.nonMatchedOptedOut || [])];
            titleText = "Live and Opted-out Members Not In Klaviyo";
        } else if (row === 3 && col === 1) {
            // Totals Row, Live Column - combine live and nonMatchedLive only
            memberIds = [...(window.memberIdsByState.live || []), ...(window.memberIdsByState.nonMatchedLive || [])];
            titleText = "All Live Members (Matched and Non-Matched)";
        } else if (row === 3 && col === 2) {
            // Totals Row, Opted-out Column - combine optedOut and nonMatchedOptedOut only
            memberIds = [...(window.memberIdsByState.optedOut || []), ...(window.memberIdsByState.nonMatchedOptedOut || [])];
            titleText = "All Opted-out Members (Matched and Non-Matched)";
        } else if (row === 3 && col === 4) {
            // Totals Row, Total Column - combine all members
            memberIds = [
                ...(window.memberIdsByState.live || []),
                ...(window.memberIdsByState.nonMatchedLive || []),
                ...(window.memberIdsByState.optedOut || []),
                ...(window.memberIdsByState.nonMatchedOptedOut || [])
            ];
            titleText = "All Members (Combined Total)";
        } else {
            // Specific Live/Opted-out for rows 1 or 2
            let key = '';
            if (col === 1) { // "Live" column
                key = row === 1 ? 'live' : 'nonMatchedLive';
            } else if (col === 2) { // "Opted-out" column
                key = row === 1 ? 'optedOut' : 'nonMatchedOptedOut';
            }

            if (window.memberIdsByState && window.memberIdsByState[key]) {
                memberIds = window.memberIdsByState[key];
                const statusText = row === 1 ? 'Already In Klaviyo' : 'Not In Klaviyo';
                const stateText = col === 1 ? 'Live' : 'Opted-out';
                titleText = `${stateText} Members ${statusText}`;
            } else {
                console.log("Key does not exist:", key);
                return;
            }
        }

        if (memberIds.length > 0) {
            await populateClashedMembersViewTableWithProgress(memberIds, progressContainer, progressBar, progressText);

            // Update the title dynamically
            const tableTitle = document.getElementById('dynamic-clashed-members-table-title');
            if (tableTitle) {
                tableTitle.textContent = titleText;
            }
        } else {
            console.log("No members found for this selection.");
        }
    });
});

async function populateClashedMembersViewTableWithProgress(memberIds, progressContainer, progressBar, progressText) {
    console.log("Populate the lower table with member data based on selected IDs");

    // Check if membersData and membersById exist
    if (!window.membersData || !window.membersData.membersById) {
        console.error("window.membersData or membersById is undefined. Cannot populate the table.");
        return; // Exit early to prevent further errors
    }

    const tableBody = document.getElementById('clashed-members-view-table-body');
    tableBody.innerHTML = ''; // Clear existing rows

    const totalItems = memberIds.length;
    const batchSize = 100; // Number of items to process before updating UI

    for (let index = 0; index < totalItems; index++) {
        const memberId = memberIds[index];
        const member = window.membersData.membersById[memberId];

        if (member) {
            const row = document.createElement('tr');
            const columns = [
                'MEMBER_ID', 'LEADER_ID', 'CHANNEL', 'PHONE_NUMBER', 'SUBSCRIPTION_STATE',
                'FIRST_NAME', 'LAST_NAME', 'EMAIL', 'DATE_OF_BIRTH', 'GENDER',
                'CITY', 'ZIP_CODE', 'STATE', 'STATE_CODE', 'COUNTRY',
                'COUNTRY_CODE', 'DEVICE_TYPE', 'FIRST_ACTIVATED_AT'
            ];

            columns.forEach(col => {
                const cell = document.createElement('td');
                cell.textContent = member[col] || 'N/A';
                row.appendChild(cell);
            });
            tableBody.appendChild(row);
        }

        // Update progress and yield control every batchSize items
        if ((index + 1) % batchSize === 0 || index + 1 === totalItems) {
            const progressPercent = Math.floor(((index + 1) / totalItems) * 100);
            if (progressBar && progressText) {
                progressBar.style.width = `${progressPercent}%`;
                progressText.textContent = `${progressPercent}%`;
            }

            // Allow UI to update
            await new Promise(resolve => setTimeout(resolve, 0));
        }
    }

    // Hide progress container when done
    if (progressContainer) {
        setTimeout(() => {
            progressContainer.style.display = 'none';
            console.log("Hide progress container when done");
        }, 500); // Slight delay for visibility
    }
}


function storeMemberIdsByState(data) {
    window.memberIdsByState = {
        live: data.live || [],
        nonMatchedLive: data.non_matched_live || [],
        optedOut: data.opted_out || [],
        nonMatchedOptedOut: data.non_matched_opted_out || [],
        deleted: data.deleted || []
    };

    // Always set these rows/columns to "Unknown"
    document.getElementById('matched-deleted').textContent = 'Unknown'; // Row 1, Column 3
    document.getElementById('non-matched-deleted').textContent = 'Unknown'; // Row 2, Column 3

    console.log("Member IDs by state stored in window.memberIdsByState:", window.memberIdsByState);
}

// Retrieve member IDs based on state and status, handle unknown for certain cases
function getMemberIdsByStateAndStatus(state, status) {
    let stateKey;

    if (state === "Live") {
        stateKey = status.includes("Not In Klaviyo") ? "nonMatchedLive" : "live";
    } else if (state === "Opted-out") {
        stateKey = status.includes("Not In Klaviyo") ? "nonMatchedOptedOut" : "optedOut";
    } else if (state === "Deleted") {
        stateKey = status.includes("Not In Klaviyo") ? "unknownNonMatched" : "unknownMatched"; // Handle unknown
    }

    return window.memberIdsByState[stateKey] || [];
}

  // Function to fetch profiles from the backend
  async function fetchFailedProfiles() {
    const csvFilePath = localStorage.getItem("stage1DroppedPath");
    if (!csvFilePath) {
      console.log("Failed to retrieve the file path for the failed profiles.");
      return;
    }

    const url = `/load_failed_profiles?file_path=${encodeURIComponent(csvFilePath)}`;

    try {
      const response = await fetch(url, {
        method: "GET",
        headers: {
          Authorization: `Bearer ${localStorage.getItem("access_token")}`,
        },
      });

      if (response.ok) {
        const data = await response.json();
        console.log("Profiles loaded:", data.profiles);
        window.profilesThatFailedQualityChecks = data.profiles;
      } else {
        const errorData = await response.json();
        console.log("Failed to load profiles:", errorData);
        alert("Error loading profiles: " + errorData.error);
      }
    } catch (error) {
      console.log("Error fetching failed profiles:", error);
      alert("Error fetching failed profiles: " + error.message);
    }
  }

  // Function to fetch profiles from the backend
  async function fetchPassedProfiles() {
    const csvFilePath = localStorage.getItem("stage1Path");
    if (!csvFilePath) {
      console.log("Failed to retrieve the file path for the failed profiles.");
      return;
    }

    const url = `/load_passed_profiles?file_path=${encodeURIComponent(csvFilePath)}`;

    try {
      const response = await fetch(url, {
        method: "GET",
        headers: {
          Authorization: `Bearer ${localStorage.getItem("access_token")}`,
        },
      });

      if (response.ok) {
        const data = await response.json();
        console.log("Profiles loaded:", data.profiles);
        window.profilesThatPassedQualityChecks = data.profiles;
      } else {
        const errorData = await response.json();
        console.log("Failed to load profiles:", errorData);
        alert("Error loading profiles: " + errorData.error);
      }
    } catch (error) {
      console.log("Error fetching failed profiles:", error);
      alert("Error fetching failed profiles: " + error.message);
    }
  }

document.addEventListener("DOMContentLoaded", async () => {
  const qualityCheckTable = document.getElementById("quality-check-table");
  const dynamicTableBody = document.getElementById("quality-checks-view-table-body");
  const dynamicTableTitle = document.getElementById("dynamic-quality-checks-table-title");

  const progressContainer = document.getElementById("quality-checks-progress-pill-container");
  const progressBar = document.getElementById("quality-checks-progress-pill-bar");
  const progressText = document.getElementById("quality-checks-progress-pill-text");

  const qualityCheckPassedQualityChecksTable = document.getElementById("passed-quality-check-table");
  const dynamicTablePassedQualityChecksBody = document.getElementById("quality-checks-passed-view-table-body");
  const dynamicTablePassedQualityChecksTitle = document.getElementById("dynamic-quality-checks-passed-table-title");

  const progressContainerPassedQualityChecks = document.getElementById("quality-checks-passed-progress-pill-container");
  const progressBarPassedQualityChecks = document.getElementById("quality-checks-passed-progress-pill-bar");
  const progressTextPassedQualityChecks = document.getElementById("quality-checks-passed-progress-pill-text");

  // Ensure profilesThatFailedQualityChecks is initialized
  if (!Array.isArray(window.profilesThatFailedQualityChecks)) {
    console.log("Fetching profiles that failed quality checks from server...");
    await fetchFailedProfiles();
    if (!Array.isArray(window.profilesThatFailedQualityChecks)) {
      window.profilesThatFailedQualityChecks = []; // Fallback to empty array if not defined
    }
  }

  // Add click listener for the Failed Quality Checks table
  if (qualityCheckTable) {
    qualityCheckTable.addEventListener("click", async (event) => {
      const clickedElement = event.target;

      // Ensure only `td` elements are clickable
      if (clickedElement.tagName === "TD") {
        // Remove existing highlights
        qualityCheckTable.querySelectorAll(".selected-cell").forEach((cell) => {
          cell.classList.remove("selected-cell");
        });

        // Highlight the clicked cell
        clickedElement.classList.add("selected-cell");

        // Determine the drop reason
        const cellIndex = clickedElement.cellIndex;
        const dropReasons = [
          "Invalid format",
          "Too short",
          "Too Long",
          "Older duplicate",
          "Invalid length for +1",
          "All"
        ];
        const dropReason = dropReasons[cellIndex] || "All";
        console.log(`Cell clicked: ${dropReason}`);

        // Show the progress pill
        if (progressContainer) {
          progressContainer.style.display = "block";
          progressBar.style.width = "0%";
          progressText.textContent = "0%";
        }

        // Filter profiles
        const filteredProfiles =
          dropReason === "All"
            ? window.profilesThatFailedQualityChecks
            : window.profilesThatFailedQualityChecks.filter(
                (profile) => profile["Drop Reason"] === dropReason
              );

        // Populate the dynamic table with progress
        await populateQualityChecksViewTableWithProgress(
          filteredProfiles,
          dynamicTableBody,
          progressContainer,
          progressBar,
          progressText,
          dynamicTableTitle,
          dropReason
        );
      }
    });
  }

  // Ensure profilesThatPassedQualityChecks is initialized
  if (!Array.isArray(window.profilesThatPassedQualityChecks)) {
    console.log("Fetching profiles that passed quality checks from the server...");
    await fetchPassedProfiles();
    if (!Array.isArray(window.profilesThatPassedQualityChecks)) {
      window.profilesThatPassedQualityChecks = []; // Fallback to empty array if not defined
    }
  }

  // Add click listener for the Passed Quality Checks table
  if (qualityCheckPassedQualityChecksTable) {
    qualityCheckPassedQualityChecksTable.addEventListener("click", async (event) => {
      const clickedElement = event.target;

      // Ensure only `td` elements are clickable
      if (clickedElement.tagName === "TD") {
        // Remove existing highlights
        qualityCheckPassedQualityChecksTable.querySelectorAll(".selected-cell").forEach((cell) => {
          cell.classList.remove("selected-cell");
        });

        // Highlight the clicked cell
        clickedElement.classList.add("selected-cell");

        // Determine the channel
        const cellIndex = clickedElement.cellIndex;
        const channels = [
          "SMS",
          "WhatsApp",
          "All"
        ];
        const channel = channels[cellIndex] || "All";
        console.log(`Cell clicked: ${channel}`);

        // Show the progress pill
        if (progressContainerPassedQualityChecks) {
          progressContainerPassedQualityChecks.style.display = "block";
          progressBarPassedQualityChecks.style.width = "0%";
          progressTextPassedQualityChecks.textContent = "0%";
        }

        // Filter profiles
        const filteredProfiles =
          channel === "All"
            ? window.profilesThatPassedQualityChecks
            : window.profilesThatPassedQualityChecks.filter(
                (profile) => profile["Channel"] === channel
              );

        // Populate the dynamic table with progress
        await populateQualityChecksPassedViewTableWithProgress(
          filteredProfiles,
          dynamicTablePassedQualityChecksBody,
          progressContainerPassedQualityChecks,
          progressBarPassedQualityChecks,
          progressTextPassedQualityChecks,
          dynamicTablePassedQualityChecksTitle,
          channel
        );
      }
    });
  }
});


// Function to populate the table with progress
async function populateQualityChecksViewTableWithProgress(
  profiles,
  tableBody,
  progressContainer,
  progressBar,
  progressText,
  tableTitle,
  dropReason
) {
  tableBody.innerHTML = ""; // Clear existing rows

  const totalItems = profiles.length;
  const batchSize = Math.max(1, Math.floor(totalItems / 10)); // Dynamically set batchSize

  if (totalItems === 0) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.textContent = "No profiles found for this drop reason";
    cell.colSpan = 13; // Update to match column count
    row.appendChild(cell);
    tableBody.appendChild(row);

    if (tableTitle) {
      tableTitle.textContent = `No Profiles Found for Drop Reason: ${dropReason}`;
    }
    if (progressContainer) {
      progressContainer.style.display = "none";
    }
    return;
  }

  for (let index = 0; index < totalItems; index++) {
    const profile = profiles[index];
    const row = document.createElement("tr");
    [
      "First Name",
      "Last Name",
      "Email",
      "Phone Number",
      "Birthday",
      "Gender",
      "City",
      "Region",
      "Zip",
      "Country",
      "Longitude",
      "Latitude",
      "Drop Reason"
    ].forEach((key) => {
      const cell = document.createElement("td");
      cell.textContent = profile[key] || "";
      row.appendChild(cell);
    });
    tableBody.appendChild(row);

    // Update progress every batch
    if ((index + 1) % batchSize === 0 || index + 1 === totalItems) {
      const progressPercent = Math.floor(((index + 1) / totalItems) * 100);
      if (progressBar && progressText) {
        progressBar.style.width = `${progressPercent}%`;
        progressText.textContent = `${progressPercent}% Complete`;
      }

      // Allow UI updates
      await new Promise((resolve) => setTimeout(resolve, 0));
    }
  }

  // Update the dynamic table title
  if (tableTitle) {
    tableTitle.textContent = `Profiles with Drop Reason: ${dropReason}`;
  }

  // Hide progress pill when done
  if (progressContainer) {
    setTimeout(() => {
      progressContainer.style.display = "none";
      console.log("Hide progress container when done");
    }, 500); // Slight delay for visibility
  }
}

// Function to populate the table with progress
async function populateQualityChecksPassedViewTableWithProgress(
  profiles,
  tableBody,
  progressContainer,
  progressBar,
  progressText,
  tableTitle,
  channel
) {
  tableBody.innerHTML = ""; // Clear existing rows

  const totalItems = profiles.length;
  const batchSize = Math.max(1, Math.floor(totalItems / 10)); // Dynamically set batchSize

  if (totalItems === 0) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.textContent = "No profiles found for this drop reason";
    cell.colSpan = 13; // Update to match column count
    row.appendChild(cell);
    tableBody.appendChild(row);

    if (tableTitle) {
      tableTitle.textContent = `No Profiles Found for Channel: ${channel}`;
    }
    if (progressContainer) {
      progressContainer.style.display = "none";
    }
    return;
  }

  for (let index = 0; index < totalItems; index++) {
    const profile = profiles[index];
    const row = document.createElement("tr");
    [
      "First Name",
      "Last Name",
      "Email",
      "Phone Number",
      "Birthday",
      "Gender",
      "City",
      "Region",
      "Zip",
      "Country",
      "Longitude",
      "Latitude",
      "Channel",
      "Created",
      "Updated",
      "Last Event",
      "IP Address",
    ].forEach((key) => {
      const cell = document.createElement("td");
      cell.textContent = profile[key] || "";
      row.appendChild(cell);
    });
    tableBody.appendChild(row);

    // Update progress every batch
    if ((index + 1) % batchSize === 0 || index + 1 === totalItems) {
      const progressPercent = Math.floor(((index + 1) / totalItems) * 100);
      if (progressBar && progressText) {
        progressBar.style.width = `${progressPercent}%`;
        progressText.textContent = `${progressPercent}% Complete`;
      }

      // Allow UI updates
      await new Promise((resolve) => setTimeout(resolve, 0));
    }
  }

  // Update the dynamic table title
  if (tableTitle) {
    tableTitle.textContent = `Profiles with Channel: ${channel}`;
  }

  // Hide progress pill when done
  if (progressContainer) {
    setTimeout(() => {
      progressContainer.style.display = "none";
      console.log("Hide progress container when done");
    }, 500); // Slight delay for visibility
  }
  enableQualityChecksPassedRowSelection()
}

function enableQualityChecksPassedRowSelection() {
    console.log("enableQualityChecksPassedRowSelection called");

    const syncPassedProfileButton = document.getElementById(
        "sync-klaviyo-profile-to-community-from-passed-quality-view-table-button"
    );
    const passedTableBody = document.getElementById(
        "quality-checks-passed-view-table-body"
    );

    // Helper functions to enable/disable buttons
    function disableButton(button) {
        if (button) {
            button.disabled = true;
            button.style.backgroundColor = "grey";
            button.style.cursor = "not-allowed";
        }
    }

    function enableButton(button) {
        if (button) {
            button.disabled = false;
            button.style.backgroundColor = "";
            button.style.cursor = "pointer";
        }
    }

    disableButton(syncPassedProfileButton);

    // Clear existing event listeners by cloning each row
    const rows = Array.from(passedTableBody.querySelectorAll("tr"));
    rows.forEach((row) => {
        const newRow = row.cloneNode(true); // Clone the row to remove all listeners
        passedTableBody.replaceChild(newRow, row); // Replace row with the clone
    });

    // Add click event listener to each row
    const updatedRows = passedTableBody.querySelectorAll("tr");
    updatedRows.forEach((row) => {
        row.addEventListener("click", () => {
            // Remove 'selected' class from any previously selected row
            updatedRows.forEach((r) => r.classList.remove("selected"));

            // Add 'selected' class to the clicked row
            row.classList.add("selected");

            // Capture the row details
            const cells = row.querySelectorAll("td");
            selectedPassedRowData = {
                first_name: cells[0]?.innerText || "",
                last_name: cells[1]?.innerText || "",
                email: cells[2]?.innerText || "",
                phoneNumber: cells[3]?.innerText || "",
                phone_number: cells[3]?.innerText || "",
                birthday: cells[4]?.innerText || "",
                gender: cells[5]?.innerText || "",
                city: cells[6]?.innerText || "",
                state_name: cells[7]?.innerText || "",
                zip: cells[8]?.innerText || "",
                country_name: cells[9]?.innerText || "",
                longitude: cells[10]?.innerText || "",
                latitude: cells[11]?.innerText || "",
                channel: cells[12]?.innerText || "",
                created: cells[13]?.innerText || "",
                updated: cells[14]?.innerText || "",
                last_event_date: cells[15]?.innerText || "",
                ip: cells[16]?.innerText || "",
            };

            // Enable buttons after row selection
            enableButton(syncPassedProfileButton);

            console.log("Selected Passed Row Data:", selectedPassedRowData);
        });
    });

    // Add click event to "Sync" button once, with a similar flag
    if (syncPassedProfileButton && !syncPassedProfileButton.hasEventListener) {
        syncPassedProfileButton.addEventListener("click", async () => {
            if (selectedPassedRowData) {
                console.log(
                    `Syncing data for profile "${selectedPassedRowData.first_name} ${selectedPassedRowData.last_name}"`
                );
                try {
                    await triggerCommunityImport(selectedPassedRowData); // Ensure this function is async
                    console.log("Data synced successfully:", selectedPassedRowData);
                } catch (error) {
                    console.error("Error syncing data:", error);
                }
            } else {
                alert("No profile selected.");
            }
        });
        syncPassedProfileButton.hasEventListener = true; // Custom flag to avoid duplicate listeners
    }
}