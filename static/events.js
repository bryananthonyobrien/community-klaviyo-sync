import { makeRequestWithTokenRefresh } from '/static/helpers.js';
import { API_URL } from '/static/helpers.js';
import { createAuthorizedHeaders } from '/static/helpers.js';
import { getUsernameFromJWT } from '/static/scripts.js';

const SelectedMemberEvents = [];

document.addEventListener('DOMContentLoaded', () => {
    // Get the logout button and only proceed if it exists
    const logoutButton = document.getElementById('logout-button');
    if (logoutButton) {
        // Fetch and set the username on the logout button
        const username = getUsernameFromJWT();
        if (username) {
            logoutButton.textContent = `Logout ${username}`;
        }
    }

    // Get the fetch, clear, and load events buttons and only proceed if they exist
    const fetchEventsButton = document.getElementById('fetch-community-member-events-button');
    const clearEventsButton = document.getElementById('clear-community-member-events-button');
    const loadEventsButton = document.getElementById('load-community-member-events-from-filebutton');

    if (fetchEventsButton && clearEventsButton) {
        // Add click event listener for fetching community member events
        fetchEventsButton.addEventListener('click', async () => {
            const clientId = document.getElementById('community-client-id-input').value;

            if (!clientId) {
                alert('Please set the Community Client ID in the Configuration tab before fetching events.');
            } else {
                await loadClientEvents(clientId);
            }
        });

        // Add click event listener for clearing community member events
        clearEventsButton.addEventListener('click', async () => {
            const clientId = document.getElementById('community-client-id-input').value;

            if (!clientId) {
                alert('Please set the Community Client ID in the Configuration tab before clearing events.');
            } else {
                await clearClientEvents(clientId);
            }
        });
    }

    if (loadEventsButton) {
        // Add click event listener for loading events from the file
        loadEventsButton.addEventListener('click', async () => {
            const clientId = document.getElementById('community-client-id-input').value;

            if (!clientId) {
                alert('Please set the Community Client ID in the Configuration tab before loading events.');
            } else {
                await loadClientEventsFromFile(clientId);
            }
        });
    }
});

export async function clearClientEvents(client_id) {
    const fetchButton = document.getElementById('fetch-community-member-events-button');
    const clearButton = document.getElementById('clear-community-member-events-button');
    const loadButton = document.getElementById('load-community-member-events-from-filebutton');
    const spinner = document.getElementById('event-unload-spinner'); // Updated to use the spinner inside the Unload button
    const titleElement = document.getElementById('community-events-count');
    const metricsContainer = document.getElementById('community-events-memory-metrics');

    try {
        console.log(`Clearing events for client_id: ${client_id}...`);

        // Disable buttons and show the spinner inside the Unload button
        fetchButton.disabled = true;
        clearButton.disabled = true;
        loadButton.disabled = true;
        spinner.style.display = 'inline-block'; // Show the spinner in the button
        titleElement.textContent = "Clearing events...";

        // Make the API call to clear events
        const response = await makeRequestWithTokenRefresh(async (token) => {
            return fetch(`${API_URL}/clear_events/${client_id}`, {
                method: 'DELETE',
                headers: createAuthorizedHeaders(token),
            });
        });

        const data = await response.json();

        // Handle the response
        if (response.ok) {
            if (data.message === "No events found to clear") {
                console.log(`No events found for client_id ${client_id}.`);
                titleElement.textContent = "No events found.";
            } else {
                console.log(`Events for client_id ${client_id} cleared successfully.`);
                titleElement.textContent = "Events cleared successfully.";
            }

            // Clear the Community Events table in the UI
            document.getElementById("community-events-table-body").innerHTML = "";
            document.getElementById("community-events-count").textContent = "(0 unique, 0 duplicates)";
            metricsContainer.textContent = "Number of events: 0, Memory used: 0 bytes";
        } else {
            throw new Error(`Failed to clear events for client_id ${client_id}: ${data.error || response.statusText}`);
        }
    } catch (error) {
        console.error(`Error clearing events for client_id ${client_id}:`, error);
        alert(`Error clearing events for client_id ${client_id}.`);
        titleElement.textContent = "Error clearing events.";
    } finally {
        // Re-enable buttons and hide the spinner inside the Unload button
        fetchButton.disabled = false;
        clearButton.disabled = false;
        loadButton.disabled = false;
        spinner.style.display = 'none'; // Hide the spinner
    }
}

// Define a globally accessible object for events in the `window` namespace
window.communityEvents = {
    events: [], // Array to hold the events
};

export async function loadClientEvents(client_id) {
    const fetchButton = document.getElementById('fetch-community-member-events-button');
    const spinner = document.getElementById('event-fetch-spinner'); // Updated spinner ID
    const metricsContainer = document.getElementById('community-events-memory-metrics');
    const titleElement = document.getElementById("community-events-count");
    const clearButton = document.getElementById("clear-community-member-events-button");

    // Record the start time
    const startTime = Date.now();

    try {
        console.log(`Loading events for client_id: ${client_id}...`);

        // Disable the "Fetch" button and show the spinner
        fetchButton.disabled = true;
        spinner.style.display = 'inline-block'; // Show spinner inside the button
        titleElement.textContent = "Fetching events...";

        const response = await makeRequestWithTokenRefresh(async (token) => {
            return fetch(`${API_URL}/get_events/${client_id}`, {
                method: 'GET',
                headers: createAuthorizedHeaders(token),
            });
        });

        const data = await response.json();
        console.log("Response data:", data);

        // Check if the request was successful
        if (!response.ok) {
            throw new Error(`Failed to load events for client_id ${client_id}: ${data.error || response.statusText}`);
        }

        // Extract results from the response
        const results = data.results || {};

        // Member Events
        const memberEvents = results.member_events || {};
        const memberNumEvents = memberEvents.num_events || 0;
        const memberMemoryUsage = memberEvents.memory_usage_bytes || 0;

        // Inbound Messages
        const inboundMessages = results.inbound_messages || {};
        const inboundNumEvents = inboundMessages.num_events || 0;
        const inboundMemoryUsage = inboundMessages.memory_usage_bytes || 0;

        // Outbound Messages
        const outboundMessages = results.outbound_messages || {};
        const outboundNumEvents = outboundMessages.num_events || 0;
        const outboundMemoryUsage = outboundMessages.memory_usage_bytes || 0;

        // Calculate elapsed time
        const elapsedTime = ((Date.now() - startTime) / 1000).toFixed(2); // Time in seconds

        // Update the UI with metrics
        titleElement.textContent = `Loaded events in ${elapsedTime}s`;
        metricsContainer.innerHTML = `
            <div>Number of Member Events: ${memberNumEvents}, Memory used: ${memberMemoryUsage.toLocaleString()} bytes</div>
            <div>Number of Inbound Messages: ${inboundNumEvents}, Memory used: ${inboundMemoryUsage.toLocaleString()} bytes</div>
            <div>Number of Outbound Messages: ${outboundNumEvents}, Memory used: ${outboundMemoryUsage.toLocaleString()} bytes</div>
        `;

        // Log first event for each structure
        if (memberEvents.events && memberEvents.events.length > 0) {
            console.log("First Member Event:", memberEvents.events[0]);
        }
        if (inboundMessages.events && inboundMessages.events.length > 0) {
            console.log("First Inbound Message:", inboundMessages.events[0]);
        }
        if (outboundMessages.events && outboundMessages.events.length > 0) {
            console.log("First Outbound Message:", outboundMessages.events[0]);
        }

        // Populate the global data structures
        window.communityEvents = {
            events: memberEvents.events || [],
            inboundMessages: inboundMessages.events || [],
            outboundMessages: outboundMessages.events || [],
        };

        // Initialize the pagination system for the loaded events
        initializeCommunityMemberEventsPagination();

        console.log(`Events for client_id ${client_id} loaded successfully in ${elapsedTime}s.`);

        // Enable or disable the "Unload" button based on the number of events
        clearButton.disabled = memberNumEvents === 0 && inboundNumEvents === 0 && outboundNumEvents === 0;
    } catch (error) {
        console.error(`Error loading events for client_id ${client_id}:`, error);
        alert(`Error loading events for client_id ${client_id}.`);

        // Update the title to indicate an error occurred
        titleElement.textContent = "Error loading events.";

        // Disable the "Unload" button if an error occurs
        clearButton.disabled = true;
    } finally {
        // Re-enable the "Fetch" button and hide the spinner
        fetchButton.disabled = false;
        spinner.style.display = 'none';
    }
}

export function populateCommunityEventsTable() {
    // Locate the table element
    const table = document.getElementById('community-events-table');

    // Check if the table exists
    if (!table) {
        console.error('Table element not found: #community-events-table');
        return;
    }

    // Locate or create the table body
    let tableBody = document.getElementById('community-events-table-body');
    if (!tableBody) {
        console.warn('Table body not found: #community-events-table-body. Creating it now...');
        tableBody = document.createElement('tbody');
        tableBody.id = 'community-events-table-body';
        table.appendChild(tableBody); // Append the new tbody to the table
    }

    // Clear existing rows
    console.log('Clearing existing table rows...');
    tableBody.innerHTML = '';

    // Limit to the most recent 1000 events (or fewer if there are less)
    const limitedEvents = window.communityEvents.events.slice(0, 1000);

    // Define the fields for the table
    const fields = [
        'timestamp', 'type', 'active', 'communication_channel', 'communication_channel_id',
        'given_name', 'surname', 'email', 'date_of_birth', 'gender_identity',
        'postal_code', 'country_code', 'longitude', 'latitude', 'city',
        'state_or_province', 'state_or_province_abbreviation', 'country', 'client_id', 'id'
    ];

    // Populate the table with rows
    limitedEvents.forEach(event => {
        const row = document.createElement('tr');

        // Add data-member-id to the row
        if (event.data && event.data.object && event.data.object.id) {
            row.setAttribute('data-member-id', event.data.object.id);
        } else {
            console.warn('Skipping row. Event is missing a valid Member ID:', event);
            return; // Skip this event
        }

        // Populate cells for the row
        fields.forEach(field => {
            const cell = document.createElement('td');

            if (field === 'type') {
                const typeMapping = {
                    'member.created': 'created',
                    'member.deleted': 'deleted',
                    'member.updated': 'updated'
                };
                cell.textContent = typeMapping[event.type] || event.type || 'unknown';
            } else if (field === 'timestamp') {
                cell.textContent = event.data.object.timestamp || event.created || '';
            } else if (field === 'longitude' || field === 'latitude') {
                cell.textContent = event.data.object.geolocation
                    ? event.data.object.geolocation[field] || ''
                    : '';
            } else {
                cell.textContent = event.data.object[field] || '';
            }

            row.appendChild(cell);
        });

        tableBody.appendChild(row);
    });

    // Update row count and duplicate count next to the title
    const totalEvents = window.communityEvents.events.length;
    document.getElementById('community-events-count').textContent = `(${limitedEvents.length} shown, ${totalEvents - limitedEvents.length} hidden)`;

    // Set up row click handlers
    setupCommunityEventsRowClickHandlers();

    console.log('Table re-rendered successfully.');
}

// Store the current sort order for each column (true = ascending, false = descending)
const columnSortOrder = {};

export function handleColumnSort(columnKey) {
    if (!window.communityEvents || !window.communityEvents.events) {
        console.error("No events found to sort.");
        return;
    }

    // Determine the sort order: Toggle between ascending and descending
    const currentSortKey = window.communityEvents.sortKey;
    const isAscending = currentSortKey === columnKey && window.communityEvents.sortOrder === 'asc' ? false : true;

    window.communityEvents.sortKey = columnKey;
    window.communityEvents.sortOrder = isAscending ? 'asc' : 'desc';

    console.log(`Sorting by ${columnKey} in ${isAscending ? "ascending" : "descending"} order.`);

    // Perform the sorting
    window.communityEvents.events.sort((a, b) => {
        let valueA, valueB;

        if (columnKey === "type") {
            // Handle 'type' at the top level
            valueA = a.type;
            valueB = b.type;

            const typeMapping = {
                "member.created": "Created",
                "member.updated": "Updated",
                "member.deleted": "Deleted",
            };
            valueA = typeMapping[valueA] || null;
            valueB = typeMapping[valueB] || null;

            // Handle missing values
            const isValueAMissing = valueA === null || valueA === "";
            const isValueBMissing = valueB === null || valueB === "";
            if (isValueAMissing && isValueBMissing) return 0;
            if (isValueAMissing) return 1;
            if (isValueBMissing) return -1;
        } else if (columnKey === "latitude" || columnKey === "longitude") {
            // Handle latitude and longitude nested in geolocation
            valueA = a.data.object.geolocation ? a.data.object.geolocation[columnKey] : null;
            valueB = b.data.object.geolocation ? b.data.object.geolocation[columnKey] : null;

            // Handle missing values
            const isValueAMissing = valueA === null || valueA === undefined;
            const isValueBMissing = valueB === null || valueB === undefined;
            if (isValueAMissing && isValueBMissing) return 0;
            if (isValueAMissing) return 1;
            if (isValueBMissing) return -1;

            // Ensure numeric comparison
            valueA = parseFloat(valueA);
            valueB = parseFloat(valueB);
        } else if (columnKey === "active") {
            // Handle boolean values
            valueA = a.data.object[columnKey] ?? false;
            valueB = b.data.object[columnKey] ?? false;

            // Handle missing values (treated as `false`)
            const isValueAMissing = valueA === null || valueA === undefined;
            const isValueBMissing = valueB === null || valueB === undefined;
            if (isValueAMissing && isValueBMissing) return 0;
            if (isValueAMissing) return 1;
            if (isValueBMissing) return -1;

            // Compare boolean values (convert to numbers: false = 0, true = 1)
            return isAscending ? Number(valueA) - Number(valueB) : Number(valueB) - Number(valueA);
        } else {
            // Default case for other columns
            valueA = a.data.object[columnKey];
            valueB = b.data.object[columnKey];

            // Handle missing values
            const isValueAMissing = valueA === null || valueA === "" || valueA === undefined;
            const isValueBMissing = valueB === null || valueB === "" || valueB === undefined;
            if (isValueAMissing && isValueBMissing) return 0;
            if (isValueAMissing) return 1;
            if (isValueBMissing) return -1;
        }

        // Compare strings
        if (typeof valueA === "string" && typeof valueB === "string") {
            return isAscending ? valueA.localeCompare(valueB) : valueB.localeCompare(valueA);
        }

        // Compare numbers
        if (typeof valueA === "number" && typeof valueB === "number") {
            return isAscending ? valueA - valueB : valueB - valueA;
        }

        console.warn(`Cannot compare values: ${valueA} and ${valueB}`);
        return 0; // Default to no sorting if values are incomparable
    });

    // Log the first 10 events after sorting
    console.log("Sorted events after column sort:", window.communityEvents.events.slice(0, 10));

    // Reset to the first page and re-render pagination and table
    currentMemberEventPage = 1;
    createCommunityMemberEventsPagination(window.communityEvents.events);
}

export function sortGlobalEvents(columnKey, isAscending = true) {
    // Determine the global events structure
    const events = window.communityEvents.events;

    // Define a mapping of column keys to object paths
    const keyMap = {
        timestamp: (event) => new Date(event.data.object.timestamp || event.created),
        type: (event) => event.type,
        active: (event) => event.data.object.active,
        communication_channel: (event) => event.data.object.communication_channel,
        communication_channel_id: (event) => event.data.object.communication_channel_id,
        given_name: (event) => event.data.object.given_name,
        surname: (event) => event.data.object.surname,
        email: (event) => event.data.object.email,
        date_of_birth: (event) => event.data.object.date_of_birth,
        gender_identity: (event) => event.data.object.gender_identity,
        postal_code: (event) => event.data.object.postal_code,
        country_code: (event) => event.data.object.country_code,
        longitude: (event) => event.data.object.geolocation?.longitude || 0,
        latitude: (event) => event.data.object.geolocation?.latitude || 0,
        city: (event) => event.data.object.city,
        state_or_province: (event) => event.data.object.state_or_province,
        state_or_province_abbreviation: (event) => event.data.object.state_or_province_abbreviation,
        country: (event) => event.data.object.country,
        client_id: (event) => event.data.object.client_id,
        id: (event) => event.data.object.id
    };

    // Perform sorting
    events.sort((a, b) => {
        const valueA = keyMap[columnKey](a);
        const valueB = keyMap[columnKey](b);

        if (valueA < valueB) return isAscending ? -1 : 1;
        if (valueA > valueB) return isAscending ? 1 : -1;
        return 0;
    });

    // Repopulate the table with the sorted events
    populateCommunityEventsTable();
}

function enableRowSelection() {
    const rows = document.querySelectorAll('#community-events-table tbody tr');

    rows.forEach(row => {
        row.addEventListener('click', function () {
            // Remove 'selected' class from all rows
            rows.forEach(r => r.classList.remove('selected'));

            // Add 'selected' class to the clicked row
            row.classList.add('selected');

            // Get the Member ID from the clicked row
            const memberId = row.querySelector('[data-label="Member ID"]').textContent.trim();

            // Find all rows with the same Member ID
            const allEvents = Array.from(document.querySelectorAll('#community-events-table tbody tr'));
            SelectedMemberEvents.length = 0; // Clear previous data
            allEvents.forEach(eventRow => {
                const eventMemberId = eventRow.querySelector('[data-label="Member ID"]').textContent.trim();
                if (eventMemberId === memberId) {
                    const rowData = Array.from(eventRow.cells).map(cell => cell.textContent.trim());
                    SelectedMemberEvents.push(rowData);
                }
            });

            // Render the selected events into the new table
            renderSelectedMemberEventsTable();
        });
    });
}

function renderSelectedMemberEventsTable() {
    const selectedTableBody = document.getElementById('selected-member-events-table-body');
    const container = document.getElementById('selected-member-events-container');
    const spinner = container.querySelector('.table-spinner');

    spinner.style.display = 'flex'; // Show spinner
    setTimeout(() => {
        selectedTableBody.innerHTML = ''; // Clear the previous rows

        SelectedMemberEvents.forEach(event => {
            const row = document.createElement('tr');
            event.forEach(cellData => {
                const cell = document.createElement('td');
                cell.textContent = cellData;
                row.appendChild(cell);
            });
            selectedTableBody.appendChild(row);
        });

        spinner.style.display = 'none'; // Hide spinner after populating
    }, 50); // Add a slight delay to simulate spinner
}

export async function loadClientEventsFromFile() {
    const loadButton = document.getElementById('load-community-member-events-from-filebutton');
    const fetchButton = document.getElementById('fetch-community-member-events-button');
    const clearButton = document.getElementById('clear-community-member-events-button');
    const spinner = document.getElementById('event-loader-spinner');
    const metricsContainer = document.getElementById('community-events-memory-metrics');
    const titleElement = document.getElementById('community-events-count');

    console.log("Starting event loading from file...");

    // Record the start time
    const startTime = Date.now();

    // Disable buttons and show spinner inside the Load button
    loadButton.classList.add('busy-button');
    loadButton.disabled = true;
    fetchButton.disabled = true;
    clearButton.disabled = true;
    spinner.style.display = 'inline-block';

    // Reset the title text to avoid redundancy
    titleElement.textContent = " - Loading events...";

    try {
        const clientId = document.getElementById('community-client-id-input').value;

        if (!clientId) {
            alert('Please provide a valid Client ID to load events.');
            return;
        }

        const response = await makeRequestWithTokenRefresh(async (token) => {
            return fetch(`${API_URL}/load_all_events_from_files/${clientId}`, {
                method: 'POST',
                headers: createAuthorizedHeaders(token),
            });
        });

        const data = await response.json();

        if (response.ok) {
            console.log("Response data:", data);

            // Extract results from the JSON
            const results = data.results || {};

            // Extract values for `member_events`, `inbound_messages`, and `outbound_messages`
            const memberEvents = results.member_events || {};
            const inboundMessages = results.inbound_messages || {};
            const outboundMessages = results.outbound_messages || {};

            // Member Events
            const memberAdded = memberEvents.added_records || 0;
            const memberSkipped = memberEvents.skipped_records || 0;
            const memberMemory = memberEvents.memory_usage || 0;

            // Inbound Messages
            const inboundAdded = inboundMessages.added_records || 0;
            const inboundSkipped = inboundMessages.skipped_records || 0;
            const inboundMemory = inboundMessages.memory_usage || 0;

            // Outbound Messages
            const outboundAdded = outboundMessages.added_records || 0;
            const outboundSkipped = outboundMessages.skipped_records || 0;
            const outboundMemory = outboundMessages.memory_usage || 0;

            // Calculate elapsed time
            const elapsedTime = ((Date.now() - startTime) / 1000).toFixed(2); // Time in seconds

            // Update the title and metrics container
            titleElement.textContent = `- Loaded ${memberAdded} events in ${elapsedTime}s`;
            metricsContainer.innerHTML = `
                <div><strong>Number of Member Events:</strong> ${memberAdded}, <strong>Memory used:</strong> ${memberMemory.toLocaleString()} bytes</div>
                <div><strong>Number of Inbound Messages:</strong> ${inboundAdded}, <strong>Memory used:</strong> ${inboundMemory.toLocaleString()} bytes</div>
                <div><strong>Number of Outbound Messages:</strong> ${outboundAdded}, <strong>Memory used:</strong> ${outboundMemory.toLocaleString()} bytes</div>
            `;

            // Re-enable the Unload button because events have been loaded
            clearButton.disabled = false;
        } else {
            console.error("Failed to load events:", data.error || response.statusText);
            alert("Failed to load events from file.");
            titleElement.textContent = "Failed to load events.";
        }
    } catch (error) {
        console.error("Error during event loading:", error);
        alert("An error occurred while loading events.");
        titleElement.textContent = "Error during loading.";
    } finally {
        // Re-enable buttons and hide spinner
        loadButton.classList.remove('busy-button');
        loadButton.disabled = false;
        fetchButton.disabled = false;
        spinner.style.display = 'none';
    }
}

let currentMemberEventPage = 1; // Current page for community member events
const rowsPerMemberEventPage = 1000; // Number of rows per page for community member events

// Function to populate Selected Member Events Table
function populateSelectedMemberTable(memberId) {
    console.log(`Populating selected member events for Member ID: ${memberId}`);

    const tableBody = document.getElementById('selected-member-events-table-body');
    if (!tableBody) {
        console.error("Table body not found: #selected-member-events-table-body");
        return;
    }
    tableBody.innerHTML = ''; // Clear existing rows

    // Filter and sort events for the selected member
    const selectedEvents = window.communityEvents.events
        .filter(event => event.data.object.id === memberId)
        .sort((a, b) => new Date(a.data.object.timestamp) - new Date(b.data.object.timestamp));

    console.log(`Found ${selectedEvents.length} events for Member ID: ${memberId}`);

    selectedEvents.forEach(event => {
        const row = document.createElement('tr');
        const fields = [
            'timestamp', 'type', 'active', 'communication_channel', 'communication_channel_id',
            'given_name', 'surname', 'email', 'date_of_birth', 'gender_identity',
            'postal_code', 'country_code', 'longitude', 'latitude', 'city',
            'state_or_province', 'state_or_province_abbreviation', 'country', 'client_id', 'id'
        ];

        fields.forEach(field => {
            const cell = document.createElement('td');
            if (field === 'type') {
                const typeMapping = {
                    'member.created': 'Created',
                    'member.updated': 'Updated',
                    'member.deleted': 'Deleted'
                };
                cell.textContent = typeMapping[event.type] || 'Unknown';
            } else if (field === 'timestamp') {
                cell.textContent = event.data.object.timestamp || event.created || '';
            } else if (field === 'longitude' || field === 'latitude') {
                cell.textContent = event.data.object.geolocation
                    ? event.data.object.geolocation[field] || ''
                    : '';
            } else {
                cell.textContent = event.data.object[field] || '';
            }
            row.appendChild(cell);
        });

        tableBody.appendChild(row);
    });
}

// Function to populate Selected Member Message Events Table
function populateSelectedMemberMessageTable(memberId) {
    console.log(`Populating message events for Member ID: ${memberId}`);

    const tableBody = document.getElementById('selected-member-message-events-table-body');
    if (!tableBody) {
        console.error("Table body not found: #selected-member-message-events-table-body");
        return;
    }
    tableBody.innerHTML = ''; // Clear existing rows

    // Combine and sort inbound and outbound messages for the selected member
    const messages = [
        ...window.communityEvents.inboundMessages.map(message => ({
            ...message,
            direction: 'Inbound',
            messageType: '', // Leave blank for inbound messages
            campaignId: '' // Leave blank for inbound messages
        })),
        ...window.communityEvents.outboundMessages.map(message => ({
            ...message,
            direction: 'Outbound',
            messageType: message.data.object.outbound_message_type || '',
            campaignId: message.data.object.thread_id || ''
        }))
    ].filter(message => message.data.object.member.id === memberId)
     .sort((a, b) => new Date(a.data.object.timestamp) - new Date(b.data.object.timestamp));

    console.log(`Found ${messages.length} messages for Member ID: ${memberId}`);

    messages.forEach(message => {
        const row = document.createElement('tr');

        // Populate each row with relevant fields
        const fields = ['timestamp', 'direction', 'messageType', 'campaignId', 'text'];

        fields.forEach(field => {
            const cell = document.createElement('td');
            if (field === 'timestamp') {
                cell.textContent = message.data.object.timestamp || message.created || '';
            } else if (field === 'direction') {
                cell.textContent = message.direction;
            } else if (field === 'messageType') {
                cell.textContent = message.messageType;
            } else if (field === 'campaignId') {
                cell.textContent = message.campaignId;
            } else if (field === 'text') {
                cell.textContent = message.data.object.text || '';
            }
            row.appendChild(cell);
        });

        tableBody.appendChild(row);
    });
}


function setupCommunityEventsRowClickHandlers() {
    console.log("Attaching click handlers to table rows...");
    const tableBody = document.getElementById('community-events-table-body');
    if (!tableBody) {
        console.error("Table body not found: #community-events-table-body");
        return;
    }

    tableBody.querySelectorAll('tr').forEach(row => {
        const memberId = row.dataset.memberId; // Retrieve data-member-id
        if (!memberId) {
            console.warn('Row is missing a data-member-id attribute:', row);
            return;
        }

        row.onclick = () => {
            console.log(`Row clicked. Member ID: ${memberId}`);
            tableBody.querySelectorAll('tr').forEach(r => r.classList.remove('highlight'));
            row.classList.add('highlight');
            populateSelectedMemberTable(memberId);
            populateSelectedMemberMessageTable(memberId);
        };
    });
}

function toggleSelectedMemberEventsSpinner(show) {
    const containerId = 'selected-member-events-container';
    const container = document.getElementById(containerId);

    if (!container) {
        console.error(`Container with ID ${containerId} not found.`);
        return;
    }

    const spinner = container.querySelector('.table-spinner');
    if (!spinner) {
        console.error(`Spinner not found in container with ID ${containerId}.`);
        return;
    }

    spinner.style.display = show ? 'flex' : 'none';
}

function renderCommunityMemberEventsForPage(events, page) {
    const start = (page - 1) * rowsPerMemberEventPage;
    const end = start + rowsPerMemberEventPage;
    const eventsToShow = events.slice(start, end);

    const tableBody = document.getElementById('community-events-table-body');

    if (!tableBody) {
        console.error("Table body not found: #community-events-table-body");
        return;
    }

    tableBody.innerHTML = ''; // Clear existing rows

    eventsToShow.forEach(event => {
        const row = document.createElement('tr');
        row.classList.add('table-row'); // Add a base class for styling

        // Set data-member-id for the row
        if (event.data && event.data.object && event.data.object.id) {
            row.setAttribute('data-member-id', event.data.object.id);
        } else {
            console.warn('Event is missing a valid Member ID:', event);
        }

        // Define the fields to display
        const fields = [
            'timestamp', 'type', 'active', 'communication_channel', 'communication_channel_id',
            'given_name', 'surname', 'email', 'date_of_birth', 'gender_identity',
            'postal_code', 'country_code', 'longitude', 'latitude', 'city',
            'state_or_province', 'state_or_province_abbreviation', 'country', 'client_id', 'id'
        ];

        fields.forEach(field => {
            const cell = document.createElement('td');

            if (field === 'type') {
                const typeMapping = {
                    'member.created': 'Created',
                    'member.updated': 'Updated',
                    'member.deleted': 'Deleted'
                };
                cell.textContent = typeMapping[event.type] || event.type || 'Unknown';
            } else if (field === 'timestamp') {
                cell.textContent = event.data.object.timestamp || event.created || '';
            } else if (field === 'longitude' || field === 'latitude') {
                cell.textContent = event.data.object.geolocation
                    ? event.data.object.geolocation[field] || ''
                    : '';
            } else {
                cell.textContent = event.data.object[field] || '';
            }

            row.appendChild(cell);
        });

        tableBody.appendChild(row);
    });

    // Attach click handlers to rows
    setupCommunityEventsRowClickHandlers();
}

// Function to render the table for the current community member events page
function renderCommunityMemberEventsForPage_works(events, page) {
    const start = (page - 1) * rowsPerMemberEventPage;
    const end = start + rowsPerMemberEventPage;
    const eventsToShow = events.slice(start, end);

    const tableBody = document.getElementById('community-events-table-body');

    if (!tableBody) {
        console.error("Table body not found: #community-events-table-body");
        return;
    }

    tableBody.innerHTML = ''; // Clear existing rows

    eventsToShow.forEach(event => {
        const row = document.createElement('tr');

        // Define the fields to display
        const fields = [
            'timestamp', 'type', 'active', 'communication_channel', 'communication_channel_id',
            'given_name', 'surname', 'email', 'date_of_birth', 'gender_identity',
            'postal_code', 'country_code', 'longitude', 'latitude', 'city',
            'state_or_province', 'state_or_province_abbreviation', 'country', 'client_id', 'id'
        ];

        fields.forEach(field => {
            const cell = document.createElement('td');

            if (field === 'type') {
                // Map the `type` field to human-readable values
                const typeMapping = {
                    'member.created': 'Created',
                    'member.updated': 'Updated',
                    'member.deleted': 'Deleted'
                };
                cell.textContent = typeMapping[event.type] || event.type || 'Unknown';
            } else if (field === 'timestamp') {
                // Use either `timestamp` or `created` for timestamp display
                cell.textContent = event.data.object.timestamp || event.created || '';
            } else if (field === 'longitude' || field === 'latitude') {
                // Handle geolocation fields
                cell.textContent = event.data.object.geolocation
                    ? event.data.object.geolocation[field] || ''
                    : '';
            } else {
                // General mapping for other fields
                cell.textContent = event.data.object[field] || '';
            }

            row.appendChild(cell);
        });

        tableBody.appendChild(row);
    });
}

export function createCommunityMemberEventsPagination(events) {
    const paginationContainer = document.getElementById('community-events-pagination-container');
    const pageIndicatorContainer = document.getElementById('community-events-page-indicator');

    if (!paginationContainer) {
        console.error("Pagination container not found: #community-events-pagination-container");
        return;
    }

    // Clear existing pagination controls
    paginationContainer.innerHTML = '';

    const totalPages = Math.ceil(events.length / rowsPerMemberEventPage);

    // If only one page, no need to render pagination
    if (totalPages <= 1) {
        if (pageIndicatorContainer) {
            pageIndicatorContainer.textContent = ""; // Clear page indicator
        }
        return;
    }

    // Update current page indicator
    if (pageIndicatorContainer) {
        pageIndicatorContainer.textContent = `Page ${currentMemberEventPage} of ${totalPages}`;
    }

    // Create First button (<<)
    const firstButton = document.createElement('button');
    firstButton.textContent = '<<';
    firstButton.className = 'pagination-button special';
    firstButton.disabled = currentMemberEventPage === 1;
    firstButton.onclick = () => {
        currentMemberEventPage = 1;
        renderCommunityMemberEventsForPage(events, currentMemberEventPage);
        createCommunityMemberEventsPagination(events);
    };
    paginationContainer.appendChild(firstButton);

    // Create Previous button (‹ Prev)
    const prevButton = document.createElement('button');
    prevButton.textContent = '‹ Prev';
    prevButton.className = 'pagination-button special';
    prevButton.disabled = currentMemberEventPage === 1;
    prevButton.onclick = () => {
        if (currentMemberEventPage > 1) {
            currentMemberEventPage--;
            renderCommunityMemberEventsForPage(events, currentMemberEventPage);
            createCommunityMemberEventsPagination(events);
        }
    };
    paginationContainer.appendChild(prevButton);

    // Page numbers (limited to 7 at a time)
    const maxPageButtons = 7;
    let startPage = Math.max(1, currentMemberEventPage - Math.floor(maxPageButtons / 2));
    let endPage = Math.min(totalPages, startPage + maxPageButtons - 1);

    if (endPage - startPage < maxPageButtons - 1) {
        startPage = Math.max(1, endPage - maxPageButtons + 1);
    }

    for (let i = startPage; i <= endPage; i++) {
        const pageButton = document.createElement('button');
        pageButton.textContent = i;
        pageButton.className = 'pagination-button';
        if (i === currentMemberEventPage) {
            pageButton.classList.add('active'); // Highlight the current page button
        }
        pageButton.onclick = () => {
            currentMemberEventPage = i;
            renderCommunityMemberEventsForPage(events, currentMemberEventPage);
            createCommunityMemberEventsPagination(events);
        };
        paginationContainer.appendChild(pageButton);
    }

    // Create Next button (Next ›)
    const nextButton = document.createElement('button');
    nextButton.textContent = 'Next ›';
    nextButton.className = 'pagination-button special';
    nextButton.disabled = currentMemberEventPage === totalPages;
    nextButton.onclick = () => {
        if (currentMemberEventPage < totalPages) {
            currentMemberEventPage++;
            renderCommunityMemberEventsForPage(events, currentMemberEventPage);
            createCommunityMemberEventsPagination(events);
        }
    };
    paginationContainer.appendChild(nextButton);

    // Create Last button (>>)
    const lastButton = document.createElement('button');
    lastButton.textContent = '>>';
    lastButton.className = 'pagination-button special';
    lastButton.disabled = currentMemberEventPage === totalPages;
    lastButton.onclick = () => {
        currentMemberEventPage = totalPages;
        renderCommunityMemberEventsForPage(events, currentMemberEventPage);
        createCommunityMemberEventsPagination(events);
    };
    paginationContainer.appendChild(lastButton);

    // Render the current page
    renderCommunityMemberEventsForPage(events, currentMemberEventPage);
}

export function createCommunityMemberEventsPagination_works(events) {
    const paginationContainer = document.getElementById('community-events-pagination-container');

    if (!paginationContainer) {
        console.error("Pagination container not found: #community-events-pagination-container");
        return;
    }

    paginationContainer.innerHTML = ''; // Clear existing pagination controls

    const totalPages = Math.ceil(events.length / rowsPerMemberEventPage);

    // If only one page, no need to render pagination
    if (totalPages <= 1) return;

    // Create First button (<<)
    const firstButton = document.createElement('button');
    firstButton.textContent = '<<';
    firstButton.className = 'pagination-button special';
    firstButton.disabled = currentMemberEventPage === 1;
    firstButton.onclick = () => {
        currentMemberEventPage = 1;
        renderCommunityMemberEventsForPage(events, currentMemberEventPage);
        createCommunityMemberEventsPagination(events);
    };
    paginationContainer.appendChild(firstButton);

    // Create Previous button (‹ Prev)
    const prevButton = document.createElement('button');
    prevButton.textContent = '‹ Prev';
    prevButton.className = 'pagination-button special';
    prevButton.disabled = currentMemberEventPage === 1;
    prevButton.onclick = () => {
        if (currentMemberEventPage > 1) {
            currentMemberEventPage--;
            renderCommunityMemberEventsForPage(events, currentMemberEventPage);
            createCommunityMemberEventsPagination(events);
        }
    };
    paginationContainer.appendChild(prevButton);

    // Page numbers (limited to 7 at a time)
    const maxPageButtons = 7;
    let startPage = Math.max(1, currentMemberEventPage - Math.floor(maxPageButtons / 2));
    let endPage = Math.min(totalPages, startPage + maxPageButtons - 1);

    if (endPage - startPage < maxPageButtons - 1) {
        startPage = Math.max(1, endPage - maxPageButtons + 1);
    }

    for (let i = startPage; i <= endPage; i++) {
        const pageButton = document.createElement('button');
        pageButton.textContent = i;
        pageButton.className = 'pagination-button';
        if (i === currentMemberEventPage) {
            pageButton.classList.add('active');
        }
        pageButton.onclick = () => {
            currentMemberEventPage = i;
            renderCommunityMemberEventsForPage(events, currentMemberEventPage);
            createCommunityMemberEventsPagination(events);
        };
        paginationContainer.appendChild(pageButton);
    }

    // Create Next button (Next ›)
    const nextButton = document.createElement('button');
    nextButton.textContent = 'Next ›';
    nextButton.className = 'pagination-button special';
    nextButton.disabled = currentMemberEventPage === totalPages;
    nextButton.onclick = () => {
        if (currentMemberEventPage < totalPages) {
            currentMemberEventPage++;
            renderCommunityMemberEventsForPage(events, currentMemberEventPage);
            createCommunityMemberEventsPagination(events);
        }
    };
    paginationContainer.appendChild(nextButton);

    // Create Last button (>>)
    const lastButton = document.createElement('button');
    lastButton.textContent = '>>';
    lastButton.className = 'pagination-button special';
    lastButton.disabled = currentMemberEventPage === totalPages;
    lastButton.onclick = () => {
        currentMemberEventPage = totalPages;
        renderCommunityMemberEventsForPage(events, currentMemberEventPage);
        createCommunityMemberEventsPagination(events);
    };
    paginationContainer.appendChild(lastButton);

    // Render the current page
    renderCommunityMemberEventsForPage(events, currentMemberEventPage);
}

// Initialize pagination for community member events
export function initializeCommunityMemberEventsPagination() {
    const events = window.communityEvents.events || [];
    if (events.length > 0) {
        currentMemberEventPage = 1; // Reset to the first page
        createCommunityMemberEventsPagination(events);
    } else {
        console.warn("No events found for Community Member Events pagination.");
    }
}



