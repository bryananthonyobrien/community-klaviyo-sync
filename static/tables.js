let isSorting = false;  // Prevent concurrent sorting

export function sortTableWithYield(tableId, columnIndex, containerId) {
    if (isSorting) return; // Skip if already sorting
    isSorting = true;

    const table = document.getElementById(tableId);
    const tbody = table.querySelector("tbody");
    const container = document.getElementById(containerId);
    const spinner = container.querySelector(".table-spinner");
    const rows = Array.from(tbody.rows);
    const isAscending = table.getAttribute("data-sort-order") !== "asc";
    table.setAttribute("data-sort-order", isAscending ? "asc" : "desc");

    if (spinner) {
        spinner.style.display = "flex";
        spinner.style.justifyContent = "center";
        spinner.style.alignItems = "center";
    }

    const isNumericColumn = !isNaN(rows[0]?.cells[columnIndex]?.innerText?.trim());

    console.log("Starting sort with yield...");

    // Break the sorting into chunks
    let index = 0; // Start index for chunk processing
    const chunkSize = 1000; // Number of rows to process per chunk

    function processChunk() {
        const start = performance.now(); // Measure processing time

        for (let i = index; i < index + chunkSize && i < rows.length; i++) {
            for (let j = i + 1; j < rows.length; j++) {
                const cellA = rows[i].cells[columnIndex].innerText.trim();
                const cellB = rows[j].cells[columnIndex].innerText.trim();

                const compareResult = isNumericColumn
                    ? (isAscending ? cellA - cellB : cellB - cellA)
                    : (isAscending ? cellA.localeCompare(cellB) : cellB.localeCompare(cellA));

                if (compareResult > 0) {
                    // Swap rows if needed
                    [rows[i], rows[j]] = [rows[j], rows[i]];
                }
            }
        }

        index += chunkSize; // Move to the next chunk

        if (index < rows.length) {
            // Schedule the next chunk
            console.log(`Processed chunk up to index ${index}`);
            setTimeout(processChunk, 100); // Yield time to the browser
        } else {
            console.log("Sorting complete. Rendering sorted rows...");

            // Detach and reattach the sorted rows
            const fragment = document.createDocumentFragment();
            rows.forEach(row => fragment.appendChild(row));
            tbody.appendChild(fragment);

            if (spinner) spinner.style.display = "none";
            isSorting = false;
        }
    }

    processChunk(); // Start the chunk processing
}

export function showSortFilterUI(columnKey, event) {
    const panel = document.getElementById("sort-filter-ui");
    const columnSelect = document.getElementById("sort-column-select");

     populateColumnOptions();

    // Set the clicked column as selected
    columnSelect.value = columnKey;

    // Display and position the panel
    panel.style.display = "block";
    panel.style.position = "absolute";

    // Get the mouse click position
    const { clientX, clientY } = event;
    const panelWidth = panel.offsetWidth;
    const panelHeight = panel.offsetHeight;

    // Get viewport dimensions
    const viewportWidth = window.innerWidth;
    const viewportHeight = window.innerHeight;

    // Calculate position while preventing overflow
    let top = clientY;
    let left = clientX;

    if (left + panelWidth > viewportWidth) {
        left = viewportWidth - panelWidth - 10; // Adjust to fit in viewport
    }

    if (top + panelHeight > viewportHeight) {
        top = viewportHeight - panelHeight - 10; // Adjust to fit in viewport
    }

    // Apply position
    panel.style.top = `${top}px`;
    panel.style.left = `${left}px`;

    console.log(`Sort/Filter UI triggered for column: ${columnKey}`);
}


export function showSortFilterUI_works(columnKey) {
    const panel = document.getElementById("sort-filter-ui");
    const columnSelect = document.getElementById("sort-column-select");
    const container = document.getElementById("community-events-container");

    // Ensure panel exists
    if (!panel || !columnSelect || !container) {
        console.error("Missing required DOM elements for Sort/Filter UI.");
        return;
    }

    // Populate the column dropdown with the selected column
    populateColumnOptions();
    columnSelect.value = columnKey;

    // Display the UI panel
    panel.style.display = "block";

    // Position the panel relative to the table container
    const containerRect = container.getBoundingClientRect();
    const panelWidth = panel.offsetWidth || 250; // Default width if not rendered
    const panelHeight = panel.offsetHeight || 300; // Default height if not rendered

    let top = containerRect.top + window.scrollY + 10; // Adjust for padding
    let left = containerRect.left + window.scrollX + containerRect.width + 20; // Place beside the table

    // Ensure the panel stays within the viewport
    const viewportWidth = window.innerWidth;
    const viewportHeight = window.innerHeight;

    if (left + panelWidth > viewportWidth) {
        left = viewportWidth - panelWidth - 10; // Adjust to stay within viewport
    }
    if (top + panelHeight > viewportHeight) {
        top = viewportHeight - panelHeight - 10; // Adjust to stay within viewport
    }

    panel.style.position = "absolute";
    panel.style.top = `${top}px`;
    panel.style.left = `${left}px`;

    console.log(`Sort/Filter UI triggered for column: ${columnKey}`);
}

function populateColumnOptions() {
    const table = document.getElementById("community-events-table");
    const headers = Array.from(table.querySelectorAll("thead th"));
    const columnSelect = document.getElementById("sort-column-select");

    // Clear existing options
    columnSelect.innerHTML = "";

    headers.forEach(header => {
        // Get the column key from the `onclick` attribute
        const columnKey = header.getAttribute("onclick").match(/'(.*?)'/)[1];
        const option = document.createElement("option");
        option.value = columnKey;
        option.textContent = header.textContent.trim();
        columnSelect.appendChild(option);
    });

    console.log("Column options populated:", columnSelect.options);
}

export function applySort() {
    const columnKey = document.getElementById("sort-column-select").value;
    const sortOrder = document.getElementById("sort-order-select").value;

    console.log(`Applying sort: Column = ${columnKey}, Order = ${sortOrder}`);

    // Set the sort order globally (optional, depending on your implementation)
    window.communityEvents.sortOrder = sortOrder;

    // Call your existing column sort function
    handleColumnSort(columnKey);

    // Add the arrow to the sorted column header
    const table = document.getElementById("community-events-table");
    const headers = Array.from(table.querySelectorAll("thead th"));

    // Remove existing arrows from all headers
    headers.forEach(header => {
        header.textContent = header.textContent.replace(/ ▲| ▼/g, ""); // Remove arrows if present
        const arrowSpan = header.querySelector(".sorted-column-arrow");
        if (arrowSpan) {
            arrowSpan.remove(); // Ensure old spans are removed
        }
    });

    // Add the appropriate arrow to the sorted column header
    const sortedHeader = headers.find(header =>
        header.getAttribute("onclick")?.includes(`'${columnKey}'`)
    );

    if (sortedHeader) {
        const arrow = document.createElement("span");
        arrow.className = "sorted-column-arrow";
        arrow.textContent = sortOrder === "asc" ? " ▲" : " ▼";
        arrow.style.marginLeft = "5px"; // Optional: Add some space between text and arrow
        sortedHeader.appendChild(arrow);
    }

    // Hide the sort/filter UI
    hideSortFilterUI();
}


export function applySort_works() {
    const columnKey = document.getElementById("sort-column-select").value;
    const sortOrder = document.getElementById("sort-order-select").value;

    console.log(`Applying sort: Column = ${columnKey}, Order = ${sortOrder}`);

    // Set the sort order globally (optional, depending on your implementation)
    window.communityEvents.sortOrder = sortOrder;

    // Call your existing column sort function
    handleColumnSort(columnKey);

    // Hide the sort/filter UI
    hideSortFilterUI();
}


export function hideSortFilterUI() {
    const panel = document.getElementById("sort-filter-ui");
    panel.style.display = "none";
}

export function sortTable(tableId, columnIndex, containerId) {
    if (isSorting) return;  // Skip if already sorting
    isSorting = true;

    const table = document.getElementById(tableId);
    const tbody = table.querySelector("tbody");
    const container = document.getElementById(containerId);
    const spinner = container.querySelector(".table-spinner");
    const rows = Array.from(tbody.rows);
    const isAscending = table.getAttribute("data-sort-order") !== "asc";
    table.setAttribute("data-sort-order", isAscending ? "asc" : "desc");

    if (spinner) {
        spinner.style.display = "flex";
        spinner.style.justifyContent = "center";
        spinner.style.alignItems = "center";
    }

    // Debounce to ensure spinner displays
    setTimeout(() => {
        // Sorting logic
        rows.sort((rowA, rowB) => {
            const cellA = rowA.cells[columnIndex].innerText.trim();
            const cellB = rowB.cells[columnIndex].innerText.trim();

            const isNumericColumn = !isNaN(cellA) && !isNaN(cellB);
            return isNumericColumn
                ? (isAscending ? cellA - cellB : cellB - cellA)
                : (isAscending ? cellA.localeCompare(cellB) : cellB.localeCompare(cellA));
        });

        // Detach and reattach the sorted rows in one go
        const fragment = document.createDocumentFragment();
        rows.forEach(row => fragment.appendChild(row));
        tbody.appendChild(fragment);

        if (spinner) spinner.style.display = "none";
        isSorting = false;
    }, 50); // Adjust the delay as needed
}

let currentWorker = null;

export function sortTable_worker(tableId, columnIndex, containerId) {
    if (isSorting) return;
    isSorting = true;

    const table = document.getElementById(tableId);
    const tbody = table.querySelector("tbody");
    const container = document.getElementById(containerId);
    const spinner = container.querySelector(".table-spinner");
    const rows = Array.from(tbody.rows);

    if (!table || !tbody || rows.length === 0) {
        console.error("Table or rows not found!");
        isSorting = false;
        return;
    }

    const isAscending = table.getAttribute("data-sort-order") !== "asc";
    const isNumericColumn = !isNaN(rows[0]?.cells[columnIndex]?.innerText?.trim());

    table.setAttribute("data-sort-order", isAscending ? "asc" : "desc");
    if (spinner) spinner.style.display = "flex";

    const rowData = rows.map((row, index) => ({
        index,
        content: Array.from(row.cells).map(cell => cell.innerText.trim()),
    }));

    console.log("Sending data to worker:", { rowData, columnIndex, isAscending, isNumericColumn });

    // Terminate the old worker if it exists
    if (currentWorker) {
        currentWorker.terminate();
        console.log("Previous worker terminated.");
    }

    currentWorker = new Worker("/static/sortingWorker.js");
    console.log("New worker created.");

    try {
        currentWorker.postMessage({ rowData, columnIndex, isAscending, isNumericColumn });
        console.log("Data posted to worker.");

        currentWorker.onmessage = function (e) {
            try {
                const sortedIndices = e.data;

                if (!Array.isArray(sortedIndices)) {
                    throw new Error("Invalid data received from worker");
                }

                console.log("Received sorted indices from worker:", sortedIndices);

                const fragment = document.createDocumentFragment();
                sortedIndices.forEach(idx => fragment.appendChild(rows[idx]));
                tbody.appendChild(fragment);

                if (spinner) spinner.style.display = "none";
                isSorting = false;
                currentWorker.terminate();
                currentWorker = null;
                console.log("Worker terminated after sorting.");
            } catch (err) {
                console.error("Error handling worker message:", err);
                if (spinner) spinner.style.display = "none";
                isSorting = false;
                currentWorker.terminate();
                currentWorker = null;
            }
        };

        currentWorker.onerror = function (error) {
            console.error("Worker encountered an error:", error.message);
            console.error("Error event:", error);

            if (spinner) spinner.style.display = "none";
            isSorting = false;
            currentWorker.terminate();
            currentWorker = null;
        };
    } catch (err) {
        console.error("Error creating or communicating with the worker:", err.message, err.stack);
        if (spinner) spinner.style.display = "none";
        isSorting = false;
    }
}



