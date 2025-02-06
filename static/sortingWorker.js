self.onmessage = function (e) {
    try {
        console.log("Worker received data:", e.data);

        const { rowData, columnIndex, isAscending } = e.data;

        if (!rowData || !Array.isArray(rowData) || rowData.length === 0) {
            throw new Error("Invalid or empty rowData received by worker.");
        }

        console.log("Processing rowData for sorting...");

        // Treat undefined or null as an empty string
        rowData.forEach((row, idx) => {
            row.content[columnIndex] = row.content[columnIndex] || "";
            console.log(`Row ${idx}, Value at columnIndex ${columnIndex}: "${row.content[columnIndex]}"`);
        });

        // Perform alphanumeric sorting
        rowData.sort((rowA, rowB) => {
            const cellA = rowA.content[columnIndex];
            const cellB = rowB.content[columnIndex];

            return isAscending
                ? cellA.localeCompare(cellB)
                : cellB.localeCompare(cellA);
        });

        console.log("Sorting completed. Sending sorted indices back.");

        const sortedIndices = rowData.map(row => row.index);
        postMessage(sortedIndices);
    } catch (err) {
        console.error("Error in worker:", err.message, err.stack);
        postMessage({ error: err.message }); // Send error back to the main thread
    } finally {
        console.log("Worker completed its task.");
    }
};
