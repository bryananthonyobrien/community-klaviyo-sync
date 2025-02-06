// Code specific to admin.html

async function fetchCpuUsage() {
    let accessToken = localStorage.getItem('access_token');
    if (!accessToken) {
        console.error('No access token available');
        alert('No access token available. Please login first.');
        return;
    }

    try {
        const response = await fetchWithTimeout(`${API_URL}/cpu-usage`, {
            method: 'GET',
            headers: createAuthorizedHeaders(accessToken),
            timeout: 20000
        });

        if (response.status === 401) {
            console.log('Access token expired, attempting to refresh...');
            accessToken = await refreshAccessToken();
            if (accessToken) {
                const retryResponse = await fetchWithTimeout(`${API_URL}/cpu-usage`, {
                    method: 'GET',
                    headers: createAuthorizedHeaders(accessToken),
                    timeout: 20000
                });

                if (retryResponse.ok) {
                    const data = await retryResponse.json();
                    console.log('CPU usage data:', data);
                    updateCpuGraph(data);
                } else {
                    logError('Fetch CPU usage after refresh', await retryResponse.json());
                    alert('Failed to fetch CPU usage after refresh');
                }
            } else {
                alert('Failed to refresh access token. Please login again.');
                return;
            }
        } else if (response.ok) {
            const data = await response.json();
            console.log('CPU usage data:', data);
            updateCpuGraph(data);
        } else {
            logError('Fetch CPU usage', await response.json());
            alert('Failed to fetch CPU usage');
        }
    } catch (error) {
        logError('Fetch CPU usage', error);
        alert('Error fetching CPU usage');
    }
}

async function fetchFileStorageUsage() {
    let accessToken = localStorage.getItem('access_token');
    if (!accessToken) {
        console.error('No access token available');
        alert('No access token available. Please login first.');
        return;
    }

    try {
        const response = await fetchWithTimeout(`${API_URL}/file-storage-usage`, {
            method: 'GET',
            headers: createAuthorizedHeaders(accessToken),
            timeout: 20000
        });

        if (response.status === 401) {
            console.log('Access token expired, attempting to refresh...');
            accessToken = await refreshAccessToken();
            if (accessToken) {
                const retryResponse = await fetchWithTimeout(`${API_URL}/file-storage-usage`, {
                    method: 'GET',
                    headers: createAuthorizedHeaders(accessToken),
                    timeout: 20000
                });

                if (retryResponse.ok) {
                    const data = await retryResponse.json();
                    console.log('File storage usage data:', data);
                    updateFileStorageGraph(data);
                } else {
                    logError('Fetch file storage usage after refresh', await retryResponse.json());
                    alert('Failed to fetch file storage usage after refresh');
                }
            } else {
                alert('Failed to refresh access token. Please login again.');
                return;
            }
        } else if (response.ok) {
            const data = await response.json();
            console.log('File storage usage data:', data);
            updateFileStorageGraph(data);
        } else {
            logError('Fetch file storage usage', await response.json());
            alert('Failed to fetch file storage usage');
        }
    } catch (error) {
        logError('Fetch file storage usage', error);
        alert('Error fetching file storage usage');
    }
}

function toggleMonitoring() {
    if (isMonitoring) {
        clearInterval(monitoringInterval);
        isMonitoring = false;
        monitorButton.textContent = 'Stop Monitoring';
        console.log('Monitoring stopped.');
    } else {
        const interval = parseInt(document.getElementById('interval-input').value);
        if (isNaN(interval) || interval <= 0) {
            alert('Please enter a valid interval in minutes.');
            return;
        }

        fetchCpuUsage();  // Fetch data immediately
        fetchFileStorageUsage();  // Fetch file storage data immediately
        monitoringInterval = setInterval(() => {
            fetchCpuUsage();
            fetchFileStorageUsage();
        }, interval * 60 * 1000);
        isMonitoring = true;
        monitorButton.textContent = 'Start Monitoring';
        console.log('Monitoring started.');
    }
}

async function burstRequest() {
    let accessToken = localStorage.getItem('access_token');
    if (!accessToken) {
        console.error('No access token available');
        alert('No access token available. Please login first.');
        return;
    }

    try {
        const response = await fetchWithTimeout(`${API_URL}/api`, {
            method: 'POST',
            headers: createAuthorizedHeaders(accessToken),
            body: JSON.stringify({ key: 'value' }),
            timeout: 20000
        });

        if (response.status === 401) {
            console.log('Access token expired, attempting to refresh...');
            accessToken = await refreshAccessToken();
            if (accessToken) {
                const retryResponse = await fetchWithTimeout(`${API_URL}/api`, {
                    method: 'POST',
                    headers: createAuthorizedHeaders(accessToken),
                    body: JSON.stringify({ key: 'value' }),
                    timeout: 20000
                });

                if (retryResponse.ok) {
                    const data = await retryResponse.json();
                    console.log('Protected resource data:', data);
                    return { success: true };
                } else {
                    logError('Fetch protected resource after refresh', await retryResponse.json());
                    return { success: false, retryAfter: 60 };
                }
            } else {
                alert('Failed to refresh access token. Please login again.');
                return { success: false, retryAfter: 60 };
            }
        } else if (response.status === 402) {
            alert('Insufficient credits');
            return { success: false, retryAfter: 60 };
        } else if (response.status === 429) {
            const retryAfter = response.headers.get('Retry-After') || 60; // Default to 60 seconds if not specified
            console.error(`Rate limit exceeded. Retry after ${retryAfter} seconds.`);
            return { success: false, retryAfter };
        } else if (response.ok) {
            const data = await response.json();
            console.log('Protected resource data:', data);
            return { success: true };
        } else {
            logError('Fetch protected resource await within burst', await response.json());
            return { success: false, retryAfter: 60 };
        }
    } catch (error) {
        logError('Burst request', error);
        return { success: false, retryAfter: 60 };
    }
}

async function burstTest() {
    const numberOfBursts = parseInt(burstNumberInput.value);
    const intervalBetweenBursts = parseInt(burstIntervalInput.value);
    const requestsPerBurst = parseInt(burstRequestsInput.value);

    for (let burstCount = 0; burstCount < numberOfBursts; burstCount++) {
        if (!isBurstTestRunning) {
            console.log('Burst test stopped.');
            break;
        }

        let burstPromises = [];
        for (let requestCount = 0; requestCount < requestsPerBurst; requestCount++) {
            burstPromises.push(burstRequest());
        }

        const burstResults = await Promise.all(burstPromises);
        const retryAfter = burstResults.reduce((max, result) => Math.max(max, result.retryAfter || 0), 0);

        if (retryAfter > 0) {
            console.log(`Burst test waiting for ${retryAfter} seconds.`);
            await new Promise(resolve => setTimeout(resolve, retryAfter * 1000));
        } else {
            await new Promise(resolve => setTimeout(resolve, intervalBetweenBursts * 1000));
        }

        if (burstCount % 2 === 0) {
            fetchCredits(); // Update credits every 2 bursts
        }
    }

    console.log('Burst test completed.');
    isBurstTestRunning = false;
    burstButton.textContent = 'Start Burst Test';
    fetchProtectedButton.disabled = false;
}

function toggleBurstTest() {
    if (isBurstTestRunning) {
        isBurstTestRunning = false;
        burstButton.textContent = 'Start Burst Test';
        fetchProtectedButton.disabled = false;
        console.log('Burst test stopped.');
    } else {
        isBurstTestRunning = true;
        burstButton.textContent = 'Stop Burst Test';
        fetchProtectedButton.disabled = true;
        burstTest();
    }
}

async function testDatabaseThroughput() {
    const count = document.getElementById('throughput-count').value || 100;
    const resultElement = document.getElementById('throughput-result');
    if (resultElement) {
        resultElement.textContent = 'Testing...';
    }

    try {
        const response = await fetch(`${API_URL}/test-throughput`, {
            method: 'POST',
            headers: createAuthorizedHeaders(localStorage.getItem('access_token')),
            body: JSON.stringify({ count })
        });

        if (response.ok) {
            const data = await response.json();
            if (resultElement) {
                resultElement.textContent = `Throughput: ${Math.floor(data.throughput)} requests/second`;
            }
        } else {
            const errorData = await response.json();
            if (resultElement) {
                resultElement.textContent = `Error: ${errorData.msg}`;
            }
        }
    } catch (error) {
        logError('Test database throughput', error);
        if (resultElement) {
            resultElement.textContent = 'Error testing throughput';
        }
    }
}


// Initialize the usage graph if the canvas element exists
const ctx = document.getElementById('usage-graph');
if (ctx) {
    const usageChart = new Chart(ctx.getContext('2d'), {
        type: 'line',
        data: {
            labels: [],
            datasets: [
                {
                    label: 'CPU Used (%)',
                    data: [],
                    borderColor: 'rgba(255, 99, 132, 1)',
                    backgroundColor: 'rgba(255, 99, 132, 0.2)',
                    fill: false
                },
                {
                    label: 'File Storage Used (%)',
                    data: [],
                    borderColor: 'rgba(54, 162, 235, 1)',
                    backgroundColor: 'rgba(54, 162, 235, 0.2)',
                    fill: false
                }
            ]
        },
        options: {
            scales: {
                x: {
                    type: 'time',
                    time: {
                        unit: 'minute'
                    }
                },
                y: {
                    beginAtZero: true,
                    ticks: {
                        callback: function(value) {
                            return value.toFixed(1) + '%';
                        }
                    }
                }
            }
        }
    });

    function updateCpuGraph(data) {
        const now = new Date();
        const cpuUsedPercentage = (data.daily_cpu_total_usage_seconds / data.daily_cpu_limit_seconds) * 100;
        usageChart.data.labels.push(now);
        usageChart.data.datasets[0].data.push(cpuUsedPercentage);
        updateMaxYScale(cpuUsedPercentage);
        usageChart.update();
    }

    function updateFileStorageGraph(data) {
        const now = new Date();
        const fileStorageUsedPercentage = (data.file_storage_used_bytes / data.file_storage_limit_bytes) * 100;
        usageChart.data.labels.push(now);
        usageChart.data.datasets[1].data.push(fileStorageUsedPercentage);
        updateMaxYScale(fileStorageUsedPercentage);
        usageChart.update();
    }

    function updateMaxYScale(newValue) {
        const currentMax = usageChart.options.scales.y.max || 100;
        const newMax = Math.max(currentMax, newValue * 2);
        if (newMax !== currentMax) {
            usageChart.options.scales.y.max = newMax;
            usageChart.update('resize');
        }
    }

    // Assign to window only if ctx exists
    window.updateCpuGraph = updateCpuGraph;
    window.updateFileStorageGraph = updateFileStorageGraph;
} else {
    console.log('#usage-graph element not found. updateCpuGraph will not work.');
    // Provide placeholder functions to avoid ReferenceErrors
    window.updateCpuGraph = () => console.warn('updateCpuGraph called, but no graph exists.');
    window.updateFileStorageGraph = () => console.warn('updateFileStorageGraph called, but no graph exists.');
}


// Ensure the Chart.js functions are available globally
window.updateCpuGraph = updateCpuGraph;
window.updateFileStorageGraph = updateFileStorageGraph;
