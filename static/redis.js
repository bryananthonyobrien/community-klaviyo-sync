import { makeRequestWithTokenRefresh } from '/static/helpers.js';
import { API_URL } from '/static/helpers.js';
import { createAuthorizedHeaders } from '/static/helpers.js';

export async function checkRedisStatus() {
    const redisStatusButton = document.getElementById('redis-status-button');
    const redisStatusResult = document.getElementById('redis-status-result');

    if (!redisStatusButton || !redisStatusResult) {
        console.error('Redis status elements not found.');
        return;
    }

    redisStatusButton.style.backgroundColor = 'grey';
    redisStatusButton.disabled = true;

    const response = await makeRequestWithTokenRefresh(async (token) => {
        return fetch(`${API_URL}/redis_status`, {
            method: 'GET',
            headers: createAuthorizedHeaders(token)
        });
    });

    // Log the raw response object
    console.log('Redis Status Response:', response);

    if (response && response.status === 404) {
        console.warn('Redis status endpoint not found (404).');
        redisStatusResult.textContent = 'Redis Status Endpoint Not Found';
        redisStatusResult.style.color = 'red';
        redisStatusButton.style.backgroundColor = 'red';
    } else if (response && response.ok) {
        const data = await response.json();
        console.log('Redis Status Data:', data);

        if (data.status === 'OK') {
            // Update the table with the Redis memory stats
            redisStatusResult.innerHTML = `
                <table border="1" style="width: 100%; border-collapse: collapse;">
                    <tr>
                        <th>Status</th>
                        <th>Used Memory</th>
                    </tr>
                    <tr>
                        <td>${data.status}</td>
                        <td>${data.used_memory_human}</td>
                    </tr>
                </table>
            `;
            redisStatusResult.style.color = 'green';
            redisStatusButton.style.backgroundColor = 'green';
        } else {
            redisStatusResult.textContent = 'Bad';
            redisStatusResult.style.color = 'red';
            redisStatusButton.style.backgroundColor = 'red';
        }
    } else {
        redisStatusResult.textContent = 'Error Checking Redis Status';
        redisStatusResult.style.color = 'red';
        redisStatusButton.style.backgroundColor = 'red';
    }

    redisStatusButton.disabled = false;
}


