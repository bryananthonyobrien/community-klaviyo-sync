import { fetchWithTimeout } from '/static/helpers.js';
import { createAuthorizedHeaders } from '/static/helpers.js';
import { clearDataFromLocalStorage } from '/static/helpers.js';
import { logError } from '/static/helpers.js';
import { API_URL } from '/static/helpers.js';

export async function logout() {
    let accessToken = localStorage.getItem('access_token');
    let refreshToken = localStorage.getItem('refresh_token');

    if (!accessToken) {
        console.error('No access token available');
        alert('No access token available. Please login first.');
        window.location.href = '/login.html'; // Redirect to login page
        return;
    }

    try {
        const response = await fetchWithTimeout(`${API_URL}/logout`, {
            method: 'POST',
            headers: createAuthorizedHeaders(accessToken),
            body: JSON.stringify({ refresh_token: refreshToken }),
            timeout: 20000 // ensure the timeout is passed to fetchWithTimeout
        });

        if (response.ok) {
            localStorage.removeItem('access_token');
            localStorage.removeItem('refresh_token');
            alert('Successfully logged out');
            window.location.href = '/';
        } else {
            logError('Logout', await response.json());
            alert(`Logout failed: ${errorData.msg}`);
        }
    } catch (error) {
        logError('Logout', error);
    } finally {
        clearDataFromLocalStorage();
        //location.reload(); // Refresh the browser after logout
    }
}
