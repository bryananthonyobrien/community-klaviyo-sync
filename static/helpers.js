const API_URL = window.NODE_ENV === 'production' 
  ? 'https://www.bryanworx.com' 
  : 'http://localhost:5001';
export { API_URL };  // Ensure this export is correct

console.log(API_URL); // Will log the appropriate URL based on NODE_ENV

// Updated fetchWithTimeout function with token refresh handling
export async function fetchWithTimeout(resource, options = {}) {
    const { timeout = 3000000 } = options;
    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), timeout);

    try {
        console.log(`Sending request to ${resource} with options:`, options);

        const response = await fetch(resource, {
            ...options,
            signal: controller.signal
        });

        clearTimeout(id);

        // Handle token expiration only if already logged in
        if (response.status === 401 && localStorage.getItem('refresh_token')) {
            console.log('Access token expired, attempting to refresh...');
            const accessToken = await refreshAccessToken();

            if (accessToken) {
                // Retry the original request with the new token
                options.headers['Authorization'] = `Bearer ${accessToken}`;
                return await fetch(resource, options);
            } else {
                console.error('Token refresh failed. Please log in again.');
                alert('Token refresh failed. Please log in again.');
                window.location.href = '/login';  // Redirect to login
                throw new Error('Unauthorized');
            }
        }

        return response;
    } catch (error) {
        clearTimeout(id);
        logError('Fetch request failed', error);
        throw error;
    }
}

export async function refreshAccessToken() {
    const refreshToken = localStorage.getItem('refresh_token');
    if (!refreshToken) {
        console.error('No refresh token available');
        alert('Session expired. Please log in again.');
        window.location.href = '/login';  // Redirect to login if no refresh token
        return null;
    }

    try {
        const response = await fetchWithTimeout(`${API_URL}/refresh`, {
            method: 'POST',
            headers: createAuthorizedHeaders(refreshToken),
            timeout: 20000
        });

        if (response.ok) {
            const data = await response.json();
            localStorage.setItem('access_token', data.access_token);
            console.log('Token refreshed successfully:', data);
            return data.access_token;
        } else {
            logError('Refresh access token failed', await response.json());
            localStorage.removeItem('access_token');
            localStorage.removeItem('refresh_token');
            alert('Session expired. Please log in again.');
            window.location.href = '/login';  // Redirect to login if refresh fails
            return null;
        }
    } catch (error) {
        logError('Refresh access token error', error);
        localStorage.removeItem('access_token');
        localStorage.removeItem('refresh_token');
        alert('Error refreshing access token. Please log in again.');
        window.location.href = '/login';  // Redirect to login
        return null;
    }
}

// Function to create authorized headers
export function createAuthorizedHeaders(token) {
    return {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
    };
}

// Function to update local storage with token data
export function updateLocalStorage(data) {
    localStorage.setItem('access_token', data.access_token);
    localStorage.setItem('refresh_token', data.refresh_token);
}

export function clearDataFromLocalStorage() {
    console.log('[Scripts] clearDataFromLocalStorage');
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
    localStorage.clear();
}

// Function to log local storage data (for debugging)
export function logLocalStorage() {
    console.log('[Scripts] Local Storage contents:');
    for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        const value = localStorage.getItem(key);
        console.log(`${key}: ${value}`);
    }
}

// Function to log errors (for debugging)
export function logError(context, error) {
    if (error.name === 'AbortError') {
        console.error(`${context} request timed out`);
    } else {
        console.error(`${context} request failed:`, error);  // error should be used, not t
    }
}

// Token refresh function with retry logic
export async function makeRequestWithTokenRefresh(requestFn, retryOnUnauthorized = true, maxRetries = 3) {
    let accessToken = localStorage.getItem('access_token');
    const refreshToken = localStorage.getItem('refresh_token');
    let retryCount = 0; // Track the number of retries

    if (!accessToken && refreshToken) {
        console.log('Access token missing, attempting to refresh using refresh token...');
        accessToken = await refreshAccessToken();
        if (!accessToken) {
            console.error('Failed to refresh access token. Please login again.');
            alert('Failed to refresh access token. Please login again.');
            window.location.href = '/login';
            return null;
        }
    }

    try {
        const response = await requestFn(accessToken);

        // If unauthorized and we haven't retried yet, refresh the token and retry the request
        if (response.status === 401 && retryOnUnauthorized && retryCount < maxRetries) {
            console.log('Access token expired, refreshing token and retrying request...');
            accessToken = await refreshAccessToken();

            if (accessToken) {
                retryCount++; // Increment the retry count
                return await makeRequestWithTokenRefresh(requestFn, false, maxRetries); // Retry the request
            } else {
                alert('Failed to refresh access token. Please login again.');
                window.location.href = '/login'; // Redirect to login if refresh fails
                return null;
            }
        }

        // If we hit the max retry count, prevent further attempts and handle the failure
        if (retryCount >= maxRetries) {
            console.error('Exceeded maximum retry attempts for refreshing the token.');
            alert('Exceeded maximum retry attempts for refreshing the token. Please log in again.');
            window.location.href = '/login'; // Redirect to login
            return null;
        }

        return response;
    } catch (error) {
        console.error('Error making request:', error);
        alert('An error occurred while making the request.');
        return null;
    }
}



export async function makeRequestWithTokenRefresh_old(requestFn, retryOnUnauthorized = true) {
    let accessToken = localStorage.getItem('access_token');
    const refreshToken = localStorage.getItem('refresh_token');

    if (!accessToken && refreshToken) {
        console.log('Access token missing, attempting to refresh using refresh token...');
        accessToken = await refreshAccessToken();
        if (!accessToken) {
            console.error('Failed to refresh access token. Please login again.');
            alert('Failed to refresh access token. Please login again.');
            window.location.href = '/login';
            return null;
        }
    }

    try {
        const response = await requestFn(accessToken);

        // If unauthorized and we haven't retried yet, refresh the token and retry the request
        if (response.status === 401 && retryOnUnauthorized) {
            console.log('Access token expired, refreshing token and retrying request...');
            accessToken = await refreshAccessToken();
            if (accessToken) {
                return await makeRequestWithTokenRefresh(requestFn, false);
            } else {
                alert('Failed to refresh access token. Please login again.');
                window.location.href = '/login';
                return null;
            }
        }

        return response;
    } catch (error) {
        console.error('Error making request:', error);
        alert('An error occurred while making the request.');
        return null;
    }
}

