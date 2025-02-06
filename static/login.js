import { updateLocalStorage, createAuthorizedHeaders, fetchWithTimeout, clearDataFromLocalStorage, logError, API_URL, logLocalStorage } from './helpers.js';

document.addEventListener('DOMContentLoaded', () => {
    const loginButton = document.getElementById('login-button');
    if (loginButton) {
        loginButton.addEventListener('click', login);
    }
});

// Login function
async function login() {
    const username = prompt('Enter username:');
    if (!username) {
        alert('Username is required');
        return;
    }

    try {
        let response = await fetchWithTimeout(`${API_URL}/login`, {
            method: 'POST',
            headers: createAuthorizedHeaders(),
            body: JSON.stringify({ username }),
            timeout: 20000
        });

        if (!response.ok) {
            const errorData = await response.json();
            console.log('Received error:', errorData);

            if (errorData.msg === 'Password is missing in request') {
                const password = prompt('Enter password:');
                if (!password) {
                    alert('Password is required');
                    return;
                }

                response = await fetchWithTimeout(`${API_URL}/login`, {
                    method: 'POST',
                    headers: createAuthorizedHeaders(),
                    body: JSON.stringify({ username, password }),
                    timeout: 20000
                });

                if (response.ok) {
                    const data = await response.json();
                    console.log('Login successful:', data);
                    updateLocalStorage(data);
                    window.location.href = (data.role === 'admin') ? '/admin' : '/client';
                } else {
                    const errorData = await response.json();
                    console.error('Login failed:', errorData);
                    alert(`Login failed: ${errorData.msg}`);
                    clearDataFromLocalStorage();
                }
            } else {
                console.error('Login failed:', errorData);
                alert(`Login failed: ${errorData.msg}`);
                clearDataFromLocalStorage();
            }
        } else {
            const data = await response.json();
            console.log('Login response data (no password step):', data);

            if (data.password_required) {
                const password = prompt('Enter password:');
                if (!password) {
                    alert('Password is required');
                    return;
                }

                response = await fetchWithTimeout(`${API_URL}/login`, {
                    method: 'POST',
                    headers: createAuthorizedHeaders(),
                    body: JSON.stringify({ username, password }),
                    timeout: 20000
                });

                if (response.ok) {
                    const data = await response.json();
                    console.log('Login successful:', data);
                    updateLocalStorage(data);
                    window.location.href = (data.role === 'admin') ? '/admin' : '/client';
                } else {
                    const errorData = await response.json();
                    console.error('Login failed:', errorData);
                    alert(`Login failed: ${errorData.msg}`);
                    clearDataFromLocalStorage();
                }
            } else {
                updateLocalStorage(data);
                window.location.href = (data.role === 'admin') ? '/admin' : '/client';
            }
        }
    } catch (error) {
        logError('Login', error);
        alert('An error occurred during login.');
        clearDataFromLocalStorage();
    }

    logLocalStorage();
}