import { makeRequestWithTokenRefresh } from '/static/helpers.js';
import { API_URL } from '/static/helpers.js';
import { createAuthorizedHeaders } from '/static/helpers.js';

export function setMaxWorkers() {
    const maxWorkersInput = document.getElementById('max-workers-input'); // Assuming there's an input field for max workers
    const maxWorkersValue = parseInt(maxWorkersInput.value);

    if (isNaN(maxWorkersValue) || maxWorkersValue <= 0) {
        alert('Please enter a valid positive integer for max workers.');
        return;
    }

    // Assuming you have a function to make requests to your server
    makeRequestWithTokenRefresh(async (token) => {
        return fetch(`${API_URL}/set_max_workers`, {
            method: 'POST',
            headers: createAuthorizedHeaders(token),
            body: JSON.stringify({
                max_workers: maxWorkersValue
            })
        });
    }).then(response => {
        if (response.ok) {
            console.log('Max workers updated successfully');
            alert('Max workers updated successfully.');
        } else {
            console.error('Failed to update max workers');
            alert('Failed to update max workers.');
        }
    }).catch(error => {
        console.error('Error updating max workers:', error);
        alert('Error updating max workers.');
    });
}

export function setKlaviyoApiKey() {
    const klaviyoApiKeyInput = document.getElementById('klaviyo-api-key-input'); // Assuming there's an input field for Klaviyo API Key
    const klaviyoApiKeyValue = klaviyoApiKeyInput.value;

    if (!klaviyoApiKeyValue) {
        return;
    }

    // Assuming you have a function to make requests to your server
    makeRequestWithTokenRefresh(async (token) => {
        return fetch(`${API_URL}/set_klaviyo_read_profile_api_key`, {
            method: 'POST',
            headers: createAuthorizedHeaders(token),
            body: JSON.stringify({
                klaviyo_read_profile_api_key: klaviyoApiKeyValue
            })
        });
    }).then(response => {
        if (response.ok) {
            console.log('Klaviyo API Key updated successfully');
            alert('Klaviyo API Key updated successfully.');
        } else {
            console.error('Failed to update Klaviyo API Key');
            alert('Failed to update Klaviyo API Key.');
        }
    }).catch(error => {
        console.error('Error updating Klaviyo API Key:', error);
        alert('Error updating Klaviyo API Key.');
    });
}

export function setCommunityClientId() {
    const communityClientIdInput = document.getElementById('community-client-id-input'); // Assuming there's an input field for Community Client ID
    const communityClientIdValue = communityClientIdInput.value;

    if (!communityClientIdValue) {
        alert('Please enter a valid Community Client ID.');
        return;
    }

    // Assuming you have a function to make requests to your server
    makeRequestWithTokenRefresh(async (token) => {
        return fetch(`${API_URL}/set_community_client_id`, {
            method: 'POST',
            headers: createAuthorizedHeaders(token),
            body: JSON.stringify({
                community_client_id: communityClientIdValue
            })
        });
    }).then(response => {
        if (response.ok) {
            console.log('Community Client ID updated successfully');
            alert('Community Client ID updated successfully.');
        } else {
            console.error('Failed to update Community Client ID');
            alert('Failed to update Community Client ID.');
        }
    }).catch(error => {
        console.error('Error updating Community Client ID:', error);
        alert('Error updating Community Client ID.');
    });
}

export function setSubCommunity() {
    const subCommunityInput = document.getElementById('sub-community-input'); // Assuming there's an input field for Sub Community
    const subCommunityValue = subCommunityInput.value;

    if (!subCommunityValue) {
        alert('Please enter a valid Sub Community.');
        return;
    }

    // Assuming you have a function to make requests to your server
    makeRequestWithTokenRefresh(async (token) => {
        return fetch(`${API_URL}/set_sub_community`, {
            method: 'POST',
            headers: createAuthorizedHeaders(token),
            body: JSON.stringify({
                sub_community: subCommunityValue
            })
        });
    }).then(response => {
        if (response.ok) {
            console.log('Sub Community updated successfully');
            alert('Sub Community updated successfully.');
        } else {
            console.error('Failed to update Sub Community');
            alert('Failed to update Sub Community.');
        }
    }).catch(error => {
        console.error('Error updating Sub Community:', error);
        alert('Error updating Sub Community.');
    });
}

export function setCommunityApiToken() {
    const communityApiTokenInput = document.getElementById('community-api-token-input'); // Assuming there's an input field for Community API Token
    const communityApiTokenValue = communityApiTokenInput.value;

    if (!communityApiTokenValue) {
        alert('Please enter a valid Community API Token.');
        return;
    }

    // Assuming you have a function to make requests to your server
    makeRequestWithTokenRefresh(async (token) => {
        return fetch(`${API_URL}/set_community_api_token`, {
            method: 'POST',
            headers: createAuthorizedHeaders(token),
            body: JSON.stringify({
                community_api_token: communityApiTokenValue
            })
        });
    }).then(response => {
        if (response.ok) {
            console.log('Community API Token updated successfully');
            alert('Community API Token updated successfully.');
        } else {
            console.error('Failed to update Community API Token');
            alert('Failed to update Community API Token.');
        }
    }).catch(error => {
        console.error('Error updating Community API Token:', error);
        alert('Error updating Community API Token.');
    });
}


export function toggleTestMode() {
    const checkbox = document.getElementById('test-mode-checkbox');
    const isTestModeEnabled = checkbox.checked;

    // Assuming you have a function to make requests to your server
    makeRequestWithTokenRefresh(async (token) => {
        return fetch(`${API_URL}/set_test_mode`, {
            method: 'POST',
            headers: createAuthorizedHeaders(token),
            body: JSON.stringify({
                test_mode: isTestModeEnabled
            })
        });
    }).then(response => {
        if (response.ok) {
            console.log('Test mode updated successfully');
        } else {
            console.error('Failed to update test mode');
        }
    });
}

