import { loadCommunityModals } from '/static/scripts.js';
import { repopulateCommunityTable } from '/static/communityFileUpload.js';
import { enableCommunityRowSelection } from '/static/communityFileUpload.js';
import { fetchMembersData } from '/static/communityFileUpload.js';
import { makeRequestWithTokenRefresh } from '/static/helpers.js';
import { API_URL } from '/static/helpers.js';
import { createAuthorizedHeaders } from '/static/helpers.js';
import { loadClientEvents } from '/static/events.js';
import { loadProfiles } from '/static/profiles.js';
import { initializeStripe } from '/static/stripe.js';
import { fetchKlaviyoDiscoveries } from '/static/klaviyo.js';
import { stripe } from '/static/stripe.js';

function pollKlaviyoStatus() {
    const accessToken = localStorage.getItem('access_token');
    if (!accessToken) {
        console.error('No access token available');
        return;
    }

    fetch(`${API_URL}/klaviyo_status`, {
        method: 'GET',
        headers: createAuthorizedHeaders(accessToken)
    })
    .then(response => {
        if (response.status === 404) {
            // Handle the case where the status is missing (e.g., process crashed)
            console.warn('Klaviyo discovery status not found. Process might have crashed or been reset.');
            // Reset the UI and button states
            return null;
        }
        return response.json();
    })
    .then(data => {
        if (!data) return;

        // Handle the 'failed' status in case discovery fails
        if (data.klaviyo_status === 'failed') {
            console.error('Klaviyo discovery has failed.');
            alert('Klaviyo discovery has failed. Please try again.');
            return;  // Exit early after handling the failure
        }

    })
    .catch(error => {
        console.error('Error fetching Klaviyo status:', error);
    });
}

export async function initializePage() {
    console.log("Initializing Client Page...");

    // Retry interval in milliseconds
    const retryInterval = 500;
    const maxRetries = 40;
    let attempts = 0;

    const waitForDependencies = (dependencies) => {
        return new Promise((resolve, reject) => {
            const interval = setInterval(() => {
                const allLoaded = dependencies.every((dep) => typeof dep === "function");
                if (allLoaded) {
                    clearInterval(interval);
                    resolve();
                } else if (++attempts > maxRetries) {
                    clearInterval(interval);
                    reject(new Error("Dependencies not loaded in time."));
                }
            }, retryInterval);
        });
    };

    try {
        // Wait for required dependencies
        await waitForDependencies([repopulateCommunityTable, loadCommunityModals]);
        console.log("1. Dependencies loaded");

        // Ensure the elements are defined before accessing them
        const configurationSpinner = document.getElementById("configuration-spinner");
        const tabButtons = document.querySelectorAll(".tab-button");

        if (configurationSpinner) configurationSpinner.style.display = "inline-block";
        tabButtons.forEach((button) => {
            button.disabled = true;
            button.style.cursor = "not-allowed";
            button.style.backgroundColor = "grey";
        });

        // Step 1: Load configuration
        await loadConfiguration();
        console.log("2. Configuration Loaded");

        // Step 2: Load community modals
        await loadCommunityModals();
        console.log("3. Community Modals Loaded");

        // Step 3: Repopulate community table
        await repopulateCommunityTable("communities");
        console.log("4. Repopulated Community Table");

        // Step 4: Enable community row selection
        enableCommunityRowSelection();
        console.log("5. Enabled Community Row Selection");

        // Step 5: Fetch members data
        await fetchMembersData();
        console.log("6. Fetched Members Data");

        // Additional Logic:
        console.log("Running additional client.html initialization logic...");

        // Add event listener for Load Profiles button
        const loadProfilesButton = document.getElementById("load-profiles");
        if (loadProfilesButton) {
            loadProfilesButton.addEventListener("click", loadProfiles);
            console.log("7. Added listener for Load Profiles button.");
        } else {
            console.log("Load Profiles button not found.");
        }

        // Add event listener for Checkout button
        const checkoutButton = document.getElementById("checkout-button");
        if (checkoutButton) {
            checkoutButton.addEventListener("click", handleCheckout);
            console.log("8. Added listener for Checkout button.");
            initializeStripe();
            console.log("8.1 Stripe Initialized.");
        } else {
            console.log("Checkout button not found.");
        }

        // Fetch past discoveries and check Redis status
        console.log("9. Automatically fetching past discoveries and checking Redis status...");
        fetchKlaviyoDiscoveries();

        // Poll for Klaviyo status
        const discoverKlaviyoButton = document.getElementById("discover-klaviyo-button");
        if (discoverKlaviyoButton) {
            console.log("10. Polling for Klaviyo status...");
            pollKlaviyoStatus();
        }

        console.log("Client Page initialization complete.");
    } catch (error) {
        console.error("Error during initialization:", error);
    } finally {
        // Reset spinner and button states
        const configurationSpinner = document.getElementById("configuration-spinner");
        if (configurationSpinner) configurationSpinner.style.display = "none";
        const tabButtons = document.querySelectorAll(".tab-button");
        tabButtons.forEach((button) => {
            button.disabled = false;
            button.style.cursor = "pointer";
            button.style.backgroundColor = ""; // Reset to original color
        });
    }
}

// Helper function for handling checkout logic
async function handleCheckout() {
    const creditsInput = document.getElementById("credits-input");
    const credits = parseInt(creditsInput.value);

    if (isNaN(credits) || credits < 10000) {
        alert("Minimum number of credits is 10000");
        return;
    }

    const payload = { credits };

    try {
        const response = await makeRequestWithTokenRefresh(async (token) => {
            return fetch(`${API_URL}/create-checkout-session`, {
                method: "POST",
                headers: createAuthorizedHeaders(token),
                body: JSON.stringify(payload),
            });
        });

        if (response.ok) {
            const session = await response.json();
            await stripe.redirectToCheckout({ sessionId: session.id });
            console.log("Checkout completed successfully.");
        } else {
            alert("Checkout process failed. Please try again.");
        }
    } catch (error) {
        console.error("Error during checkout:", error);
    }
}

// Function to load configuration from the server and populate fields
export async function loadConfiguration() {
    try {
        console.log('Loading configuration...');
        const response = await makeRequestWithTokenRefresh(async (token) => {
            return fetch(`${API_URL}/get_configuration`, {
                method: 'GET',
                headers: createAuthorizedHeaders(token),
            });
        });

        const data = await response.json();

        // Populate the input fields with the retrieved configuration values
        document.getElementById('klaviyo-api-key-input').value = data.klaviyo_api_key || '';
        document.getElementById('community-client-id-input').value = data.community_client_id || '';
        document.getElementById('community-api-token-input').value = data.community_api_token || '';
        document.getElementById('max-workers-input').value = data.max_workers || '';
        document.getElementById('sub-community-input').value = data.sub_community || '';
        document.getElementById('stripe-publishable-key-input').value = data.stripe_publishable_key || '';

        console.log('Configuration loaded successfully:', data);

        // Call loadClientEvents using the retrieved community_client_id
        if (data.community_client_id) {
            loadClientEvents(data.community_client_id);
        } else {
            console.info('community_client_id not found in configuration data.');
        }

    } catch (error) {
        console.error('Error fetching configuration:', error);
        alert('Error fetching configuration.');
    }
}

export async function showTab(tabIndex) {
    console.info('Entered showTab : ', tabIndex);

    const tabs = document.querySelectorAll('.tab-content');
    const tabButtons = document.querySelectorAll('.tab-button');
    const activeTabSpinner = tabs[tabIndex].querySelector('.spinner');
    const tabButtonSpinner = tabButtons[tabIndex].querySelector('.button_spinner');

    // Disable all tab buttons and change style
    tabButtons.forEach(button => {
        button.disabled = true;
        button.style.cursor = 'not-allowed';
        button.style.backgroundColor = 'grey';
    });

    // Show the spinner immediately for the selected tab button
    if (tabButtonSpinner) {
        tabButtonSpinner.style.display = 'inline-block';
    }

    // Show the spinner inside the tab content (if applicable)
    if (activeTabSpinner) {
        activeTabSpinner.style.display = 'inline-block';
    }

    // Use a microtask to ensure the spinner is rendered before loading data
    await Promise.resolve().then(() => {
        setTimeout(async () => {
            try {
                // Hide all tab contents and reset button styles
                tabs.forEach(tab => tab.classList.remove('active'));
                tabButtons.forEach(button => {
                    button.classList.remove('active');
                    button.classList.add('inactive'); // Change to grey when inactive
                });

                // Show the selected tab
                tabs[tabIndex].classList.add('active');
                tabButtons[tabIndex].classList.add('active');
                tabButtons[tabIndex].classList.remove('inactive'); // Keep active button color

                // Perform any data-loading operations for the tab here
                if (tabIndex === 6) { // Example: Load Community Data tab
                    // Add tab-specific logic here if needed
                }
            } catch (error) {
                console.error('Error while switching tabs:', error);
            } finally {
                // Hide the spinners and re-enable all tab buttons after loading completes
                if (activeTabSpinner) {
                    activeTabSpinner.style.display = 'none';
                }
                if (tabButtonSpinner) {
                    tabButtonSpinner.style.display = 'none';
                }
                tabButtons.forEach(button => {
                    button.disabled = false;
                    button.style.cursor = 'pointer';
                    button.style.backgroundColor = ''; // Reset to original color
                });
            }
        }, 100); // Slight delay to ensure spinner is rendered before data loads
    });
}
