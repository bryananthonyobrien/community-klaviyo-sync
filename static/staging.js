import { makeRequestWithTokenRefresh } from '/static/helpers.js';
import { API_URL } from '/static/helpers.js';
import { createAuthorizedHeaders } from '/static/helpers.js';
import { logError } from '/static/helpers.js';

function enableDownloadButtons() {
    const stage1Path = localStorage.getItem('stage1Path');
    const stage1DroppedPath = localStorage.getItem('stage1DroppedPath');
    const stage2Path = localStorage.getItem('stage2Path');

    // Enable buttons based on the existence of paths
    document.getElementById('download-failed-profiles').disabled = !stage1DroppedPath;
    document.getElementById('download-eligible-profiles').disabled = !stage1Path;
    document.getElementById('download-passed-profiles').disabled = !stage1Path;
    document.getElementById('download-members-not-in-klaviyo').disabled = !stage2Path;
}

export async function createStagingFiles() {
    const accessToken = localStorage.getItem('access_token');
    console.info('Access Token:', accessToken); // Debug: log the access token

    if (!accessToken) {
        console.info('No access token available');
        alert('No access token available. Please login first.');
        return;
    }

    // Get the button and spinner elements
    const button = document.getElementById('create-staging-files-button');
    const spinner = document.getElementById('clash-loading-spinner'); // Use the spinner for the "Clash Members and Profiles" tab

    // Disable the button and show the spinner
    if (button) {
        button.classList.add('busy-button'); // Add busy-button class for grey color
        button.disabled = true; // Disable the button
        console.info('Button disabled and busy-spinner displayed.'); // Debug: log button state
    }

    if (spinner) {
        spinner.style.display = 'block';  // Show the spinner
        console.info('Loading spinner displayed.'); // Debug: log spinner state
    } else {
        console.info('Spinner element not found.');
    }

    // Create a request function to create staging files
    const requestFn = async (token) => {
        console.info('Creating fetch request to create staging files.'); // Debug: log request creation
        return fetch(`${API_URL}/create_stage_csv_files`, {
            method: 'POST',
            headers: createAuthorizedHeaders(token)
        });
    };

    try {
        const response = await makeRequestWithTokenRefresh(requestFn);
        console.info("Raw Response:", response); // Debug: log the raw response

        if (response && response.ok) {
            const data = await response.json();
            console.debug("Response JSON:", data); // Debug: log the parsed JSON response

            // Ensure we have a success response
            if (data.success) {
                console.debug('Staging files created successfully:', data); // Debug: log success message
                const stageData = data.data; // Use directly as data is not an array

                // Save paths to local storage
                localStorage.setItem('stage1Path', stageData['stage1.csv'].path);
                localStorage.setItem('stage1DroppedPath', stageData['stage1_dropped.csv'].path);
                localStorage.setItem('stage2Path', stageData['stage2.csv'].path);
                console.debug('Paths saved to local storage:', {
                    stage1Path: stageData['stage1.csv'].path,
                    stage1DroppedPath: stageData['stage1_dropped.csv'].path,
                    stage2Path: stageData['stage2.csv'].path
                });

                // Enable buttons if paths exist
                enableDownloadButtons();

                // Update the drop counts for stage1_dropped.csv
                const dropCounts = stageData['stage1_dropped.csv'].drop_counts || {};
                console.debug('Drop Counts:', dropCounts); // Debug: log drop counts

                document.getElementById('invalid-format').textContent = dropCounts['Invalid format'] || 0;
                document.getElementById('too-short').textContent = dropCounts['Too short'] || 0;
                document.getElementById('too-long').textContent = dropCounts['Too long'] || 0;
                document.getElementById('duplicates').textContent = dropCounts['Older duplicate'] || 0;
                document.getElementById('invalid-length').textContent = dropCounts['Invalid length for +1'] || 0;

                // Update the totals
                const totalDropped = Object.values(dropCounts).reduce((a, b) => a + b, 0);
                document.getElementById('total-failed').textContent = totalDropped;

                // Update the passed quality check counts
                const channelCounts = stageData['stage1.csv'].channel_counts || {};
                document.getElementById('sms-passed').textContent = channelCounts['SMS'] || 0;
                document.getElementById('whatsapp-passed').textContent = channelCounts['WhatsApp'] || 0;
                document.getElementById('total-passed').textContent = stageData['stage1.csv'].row_count || 0;

                // Update the already_member counts
                const alreadyMemberData = stageData['stage1.csv'].already_member?.['TRUE'];
                if (alreadyMemberData) {
                    const liveCounts = alreadyMemberData.subscription_state?.live || {};
                    document.getElementById('live-sms').textContent = liveCounts['SMS'] || 0;
                    document.getElementById('live-whatsapp').textContent = liveCounts['WhatsApp'] || 0;
                    document.getElementById('live-total').textContent = (liveCounts['SMS'] || 0) + (liveCounts['WhatsApp'] || 0);

                    const optedOutCounts = alreadyMemberData.subscription_state?.opted_out || {};
                    document.getElementById('optout-sms').textContent = optedOutCounts['SMS'] || 0;
                    document.getElementById('optout-whatsapp').textContent = 0; // Default to 0
                    document.getElementById('optout-total').textContent = (optedOutCounts['SMS'] || 0) + 0; // Total opted out

                    // Update the total counts
                    document.getElementById('total-sms').textContent = (liveCounts['SMS'] || 0) + (optedOutCounts['SMS'] || 0);
                    document.getElementById('total-whatsapp').textContent = (liveCounts['WhatsApp'] || 0) + 0;
                    document.getElementById('total-community').textContent = alreadyMemberData.total || 0;
                }

                // Update the eligible counts
                const notAlreadyMemberData = stageData['stage1.csv'].already_member?.['FALSE'];
                if (notAlreadyMemberData) {
                    document.getElementById('eligible-sms').textContent = notAlreadyMemberData.channel?.['SMS'] || 0;
                    document.getElementById('eligible-whatsapp').textContent = notAlreadyMemberData.channel?.['WhatsApp'] || 0;
                    document.getElementById('eligible-total').textContent = notAlreadyMemberData.total || 0;
                }

                // Update the member counts from stage2.csv
                const stage2Data = stageData['stage2.csv'];
                if (stage2Data) {
                    document.getElementById('members-not-in-klayvio-live-sms').textContent = stage2Data.channel_counts?.['Text']?.subscription_state?.['live'] || 0;
                    document.getElementById('members-not-in-klayvio-live-whatsapp').textContent = stage2Data.channel_counts?.['WhatsApp']?.subscription_state?.['live'] || 0;
                    document.getElementById('members-not-in-klayvio-live-total').textContent =
                        (stage2Data.channel_counts?.['Text']?.subscription_state?.['live'] || 0) +
                        (stage2Data.channel_counts?.['WhatsApp']?.subscription_state?.['live'] || 0);

                    document.getElementById('members-not-in-klayvio-optout-sms').textContent = stage2Data.channel_counts?.['Text']?.subscription_state?.['opted_out'] || 0;
                    document.getElementById('members-not-in-klayvio-optout-whatsapp').textContent = stage2Data.channel_counts?.['WhatsApp']?.subscription_state?.['opted_out'] || 0;
                    document.getElementById('members-not-in-klayvio-optout-total').textContent =
                        (stage2Data.channel_counts?.['Text']?.subscription_state?.['opted_out'] || 0) +
                        (stage2Data.channel_counts?.['WhatsApp']?.subscription_state?.['opted_out'] || 0);

                    document.getElementById('members-not-in-klayvio-total-sms').textContent = stage2Data.channel_counts?.['Text']?.total || 0;
                    document.getElementById('members-not-in-klayvio-total-whatsapp').textContent = stage2Data.channel_counts?.['WhatsApp']?.total || 0;
                    document.getElementById('members-not-in-klayvio-total').textContent = stage2Data.row_count || 0;
                }


            } else {
                console.error('Create Staging Files request failed:', data); // Debug: log failure
                alert('Failed to create staging files');
            }
        } else if (response && response.status === 401) {
            console.info('Unauthorized: Token information not found');
            alert('Session expired. Please log in again.');
        } else {
            const errorResponse = await response.json();
            console.info('Error creating staging files:', errorResponse); // Debug: log error response
            alert('Failed to create staging files');
        }
    } catch (error) {
        console.info('Error in createStagingFiles:', error); // Debug: log catch error
        logError('Create Staging Files', error); // Log the error for further analysis
    } finally {
        // Hide the spinner and re-enable the button when the request is done
        if (spinner) {
            spinner.style.display = 'none';
            console.info('Loading spinner hidden.'); // Debug: log spinner hidden
        }
        if (button) {
            button.classList.remove('busy-button'); // Remove busy-button class
            button.disabled = false; // Re-enable the button
            console.info('Button re-enabled.'); // Debug: log button re-enabled
        }
    }
}


