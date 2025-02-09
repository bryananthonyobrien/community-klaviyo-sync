export let stripe;

export function initializeStripe() {
    // Retrieve the Stripe Publishable Key from the input field
    const stripePublishableKey = document.getElementById('stripe-publishable-key-input').value;

    if (!stripePublishableKey) {
        console.error("Stripe Publishable Key is not set.");
        return;
    }

    if (typeof Stripe !== 'undefined') {
        // Initialize Stripe with the dynamic publishable key
        stripe = Stripe(stripePublishableKey); 
        console.log('Stripe initialized with the key:', stripePublishableKey);
    } else {
        console.error('Stripe.js not loaded');
    }
}


