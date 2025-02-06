export let stripe;

export function initializeStripe() {
    if (typeof Stripe !== 'undefined') {
        stripe = Stripe('pk_test_51LuEURDlGWelEs72T4s5jVw6TCXeK7x17O8EOz7eblhAwVko1hILuqtRhcfBBqWDVsW2hXzrqqcpKSrW3fYiuapb00V2ctz4ip'); // Replace with your Stripe publishable key
        console.log('Initialised Stripe');
    } else {
        console.error('Stripe.js not loaded');
    }
}


