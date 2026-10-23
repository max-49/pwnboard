// Helpers for pages that call the JSON API.

// A readable message for a failed API response. The API answers errors as
// {"error": {"code": ..., "message": ..., "details": [...]}}.
async function apiErrorMessage(res, fallback) {
    try {
        const body = await res.clone().json();
        if (body && body.error && body.error.message) return body.error.message;
    } catch (e) { /* not JSON */ }
    return fallback;
}

// The list of individual problems in a failed API response, or an empty list.
async function apiErrorDetails(res) {
    try {
        const body = await res.clone().json();
        if (body && body.error && Array.isArray(body.error.details)) return body.error.details;
    } catch (e) { /* not JSON */ }
    return [];
}

// Send the user to the login page if their session has ended. Returns true if it did.
function redirectIfSessionExpired(res) {
    if (res.status === 401) {
        window.location.href = '/';
        return true;
    }
    return false;
}
