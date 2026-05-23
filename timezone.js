// Initialize timezone handling when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    convertAllTimesToLocal();
    setupRealtimeClock();
});

/**
 * Convert all elements with data-utc attribute to local time
 */
function convertAllTimesToLocal() {
    // Convert elements with data-utc attribute
    document.querySelectorAll('[data-utc]').forEach(el => {
        const utcTime = el.getAttribute('data-utc');
        if (utcTime) {
            const localTime = formatToLocalTime(utcTime);
            el.textContent = localTime;
        }
    });

    // Convert elements with data-timestamp attribute (Unix timestamp)
    document.querySelectorAll('[data-timestamp]').forEach(el => {
        const timestamp = el.getAttribute('data-timestamp');
        if (timestamp) {
            const localTime = formatUnixToLocalTime(parseInt(timestamp));
            el.textContent = localTime;
        }
    });

    // Convert ISO format times (with Z suffix)
    document.querySelectorAll('[data-iso]').forEach(el => {
        const isoTime = el.getAttribute('data-iso');
        if (isoTime) {
            const localTime = formatISOTime(isoTime);
            el.textContent = localTime;
        }
    });
}

/**
 * Format UTC time string to local time
 * @param {string} utcTime - UTC time string (YYYY-MM-DD HH:MM:SS or ISO format)
 * @returns {string} Formatted local time
 */
function formatToLocalTime(utcTime) {
    try {
        // Ensure the time is treated as UTC
        let date;
        if (utcTime.includes('T') || utcTime.includes('Z')) {
            // ISO format
            date = new Date(utcTime);
        } else {
            // SQLite format: YYYY-MM-DD HH:MM:SS
            // Append Z to indicate UTC
            date = new Date(utcTime + 'Z');
        }

        if (isNaN(date.getTime())) {
            return utcTime; // Return original if parsing fails
        }

        // Format using browser's locale
        return date.toLocaleString(undefined, {
            year: 'numeric',
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit',
            hour12: true
        });
    } catch (e) {
        console.error('Time conversion error:', e);
        return utcTime;
    }
}

/**
 * Format Unix timestamp to local time
 * @param {number} timestamp - Unix timestamp in seconds or milliseconds
 * @returns {string} Formatted local time
 */
function formatUnixToLocalTime(timestamp) {
    try {
        // Detect if timestamp is in seconds or milliseconds
        if (timestamp < 10000000000) {
            timestamp = timestamp * 1000; // Convert to milliseconds
        }
        
        const date = new Date(timestamp);
        return date.toLocaleString(undefined, {
            year: 'numeric',
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit',
            hour12: true
        });
    } catch (e) {
        console.error('Unix time conversion error:', e);
        return timestamp;
    }
}

/**
 * Format ISO time string to local time
 * @param {string} isoTime - ISO 8601 time string
 * @returns {string} Formatted local time
 */
function formatISOTime(isoTime) {
    try {
        const date = new Date(isoTime);
        if (isNaN(date.getTime())) {
            return isoTime;
        }
        
        return date.toLocaleString(undefined, {
            year: 'numeric',
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
            hour12: true,
            timeZoneName: 'short'
        });
    } catch (e) {
        console.error('ISO time conversion error:', e);
        return isoTime;
    }
}

/**
 * Format time for recent orders (relative time)
 * @param {string} utcTime - UTC time string
 * @returns {string} Relative time (e.g., "5 minutes ago")
 */
function formatRelativeTime(utcTime) {
    try {
        let date;
        if (utcTime.includes('T') || utcTime.includes('Z')) {
            date = new Date(utcTime);
        } else {
            date = new Date(utcTime + 'Z');
        }
        
        const now = new Date();
        const diffMs = now - date;
        const diffMins = Math.floor(diffMs / 60000);
        const diffHours = Math.floor(diffMs / 3600000);
        const diffDays = Math.floor(diffMs / 86400000);
        
        if (diffMins < 1) {
            return 'Just now';
        } else if (diffMins < 60) {
            return `${diffMins} minute${diffMins > 1 ? 's' : ''} ago`;
        } else if (diffHours < 24) {
            return `${diffHours} hour${diffHours > 1 ? 's' : ''} ago`;
        } else if (diffDays < 7) {
            return `${diffDays} day${diffDays > 1 ? 's' : ''} ago`;
        } else {
            return date.toLocaleDateString();
        }
    } catch (e) {
        return utcTime;
    }
}

/**
 * Setup realtime clock display in header if needed
 */
function setupRealtimeClock() {
    // Add current time to header if element exists
    const clockEl = document.getElementById('realtime-clock');
    if (clockEl) {
        setInterval(() => {
            clockEl.textContent = new Date().toLocaleTimeString(undefined, {
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit'
            });
        }, 1000);
    }
}

/**
 * Get client's timezone info
 * @returns {Object} Timezone information
 */
function getClientTimezoneInfo() {
    return {
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
        offset: new Date().getTimezoneOffset(),
        offsetHours: -(new Date().getTimezoneOffset() / 60),
        locale: navigator.language || navigator.userLanguage
    };
}

/**
 * Convert local time to UTC for sending to server
 * @param {Date} localDate - Local date object
 * @returns {string} ISO 8601 UTC string
 */
function localToUTC(localDate) {
    return localDate.toISOString();
}

/**
 * Format currency based on locale
 * @param {number} amount - Amount to format
 * @param {string} currency - Currency code (default: PHP)
 * @returns {string} Formatted currency string
 */
function formatCurrency(amount, currency = 'PHP') {
    return new Intl.NumberFormat(undefined, {
        style: 'currency',
        currency: currency
    }).format(amount);
}

// Export functions for use in other scripts
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        formatToLocalTime,
        formatUnixToLocalTime,
        formatISOTime,
        formatRelativeTime,
        getClientTimezoneInfo,
        localToUTC,
        formatCurrency
    };
}
