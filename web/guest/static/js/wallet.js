/**
 * AirFi Wallet Utilities
 * Simple address validation for manual input flow.
 */

const AirFiWallet = {
    /**
     * Validate a CKB address.
     * @param {string} address - The address to validate.
     * @returns {boolean} True if valid.
     */
    validateAddress(address) {
        if (!address || typeof address !== 'string') {
            return false;
        }

        // CKB testnet addresses start with ckt1
        if (address.startsWith('ckt1')) {
            return address.length >= 40;
        }

        // CKB mainnet addresses start with ckb1
        if (address.startsWith('ckb1')) {
            return address.length >= 40;
        }

        return false;
    },

    /**
     * Truncate address for display.
     * @param {string} address - Full address.
     * @param {number} startChars - Characters to show at start.
     * @param {number} endChars - Characters to show at end.
     * @returns {string} Truncated address.
     */
    truncateAddress(address, startChars = 8, endChars = 6) {
        if (!address || address.length <= startChars + endChars) {
            return address;
        }
        return `${address.slice(0, startChars)}...${address.slice(-endChars)}`;
    },

    /**
     * Format CKB amount with commas.
     * @param {number|string} amount - Amount in CKBytes.
     * @returns {string} Formatted amount.
     */
    formatAmount(amount) {
        const num = typeof amount === 'string' ? parseInt(amount, 10) : amount;
        return num.toLocaleString();
    },

    /**
     * Calculate duration from CKB amount.
     * @param {number} amount - Amount in CKBytes.
     * @param {number} ratePerMinute - CKB per minute rate.
     * @returns {string} Human-readable duration.
     */
    calculateDuration(amount, ratePerMinute = 1) {
        const minutes = Math.floor(amount / ratePerMinute);
        const hours = Math.floor(minutes / 60);
        const remainingMinutes = minutes % 60;

        if (hours > 0 && remainingMinutes > 0) {
            return `${hours}h ${remainingMinutes}m`;
        } else if (hours > 0) {
            return `${hours}h`;
        } else if (remainingMinutes > 0) {
            return `${remainingMinutes}m`;
        }
        return '< 1m';
    },

    /**
     * Parse duration string to minutes.
     * @param {string} duration - Duration string like "1h30m" or "45m".
     * @returns {number} Duration in minutes.
     */
    parseDuration(duration) {
        const hourMatch = duration.match(/(\d+)h/);
        const minMatch = duration.match(/(\d+)m/);

        let minutes = 0;
        if (hourMatch) minutes += parseInt(hourMatch[1], 10) * 60;
        if (minMatch) minutes += parseInt(minMatch[1], 10);

        return minutes;
    },
};

// Export for global use
window.AirFiWallet = AirFiWallet;
