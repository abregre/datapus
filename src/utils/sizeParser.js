function parseSize(sizeString) {
    if (!sizeString) {
        throw new Error("Invalid size string: empty or null");
    }

    const regex = /^(\d+(\.\d+)?)\s*(B|KB|MB|GB|TB)$/i;
    const match = sizeString.match(regex);

    if (!match) {
        throw new Error(`Invalid size format: "${sizeString}"`);
    }

    const value = parseFloat(match[1]);
    const unit = match[3].toUpperCase();

    const multipliers = {
        B: 1,
        KB: 1024,
        MB: 1024 * 1024,
        GB: 1024 * 1024 * 1024,
        TB: 1024 * 1024 * 1024 * 1024,
    };

    return Math.round(value * multipliers[unit]);
}

module.exports = {
    parseSize,
};