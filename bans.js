const bannedIds = new Set();

async function isBanned(deviceId) {
    return bannedIds.has(deviceId);
}

async function banDevice(deviceId) {
    bannedIds.add(deviceId);
}

module.exports = { isBanned, banDevice };