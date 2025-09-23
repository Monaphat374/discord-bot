// uptimekuma.js
// Fetches monitor list from UptimeKuma API
// Usage: require('./uptimekuma').getMonitors(apiUrl, apiToken)

const axios = require('axios'); // npm install axios

async function getMonitors(apiUrl, apiToken) {
    try {
        const res = await axios.post(
            apiUrl + '/api/login',
            { username: apiToken.username, password: apiToken.password },
            { withCredentials: true }
        );
        const cookies = res.headers['set-cookie'];
        const monitorsRes = await axios.get(apiUrl + '/api/monitor', {
            headers: { Cookie: cookies.join('; ') },
            withCredentials: true
        });
        return monitorsRes.data.monitors || [];
    } catch (err) {
        return [];
    }
}

module.exports = { getMonitors };
