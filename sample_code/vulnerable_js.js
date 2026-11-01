// Sample vulnerable Node.js / JavaScript application
const child_process = require('child_process');

// Hardcoded GitHub Token
const GITHUB_TOKEN = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";

// DOM-Based Cross-Site Scripting (XSS)
function renderUserProfile(container, userInput) {
    // Dangerous innerHTML assignment
    container.innerHTML = "<h1>Welcome " + userInput + "</h1>";
}

// OS Command Injection
function checkNetworkHost(host) {
    // Dynamic command string allows semicolon chaining
    child_process.exec("ping -c 1 " + host, (err, stdout, stderr) => {
        console.log(stdout);
    });
}

// Insecure Code Execution
function parseUserExpression(expression) {
    return eval(expression);
}

module.exports = { renderUserProfile, checkNetworkHost, parseUserExpression };
