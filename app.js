// index.js
const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const { v4: uuidv4 } = require('uuid'); // For generating unique IDs
require('dotenv').config(); // Load environment variables from .env file
const axios = require('axios'); // Add axios

const app = express();
const port = process.env.PORT || 3000;

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'your-secret-key', // Use a strong, randomly generated secret in production
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false } // Set to true in HTTPS environments
}));
app.use(express.json());


// In-memory storage (for demo purposes - replace with a database in production)
const clients = {}; // Registered clients
const users = {
  'user1': 'password123',
  'user2': 'anotherpassword'
}; // Replace with proper user authentication
const accessTokens = {}; // Store access tokens (key: token, value: user)
const authorizationCodes = {}; // Store authorization codes (key: code, value: {client_id, redirect_uri, user})

// --- Routes ---

// 3. Client Registration (Endpoint to Register OAuth Clients)
app.post('/register', (req, res) => {
    const client_id = uuidv4();
    const client_secret = uuidv4();
    const redirect_uris = req.body.redirect_uris || [];

    clients[client_id] = {
        client_secret: client_secret,
        redirect_uris: redirect_uris
    };

    res.json({
        client_id: client_id,
        client_secret: client_secret
    });
});

// 4. Authorization Endpoint (User Login and Grant Permission)
app.get('/authorize', (req, res) => {
    const { client_id, redirect_uri, response_type } = req.query;

    if (!client_id || !redirect_uri || !response_type) {
        return res.status(400).send('Missing parameters');
    }

    if (!clients[client_id] || !clients[client_id].redirect_uris.includes(redirect_uri)) {
        return res.status(400).send('Invalid client or redirect URI');
    }

    // Store client_id and redirect_uri in the session for later use
    req.session.client_id = client_id;
    req.session.redirect_uri = redirect_uri;
    req.session.response_type = response_type;

    // Simulate a login form
    let loginForm = `
    <!DOCTYPE html>
    <html>
    <head><title>Login</title></head>
    <body>
        <h1>Login</h1>
        <form method="POST" action="/login">
            <input type="hidden" name="client_id" value="${client_id}">
            <input type="hidden" name="redirect_uri" value="${redirect_uri}">
            <input type="hidden" name="response_type" value="${response_type}">
            <label>Username:</label><input type="text" name="username"><br><br>
            <label>Password:</label><input type="password" name="password"><br><br>
            <button type="submit">Login</button>
        </form>
    </body>
    </html>
    `;
    res.send(loginForm);
});

app.post('/login', async (req, res) => { // Make the handler async
    const { username, password, client_id, redirect_uri, response_type } = req.body;

    // --- CALL USER SERVICE TO AUTHENTICATE ---
    try {
        const userServiceUrl = process.env.USER_SERVICE_URL || 'http://localhost:3001'; // Get URL from env or default
        const authResponse = await axios.post(`${userServiceUrl}/authenticate`, {
            identifier: username, // User service expects 'identifier'
            password: password
        });

        // Check if authentication was successful (User service returns 200 on success)
        if (authResponse.status === 200 && authResponse.data && authResponse.data.userId) {
            // User is authenticated by the User Service.
            // Store the USER ID from the user service in the session.
            req.session.userId = authResponse.data.userId; // Store the actual User ID
            req.session.username = authResponse.data.username; // Keep username for display if needed

            // Now, show the consent form
            let consentForm = `
            <!DOCTYPE html>
            <html>
            <head><title>Consent</title></head>
            <body>
                <h1>Consent</h1>
                <p>Hello ${req.session.username || 'User'}!</p>
                <p>The application <strong>${client_id}</strong> wants permission. Do you allow it?</p>
                <form method="POST" action="/consent">
                    <input type="hidden" name="client_id" value="${client_id}">
                    <input type="hidden" name="redirect_uri" value="${redirect_uri}">
                    <input type="hidden" name="response_type" value="${response_type}">
                    <button type="submit" name="allow" value="true">Allow</button>
                    <button type="submit" name="allow" value="false">Deny</button>
                </form>
            </body>
            </html>
            `;
            res.send(consentForm);

        } else {
            // Should not happen if user service returns correct codes, but handle defensively
             console.error("Authentication failed - Unexpected response from user service:", authResponse.status, authResponse.data);
            return res.status(401).send('Authentication failed via User Service.');
        }

    } catch (error) {
        // Handle errors from the User Service call
        if (error.response && error.response.status === 401) {
            // User service indicated invalid credentials
            return res.status(401).send('Invalid username or password.');
        } else {
            // Other errors (network, user service down, etc.)
            console.error("Error calling User Service:", error.message);
             if (error.response) {
                console.error("User Service Response:", error.response.status, error.response.data);
            }
            return res.status(500).send('An error occurred during authentication.');
        }
    }
    // --- END USER SERVICE CALL ---

    /* Remove the old direct password check:
    if (users[username] !== password) {
        return res.status(401).send('Invalid username or password');
    }
    req.session.username = username;
    // ... rest of the old consent form logic ...
    */
});


app.post('/consent', (req, res) => {
    const { allow, client_id, redirect_uri, response_type } = req.body;
    const userId = req.session.userId; // Use userId stored from successful login

    // Make sure user is actually logged in via session
    if (!userId) {
       console.error("Consent attempt without valid session/userId");
       // Redirect to login or show error
       return res.status(400).send("Session expired or invalid. Please log in again.");
    }

    if (allow === 'true') {
        const authorization_code = uuidv4();
        authorizationCodes[authorization_code] = {
            client_id: client_id,
            redirect_uri: redirect_uri,
            userId: userId // Store the actual user ID
        };
        const redirectURL = `${redirect_uri}?code=${authorization_code}`;
        res.redirect(redirectURL);
    } else {
        const redirectURL = `${redirect_uri}?error=access_denied`;
        res.redirect(redirectURL);
    }
});


// 5. Token Endpoint (Exchange Authorization Code for Access Token)
app.post('/token', (req, res) => {
    console.log('[OAuth Server /token] Received request.');
    // Avoid logging secrets directly in production logs if possible
    // Consider logging only keys or presence of sensitive fields
    // console.log('[OAuth Server /token] Request Body:', req.body); // Be cautious logging body if it contains secrets

    const { grant_type, code, redirect_uri, client_id, client_secret } = req.body;
    console.log(`[OAuth Server /token]   -> grant_type: ${grant_type}`);
    console.log(`[OAuth Server /token]   -> code: ${code}`);
    console.log(`[OAuth Server /token]   -> redirect_uri: ${redirect_uri}`);
    console.log(`[OAuth Server /token]   -> client_id: ${client_id}`);
    console.log(`[OAuth Server /token]   -> client_secret: ${client_secret ? '*** Present ***' : '!!! MISSING !!!'}`);

    // --- Validation Steps ---

    // 1. Validate grant_type
    if (grant_type !== 'authorization_code') {
        console.error(`[OAuth Server /token] Validation Fail: Invalid grant_type [${grant_type}]`);
        return res.status(400).json({ error: 'unsupported_grant_type', error_description: 'Only authorization_code grant type is supported' });
    }

    // 2. Validate Authorization Code
    const authCodeData = authorizationCodes[code];
    console.log(`[OAuth Server /token] Code lookup for [${code}]: ${authCodeData ? 'Found' : '!!! NOT Found or Expired !!!'}`);
    if (!authCodeData) {
        console.error(`[OAuth Server /token] Validation Fail: Authorization code [${code}] not found, likely expired or invalid.`);
        // Note: spec recommends 'invalid_grant' for invalid/expired codes
        return res.status(400).json({ error: 'invalid_grant', error_description: 'Authorization code is invalid, expired, or already used' });
    }
    console.log(`[OAuth Server /token]   -> Stored data for code [${code}]:`, authCodeData);


    // 3. Validate Client ID against Code Data
    console.log(`[OAuth Server /token] Comparing client_id: Received [${client_id}] vs Stored [${authCodeData.client_id}]`);
    if (authCodeData.client_id !== client_id) {
        console.error(`[OAuth Server /token] Validation Fail: client_id [${client_id}] does not match code's client_id [${authCodeData.client_id}]`);
        return res.status(400).json({ error: 'invalid_grant', error_description: 'Client ID mismatch for the provided code' });
    }

    // 4. Validate Redirect URI against Code Data
    console.log(`[OAuth Server /token] Comparing redirect_uri: Received [${redirect_uri}] vs Stored [${authCodeData.redirect_uri}]`);
    if (authCodeData.redirect_uri !== redirect_uri) {
        console.error(`[OAuth Server /token] Validation Fail: redirect_uri [${redirect_uri}] does not match code's redirect_uri [${authCodeData.redirect_uri}]`);
        return res.status(400).json({ error: 'invalid_grant', error_description: 'Redirect URI mismatch for the provided code' });
    }

    // 5. Validate Client Authentication (Client ID & Secret)
    const clientData = clients[client_id];
    console.log(`[OAuth Server /token] Client lookup for [${client_id}]: ${clientData ? 'Found' : '!!! NOT Found !!!'}`);
    if (!clientData) {
         console.error(`[OAuth Server /token] Authentication Fail: Invalid client_id [${client_id}]`);
         // 'invalid_client' is appropriate when client cannot be authenticated
         return res.status(401).json({error: 'invalid_client', error_description: 'Client authentication failed (invalid client ID)'});
    }

    // Compare secrets
    const isSecretValid = clientData.client_secret === client_secret;
    console.log(`[OAuth Server /token] Comparing client_secret: ${isSecretValid ? 'Match' : '!!! MISMATCH !!!'}`);
    if (!isSecretValid) {
      console.error(`[OAuth Server /token] Authentication Fail: Invalid client_secret for client_id [${client_id}]`);
      return res.status(401).json({error: 'invalid_client', error_description: 'Client authentication failed (invalid client secret)'});
    }

    // --- All Validations Passed ---
    console.log(`[OAuth Server /token] All validations passed for code [${code}] and client [${client_id}]`);

    // Generate an access token
    const access_token = uuidv4();
    const tokenExpiryTime = Date.now() + (3600 * 1000); // 1 hour from now
    const expiresInSeconds = 3600;

    accessTokens[access_token] = {
        userId: authCodeData.userId, // Make sure userId was stored correctly during /consent
        clientId: client_id,
        expires: tokenExpiryTime
    };
    console.log(`[OAuth Server /token] Generated access token [${access_token.substring(0,8)}...] for user [${authCodeData.userId}]`);
    console.log(`[OAuth Server /token]   -> Stored token data:`, accessTokens[access_token]);


    // Remove the authorization code (it's single-use) *after* successful validation
    delete authorizationCodes[code];
    console.log(`[OAuth Server /token] Deleted used authorization code [${code}]`);

    // Return the successful token response
    console.log('[OAuth Server /token] Sending successful token response.');
    res.status(200).json({
        access_token: access_token,
        token_type: 'bearer',
        expires_in: expiresInSeconds,
        // Optionally include scope, user_id etc. if needed by the client and granted
        // user_id: authCodeData.userId
    });
});

// 6. Protected Resource Endpoint (Example)
app.get('/resource', (req, res) => {
    const authHeader = req.headers.authorization;
    const accessToken = authHeader?.split(' ')[1]; // Extract token from Authorization: Bearer <token>

    if (!accessToken) {
        return res.status(401).json({ error: 'missing_token' });
    }

    const tokenData = accessTokens[accessToken];

    if (!tokenData || Date.now() > tokenData.expires) {
         // Clean up expired token
         if (tokenData) delete accessTokens[accessToken];
        return res.status(401).json({ error: 'invalid_or_expired_token' });
    }

    // Token is valid, get the user ID
    const userId = tokenData.userId;

    // Here you could potentially fetch more user details from the User Service if needed
    // using the userId, but for now, just return a message with the ID.

    res.json({
        message: `Hello, User ${userId}! This is a protected resource accessed via OAuth.`,
        data: { your_user_id: userId, accessed_by_client: tokenData.clientId }
    });
});


app.listen(port, () => {
    console.log(`OAuth Server listening at http://localhost:${port}`);
});