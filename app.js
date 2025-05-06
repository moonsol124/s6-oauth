// my-oauth-server/index.js
const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const { v4: uuidv4 } = require('uuid');
require('dotenv').config(); // Load environment variables first
const axios = require('axios');
const supabase = require('./supabaseClient'); // <<< Import Supabase client

const app = express();
// Use PORT from env, default to 3000 if not set
const port = process.env.PORT || 3000;

// --- Middleware --- 
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json()); // Add json parser for potentially different client calls
app.use(session({
  // Load secret from environment variable, provide a fallback ONLY for local dev if necessary
  secret: process.env.SESSION_SECRET || 'local-dev-unsafe-secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    // Set secure flag based on environment (true if NODE_ENV is 'production')
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true, // Recommended
    sameSite: 'lax' // Recommended for CSRF protection
  }
}));

// --- Storage ---
// Removed in-memory 'clients' object. Client data is now in Supabase.
// TODO: Persist authorizationCodes and accessTokens (e.g., in Redis or Database)
const authorizationCodes = {}; // Temporary in-memory store
const accessTokens = {}; // Temporary in-memory store

// --- Helper Function to Parse Redirect URIs ---
function parseRedirectUris(input) {
    let uris = [];
    if (typeof input === 'string') {
        uris = input.split(',').map(uri => uri.trim()).filter(uri => uri);
    } else if (Array.isArray(input)) {
        uris = input.filter(uri => typeof uri === 'string' && uri.trim());
    }
    return uris.filter(uri => { // Basic URL validation
        try {
            new URL(uri);
            return true;
        } catch (_) {
            return false;
        }
    });
}


// --- Routes ---

// 1. Client Registration (Uses Supabase)
app.post('/register', async (req, res) => {
    const client_id = uuidv4();
    // WARNING: In a real app, hash the client_secret before storing!
    const client_secret = uuidv4();
    const client_name = req.body.client_name || null;
    const raw_redirect_uris = req.body.redirect_uris;

    const redirect_uris = parseRedirectUris(raw_redirect_uris);

    if (redirect_uris.length === 0) {
        return res.status(400).json({ error: 'At least one valid redirect_uri is required.' });
    }

    console.log(`[OAuth Server /register] Attempting to register client. Name: ${client_name}, URIs: ${redirect_uris.join(', ')}`);

    try {
        const { data, error } = await supabase
            .from('oauth_clients')
            .insert({
                client_id: client_id,
                client_secret: client_secret, // Store plain for now, HASH IN PRODUCTION!
                redirect_uris: redirect_uris,
                client_name: client_name
            })
            .select('client_id') // Only need to confirm insert
            .single();

        if (error) {
            console.error('[OAuth Server /register] Supabase insert error:', error);
            return res.status(500).json({ error: 'Failed to register client', details: error.message });
        }

        if (!data) {
            console.error('[OAuth Server /register] Failed to insert client, no data returned.');
            return res.status(500).json({ error: 'Failed to register client (no data)' });
        }

        console.log(`[OAuth Server /register] Client registered successfully: ${client_id}`);
        // Respond with the generated credentials for the client application
        res.status(201).json({
            client_id: client_id,
            client_secret: client_secret
        });

    } catch (err) {
        console.error('[OAuth Server /register] Server error:', err);
        res.status(500).json({ error: 'Internal server error during registration' });
    }
});

// 2. Authorization Endpoint (Uses Supabase for Client Validation)
app.get('/authorize', async (req, res) => {
    const { client_id, redirect_uri, response_type, scope, state } = req.query; // Added scope and state
    console.log(`[OAuth Server /authorize] Request received. Client: ${client_id}, Redirect URI: ${redirect_uri}, Type: ${response_type}, Scope: ${scope}, State: ${state}`);

    if (!client_id || !redirect_uri || !response_type) {
        console.warn('[OAuth Server /authorize] Missing parameters.');
        // TODO: Redirect back to client with error if possible/safe
        return res.status(400).send('Missing required parameters: client_id, redirect_uri, response_type');
    }

    if (response_type !== 'code') {
         console.warn(`[OAuth Server /authorize] Unsupported response_type: ${response_type}`);
         return res.status(400).send('Unsupported response_type. Only "code" is supported.');
    }

    try {
        // Fetch client details from Supabase
        const { data: clientData, error: dbError } = await supabase
            .from('oauth_clients')
            .select('client_id, redirect_uris')
            .eq('client_id', client_id)
            .maybeSingle();

        if (dbError) {
            console.error(`[OAuth Server /authorize] Supabase error fetching client [${client_id}]:`, dbError);
            return res.status(500).send('Error validating client information.');
        }

        // Validate client and redirect URI
        let isValidClient = false;
        if (clientData && Array.isArray(clientData.redirect_uris)) {
             console.log(`[OAuth Server /authorize] Found client [${client_id}]. Allowed URIs:`, clientData.redirect_uris);
             isValidClient = clientData.redirect_uris.includes(redirect_uri);
             console.log(`[OAuth Server /authorize] Checking redirect URI [${redirect_uri}]: ${isValidClient ? 'VALID' : 'INVALID'}`);
        } else {
            console.warn(`[OAuth Server /authorize] Client [${client_id}] not found or redirect URIs misconfigured.`);
        }

        if (!isValidClient) {
            // TODO: Consider security implications of revealing invalid client vs invalid URI
            return res.status(400).send('Invalid client_id or redirect_uri.');
        }

        // --- Client is valid, proceed ---

        // Store necessary info in session to survive login/consent steps
        req.session.oauth = {
            client_id: client_id,
            redirect_uri: redirect_uri,
            response_type: response_type,
            scope: scope, // Store requested scope
            state: state // Store state parameter
        };
        console.log('[OAuth Server /authorize] Session data stored:', req.session.oauth);


        // --- Redirect to Login Form ---
        // In a real app, check if user is *already* logged in via session.
        // If logged in, skip to consent. If not, show login.
        console.log(`[OAuth Server /authorize] Client valid, proceeding to login form.`);
        let loginForm = `
        <!DOCTYPE html>
        <html>
        <head><title>Login</title></head>
        <body>
            <h1>Login to Grant Access</h1>
            <p>Application <strong>${client_id}</strong> wants access.</p>
            <form method="POST" action="/login">
                <!-- No need to pass hidden fields, use session data server-side -->
                <label>Username:</label><input type="text" name="username" required><br><br>
                <label>Password:</label><input type="password" name="password" required><br><br>
                <button type="submit">Login</button>
            </form>
        </body>
        </html>
        `;
        res.send(loginForm);
        // --- End Login Form ---

    } catch(err) {
         console.error('[OAuth Server /authorize] Server error:', err);
         res.status(500).send('Internal server error during authorization setup.');
    }
});

// 3. Handle Login Submission (Calls User Service)
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const oauthData = req.session.oauth; // Retrieve data stored in /authorize

    console.log(`[OAuth Server /login] Attempting login for user: ${username}`);

    // Check if OAuth session data exists
    if (!oauthData || !oauthData.client_id || !oauthData.redirect_uri) {
        console.error("[OAuth Server /login] Missing OAuth context in session. Aborting.");
        return res.status(400).send("Invalid session state. Please start the authorization process again.");
    }

    if (!username || !password) {
        console.warn("[OAuth Server /login] Missing username or password in submission.");
        // TODO: Re-render login form with an error message
        return res.status(400).send("Username and password are required.");
    }

    // --- CALL USER SERVICE TO AUTHENTICATE ---
    try {
        // Ensure USER_SERVICE_URL is configured via environment variables
        const userServiceUrl = process.env.USER_SERVICE_URL;
        if (!userServiceUrl) {
            console.error("[OAuth Server /login] USER_SERVICE_URL environment variable not set!");
            return res.status(500).send("User service configuration error.");
        }
        console.log(`[OAuth Server /login] Calling User Service at ${userServiceUrl}/authenticate`);

        const authResponse = await axios.post(`${userServiceUrl}/authenticate`, {
            identifier: username, // User service expects 'identifier'
            password: password
        });

        // Check if authentication was successful
        if (authResponse.status === 200 && authResponse.data && authResponse.data.userId) {
            console.log(`[OAuth Server /login] User Service authenticated user: ${authResponse.data.username} (ID: ${authResponse.data.userId})`);

            // Store authenticated user info in the main session
            // WARNING: Storing sensitive info directly in session can be risky.
            // Consider storing only essential identifiers (like userId) and fetching details later.
            req.session.userId = authResponse.data.userId;
            req.session.username = authResponse.data.username;

            // --- Proceed to Consent Screen ---
            console.log('[OAuth Server /login] Authentication successful, proceeding to consent form.');
            // Scopes would be parsed/validated here if used
            const scopeInfo = oauthData.scope ? `Requested permissions: ${oauthData.scope}` : "Basic access requested.";

            let consentForm = `
            <!DOCTYPE html>
            <html>
            <head><title>Grant Access</title></head>
            <body>
                <h1>Grant Access</h1>
                <p>Hello ${req.session.username || 'User'}!</p>
                <p>The application <strong>${oauthData.client_id}</strong> wants permission to access your account.</p>
                <p><em>${scopeInfo}</em></p>
                <form method="POST" action="/consent">
                    <!-- Pass state back if it was provided -->
                    ${oauthData.state ? `<input type="hidden" name="state" value="${oauthData.state}">` : ''}
                    <button type="submit" name="allow" value="true">Allow</button>
                    <button type="submit" name="allow" value="false">Deny</button>
                </form>
            </body>
            </html>
            `;
            res.send(consentForm);
            // --- End Consent Screen ---

        } else {
            // Should not happen if user service returns correct codes, but handle defensively
             console.error("[OAuth Server /login] Authentication failed - Unexpected response from user service:", authResponse.status, authResponse.data);
             // TODO: Re-render login form with error
             return res.status(401).send('Authentication failed via User Service.');
        }

    } catch (error) {
        // Handle errors from the User Service call
        if (error.response && error.response.status === 401) {
            console.warn(`[OAuth Server /login] User Service returned 401 for user: ${username}`);
             // TODO: Re-render login form with error
            return res.status(401).send('Invalid username or password provided.');
        } else {
            console.error("[OAuth Server /login] Error calling User Service:", error.message);
             if (error.response) {
                console.error("[OAuth Server /login] User Service Response:", error.response.status, error.response.data);
            }
             // TODO: Show generic error page or re-render login with error
            return res.status(500).send('An error occurred during authentication attempt.');
        }
    }
    // --- END USER SERVICE CALL ---
});

// 4. Handle Consent Submission
app.post('/consent', (req, res) => {
    const { allow, state } = req.body; // Get potential state from form
    const oauthData = req.session.oauth; // Get stored OAuth context
    const userId = req.session.userId;   // Get authenticated user ID

    console.log(`[OAuth Server /consent] Consent received. Allow: ${allow}, State: ${state}`);

    // Validate session state
    if (!userId || !oauthData || !oauthData.client_id || !oauthData.redirect_uri) {
       console.error("[OAuth Server /consent] Missing user or OAuth context in session. Aborting.");
       return res.status(400).send("Session expired or invalid. Please log in again.");
    }

    let redirectURL = new URL(oauthData.redirect_uri);

    if (allow === 'true') {
        console.log(`[OAuth Server /consent] User [${userId}] granted access to client [${oauthData.client_id}]`);
        // --- Generate and Store Authorization Code ---
        const authorization_code = uuidv4();
        const codeExpiry = Date.now() + (10 * 60 * 1000); // e.g., 10 minutes expiry

        // TODO: Store this in Redis or Database with TTL
        authorizationCodes[authorization_code] = {
            client_id: oauthData.client_id,
            redirect_uri: oauthData.redirect_uri, // Store the specific URI used
            userId: userId,
            scope: oauthData.scope, // Store granted scope
            expires: codeExpiry
        };
        console.log(`[OAuth Server /consent] Stored auth code [${authorization_code}]`);

        // Append code and state (if provided) to redirect URI
        redirectURL.searchParams.set('code', authorization_code);
        if (oauthData.state) { // Use state from session if it exists
             redirectURL.searchParams.set('state', oauthData.state);
             console.log(`[OAuth Server /consent] Appending state [${oauthData.state}] to redirect.`);
        } else if (state) { // Fallback to form state if needed (less secure)
             redirectURL.searchParams.set('state', state);
             console.log(`[OAuth Server /consent] Appending state [${state}] from form to redirect.`);
        }
        // --- End Auth Code Generation ---

    } else {
        console.log(`[OAuth Server /consent] User [${userId}] denied access to client [${oauthData.client_id}]`);
        // Append error and state (if provided) to redirect URI
        redirectURL.searchParams.set('error', 'access_denied');
         if (oauthData.state) {
             redirectURL.searchParams.set('state', oauthData.state);
         } else if (state) {
             redirectURL.searchParams.set('state', state);
         }
    }

    // Clean up session data related to this specific auth flow
    delete req.session.oauth;
    console.log('[OAuth Server /consent] Cleared OAuth session data.');

    console.log(`[OAuth Server /consent] Redirecting user agent to: ${redirectURL.toString()}`);
    res.redirect(redirectURL.toString());
});


// 5. Token Endpoint (Uses Supabase for Client Auth)
app.post('/token', async (req, res) => {
    console.log('[OAuth Server /token] Received request.');
    const { grant_type, code, redirect_uri, client_id, client_secret } = req.body;
    // Add detailed logging if needed, be careful with secrets

    // --- Validation Steps ---

    // 1. Validate grant_type
    if (grant_type !== 'authorization_code') {
        console.error(`[OAuth Server /token] Validation Fail: Invalid grant_type [${grant_type}]`);
        return res.status(400).json({ error: 'unsupported_grant_type', error_description: 'Only authorization_code grant type is supported' });
    }

    // 2. Validate Authorization Code (from in-memory store for now)
    // TODO: Fetch code from persistent store (Redis/DB) and check expiry
    const authCodeData = authorizationCodes[code];
    const isCodeExpired = authCodeData ? Date.now() > authCodeData.expires : true;

    console.log(`[OAuth Server /token] Code lookup for [${code}]: ${authCodeData ? 'Found' : 'NOT Found'}. Expired: ${isCodeExpired}`);
    if (!authCodeData || isCodeExpired) {
        if (authCodeData) delete authorizationCodes[code]; // Clean up expired code
        console.error(`[OAuth Server /token] Validation Fail: Authorization code [${code}] not found, expired, or already used.`);
        return res.status(400).json({ error: 'invalid_grant', error_description: 'Authorization code is invalid, expired, or already used' });
    }
    // Note: Codes should be strictly single-use. Delete immediately after validation passes.

    // 3. Validate Client ID against Code Data
    console.log(`[OAuth Server /token] Comparing client_id: Received [${client_id}] vs Code [${authCodeData.client_id}]`);
    if (authCodeData.client_id !== client_id) {
        console.error(`[OAuth Server /token] Validation Fail: client_id mismatch.`);
        // Don't delete code yet if client ID is wrong
        return res.status(400).json({ error: 'invalid_grant', error_description: 'Client ID mismatch for the provided code' });
    }

    // 4. Validate Redirect URI against Code Data
    console.log(`[OAuth Server /token] Comparing redirect_uri: Received [${redirect_uri}] vs Code [${authCodeData.redirect_uri}]`);
    if (authCodeData.redirect_uri !== redirect_uri) {
        console.error(`[OAuth Server /token] Validation Fail: redirect_uri mismatch.`);
        // Don't delete code yet if redirect URI is wrong
        return res.status(400).json({ error: 'invalid_grant', error_description: 'Redirect URI mismatch for the provided code' });
    }

    // --- Authorization Code is Valid and Matches ---
    // Delete the code now as it's single-use and passed initial checks
    delete authorizationCodes[code];
    console.log(`[OAuth Server /token] Authorization code [${code}] validated and deleted.`);

    // --- 5. Validate Client Authentication (Client ID & Secret from Supabase) ---
    try {
        console.log(`[OAuth Server /token] Authenticating client [${client_id}]...`);
        const { data: clientData, error: dbError } = await supabase
            .from('oauth_clients')
            .select('client_id, client_secret') // Fetch secret
            .eq('client_id', client_id)
            .maybeSingle();

        if (dbError) {
            console.error(`[OAuth Server /token] Supabase error fetching client [${client_id}] for auth:`, dbError);
            return res.status(500).json({ error: 'server_error', error_description: 'Failed to verify client credentials' });
        }

        // Check if client exists and secret matches
        let isClientSecretValid = false;
        if (clientData) {
             // WARNING: Comparing plain text secrets. Hash secrets in production!
             isClientSecretValid = clientData.client_secret === client_secret;
             console.log(`[OAuth Server /token] Client found. Secret comparison: ${isClientSecretValid ? 'Match' : 'Mismatch'}`);
        } else {
             console.warn(`[OAuth Server /token] Client [${client_id}] not found during authentication.`);
        }

        if (!isClientSecretValid) { // Covers both client not found and secret mismatch
          console.error(`[OAuth Server /token] Client authentication failed for [${client_id}]`);
          return res.status(401).json({error: 'invalid_client', error_description: 'Client authentication failed (invalid client ID or secret)'});
        }

        // --- Client Authentication Successful ---
        console.log(`[OAuth Server /token] Client [${client_id}] authenticated successfully.`);

        // --- Issue Access Token ---
        const access_token = uuidv4();
        const tokenExpiryTime = Date.now() + (3600 * 1000); // 1 hour
        const expiresInSeconds = 3600;

        // TODO: Store token in persistent store (Redis/DB) with expiry
        accessTokens[access_token] = {
            userId: authCodeData.userId,
            clientId: client_id,
            scope: authCodeData.scope, // Store granted scope with token
            expires: tokenExpiryTime
        };
        console.log(`[OAuth Server /token] Issued access token [${access_token.substring(0,8)}...] for user [${authCodeData.userId}]`);

        // Return the successful token response
        console.log('[OAuth Server /token] Sending successful token response.');
        res.status(200).json({
            access_token: access_token,
            token_type: 'bearer',
            expires_in: expiresInSeconds,
            scope: authCodeData.scope // Return granted scope
            // user_id: authCodeData.userId // Optionally return user ID if needed
        });
        // --- End Issue Token ---

    } catch(err) {
        console.error('[OAuth Server /token] Server error during client validation or token issuance:', err);
        res.status(500).json({ error: 'server_error', error_description: 'Internal error during token processing' });
    }
    // --- END Client Authentication ---
});

// 6. Protected Resource Endpoint (Example - Uses In-Memory Tokens)
// TODO: Modify to validate token against persistent store
app.get('/resource', (req, res) => {
    const authHeader = req.headers.authorization;
    const accessToken = authHeader?.split(' ')[1];

    if (!accessToken) {
        return res.status(401).json({ error: 'missing_token' });
    }

    // Check in-memory store
    const tokenData = accessTokens[accessToken];
    const isTokenExpired = tokenData ? Date.now() > tokenData.expires : true;

    if (!tokenData || isTokenExpired) {
         if (tokenData) delete accessTokens[accessToken]; // Clean up expired
        return res.status(401).json({ error: 'invalid_or_expired_token' });
    }

    // Token is valid
    const userId = tokenData.userId;
    console.log(`[OAuth Server /resource] Access granted for token [${accessToken.substring(0,8)}...], User ID: ${userId}`);

    // TODO: Check token scope against required scope for this resource

    res.json({
        message: `Hello, User ${userId}! This is a protected resource.`,
        data: { your_user_id: userId, accessed_by_client: tokenData.clientId, scope: tokenData.scope }
    });
});


// --- Start Server ---
app.listen(port, () => {
    console.log(`OAuth Server listening on port ${port}`);
    // Log crucial environment variables on startup (be careful with secrets in real logs)
    console.log(`  -> USER_SERVICE_URL: ${process.env.USER_SERVICE_URL || 'Not Set!'}`);
    console.log(`  -> Session Secret: ${process.env.SESSION_SECRET ? 'Loaded from ENV' : 'Using Fallback!'}`);
    console.log(`  -> Supabase URL: ${process.env.SUPABASE_URL ? 'Loaded' : 'Not Set!'}`);
    console.log(`  -> Supabase Key: ${process.env.SUPABASE_KEY ? 'Loaded' : 'Not Set!'}`);
});