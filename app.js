const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const { v4: uuidv4 } = require('uuid');
require('dotenv').config();
const axios = require('axios');
const supabase = require('./supabaseClient'); // Assumes supabaseClient.js is configured
const jwt = require('jsonwebtoken'); // <<< Add this line

const app = express();
const port = process.env.PORT || 3000;

// --- JWT Secret Key ---
// !! IMPORTANT: This secret key must be stored securely and kept confidential.
// !! DO NOT hardcode secrets in production. Use environment variables.
// !! This same secret key (or the corresponding public key for RS256)
// !! will be needed by your API Gateway to verify the JWTs.
const jwtSecret = process.env.JWT_SECRET || 'insecure-dev-secret-fallback-CHANGE-ME'; // MUST CONFIGURE IN ENV!
if (jwtSecret === 'insecure-dev-secret-fallback-CHANGE-ME' && process.env.NODE_ENV === "production") {
    console.error('!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!');
    console.error('!! WARNING: Using insecure default JWT_SECRET in PRODUCTION!!');
    console.error('!! Set a strong, random JWT_SECRET environment variable !!');
    console.error('!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!');
    // In a real production app, you might want to exit here if the secret is missing/default
    // process.exit(1);
}


// --- Middleware ---
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(session({
  secret: process.env.SESSION_SECRET || 'local-dev-unsafe-secret-fallback', // MUST configure SESSION_SECRET in env
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    sameSite: 'lax'
  }
}));

// --- Storage ---
// Client data in Supabase ('oauth_clients')
// Consent data in Supabase ('user_consents')
// TODO: Replace in-memory storage for production
const authorizationCodes = {}; // Temporary in-memory store
// accessTokens is no longer needed for JWT validation
// const accessTokens = {}; // Temporary in-memory store
// TODO: Add persistent storage for refresh tokens if you implement them
// const refreshTokensStorage = {};

// --- Helper Functions ---
// ... (Keep your existing helper functions: parseRedirectUris, parseScopes, buildRedirectUrl, finalizeAuthorization, generateStyledHTML, etc.) ...
function parseRedirectUris(input) {
    // ... (keep existing parseRedirectUris function)
    let uris = [];
    if (typeof input === 'string') {
        uris = input.split(',').map(uri => uri.trim()).filter(uri => uri);
    } else if (Array.isArray(input)) {
        uris = input.filter(uri => typeof uri === 'string' && uri.trim());
    }
    return uris.filter(uri => {
        try {
            new URL(uri);
            return true;
        } catch (_) {
            return false;
        }
    });
}

// Parses scope string into an array (basic space separation)
function parseScopes(scopeString) {
    if (!scopeString || typeof scopeString !== 'string') {
        return null; // Or return default scopes if applicable
    }
    // Normalize spaces and split, filter empty strings
    return scopeString.trim().replace(/\s+/g, ' ').split(' ').filter(s => s);
}

// Generates the final redirect URL with code/error and state
function buildRedirectUrl(baseRedirectUri, params) {
     try {
        let redirectURL = new URL(baseRedirectUri);
        for (const key in params) {
            if (params[key] !== undefined && params[key] !== null) {
                redirectURL.searchParams.set(key, params[key]);
            }
        }
        return redirectURL.toString();
    } catch (e) {
        console.error(`[OAuth Server] Error building redirect URL for base URI "${baseRedirectUri}":`, e);
        // Fallback or handle error appropriately, maybe return an error object?
        // For now, returning null indicates an error
        return null;
    }
}

// Handles the final steps after consent is confirmed (either previously or just now)
function finalizeAuthorization(req, res, userId, oauthData) {
    console.log(`[OAuth Server] Finalizing authorization for user [${userId}], client [${oauthData.client_id}]`);

    const authorization_code = uuidv4();
    const codeExpiry = Date.now() + (10 * 60 * 1000); // 10 minutes

    // TODO: Store this in Redis or Database with TTL
    authorizationCodes[authorization_code] = {
        client_id: oauthData.client_id,
        redirect_uri: oauthData.redirect_uri,
        userId: userId,
        scope: oauthData.scope, // Use scope stored in session
        expires: codeExpiry
    };
    console.log(`[OAuth Server] Stored auth code [${authorization_code.substring(0,8)}...]`);

    // Build redirect URL
    const redirectParams = {
        code: authorization_code,
        state: oauthData.state // Use state from session
    };
    const finalRedirectUrl = buildRedirectUrl(oauthData.redirect_uri, redirectParams);

    // Clean up session data related to this specific auth flow
    delete req.session.oauth;
    console.log('[OAuth Server] Cleared OAuth session data.');

    if (finalRedirectUrl) {
        console.log(`[OAuth Server] Redirecting user agent to: ${finalRedirectUrl}`);
        res.redirect(finalRedirectUrl);
    } else {
         console.error(`[OAuth Server] Failed to build final redirect URL for client ${oauthData.client_id}.`);
         // Handle this error - maybe show an error page to the user?
         res.status(500).send("An error occurred during the final redirection step.");
    }
}

// New function to handle logic after user is confirmed logged in (either via session or POST /login)
async function handleLoggedInUser(req, res) {
    const userId = req.session.userId;
    const username = req.session.username; // Get username if available
    const oauthData = req.session.oauth;

    if (!userId || !oauthData) {
        console.error("[OAuth Server handleLoggedInUser] Critical session data missing.");
        // Redirect to login or show error
        return res.redirect('/authorize'); // Or an error page
    }

    console.log(`[OAuth Server handleLoggedInUser] Checking consent for User [${userId}], Client [${oauthData.client_id}]`);

    try {
        // --- Check Database for Existing Consent ---
        const { data: consentData, error: consentError } = await supabase
            .from('user_consents')
            .select('granted_at, scopes') // Select scopes if needed for comparison later
            .eq('user_id', userId)
            .eq('client_id', oauthData.client_id)
            .maybeSingle();

        if (consentError) throw consentError;

        // --- Decision Point: Consent Exists? ---
        if (consentData) {
            // TODO: Add scope validation if necessary.
            // E.g., compare parseScopes(oauthData.scope) with consentData.scopes
            console.log(`[OAuth Server handleLoggedInUser] Consent already granted at ${consentData.granted_at}. Finalizing authorization.`);
            // Consent exists, skip the form and issue the code directly
            finalizeAuthorization(req, res, userId, oauthData);
        } else {
            console.log(`[OAuth Server handleLoggedInUser] No existing consent found. Displaying consent form.`);
            // No consent found, display the consent form to the user
            // Pass the oauthData state to the consent form for hidden input
            res.send(generateConsentFormHTML(username, oauthData.client_id, oauthData.scope, oauthData.state));
        }
        // --- End Consent Decision ---

    } catch (err) {
        console.error('[OAuth Server handleLoggedInUser] Error checking/handling consent:', err);
        res.status(500).send(`Error processing request: ${err.message || 'Internal server error'}`);
    }
}

// ... (Keep your existing UI generation functions: generateStyledHTML, generateLoginFormHTML, generateConsentFormHTML) ...

function generateStyledHTML(title, bodyContent) {
    // Basic CSS for centering and styling
    const styles = `
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
            background-color: #f0f2f5;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            color: #333;
        }
        .container {
            background-color: #ffffff;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
            text-align: center;
            max-width: 400px;
            width: 90%;
        }
        .logo {
            font-size: 24px;
            font-weight: bold;
            color: #1877f2; /* Example blue color */
            margin-bottom: 10px;
        }
         h1 {
            font-size: 22px;
            margin-bottom: 20px;
            color: #1c1e21;
         }
        label {
            display: block;
            text-align: left;
            margin-bottom: 5px;
            font-weight: 500;
            font-size: 14px;
        }
        input[type="text"], input[type="password"] {
            width: calc(100% - 20px);
            padding: 10px;
            margin-bottom: 15px;
            border: 1px solid #ccd0d5;
            border-radius: 6px;
            font-size: 16px;
        }
        button[type="submit"] {
            background-color: #1877f2;
            color: white;
            padding: 10px 20px;
            border: none;
            border-radius: 6phalox;
            font-size: 16px;
            font-weight: bold;
            cursor: pointer;
            transition: background-color 0.2s;
            width: 100%;
        }
        button[type="submit"]:hover {
            background-color: #166fe5;
        }
        .consent-buttons {
            display: flex;
            gap: 15px;
            justify-content: center;
            margin-top: 25px;
        }
         .consent-buttons button {
             width: auto;
             padding: 10px 25px;
         }
        .consent-buttons button[name="allow"][value="false"] {
            background-color: #e4e6eb;
            color: #4b4f56;
        }
        .consent-buttons button[name="allow"][value="false"]:hover {
            background-color: #dadde1;
        }
        p {
            margin-bottom: 15px;
            line-height: 1.5;
            font-size: 14px;
            color: #606770;
        }
        strong { color: #1c1e21; }
        em { color: #606770; font-style: normal; }
    `;

    return `
    <!DOCTYPE html>
    <html>
    <head>
        <title>${title}</title>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>${styles}</style>
    </head>
    <body>
        <div class="container">
            <div class="logo">YourApp™</div> <!-- Placeholder Logo Text -->
            ${bodyContent}
        </div>
    </body>
    </html>
    `;
}

function generateLoginFormHTML(client_id) {
    const body = `
        <h1>Login Required</h1>
        <p>Please log in to continue the request for application <strong>${client_id}</strong>.</p>
        <form method="POST" action="/login">
            <label for="username">Username:</label>
            <input type="text" id="username" name="username" required><br>
            <label for="password">Password:</label>
            <input type="password" id="password" name="password" required><br>
            <button type="submit">Login</button>
        </form>
    `;
    return generateStyledHTML("Login - YourApp", body);
}

function generateConsentFormHTML(username, client_id, scope, state) {
    const scopeInfo = scope ? `This application wants the following permissions: <em>${parseScopes(scope).join(', ')}</em>` : "This application requests basic access.";
    const body = `
        <h1>Grant Access?</h1>
        <p>Hello, <strong>${username || 'User'}</strong>!</p>
        <p>The application <strong>${client_id}</strong> wants permission to access your account on your behalf.</p>
        <p>${scopeInfo}</p>
        <form method="POST" action="/consent">
            ${state ? `<input type="hidden" name="state" value="${state}">` : ''}
            <div class="consent-buttons">
                 <button type="submit" name="allow" value="false">Deny</button>
                 <button type="submit" name="allow" value="true">Allow</button>
            </div>
        </form>
    `;
    return generateStyledHTML("Grant Access - YourApp", body);
}


// --- Routes ---

// 1. Client Registration (Uses Supabase) - No changes needed here
app.post('/register', async (req, res) => {
    // ... (Keep existing /register code) ...
    const client_id = uuidv4();
    const client_secret = uuidv4();
    const client_name = req.body.client_name || null;
    const raw_redirect_uris = req.body.redirect_uris;

    const redirect_uris = parseRedirectUris(raw_redirect_uris);

    if (redirect_uris.length === 0) {
        return res.status(400).json({ error: 'At least one valid redirect_uri is required.' });
    }
    console.log(`[OAuth Server /register] Attempting to register client. Name: ${client_name}, URIs: ${redirect_uris.join(', ')}`);
    try {
        const { data, error } = await supabase.from('oauth_clients').insert({
            client_id: client_id, client_secret: client_secret, redirect_uris: redirect_uris, client_name: client_name
        }).select('client_id').single();
        if (error) throw error;
        if (!data) throw new Error("Insert returned no data");
        console.log(`[OAuth Server /register] Client registered successfully: ${client_id}`);
        res.status(201).json({ client_id: client_id, client_secret: client_secret });
    } catch (err) {
        console.error('[OAuth Server /register] Error:', err);
        res.status(500).json({ error: 'Failed to register client', details: err.message });
    }
});


// 2. Authorization Endpoint (Checks Session, Uses Supabase for Client Validation)
app.get('/authorize', async (req, res) => {
    const { client_id, redirect_uri, response_type, scope, state } = req.query;
    console.log(`[OAuth Server /authorize] Request received. Client: ${client_id}, Redirect: ${redirect_uri}, Type: ${response_type}, Scope: ${scope}, State: ${state}`);

    // --- Basic Parameter Validation ---
    if (!client_id || !redirect_uri || !response_type) {
        console.warn('[OAuth Server /authorize] Missing parameters.');
        return res.status(400).send('Missing required parameters: client_id, redirect_uri, response_type');
    }
    if (response_type !== 'code') {
        console.warn(`[OAuth Server /authorize] Unsupported response_type: ${response_type}`);
        return res.status(400).send('Unsupported response_type. Only "code" is supported.');
    }
    // --- End Basic Validation ---

    try {
        console.log("running???")
        // --- Client & Redirect URI Validation ---
        const { data: clientData, error: dbError } = await supabase
            .from('oauth_clients')
            .select('client_id, redirect_uris')
            .eq('client_id', client_id)
            .maybeSingle();

        console.log("running??? 1")

        if (dbError) {
            console.log(dbError)
            throw dbError; // Let main error handler catch db issues
        
        }let isValidClient = false;

        console.log("running??? 3")

        if (clientData && Array.isArray(clientData.redirect_uris)) {
            isValidClient = clientData.redirect_uris.includes(redirect_uri);
        }
        console.log("running??? 2")

        if (!isValidClient) {
            console.warn(`[OAuth Server /authorize] Invalid client or redirect URI. Client Found: ${!!clientData}, URI Valid: ${isValidClient}`);
            return res.status(400).send('Invalid client_id or redirect_uri.');
        }
        console.log(`[OAuth Server /authorize] Client [${client_id}] and Redirect URI [${redirect_uri}] are valid.`);
        // --- End Client Validation ---

        // Store flow details in session
        req.session.oauth = { client_id, redirect_uri, response_type, scope, state };
        console.log('[OAuth Server /authorize] Session data stored:', req.session.oauth);

        // --- Check if User is Already Logged In ---
        if (req.session.userId) {
            console.log(`[OAuth Server /authorize] User [${req.session.userId}] already logged in. Checking consent.`);
            // User is logged in, proceed directly to check consent (moved logic to /login endpoint simulation)
            // Simulate internal redirect or call logic directly
            return handleLoggedInUser(req, res); // Call new handler function
        } else {
            console.log('[OAuth Server /authorize] User not logged in. Displaying login form.');
            // User not logged in, show login form
            res.send(generateLoginFormHTML(client_id));
        }
        // --- End Login Check ---

    } catch(err) {
         console.error('[OAuth Server /authorize] Error:', err);
         res.status(500).send(`Authorization error: ${err.message || 'Internal server error'}`);
    }
});

// 3. Handle Login Submission (Calls User Service, then checks consent)
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const oauthData = req.session.oauth; // Retrieve data stored in /authorize

    console.log(`[OAuth Server /login] Attempting login for user: ${username}`);

    // Validate state
    if (!oauthData) {
        console.error("[OAuth Server /login] Missing OAuth context in session.");
        return res.status(400).send("Invalid session state. Please start the authorization process again.");
    }
    if (!username || !password) {
        return res.status(400).send(generateLoginFormHTML(oauthData.client_id)); // Re-render form on error
    }

    // --- Authenticate User via User Service ---
    try {
        const userServiceUrl = process.env.USER_SERVICE_URL;
        if (!userServiceUrl) throw new Error("USER_SERVICE_URL not configured");

        console.log(`[OAuth Server /login] Calling User Service at ${userServiceUrl}/authenticate`);
        const authResponse = await axios.post(`${userServiceUrl}/authenticate`, { identifier: username, password: password });

        if (authResponse.status === 200 && authResponse.data?.userId) {
            console.log(`[OAuth Server /login] User Service authenticated user: ${authResponse.data.username} (ID: ${authResponse.data.userId})`);
            // Store user details in session
            req.session.userId = authResponse.data.userId;
            req.session.username = authResponse.data.username;

            // User is authenticated, now check consent / show form
            await handleLoggedInUser(req, res); // Reuse the consent checking logic

        } else {
            console.error("[OAuth Server /login] Authentication failed - Unexpected response from user service:", authResponse.status, authResponse.data);
            res.status(401).send(generateLoginFormHTML(oauthData.client_id)); // Re-render form on error
        }
    } catch (error) {
        if (error.response && error.response.status === 401) {
            console.warn(`[OAuth Server /login] User Service returned 401 for user: ${username}`);
            res.status(401).send(generateLoginFormHTML(oauthData.client_id)); // Re-render form on error
        } else {
            console.error("[OAuth Server /login] Error communicating with User Service:", error.message);
            res.status(500).send('An error occurred during authentication.');
        }
    }
    // --- End User Service Call ---
});

// 4. Handle Consent Submission (Saves Consent to DB)
app.post('/consent', async (req, res) => { // <<< Make async
    const { allow, state } = req.body;
    const oauthData = req.session.oauth;
    const userId = req.session.userId;

    console.log(`[OAuth Server /consent] Consent submission received. Allow: ${allow}, State: ${state}`);

    // Validate session state
    if (!userId || !oauthData) {
       console.error("[OAuth Server /consent] Missing user or OAuth context in session.");
       return res.status(400).send("Session expired or invalid. Please log in again.");
    }

    let finalRedirectUrl;

    if (allow === 'true') {
        console.log(`[OAuth Server /consent] User [${userId}] GRANTING access to client [${oauthData.client_id}]`);

        try {
            // --- Save Consent to Database ---
            const scopesToSave = parseScopes(oauthData.scope); // Parse scopes before saving
            console.log(`[OAuth Server /consent] Saving consent to DB. User: ${userId}, Client: ${oauthData.client_id}, Scopes: ${scopesToSave}`);

            // Use upsert to handle potential re-consent attempts gracefully
            const { error: upsertError } = await supabase
                .from('user_consents')
                .upsert({
                    user_id: userId,
                    client_id: oauthData.client_id,
                    scopes: scopesToSave // Store parsed scopes array (or null)
                    // granted_at is handled by default value
                }, {
                    onConflict: 'user_id, client_id' // Specify conflict target for upsert
                });

            if (upsertError) throw upsertError; // Let error handler catch DB issues

            console.log(`[OAuth Server /consent] Consent saved successfully.`);
            // --- End Save Consent ---

            // Consent granted and saved, finalize the authorization flow
            return finalizeAuthorization(req, res, userId, oauthData); // finalize handles the redirect

        } catch(err) {
             console.error('[OAuth Server /consent] Error saving consent:', err);
             // Build redirect URL with server_error
             const errorParams = { error: 'server_error', state: oauthData.state };
             finalRedirectUrl = buildRedirectUrl(oauthData.redirect_uri, errorParams);
             // Don't clear oauth session here, maybe user can retry? Or clear depending on policy.
             // delete req.session.oauth;
             if(finalRedirectUrl) {
                 return res.redirect(finalRedirectUrl);
             } else {
                 return res.status(500).send("An error occurred while saving consent.");
             }
        }

    } else {
        // User denied consent
        console.log(`[OAuth Server /consent] User [${userId}] DENIED access to client [${oauthData.client_id}]`);
        const errorParams = { error: 'access_denied', state: oauthData.state };
        finalRedirectUrl = buildRedirectUrl(oauthData.redirect_uri, errorParams);
         // Clean up session data for this flow
         delete req.session.oauth;
         console.log('[OAuth Server /consent] Cleared OAuth session data after denial.');
         if(finalRedirectUrl) {
            return res.redirect(finalRedirectUrl);
         } else {
             return res.status(400).send("Access denied. Error constructing redirect URL."); // Should not happen if initial redirect_uri was valid
         }
    }
});


// 5. Token Endpoint (Issues JWT and Refresh Token)
app.post('/token', async (req, res) => {
    console.log('[OAuth Server /token] Received request.');
    const { grant_type, code, redirect_uri, client_id, client_secret } = req.body;

    // --- 1. Validate grant_type ---
    if (grant_type !== 'authorization_code') {
        console.warn(`[OAuth Server /token] Invalid grant_type: ${grant_type}`);
        return res.status(400).json({ error: 'unsupported_grant_type', error_description: 'Only authorization_code grant type is supported' });
    }

    // --- 2. Validate Authorization Code ---
    const authCodeData = authorizationCodes[code];
    const isCodeExpired = authCodeData ? Date.now() > authCodeData.expires : true;

    if (!authCodeData || isCodeExpired) {
        console.warn(`[OAuth Server /token] Invalid or expired authorization code: [${code?.substring(0,8) || 'N/A'}]`);
        if (authCodeData) delete authorizationCodes[code]; // Ensure code is deleted after use
        return res.status(400).json({ error: 'invalid_grant', error_description: 'Authorization code is invalid, expired, or already used' });
    }

    // --- 3. Validate Client ID against Code Data ---
    if (authCodeData.client_id !== client_id) {
         console.warn(`[OAuth Server /token] Client ID mismatch. Code client: ${authCodeData.client_id}, Request client: ${client_id}`);
        return res.status(400).json({ error: 'invalid_grant', error_description: 'Client ID mismatch for the provided code' });
    }

    // --- 4. Validate Redirect URI against Code Data ---
    if (authCodeData.redirect_uri !== redirect_uri) {
         console.warn(`[OAuth Server /token] Redirect URI mismatch. Code URI: ${authCodeData.redirect_uri}, Request URI: ${redirect_uri}`);
        return res.status(400).json({ error: 'invalid_grant', error_description: 'Redirect URI mismatch for the provided code' });
    }

    // Authorization Code is valid and consumed
    delete authorizationCodes[code];
    console.log(`[OAuth Server /token] Authorization code [${code.substring(0,8)}...] validated and deleted.`);

    // --- 5. Validate Client Authentication ---
    try {
        const { data: clientData, error: dbError } = await supabase
            .from('oauth_clients').select('client_id, client_secret')
            .eq('client_id', client_id).maybeSingle();

        if (dbError) {
             console.error('[OAuth Server /token] Database error during client lookup:', dbError);
            throw dbError; // Propagate DB error
        }

        // !!! IMPORTANT: In production, HASH the client_secret in the DB and compare hash here !!!
        let isClientSecretValid = clientData && clientData.client_secret === client_secret;
        if (!isClientSecretValid) {
            console.warn(`[OAuth Server /token] Client authentication failed for [${client_id}] - Invalid secret.`);
            return res.status(401).json({error: 'invalid_client', error_description: 'Client authentication failed'});
        }
        console.log(`[OAuth Server /token] Client [${client_id}] authenticated successfully.`);

        // --- 6. Issue Access Token (JWT) and Refresh Token ---

        // JWT Payload (the claims you want to include)
        const jwtPayload = {
            sub: authCodeData.userId, // Subject (typically the user ID)
            client_id: client_id,   // Client who initiated the flow
            scope: authCodeData.scope, // Granted scopes
            // Add other claims here as needed, e.g., 'name', 'email', 'roles' (from user service)
            // exp, iat, etc. are handled by jwt.sign options
        };

        // Access Token Options (expiry, algorithm)
        const expiresInSeconds = 3600; // Access token valid for 1 hour (adjust as needed)
        const jwtOptions = {
            expiresIn: expiresInSeconds, // Token expires in expiresInSeconds
            algorithm: 'HS256', // Use HMAC SHA256 for symmetric signing
            issuer: process.env.OAUTH_SERVER_URL || 'your-oauth-issuer', // Standard 'iss' claim
            // audience: client_id // Standard 'aud' claim (optional, but good practice)
        };

        // Generate the JWT Access Token
        const access_token = jwt.sign(jwtPayload, jwtSecret, jwtOptions);

        console.log(`[OAuth Server /token] Issued JWT access token for user [${authCodeData.userId}]`);

        // --- Issue Refresh Token ---
        // Refresh tokens are typically opaque strings and long-lived.
        // They MUST be stored persistently and securely linked to the user/client.
        const refresh_token = uuidv4(); // Using UUID for simplicity, needs real persistence

        // TODO: Store refresh_token securely in Database or Redis with:
        // - refresh_token (the UUID)
        // - user_id (authCodeData.userId)
        // - client_id (client_id)
        // - scopes (authCodeData.scope)
        // - expiry_date (long-lived, e.g., 90 days or rotation based)
        // Example (conceptual - needs real DB/Redis implementation):
        // const refreshTokenExpiry = Date.now() + (90 * 24 * 3600 * 1000); // 90 days
        // refreshTokensStorage[refresh_token] = {
        //    userId: authCodeData.userId,
        //    clientId: client_id,
        //    scope: authCodeData.scope,
        //    expires: refreshTokenExpiry
        // };

        console.log(`[OAuth Server /token] Issued refresh token [${refresh_token.substring(0,8)}...] for user [${authCodeData.userId}]`);


        // --- 7. Return Tokens in Response ---
        res.status(200).json({
            access_token: access_token,
            token_type: 'bearer',
            expires_in: expiresInSeconds,
            refresh_token: refresh_token, // Include refresh token in response
            scope: authCodeData.scope
        });

    } catch(err) {
        console.error('[OAuth Server /token] Unhandled error during client validation/token issuance:', err);
        // Return a generic server error
        res.status(500).json({ error: 'server_error', error_description: 'Internal error during token processing' });
    }
});

// 6. Protected Resource Endpoint (Example - This endpoint is just for demonstration
//    and should ideally be on a separate backend service, *not* the OAuth server.
//    It would receive the JWT from the API Gateway and validate it there.)
//    To make this example work, you would need to implement JWT verification here.
//    However, the standard pattern is that *backend resources* (like your User Service)
//    don't directly receive the JWT from the frontend; the API Gateway handles validation
//    and forwards user info.
/*
app.get('/resource', (req, res) => {
     console.log('[OAuth Server /resource] Received request.');
    // This logic is typically done by your API Gateway or the target service.
    // It needs to verify the JWT signature and claims.
    const authHeader = req.headers.authorization;
    const token = authHeader?.split(' ')[1]; // Extract the token

    if (!token) {
        return res.status(401).json({ error: 'missing_token' });
    }

    try {
         const decoded = jwt.verify(token, jwtSecret); // Verify the signature using the same secret

         // Now you can use the decoded claims, e.g., userId from 'sub'
         const userId = decoded.sub;
         const clientId = decoded.client_id; // If you included it
         const scope = decoded.scope;     // If you included it

         console.log(`[OAuth Server /resource] Access granted for token, User ID: ${userId}`);

         // Return the protected resource data
        res.json({ message: `Hello, User ${userId}! This is a protected resource.`, data: { your_user_id: userId, accessed_by_client: clientId, scope: scope } });

    } catch (err) {
        console.error('JWT Validation Error on /resource:', err.message);
        return res.status(401).json({ error: 'invalid_or_expired_token' });
    }
});
*/

// Get All Profiles (GET /profiles)
app.get('/profiles', async (req, res) => {
    console.log(`[User Service GET /profiles] Received request`);

    // TODO: Add Authorization Check here! Only admins should view all users.
    // Example: Check the X-User-ID header and query that user's role.

    try {
        const { data, error } = await supabase
            .from('users')
            // --- SELECT 'role' column ---
            .select('id, username, email, created_at, role'); // <<< Ensure 'role' is selected

        if (error) {
            console.error('[User Service GET /profiles] Supabase fetch error:', error);
            return res.status(500).json({ error: 'Database error fetching profiles' });
        }
        console.log(`[User Service GET /profiles] Found ${data?.length || 0} profiles.`);
        res.status(200).json(data || []);
    } catch (error) {
        console.error('[User Service GET /profiles] Unhandled error:', error);
        res.status(500).json({ error: 'Internal server error fetching profiles' });
    }
});

// --- Start Server ---
app.listen(port, () => {
    console.log(`OAuth Server listening on port ${port}`);
    console.log(`  -> USER_SERVICE_URL: ${process.env.USER_SERVICE_URL || 'Not Set!'}`);
    console.log(`  -> Session Secret: ${process.env.SESSION_SECRET ? 'Loaded from ENV' : 'Using Fallback!'}`);
    console.log(`  -> JWT Secret: ${process.env.JWT_SECRET ? 'Loaded from ENV' : 'Using Fallback!'}`);
    console.log(`  -> Supabase URL: ${process.env.SUPABASE_USER_URL ? 'Loaded' : 'Not Set!'}`);
    console.log(`  -> Supabase Key: ${process.env.SUPABASE_USER_KEY ? 'Loaded' : 'Not Set!'}`);
});