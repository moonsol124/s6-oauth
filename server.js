// --- server.js ---

// Load environment variables *before* requiring app if app relies on them at load time
require('dotenv').config();

// Import the Express application instance from app.js
const app = require('./app'); // Assuming server.js is in the same directory as app.js

// Define the port for the server
const port = process.env.PORT || 3000;

// Start the HTTP server using the exported app instance
const server = app.listen(port, () => {
    // Keep your startup logs here, they will now only show when you run server.js
    console.log(`OAuth Server listening on port ${port}`);
    console.log(`  -> USER_SERVICE_URL: ${process.env.USER_SERVICE_URL || 'Not Set!'}`);
    console.log(`  -> Session Secret: ${process.env.SESSION_SECRET ? 'Loaded from ENV' : 'Using Fallback!'}`);
    console.log(`  -> JWT Secret: ${process.env.JWT_SECRET ? 'Loaded from ENV' : 'Using Fallback!'}`);
    console.log(`  -> Supabase URL: ${process.env.SUPABASE_USER_URL ? 'Loaded' : 'Not Set!'}`);
    console.log(`  -> Supabase Key: ${process.env.SUPABASE_USER_KEY ? 'Loaded' : 'Not Set!'}`);
});

// Optional: Export the server instance if you need to explicitly close it in tests
// (Less common when using supertest)
// module.exports = server;