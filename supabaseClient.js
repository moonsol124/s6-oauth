// my-oauth-server/supabaseClient.js
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config(); // Load environment variables from .env file

const supabaseUrl = process.env.SUPABASE_USER_URL;
const supabaseKey = process.env.SUPABASE_USER_KEY; // Use the ANON key or SERVICE_ROLE key depending on your setup/RLS

if (!supabaseUrl || !supabaseKey) {
    throw new Error("Supabase URL and Key are required. Check environment variables.");
}

const supabase = createClient(supabaseUrl, supabaseKey);

module.exports = supabase;