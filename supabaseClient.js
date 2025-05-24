// supabaseClient.js
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config(); // Load environment variables from .env file

const supabaseUrl = process.env.SUPABASE_USER_URL; // Use process.env
const supabaseKey = process.env.SUPABASE_USER_KEY; // Use process.env

if (!supabaseUrl || !supabaseKey) {
    throw new Error("Supabase URL and Anon Key are required. Check your .env file.");
}

// Create a single supabase client for interacting with your database
const supabase = createClient(supabaseUrl, supabaseKey);

module.exports = supabase;