// __mocks__/supabaseClient.js

// Mock the final execution methods
const mockSingle = jest.fn();
const mockMaybeSingle = jest.fn();

// Mock intermediate methods. They return objects with the next step's mocks.
const mockEq = jest.fn(() => ({
    maybeSingle: mockMaybeSingle,
    single: mockSingle,
}));

const mockSelect = jest.fn(() => ({
    eq: mockEq,
    single: mockSingle,
    // Add other chain methods if used
    // order: jest.fn(() => ({ maybeSingle: mockMaybeSingle, single: mockSingle, eq: mockEq })),
}));

const mockInsert = jest.fn(() => ({
    select: jest.fn(() => ({
        single: mockSingle,
    })),
    // Add other insert methods if used
}));

const mockOnConflict = jest.fn(() => ({
    select: jest.fn(() => ({
        single: mockSingle,
    })),
    // Add other onConflict methods if used
}));

const mockUpsert = jest.fn(() => ({
    select: jest.fn(() => ({
        single: mockSingle,
    })),
    onConflict: mockOnConflict,
    // Add other upsert methods if used
}));


// Mock the top-level 'from' method
const mockFrom = jest.fn((tableName) => {
    return {
        select: mockSelect,
        insert: mockInsert,
        upsert: mockUpsert,
        // Add other top-level methods (delete, update)
    };
});

// Mock the main createClient function (for Jest's mock resolution)
const mockCreateClient = jest.fn((url, key) => {
    // Return the mock client instance
    return {
        from: mockFrom,
        // Add other client-level mocks (auth, storage)
    };
});


// --- EXPORTING THE MOCKS ---
// Export the mock client instance as the default export (what app.js requires)
// Export the individual mock functions as named exports for test control (resetting, setting return values)
module.exports = {
    // Default export (the mock client instance)
    from: mockFrom,
    // Add other client-level mocks here if used directly on the client instance
    // auth: { signInWithPassword: jest.fn() },

    // Named exports (the individual mock functions for testing)
    mockFrom,
    mockSelect,
    mockEq,
    mockMaybeSingle,
    mockSingle,
    mockInsert,
    mockUpsert,
    mockOnConflict,
    // Export createClient if you need to spy on it, though usually not needed for basic tests
    // mockCreateClient,
};