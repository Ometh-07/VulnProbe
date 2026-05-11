const { MongoClient } = require('mongodb');

const MONGODB_URI = process.env.atlas_URL || process.env.MONGODB_URI || 'mongodb://localhost:27017/vulnprobe';
let cachedClient = null;
let cachedDb = null;

async function connectToDatabase() {
  if (cachedClient && cachedDb) {
    return { client: cachedClient, db: cachedDb };
  }

  try {
    const client = new MongoClient(MONGODB_URI, {
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
      connectTimeoutMS: 10000,
    });

    await client.connect();
    console.log('✓ Connected to MongoDB');

    const db = client.db();
    cachedClient = client;
    cachedDb = db;

    return { client, db };
  } catch (error) {
    console.error('✗ MongoDB connection failed:', error.message);
    throw error;
  }
}

async function getDatabase() {
  const { db } = await connectToDatabase();
  return db;
}

module.exports = { connectToDatabase, getDatabase };
