const { MongoClient } = require('mongodb');
require('dotenv').config();

// Use the connection string from .env
const uri = process.env.atlas_URL || 'mongodb+srv://huduammata_db_user:PWJ5x4Jvagxjntii@cluster0.te8qwee.mongodb.net/?appName=Cluster0';

(async () => {
  try {
    console.log('Testing MongoDB connection...');
    const client = new MongoClient(uri);
    await client.connect();
    console.log('✓ Connected to MongoDB successfully!');
    
    const db = client.db('vulnprobe');
    const scan = db.collection('Scan');
    console.log('✓ Database and collection accessible');
    
    await client.close();
    console.log('✓ Connection closed');
  } catch (e) {
    console.error('✗ Error:', e.message);
    process.exit(1);
  }
})();
