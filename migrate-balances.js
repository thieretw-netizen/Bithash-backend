// migrate-balances.js
require('dotenv').config();
const mongoose = require('mongoose');

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

// Define User schema (minimal version for migration)
const UserSchema = new mongoose.Schema({}, { strict: false });
const User = mongoose.model('User', UserSchema);

const migrateOldUsers = async () => {
  try {
    console.log('Starting migration...');
    
    // Find all users that have the old wallet structure
    const oldUsers = await User.find({ 
      $or: [
        { 'wallets.main': { $exists: true } },
        { cryptoWallets: { $exists: true } },
        { cryptoBalances: { $exists: true } }
      ]
    });
    
    console.log(`Found ${oldUsers.length} users with old wallet structure`);
    
    let migratedCount = 0;
    
    for (const user of oldUsers) {
      // Get old balances
      const oldMainUSD = user.wallets?.main || 0;
      const oldMaturedUSD = user.wallets?.matured || 0;
      
      // Get crypto balances from old structure
      const oldCryptoBalances = user.cryptoBalances || {};
      const oldCryptoWallets = user.cryptoWallets || {};
      
      // Create new structure for main wallet
      const newMain = {};
      
      // If there was USD balance, convert to USDT (stablecoin)
      if (oldMainUSD > 0) {
        newMain.USDT = oldMainUSD;
      }
      
      // Migrate crypto balances to main wallet
      for (const [asset, amount] of Object.entries(oldCryptoBalances)) {
        if (amount > 0) {
          const assetUpper = asset.toUpperCase();
          newMain[assetUpper] = (newMain[assetUpper] || 0) + amount;
        }
      }
      
      for (const [asset, amount] of Object.entries(oldCryptoWallets)) {
        if (amount > 0) {
          const assetUpper = asset.toUpperCase();
          newMain[assetUpper] = (newMain[assetUpper] || 0) + amount;
        }
      }
      
      // Create new structure for matured wallet
      const newMatured = {};
      if (oldMaturedUSD > 0) {
        newMatured.USDT = oldMaturedUSD;
      }
      
      // Update user with new structure
      await User.updateOne(
        { _id: user._id },
        {
          $set: {
            balances: {
              main: newMain,
              active: {},
              matured: newMatured
            }
          },
          $unset: {
            wallets: "",
            cryptoWallets: "",
            cryptoBalances: "",
            main: "",
            matured: ""
          }
        }
      );
      
      migratedCount++;
      console.log(`✅ Migrated (${migratedCount}/${oldUsers.length}): ${user.email}`);
    }
    
    console.log(`\n🎉 Migration complete! ${migratedCount} users migrated.`);
    process.exit(0);
    
  } catch (err) {
    console.error('Migration failed:', err);
    process.exit(1);
  }
};

// Run the migration
migrateOldUsers();
