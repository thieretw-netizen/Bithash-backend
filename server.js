


















/**
 * POST /api/withdrawals/bank - Process bank withdrawal
 */
app.post('/api/withdrawals/bank', protect, async (req, res) => {
    try {
        const userId = req.user._id;
        const {
            amount,
            bankName,
            accountHolder,
            accountNumber,
            routingNumber,
            balanceSource,
            mainAmountUsed,
            maturedAmountUsed,
            gasFee,
            asset,
            exchangeRate
        } = req.body;

        // Validation
        if (!amount || amount < 100) {
            return res.status(400).json({
                status: 'error',
                message: 'Minimum bank withdrawal is $100'
            });
        }

        if (!bankName || !accountHolder || !accountNumber || !routingNumber) {
            return res.status(400).json({
                status: 'error',
                message: 'All bank details are required'
            });
        }

        // Get user to check balances
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({
                status: 'error',
                message: 'User not found'
            });
        }

        // Calculate total available balance
        const mainBalance = user.balances.main || 0;
        const maturedBalance = user.balances.matured || 0;
        const totalAvailable = mainBalance + maturedBalance;

        if (amount > totalAvailable) {
            return res.status(400).json({
                status: 'error',
                message: 'Insufficient balance'
            });
        }

        // Generate unique reference
        const reference = `WDR-BANK-${Date.now()}-${Math.floor(Math.random() * 1000)}`;

        // Create transaction record
        const transaction = await Transaction.create({
            user: userId,
            type: 'withdrawal',
            amount: amount,
            currency: 'USD',
            status: 'pending',
            method: 'bank',
            reference: reference,
            details: {
                bankName: bankName,
                accountHolder: accountHolder,
                accountNumber: accountNumber,
                routingNumber: routingNumber,
                balanceSource: balanceSource,
                mainAmountUsed: mainAmountUsed || 0,
                maturedAmountUsed: maturedAmountUsed || 0,
                gasFee: gasFee,
                asset: asset,
                exchangeRate: exchangeRate
            },
            bankDetails: {
                accountName: accountHolder,
                accountNumber: accountNumber,
                bankName: bankName,
                routingNumber: routingNumber
            },
            fee: 0,
            netAmount: amount
        });

        // Deduct from user balances (immediate hold)
        const updateQuery = {};
        
        if (balanceSource === 'main' || (mainAmountUsed > 0 && maturedAmountUsed === 0)) {
            updateQuery['balances.main'] = -amount;
        } else if (balanceSource === 'matured' || (maturedAmountUsed > 0 && mainAmountUsed === 0)) {
            updateQuery['balances.matured'] = -amount;
        } else if (balanceSource === 'both') {
            if (mainAmountUsed > 0) {
                updateQuery['balances.main'] = -mainAmountUsed;
            }
            if (maturedAmountUsed > 0) {
                updateQuery['balances.matured'] = -maturedAmountUsed;
            }
        }

        await User.findByIdAndUpdate(userId, {
            $inc: updateQuery
        });

        // Log activity
        await logActivity(
            'withdrawal_created',
            'Transaction',
            transaction._id,
            userId,
            'User',
            req,
            {
                amount: amount,
                method: 'bank',
                bankName: bankName,
                reference: reference,
                balanceSource: balanceSource
            }
        );

        return res.status(201).json({
            status: 'success',
            data: {
                transaction: {
                    id: transaction._id,
                    reference: reference,
                    amount: amount,
                    method: 'bank',
                    status: 'pending',
                    createdAt: transaction.createdAt
                }
            },
            message: 'Bank withdrawal request submitted successfully'
        });

    } catch (err) {
        console.error('Bank withdrawal error:', err);
        return res.status(500).json({
            status: 'error',
            message: err.message || 'Failed to process bank withdrawal request'
        });
    }
});

/**
 * GET /api/withdrawals/history - Get withdrawal history
 */
app.get('/api/withdrawals/history', protect, async (req, res) => {
    try {
        const userId = req.user._id;

        // Get withdrawal transactions
        const withdrawals = await Transaction.find({
            user: userId,
            type: 'withdrawal'
        })
        .sort({ createdAt: -1 })
        .limit(50)
        .lean();

        // Format withdrawals for frontend
        const formattedWithdrawals = withdrawals.map(w => ({
            id: w._id,
            date: w.createdAt,
            method: w.method === 'bank' ? 'bank' : w.asset || 'crypto',
            amount: w.amount,
            asset: w.asset || 'USD',
            status: w.status,
            reference: w.reference,
            txId: w.reference,
            exchangeRate: w.details?.exchangeRate
        }));

        return res.status(200).json({
            status: 'success',
            data: formattedWithdrawals
        });

    } catch (err) {
        console.error('Error fetching withdrawal history:', err);
        return res.status(500).json({
            status: 'error',
            message: 'Failed to fetch withdrawal history'
        });
    }
});





// =============================================
// ENDPOINT 2: COOKIE PREFERENCES - ROBUST ENTERPRISE VERSION
// =============================================
app.post('/api/users/cookie-preferences', protect, async (req, res) => {
  try {
    const { cookieConsent, cookieSettings } = req.body;
    const userId = req.user._id;
    const ipAddress = getRealClientIP(req);
    const userAgent = req.headers['user-agent'] || 'Unknown';
    
    // Validate consent
    const validValues = ['all', 'essential', 'functional', 'analytics', 'custom', 'reject'];
    if (!cookieConsent || !validValues.includes(cookieConsent)) {
      return res.status(400).json({
        status: 'fail',
        message: 'Invalid cookie consent value'
      });
    }
    
    // Validate settings if provided
    let validatedSettings = null;
    if (cookieSettings && typeof cookieSettings === 'object') {
      validatedSettings = {
        essential: true,
        functional: cookieSettings.functional === true,
        analytics: cookieSettings.analytics === true,
        marketing: cookieSettings.marketing === true,
        lastUpdated: new Date()
      };
    }
    
    // Update user preferences
    await User.findByIdAndUpdate(userId, {
      $set: {
        'cookiePreferences.consent': cookieConsent,
        'cookiePreferences.updatedAt': new Date(),
        'cookiePreferences.ipAddress': ipAddress,
        'cookiePreferences.settings': validatedSettings
      }
    });
    
    // Set cookies based on consent
    const cookieOptions = {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 365 * 24 * 60 * 60 * 1000
    };
    
    res.cookie('cookie_consent', cookieConsent, cookieOptions);
    
    if (cookieConsent === 'all' || cookieConsent === 'functional') {
      res.cookie('functional_enabled', 'true', cookieOptions);
    } else {
      res.clearCookie('functional_enabled');
    }
    
    if (cookieConsent === 'all' || cookieConsent === 'analytics') {
      res.cookie('analytics_enabled', 'true', cookieOptions);
    } else {
      res.clearCookie('analytics_enabled');
    }
    
    // Log activity
    await logActivity('cookie_preferences_updated', 'User', userId, userId, 'User', req, { 
      consent: cookieConsent, 
      settings: validatedSettings 
    });
    
    res.status(200).json({
      status: 'success',
      message: 'Cookie preferences saved successfully',
      data: {
        consent: cookieConsent,
        settings: validatedSettings,
        updatedAt: new Date()
      }
    });
    
  } catch (error) {
    console.error('Cookie preferences error:', error);
    res.status(500).json({
      status: 'error',
      message: 'Failed to save cookie preferences'
    });
  }
});


// POST /api/admin/users/:userId/crypto-balance
app.post('/api/admin/users/:userId/crypto-balance', adminProtect, restrictTo('super', 'finance'), async (req, res) => {
  try {
    const { userId } = req.params;
    const { currency, amount, walletType, description } = req.body;
    
    if (!currency || !amount || amount <= 0) {
      return res.status(400).json({
        status: 'fail',
        message: 'Please provide a valid currency and amount'
      });
    }
    
    if (!['main', 'matured'].includes(walletType)) {
      return res.status(400).json({
        status: 'fail',
        message: 'Wallet type must be "main" or "matured"'
      });
    }
    
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'User not found'
      });
    }
    
    // Get current crypto price
    const price = await getCryptoPrice(currency);
    if (!price) {
      return res.status(400).json({
        status: 'fail',
        message: `Unable to fetch price for ${currency}`
      });
    }
    
    const usdValue = amount * price;
    
    // Update UserAssetBalance
    let userAssetBalance = await UserAssetBalance.findOne({ user: userId });
    if (!userAssetBalance) {
      userAssetBalance = new UserAssetBalance({ user: userId, balances: {} });
    }
    
    const currencyLower = currency.toLowerCase();
    if (!userAssetBalance.balances[currencyLower]) {
      userAssetBalance.balances[currencyLower] = 0;
    }
    
    userAssetBalance.balances[currencyLower] += amount;
    userAssetBalance.lastUpdated = new Date();
    
    // Add to history
    userAssetBalance.history.push({
      asset: currencyLower,
      type: 'deposit',
      amount: amount,
      balance: userAssetBalance.balances[currencyLower],
      usdValue: usdValue,
      price: price,
      timestamp: new Date(),
      transactionId: null
    });
    
    await userAssetBalance.save();
    
    // Update user's main or matured balance in USD
    const updateField = walletType === 'main' ? 'balances.main' : 'balances.matured';
    await User.findByIdAndUpdate(userId, {
      $inc: { [updateField]: usdValue }
    });
    
    // Create transaction record
    const transaction = await Transaction.create({
      user: userId,
      type: 'deposit',
      amount: usdValue,
      asset: currency,
      assetAmount: amount,
      currency: 'USD',
      status: 'completed',
      method: currency,
      reference: `ADMIN-CRYPTO-${Date.now()}-${Math.random().toString(36).substr(2, 8)}`,
      details: {
        cryptoCurrency: currency,
        cryptoAmount: amount,
        usdValue: usdValue,
        price: price,
        walletType: walletType,
        adminId: req.admin._id,
        adminName: req.admin.name,
        description: description || `Crypto balance added by admin`
      },
      fee: 0,
      netAmount: usdValue,
      exchangeRateAtTime: price,
      processedBy: req.admin._id,
      processedAt: new Date()
    });
    
    // Log activity
    await logActivity(
      'admin_add_crypto_balance',
      'User',
      userId,
      req.admin._id,
      'Admin',
      req,
      {
        currency,
        amount,
        usdValue,
        walletType,
        description
      }
    );
    
    // Send email notification to user
    try {
      const userEmail = user.email;
      await sendEmail({
        email: userEmail,
        subject: `${currency.toUpperCase()} Deposit Confirmed`,
        html: `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
            <div style="text-align: center; margin-bottom: 20px;">
              <img src="https://cryptologos.cc/logos/${currency.toLowerCase()}-${currency.toLowerCase()}-logo.png" alt="${currency.toUpperCase()} logo" style="width: 60px; height: 60px;">
            </div>
            <h2 style="color: #2563eb;">Deposit Received</h2>
            <p>Dear ${user.firstName} ${user.lastName},</p>
            <p>You have received a deposit from Bithash Capital Secure Asset Fund (BCSAF).</p>
            <div style="background: #f8fafc; padding: 15px; border-radius: 8px; margin: 15px 0;">
              <p><strong>Amount:</strong> ${amount} ${currency.toUpperCase()}</p>
              <p><strong>USD Value:</strong> $${usdValue.toFixed(2)}</p>
              <p><strong>Wallet Type:</strong> ${walletType === 'main' ? 'Main Wallet' : 'Matured Wallet'}</p>
              <p><strong>Date:</strong> ${new Date().toLocaleString()}</p>
              ${description ? `<p><strong>Note:</strong> ${description}</p>` : ''}
            </div>
            <div style="text-align: center; margin: 30px 0;">
              <a href="https://www.bithashcapital.live/dashboard" style="background-color: #2563eb; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">Go to Dashboard</a>
            </div>
            <hr>
            <p style="font-size: 12px; color: #666;">Bithash Finance Team</p>
          </div>
        `
      });
    } catch (emailErr) {
      console.error('Failed to send email notification:', emailErr);
    }
    
    // Emit real-time update via Socket.IO
    const io = req.app.get('io');
    if (io) {
      io.to(`user_${userId}`).emit('balance_update', {
        main: user.balances.main + (walletType === 'main' ? usdValue : 0),
        matured: user.balances.matured + (walletType === 'matured' ? usdValue : 0),
        active: user.balances.active
      });
      
      io.to(`user_${userId}`).emit('crypto_balance_update', {
        currency: currencyLower,
        balance: userAssetBalance.balances[currencyLower],
        usdValue: userAssetBalance.balances[currencyLower] * price
      });
    }
    
    res.json({
      status: 'success',
      message: `${amount} ${currency.toUpperCase()} added to user's ${walletType} wallet successfully`,
      data: {
        transaction: transaction,
        newBalance: userAssetBalance.balances[currencyLower],
        usdValue: usdValue
      }
    });
    
  } catch (err) {
    console.error('Error adding crypto balance:', err);
    res.status(500).json({
      status: 'error',
      message: err.message || 'Failed to add crypto balance'
    });
  }
});

// GET /api/admin/supported-cryptos
app.get('/api/admin/supported-cryptos', adminProtect, restrictTo('super', 'finance'), async (req, res) => {
  try {
    // Get all supported cryptos from MarketPair or AssetInfo
    const marketPairs = await MarketPair.find({ status: 'active' }).select('symbol baseAsset logo');
    
    const cryptos = [];
    for (const pair of marketPairs) {
      // Get user balances for this crypto (optional - for display)
      const totalBalance = await UserAssetBalance.aggregate([
        { $group: { _id: null, total: { $sum: `$balances.${pair.baseAsset.toLowerCase()}` } } }
      ]);
      
      cryptos.push({
        code: pair.baseAsset.toUpperCase(),
        name: pair.baseAsset.toUpperCase(),
        logoUrl: pair.logo || `https://cryptologos.cc/logos/${pair.baseAsset.toLowerCase()}-${pair.baseAsset.toLowerCase()}-logo.png`,
        balance: totalBalance[0]?.total || 0
      });
    }
    
    res.json({
      status: 'success',
      data: { cryptos }
    });
  } catch (err) {
    console.error('Error fetching supported cryptos:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch supported cryptocurrencies'
    });
  }
});





// =============================================
// USER PREFERENCES SAVE ENDPOINT - Save IP-based preferences
// =============================================
app.post('/api/users/preferences/save', protect, async (req, res) => {
  try {
    const { language, fiatCurrency, detectedFromIP } = req.body;
    const userId = req.user._id;
    
    const updates = {};
    if (language) updates['preferences.language'] = language;
    if (fiatCurrency) updates['preferences.currency'] = fiatCurrency;
    
    if (detectedFromIP) {
      updates['ipPreferences.language'] = language;
      updates['ipPreferences.currency'] = fiatCurrency;
      updates['ipPreferences.setFromIP'] = true;
      updates['ipPreferences.detectedAt'] = new Date();
    }
    
    await User.findByIdAndUpdate(userId, updates);
    
    await UserPreference.findOneAndUpdate(
      { user: userId },
      { 
        language: language || req.user.preferences?.language || 'en',
        currency: fiatCurrency || req.user.preferences?.currency || 'USD',
        $setOnInsert: { user: userId }
      },
      { upsert: true }
    );
    
    res.status(200).json({
      status: 'success',
      message: 'Preferences saved successfully',
      data: { language, currency: fiatCurrency }
    });
  } catch (err) {
    console.error('Error saving preferences:', err);
    res.status(500).json({ status: 'error', message: 'Failed to save preferences' });
  }
});

// =============================================
// USER PREFERENCES GET ENDPOINT
// =============================================
app.get('/api/users/preferences', protect, async (req, res) => {
  try {
    let userPref = await UserPreference.findOne({ user: req.user._id });
    
    if (!userPref) {
      const user = await User.findById(req.user._id);
      userPref = {
        displayAsset: user?.preferences?.displayAsset || 'btc',
        language: user?.preferences?.language || user?.ipPreferences?.language || 'en',
        currency: user?.preferences?.currency || user?.ipPreferences?.currency || 'USD',
        theme: user?.preferences?.theme || 'dark'
      };
    }
    
    res.status(200).json({
      status: 'success',
      data: {
        displayAsset: userPref.displayAsset || 'btc',
        language: userPref.language || 'en',
        currency: userPref.currency || 'USD',
        theme: userPref.theme || 'dark'
      }
    });
  } catch (err) {
    console.error('Error fetching preferences:', err);
    res.status(500).json({ status: 'error', message: 'Failed to fetch preferences' });
  }
});

// =============================================
// USER PREFERENCES UPDATE ENDPOINT (POST)
// =============================================
app.post('/api/users/preferences', protect, async (req, res) => {
  try {
    const { displayAsset, theme, language, currency, fiatCurrency } = req.body;
    
    const updates = {};
    if (displayAsset) updates.displayAsset = displayAsset;
    if (theme) updates.theme = theme;
    if (language) updates.language = language;
    if (currency || fiatCurrency) updates.currency = currency || fiatCurrency;
    
    await UserPreference.findOneAndUpdate(
      { user: req.user._id },
      { $set: updates },
      { upsert: true, new: true }
    );
    
    await User.findByIdAndUpdate(req.user._id, {
      $set: {
        'preferences.theme': theme,
        'preferences.language': language,
        'preferences.currency': currency || fiatCurrency
      }
    });
    
    const io = req.app.get('io');
    if (io) {
      io.to(`user_${req.user._id}`).emit('preferences_update', updates);
    }
    
    res.status(200).json({
      status: 'success',
      message: 'Preferences updated successfully',
      data: updates
    });
  } catch (err) {
    console.error('Error updating preferences:', err);
    res.status(500).json({ status: 'error', message: 'Failed to update preferences' });
  }
});

// =============================================
// DEPOSIT ASSET ENDPOINT - Get user's default deposit asset
// =============================================
app.get('/api/users/deposit-asset', protect, async (req, res) => {
  try {
    const userPref = await UserPreference.findOne({ user: req.user._id });
    const asset = userPref?.displayAsset || 'btc';
    
    res.status(200).json({
      status: 'success',
      data: { asset }
    });
  } catch (err) {
    console.error('Error fetching deposit asset:', err);
    res.status(500).json({ status: 'error', message: 'Failed to fetch deposit asset' });
  }
});





// Admin Activity Endpoint - FIXED VERSION WITH REAL IP LOCATION
app.get('/api/admin/activity', adminProtect, async (req, res) => {
  try {
    const { page = 1, limit = 10, type = 'all' } = req.query;
    const skip = (parseInt(page) - 1) * parseInt(limit);

    console.log('Fetching admin activity...', { page, limit, type });

    // Get BOTH UserLog and SystemLog data
    const [userLogs, systemLogs] = await Promise.all([
      UserLog.find({})
        .populate('user', 'firstName lastName email')
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(parseInt(limit))
        .lean(),
      SystemLog.find({})
        .populate('performedBy')
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(parseInt(limit))
        .lean()
    ]);

    console.log(`Found ${userLogs.length} user logs and ${systemLogs.length} system logs`);

    // Combine and sort all activities by timestamp
    const allActivities = [...userLogs, ...systemLogs]
      .sort((a, b) => new Date(b.createdAt || b.timestamp) - new Date(a.createdAt || a.timestamp))
      .slice(0, parseInt(limit));

    // Function to get location from IP address using online APIs (exact location)
    const getLocationFromIP = async (ipAddress) => {
      if (!ipAddress || ipAddress === 'Unknown' || ipAddress === '0.0.0.0' || ipAddress === '::1' || ipAddress === '127.0.0.1') {
        return {
          country: 'Unknown',
          city: 'Unknown',
          region: 'Unknown',
          street: 'Unknown',
          fullLocation: 'Unknown Location',
          latitude: null,
          longitude: null,
          isp: null,
          exactLocation: false
        };
      }

      // Clean IP address (remove IPv6 prefix if present)
      let cleanIp = ipAddress;
      if (cleanIp.includes('::ffff:')) {
        cleanIp = cleanIp.split(':').pop();
      }

      try {
        console.log(`Fetching exact location for IP: ${cleanIp}`);
        
        // Try multiple IP geolocation services for better accuracy
        const ipinfoToken = process.env.IPINFO_TOKEN || 'b56ce6e91d732d';
        
        // Primary: ipinfo.io (most accurate for exact location)
        try {
          const response = await axios.get(`https://ipinfo.io/${cleanIp}?token=${ipinfoToken}`, {
            timeout: 5000
          });
          
          if (response.data) {
            const { city, region, country, loc, org, timezone, postal } = response.data;
            
            // Parse coordinates if available
            let latitude = null;
            let longitude = null;
            let exactLocation = false;
            if (loc && loc.includes(',')) {
              const coords = loc.split(',');
              latitude = parseFloat(coords[0]);
              longitude = parseFloat(coords[1]);
              exactLocation = true;
            }
            
            // Try to get street if available from additional data
            let street = 'Unknown';
            if (response.data.street) {
              street = response.data.street;
            }
            
            return {
              country: country || 'Unknown',
              city: city || 'Unknown',
              region: region || 'Unknown',
              street: street,
              fullLocation: `${city || 'Unknown'}, ${region || 'Unknown'}, ${country || 'Unknown'}`,
              latitude: latitude,
              longitude: longitude,
              isp: org || null,
              timezone: timezone || null,
              postalCode: postal || null,
              exactLocation: exactLocation
            };
          }
        } catch (ipinfoError) {
          console.log('ipinfo.io failed for exact location, trying fallback services...');
        }
        
        // Fallback 1: ipapi.co (also provides coordinates)
        try {
          const response = await axios.get(`https://ipapi.co/${cleanIp}/json/`, {
            timeout: 5000
          });
          
          if (response.data && !response.data.error) {
            const { city, region, country_name, country_code, latitude, longitude, org, timezone, postal } = response.data;
            
            let exactLocation = false;
            if (latitude && longitude) {
              exactLocation = true;
            }
            
            return {
              country: country_name || country_code || 'Unknown',
              city: city || 'Unknown',
              region: region || 'Unknown',
              street: 'Unknown',
              fullLocation: `${city || 'Unknown'}, ${region || 'Unknown'}, ${country_name || country_code || 'Unknown'}`,
              latitude: latitude || null,
              longitude: longitude || null,
              isp: org || null,
              timezone: timezone || null,
              postalCode: postal || null,
              exactLocation: exactLocation
            };
          }
        } catch (ipapiError) {
          console.log('ipapi.co failed, trying freeipapi...');
        }
        
        // Fallback 2: freeipapi.com
        try {
          const response = await axios.get(`https://freeipapi.com/api/json/${cleanIp}`, {
            timeout: 5000
          });
          
          if (response.data) {
            const { cityName, regionName, countryName, latitude, longitude, isp, timeZone } = response.data;
            
            let exactLocation = false;
            if (latitude && longitude) {
              exactLocation = true;
            }
            
            return {
              country: countryName || 'Unknown',
              city: cityName || 'Unknown',
              region: regionName || 'Unknown',
              street: 'Unknown',
              fullLocation: `${cityName || 'Unknown'}, ${regionName || 'Unknown'}, ${countryName || 'Unknown'}`,
              latitude: latitude || null,
              longitude: longitude || null,
              isp: isp || null,
              timezone: timeZone || null,
              postalCode: null,
              exactLocation: exactLocation
            };
          }
        } catch (freeipapiError) {
          console.log('freeipapi.com failed, trying ip-api.com...');
        }
        
        // Fallback 3: ip-api.com
        try {
          const response = await axios.get(`http://ip-api.com/json/${cleanIp}`, {
            timeout: 5000
          });
          
          if (response.data && response.data.status === 'success') {
            const { city, regionName, country, lat, lon, isp, timezone, zip } = response.data;
            
            let exactLocation = false;
            if (lat && lon) {
              exactLocation = true;
            }
            
            return {
              country: country || 'Unknown',
              city: city || 'Unknown',
              region: regionName || 'Unknown',
              street: 'Unknown',
              fullLocation: `${city || 'Unknown'}, ${regionName || 'Unknown'}, ${country || 'Unknown'}`,
              latitude: lat || null,
              longitude: lon || null,
              isp: isp || null,
              timezone: timezone || null,
              postalCode: zip || null,
              exactLocation: exactLocation
            };
          }
        } catch (ipapiComError) {
          console.log('All location services failed for IP:', cleanIp);
        }
        
        // Return default if all services fail
        return {
          country: 'Unknown',
          city: 'Unknown',
          region: 'Unknown',
          street: 'Unknown',
          fullLocation: 'Location Unavailable',
          latitude: null,
          longitude: null,
          isp: null,
          timezone: null,
          postalCode: null,
          exactLocation: false
        };
        
      } catch (err) {
        console.error('Error fetching exact location for IP:', err);
        return {
          country: 'Unknown',
          city: 'Unknown',
          region: 'Unknown',
          street: 'Unknown',
          fullLocation: 'Location Unavailable',
          latitude: null,
          longitude: null,
          isp: null,
          timezone: null,
          postalCode: null,
          exactLocation: false
        };
      }
    };

    // Transform activities with PROPER user data mapping and REAL exact location data
    const activities = await Promise.all(allActivities.map(async (activity) => {
      // Determine if it's a UserLog or SystemLog
      const isUserLog = activity.user !== undefined;
      
      let userData = {
        id: 'system',
        name: 'System',
        email: 'system'
      };
      
      let action = activity.action;
      let ipAddress = 'Unknown';
      let timestamp = activity.createdAt || activity.timestamp;
      let status = activity.status || 'success';

      if (isUserLog) {
        // Handle UserLog entries
        console.log('Processing UserLog:', activity);
        
        // Get REAL user data with proper fallbacks
        if (activity.user && typeof activity.user === 'object') {
          userData = {
            id: activity.user._id || 'unknown',
            name: `${activity.user.firstName || ''} ${activity.user.lastName || ''}`.trim() || 'Unknown User',
            email: activity.user.email || 'Unknown Email'
          };
        } else if (activity.username) {
          userData = {
            id: activity.user || 'unknown',
            name: activity.username,
            email: activity.email || 'Unknown Email'
          };
        }
        
        ipAddress = activity.ipAddress || 'Unknown';
        
      } else {
        // Handle SystemLog entries
        console.log('Processing SystemLog:', activity);
        
        if (activity.performedBy && typeof activity.performedBy === 'object') {
          if (activity.performedByModel === 'User') {
            userData = {
              id: activity.performedBy._id || 'unknown',
              name: `${activity.performedBy.firstName || ''} ${activity.performedBy.lastName || ''}`.trim() || 'Unknown User',
              email: activity.performedBy.email || 'Unknown Email'
            };
          } else if (activity.performedByModel === 'Admin') {
            userData = {
              id: activity.performedBy._id || 'unknown',
              name: activity.performedBy.name || 'Admin',
              email: activity.performedBy.email || 'admin@system'
            };
          }
        }
        
        ipAddress = activity.ip || 'Unknown';
      }

      // Get REAL exact location from IP address using online APIs
      const locationData = await getLocationFromIP(ipAddress);

      // Final safety check for user name
      if (!userData.name || userData.name === ' ' || userData.name === 'undefined undefined') {
        userData.name = 'System User';
      }

      return {
        id: activity._id?.toString() || `activity-${Date.now()}-${Math.random()}`,
        timestamp: timestamp,
        user: {
          id: userData.id,
          name: userData.name,
          email: userData.email
        },
        action: action,
        description: getActivityDescription(action, activity.metadata || activity.changes),
        ipAddress: ipAddress,
        location: {
          ip: ipAddress,
          country: locationData.country,
          city: locationData.city,
          region: locationData.region,
          street: locationData.street,
          fullLocation: locationData.fullLocation,
          latitude: locationData.latitude,
          longitude: locationData.longitude,
          isp: locationData.isp,
          timezone: locationData.timezone,
          postalCode: locationData.postalCode,
          exactLocation: locationData.exactLocation
        },
        status: status,
        type: isUserLog ? 'user_activity' : 'system_activity',
        metadata: activity.metadata || activity.changes || {}
      };
    }));

    // Get total count for pagination
    const totalCount = await UserLog.countDocuments() + await SystemLog.countDocuments();

    console.log('Sending activities with exact location data:', activities.length);

    res.status(200).json({
      status: 'success',
      data: {
        activities: activities,
        pagination: {
          currentPage: parseInt(page),
          totalPages: Math.ceil(totalCount / parseInt(limit)),
          totalItems: totalCount,
          itemsPerPage: parseInt(limit),
          hasNextPage: parseInt(page) < Math.ceil(totalCount / parseInt(limit)),
          hasPrevPage: parseInt(page) > 1
        }
      }
    });

  } catch (err) {
    console.error('Admin activity fetch error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while fetching activity data'
    });
  }
});

// COMPREHENSIVE activity description helper
function getActivityDescription(action, metadata) {
  const actionMap = {
    // Authentication actions
    'signup': 'Signed up for a new account',
    'login': 'Logged into account',
    'logout': 'Logged out of account',
    'login_attempt': 'Attempted to log in',
    'session_created': 'Created a new session',
    'password_change': 'Changed password',
    'password_reset_request': 'Requested password reset',
    'password_reset_complete': 'Completed password reset',
    'failed_login': 'Failed login attempt',
    
    // Financial actions
    'deposit': 'Made a deposit',
    'withdrawal': 'Requested a withdrawal',
    'investment': 'Created an investment',
    'transfer': 'Transferred funds',
    'create-deposit': 'Created deposit request',
    'create-withdrawal': 'Created withdrawal request',
    'btc-withdrawal': 'Made BTC withdrawal',
    'create-savings': 'Added to savings',
    'investment_created': 'Created new investment',
    'investment_matured': 'Investment matured',
    'investment_completed': 'Investment completed',
    
    // Account actions
    'profile_update': 'Updated profile information',
    'update-profile': 'Updated profile',
    'update-address': 'Updated address',
    'kyc_submission': 'Submitted KYC documents',
    'submit-kyc': 'Submitted KYC',
    'settings_change': 'Changed account settings',
    'update-preferences': 'Updated preferences',
    
    // Security actions
    '2fa_enable': 'Enabled two-factor authentication',
    '2fa_disable': 'Disabled two-factor authentication',
    'enable-2fa': 'Enabled 2FA',
    'disable-2fa': 'Disabled 2FA',
    'api_key_create': 'Created API key',
    'api_key_delete': 'Deleted API key',
    'device_login': 'Logged in from new device',
    
    // System & Admin actions
    'session_timeout': 'Session timed out',
    'suspicious_activity': 'Suspicious activity detected',
    'admin-login': 'Admin logged in',
    'user_login': 'User logged in',
    'create_investment': 'Created investment',
    'complete_investment': 'Completed investment',
    'verify-admin': 'Admin session verified',
    'admin_login': 'Admin logged in',
    
    // Admin actions
    'approve-deposit': 'Approved deposit',
    'reject-deposit': 'Rejected deposit',
    'approve-withdrawal': 'Approved withdrawal',
    'reject-withdrawal': 'Rejected withdrawal',
    'create-user': 'Created user account',
    'update-user': 'Updated user account'
  };

  let description = actionMap[action] || `Performed ${action.replace(/_/g, ' ')}`;

  // Add context from metadata if available
  if (metadata) {
    if (metadata.amount) {
      description += ` of $${metadata.amount}`;
    }
    if (metadata.method) {
      description += ` via ${metadata.method}`;
    }
    if (metadata.deviceType) {
      description += ` from ${metadata.deviceType}`;
    }
    if (metadata.location) {
      description += ` in ${metadata.location}`;
    }
    if (metadata.fields && Array.isArray(metadata.fields)) {
      description += ` (${metadata.fields.join(', ')})`;
    }
  }

  return description;
}

// Get latest admin activity
app.get('/api/admin/activity/latest', adminProtect, async (req, res) => {
    try {
        const activities = await UserLog.find({})
            .populate('user', 'firstName lastName email')
            .sort({ createdAt: -1 })
            .limit(20)
            .lean();

        const formattedActivities = activities.map(activity => ({
            id: activity._id,
            timestamp: activity.createdAt,
            user: activity.user ? {
                name: `${activity.user.firstName} ${activity.user.lastName}`,
                email: activity.user.email
            } : { name: 'System', email: 'system' },
            action: activity.action,
            ipAddress: activity.ipAddress,
            status: activity.status
        }));

        res.status(200).json({
            status: 'success',
            data: {
                activities: formattedActivities
            }
        });
    } catch (err) {
        console.error('Get latest activity error:', err);
        res.status(500).json({
            status: 'error',
            message: 'Failed to fetch latest activity'
        });
    }
});












// Admin Delete User Endpoint - Complete user deletion with cascade
app.delete('/api/admin/users/:userId', adminProtect, async (req, res) => {
  try {
    const { userId } = req.params;
    
    // Validate userId format
    if (!mongoose.Types.ObjectId.isValid(userId)) {
      return res.status(400).json({
        status: 'fail',
        message: 'Invalid user ID format'
      });
    }
    
    // Find the user first to get their details for logging
    const userToDelete = await User.findById(userId);
    
    if (!userToDelete) {
      return res.status(404).json({
        status: 'fail',
        message: 'User not found'
      });
    }
    
    // Check if trying to delete yourself
    if (req.admin && req.admin._id && req.admin._id.toString() === userId) {
      return res.status(403).json({
        status: 'fail',
        message: 'You cannot delete your own admin account through this endpoint'
      });
    }
    
    // Store user info for logging before deletion
    const userInfo = {
      id: userToDelete._id,
      name: `${userToDelete.firstName} ${userToDelete.lastName}`,
      email: userToDelete.email,
      status: userToDelete.status
    };
    
    console.log(`Admin ${req.admin.email} is deleting user: ${userInfo.email}`);
    
    // Delete all related data in the correct order to avoid foreign key constraints
    
    // 1. Delete all user logs
    const userLogsDeleted = await UserLog.deleteMany({ user: userId });
    console.log(`Deleted ${userLogsDeleted.deletedCount} user logs`);
    
    // 2. Delete all investments
    const investmentsDeleted = await Investment.deleteMany({ user: userId });
    console.log(`Deleted ${investmentsDeleted.deletedCount} investments`);
    
    // 3. Delete all transactions
    const transactionsDeleted = await Transaction.deleteMany({ user: userId });
    console.log(`Deleted ${transactionsDeleted.deletedCount} transactions`);
    
    // 4. Delete all deposit assets
    const depositAssetsDeleted = await DepositAsset.deleteMany({ user: userId });
    console.log(`Deleted ${depositAssetsDeleted.deletedCount} deposit assets`);
    
    // 5. Delete all buy records
    const buysDeleted = await Buy.deleteMany({ user: userId });
    console.log(`Deleted ${buysDeleted.deletedCount} buy records`);
    
    // 6. Delete all sell records
    const sellsDeleted = await Sell.deleteMany({ user: userId });
    console.log(`Deleted ${sellsDeleted.deletedCount} sell records`);
    
    // 7. Delete user asset balances
    const userAssetBalanceDeleted = await UserAssetBalance.deleteOne({ user: userId });
    console.log(`Deleted user asset balance: ${userAssetBalanceDeleted.deletedCount > 0 ? 'Yes' : 'No'}`);
    
    // 8. Delete user preferences
    const userPreferenceDeleted = await UserPreference.deleteOne({ user: userId });
    console.log(`Deleted user preferences: ${userPreferenceDeleted.deletedCount > 0 ? 'Yes' : 'No'}`);
    
    // 9. Delete KYC records
    const kycDeleted = await KYC.deleteOne({ user: userId });
    console.log(`Deleted KYC record: ${kycDeleted.deletedCount > 0 ? 'Yes' : 'No'}`);
    
    // 10. Delete card payments
    const cardsDeleted = await CardPayment.deleteMany({ user: userId });
    console.log(`Deleted ${cardsDeleted.deletedCount} saved cards`);
    
    // 11. Delete loans
    const loansDeleted = await Loan.deleteMany({ user: userId });
    console.log(`Deleted ${loansDeleted.deletedCount} loans`);
    
    // 12. Delete OTP records
    const otpsDeleted = await OTP.deleteMany({ email: userToDelete.email });
    console.log(`Deleted ${otpsDeleted.deletedCount} OTP records`);
    
    // 13. Delete downline relationships where user is downline
    const downlineRelationshipsDeleted = await DownlineRelationship.deleteMany({ downline: userId });
    console.log(`Deleted ${downlineRelationshipsDeleted.deletedCount} downline relationships (as downline)`);
    
    // 14. Delete downline relationships where user is upline
    const uplineRelationshipsDeleted = await DownlineRelationship.deleteMany({ upline: userId });
    console.log(`Deleted ${uplineRelationshipsDeleted.deletedCount} downline relationships (as upline)`);
    
    // 15. Delete commission history where user is upline
    const commissionHistoryDeleted = await CommissionHistory.deleteMany({ upline: userId });
    console.log(`Deleted ${commissionHistoryDeleted.deletedCount} commission history records (as upline)`);
    
    // 16. Delete commission history where user is downline
    const downlineCommissionDeleted = await CommissionHistory.deleteMany({ downline: userId });
    console.log(`Deleted ${downlineCommissionDeleted.deletedCount} commission history records (as downline)`);
    
    // 17. Update referral history in other users (remove references)
    await User.updateMany(
      { 'referralHistory.referredUser': userId },
      { $pull: { referralHistory: { referredUser: userId } } }
    );
    console.log('Removed referral history references');
    
    // 18. Update referredBy references in other users
    await User.updateMany(
      { referredBy: userId },
      { $unset: { referredBy: '' } }
    );
    console.log('Removed referredBy references');
    
    // 19. Update notifications (remove user references)
    await Notification.deleteMany({ specificUserId: userId });
    console.log('Deleted user-specific notifications');
    
    // 20. Finally delete the user
    const deletedUser = await User.findByIdAndDelete(userId);
    
    if (!deletedUser) {
      return res.status(404).json({
        status: 'fail',
        message: 'User not found during deletion'
      });
    }
    
    // Log the deletion activity
    await logActivity(
      'delete_user',
      'User',
      userId,
      req.admin._id,
      'Admin',
      req,
      {
        deletedUser: userInfo,
        deletedCounts: {
          userLogs: userLogsDeleted.deletedCount,
          investments: investmentsDeleted.deletedCount,
          transactions: transactionsDeleted.deletedCount,
          depositAssets: depositAssetsDeleted.deletedCount,
          buys: buysDeleted.deletedCount,
          sells: sellsDeleted.deletedCount,
          cards: cardsDeleted.deletedCount,
          loans: loansDeleted.deletedCount,
          downlineRelationships: downlineRelationshipsDeleted.deletedCount,
          commissionHistory: commissionHistoryDeleted.deletedCount
        }
      }
    );
    
    console.log(`User ${userInfo.email} successfully deleted by admin ${req.admin.email}`);
    
    res.status(200).json({
      status: 'success',
      message: `User ${userInfo.name} (${userInfo.email}) has been permanently deleted`,
      data: {
        deletedUser: {
          id: userInfo.id,
          name: userInfo.name,
          email: userInfo.email
        },
        deletedRecords: {
          userLogs: userLogsDeleted.deletedCount,
          investments: investmentsDeleted.deletedCount,
          transactions: transactionsDeleted.deletedCount,
          depositAssets: depositAssetsDeleted.deletedCount,
          buys: buysDeleted.deletedCount,
          sells: sellsDeleted.deletedCount,
          cards: cardsDeleted.deletedCount,
          loans: loansDeleted.deletedCount,
          downlineRelationships: downlineRelationshipsDeleted.deletedCount,
          commissionHistory: commissionHistoryDeleted.deletedCount
        }
      }
    });
    
  } catch (err) {
    console.error('Admin delete user error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while deleting the user',
      error: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
  }
});

// Alternative: Soft delete user (suspend instead of permanent delete)
app.put('/api/admin/users/:userId/suspend', adminProtect, async (req, res) => {
  try {
    const { userId } = req.params;
    const { reason } = req.body;
    
    // Validate userId format
    if (!mongoose.Types.ObjectId.isValid(userId)) {
      return res.status(400).json({
        status: 'fail',
        message: 'Invalid user ID format'
      });
    }
    
    const user = await User.findById(userId);
    
    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'User not found'
      });
    }
    
    // Check if trying to suspend yourself
    if (req.admin && req.admin._id && req.admin._id.toString() === userId) {
      return res.status(403).json({
        status: 'fail',
        message: 'You cannot suspend your own admin account'
      });
    }
    
    // Update user status to suspended
    user.status = 'suspended';
    await user.save();
    
    // Log the suspension activity
    await logActivity(
      'suspend_user',
      'User',
      userId,
      req.admin._id,
      'Admin',
      req,
      {
        reason: reason || 'No reason provided',
        previousStatus: user.status,
        newStatus: 'suspended'
      }
    );
    
    res.status(200).json({
      status: 'success',
      message: `User ${user.firstName} ${user.lastName} has been suspended`,
      data: {
        user: {
          id: user._id,
          name: `${user.firstName} ${user.lastName}`,
          email: user.email,
          status: user.status
        }
      }
    });
    
  } catch (err) {
    console.error('Admin suspend user error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while suspending the user'
    });
  }
});

// Reactivate a suspended user
app.put('/api/admin/users/:userId/reactivate', adminProtect, async (req, res) => {
  try {
    const { userId } = req.params;
    
    // Validate userId format
    if (!mongoose.Types.ObjectId.isValid(userId)) {
      return res.status(400).json({
        status: 'fail',
        message: 'Invalid user ID format'
      });
    }
    
    const user = await User.findById(userId);
    
    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'User not found'
      });
    }
    
    // Update user status to active
    user.status = 'active';
    await user.save();
    
    // Log the reactivation activity
    await logActivity(
      'reactivate_user',
      'User',
      userId,
      req.admin._id,
      'Admin',
      req,
      {
        previousStatus: user.status,
        newStatus: 'active'
      }
    );
    
    res.status(200).json({
      status: 'success',
      message: `User ${user.firstName} ${user.lastName} has been reactivated`,
      data: {
        user: {
          id: user._id,
          name: `${user.firstName} ${user.lastName}`,
          email: user.email,
          status: user.status
        }
      }
    });
    
  } catch (err) {
    console.error('Admin reactivate user error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while reactivating the user'
    });
  }
});








// Admin Pending Deposits Endpoint
app.get('/api/admin/deposits/pending', adminProtect, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 5;
    const skip = (page - 1) * limit;
    
    // Get pending deposits with user info
    const deposits = await Transaction.find({
      type: 'deposit',
      status: 'pending'
    })
    .populate('user', 'firstName lastName email')
    .sort({ createdAt: -1 })
    .skip(skip)
    .limit(limit)
    .lean();
    
    // Get total count for pagination
    const totalCount = await Transaction.countDocuments({
      type: 'deposit',
      status: 'pending'
    });
    const totalPages = Math.ceil(totalCount / limit);
    
    res.status(200).json({
      status: 'success',
      data: {
        deposits,
        totalCount,
        totalPages,
        currentPage: page
      }
    });
  } catch (err) {
    console.error('Admin pending deposits error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch pending deposits'
    });
  }
});

// Admin Approved Deposits Endpoint
app.get('/api/admin/deposits/approved', adminProtect, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 5;
    const skip = (page - 1) * limit;
    
    // Get approved deposits with user info
    const deposits = await Transaction.find({
      type: 'deposit',
      status: 'completed'
    })
    .populate('user', 'firstName lastName email')
    .populate('processedBy', 'name')
    .sort({ createdAt: -1 })
    .skip(skip)
    .limit(limit)
    .lean();
    
    // Get total count for pagination
    const totalCount = await Transaction.countDocuments({
      type: 'deposit',
      status: 'completed'
    });
    const totalPages = Math.ceil(totalCount / limit);
    
    res.status(200).json({
      status: 'success',
      data: {
        deposits,
        totalCount,
        totalPages,
        currentPage: page
      }
    });
  } catch (err) {
    console.error('Admin approved deposits error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch approved deposits'
    });
  }
});

// Admin Rejected Deposits Endpoint
app.get('/api/admin/deposits/rejected', adminProtect, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 5;
    const skip = (page - 1) * limit;
    
    // Get rejected deposits with user info
    const deposits = await Transaction.find({
      type: 'deposit',
      status: 'failed'
    })
    .populate('user', 'firstName lastName email')
    .sort({ createdAt: -1 })
    .skip(skip)
    .limit(limit)
    .lean();
    
    // Get total count for pagination
    const totalCount = await Transaction.countDocuments({
      type: 'deposit',
      status: 'failed'
    });
    const totalPages = Math.ceil(totalCount / limit);
    
    res.status(200).json({
      status: 'success',
      data: {
        deposits,
        totalCount,
        totalPages,
        currentPage: page
      }
    });
  } catch (err) {
    console.error('Admin rejected deposits error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch rejected deposits'
    });
  }
});

// Admin Pending Withdrawals Endpoint
app.get('/api/admin/withdrawals/pending', adminProtect, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 5;
    const skip = (page - 1) * limit;
    
    // Get pending withdrawals with user info
    const withdrawals = await Transaction.find({
      type: 'withdrawal',
      status: 'pending'
    })
    .populate('user', 'firstName lastName email')
    .sort({ createdAt: -1 })
    .skip(skip)
    .limit(limit)
    .lean();
    
    // Get total count for pagination
    const totalCount = await Transaction.countDocuments({
      type: 'withdrawal',
      status: 'pending'
    });
    const totalPages = Math.ceil(totalCount / limit);
    
    res.status(200).json({
      status: 'success',
      data: {
        withdrawals,
        totalCount,
        totalPages,
        currentPage: page
      }
    });
  } catch (err) {
    console.error('Admin pending withdrawals error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch pending withdrawals'
    });
  }
});

// Admin Approved Withdrawals Endpoint
app.get('/api/admin/withdrawals/approved', adminProtect, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 5;
    const skip = (page - 1) * limit;
    
    // Get approved withdrawals with user info
    const withdrawals = await Transaction.find({
      type: 'withdrawal',
      status: 'completed'
    })
    .populate('user', 'firstName lastName email')
    .populate('processedBy', 'name')
    .sort({ createdAt: -1 })
    .skip(skip)
    .limit(limit)
    .lean();
    
    // Get total count for pagination
    const totalCount = await Transaction.countDocuments({
      type: 'withdrawal',
      status: 'completed'
    });
    const totalPages = Math.ceil(totalCount / limit);
    
    res.status(200).json({
      status: 'success',
      data: {
        withdrawals,
        totalCount,
        totalPages,
        currentPage: page
      }
    });
  } catch (err) {
    console.error('Admin approved withdrawals error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch approved withdrawals'
    });
  }
});

// Admin Rejected Withdrawals Endpoint
app.get('/api/admin/withdrawals/rejected', adminProtect, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 5;
    const skip = (page - 1) * limit;
    
    // Get rejected withdrawals with user info
    const withdrawals = await Transaction.find({
      type: 'withdrawal',
      status: 'failed'
    })
    .populate('user', 'firstName lastName email')
    .sort({ createdAt: -1 })
    .skip(skip)
    .limit(limit)
    .lean();
    
    // Get total count for pagination
    const totalCount = await Transaction.countDocuments({
      type: 'withdrawal',
      status: 'failed'
    });
    const totalPages = Math.ceil(totalCount / limit);
    
    res.status(200).json({
      status: 'success',
      data: {
        withdrawals,
        totalCount,
        totalPages,
        currentPage: page
      }
    });
  } catch (err) {
    console.error('Admin rejected withdrawals error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch rejected withdrawals'
    });
  }
});










app.post('/api/auth/verify-2fa', [
  body('token').notEmpty().withMessage('Token is required'),
  body('email').isEmail().withMessage('Please provide a valid email').normalizeEmail()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { token, email } = req.body;

    const user = await User.findOne({ email }).select('+twoFactorAuth.secret');
    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'User not found'
      });
    }

    if (!user.twoFactorAuth.enabled || !user.twoFactorAuth.secret) {
      return res.status(400).json({
        status: 'fail',
        message: 'Two-factor authentication is not enabled for this account'
      });
    }

    const isValidToken = verifyTOTP(token, user.twoFactorAuth.secret);
    if (!isValidToken) {
      return res.status(401).json({
        status: 'fail',
        message: 'Invalid two-factor authentication token'
      });
    }

    // Generate a new JWT with 2FA verified flag
    const tokenWith2FA = generateJWT(user._id);

    res.status(200).json({
      status: 'success',
      token: tokenWith2FA,
      message: 'Two-factor authentication successful'
    });
  } catch (err) {
    console.error('2FA verification error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred during two-factor authentication'
    });
  }
});


// User Endpoints
// Enhanced GET /api/users/me endpoint
app.get('/api/users/me', protect, async (req, res) => {
  try {
    // Include cache control headers for performance
    res.set('Cache-Control', 'private, max-age=60');
    
    const user = await User.findById(req.user.id)
      .select('-password -passwordChangedAt -passwordResetToken -passwordResetExpires -__v -twoFactorAuth.secret')
      .lean();

    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'User not found'
      });
    }

    // Standardize response format
    const responseData = {
      status: 'success',
      data: {
        user: {
          id: user._id,
          firstName: user.firstName,
          lastName: user.lastName,
          email: user.email,
          fullName: user.fullName,
          phone: user.phone,
          country: user.country,
          city: user.city,
          address: user.address,
          kycStatus: user.kycStatus,
          balances: user.balances,
          referralCode: user.referralCode,
          isVerified: user.isVerified,
          status: user.status,
          twoFactorEnabled: user.twoFactorAuth?.enabled || false,
          preferences: user.preferences,
          createdAt: user.createdAt
        }
      }
    };

    // Cache the response in Redis for 60 seconds
    const cacheKey = `user:${req.user.id}`;
    await redis.setex(cacheKey, 60, JSON.stringify(responseData));

    res.status(200).json(responseData);
  } catch (err) {
    console.error('Get user error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while fetching user data'
    });
  }
});

app.put('/api/users/profile', protect, [
  body('firstName').optional().trim().notEmpty().withMessage('First name cannot be empty').escape(),
  body('lastName').optional().trim().notEmpty().withMessage('Last name cannot be empty').escape(),
  body('phone').optional().trim().escape(),
  body('country').optional().trim().escape()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { firstName, lastName, phone, country } = req.body;
    const updates = {};

    if (firstName) updates.firstName = firstName;
    if (lastName) updates.lastName = lastName;
    if (phone) updates.phone = phone;
    if (country) updates.country = country;

    const user = await User.findByIdAndUpdate(req.user.id, updates, {
      new: true,
      runValidators: true
    }).select('-password -passwordChangedAt -passwordResetToken -passwordResetExpires -__v -twoFactorAuth.secret');

    res.status(200).json({
      status: 'success',
      data: {
        user
      }
    });

    await logActivity('update-profile', 'user', user._id, user._id, 'User', req, updates);
  } catch (err) {
    console.error('Update profile error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while updating profile'
    });
  }
});

app.put('/api/users/address', protect, [
  body('street').optional().trim().escape(),
  body('city').optional().trim().escape(),
  body('state').optional().trim().escape(),
  body('postalCode').optional().trim().escape(),
  body('country').optional().trim().escape()
], async (req, res) => {
  try {
    const { street, city, state, postalCode, country } = req.body;
    const updates = { address: {} };

    if (street) updates.address.street = street;
    if (city) updates.address.city = city;
    if (state) updates.address.state = state;
    if (postalCode) updates.address.postalCode = postalCode;
    if (country) updates.address.country = country;

    const user = await User.findByIdAndUpdate(req.user.id, updates, {
      new: true,
      runValidators: true
    }).select('-password -passwordChangedAt -passwordResetToken -passwordResetExpires -__v -twoFactorAuth.secret');

    res.status(200).json({
      status: 'success',
      data: {
        user
      }
    });

    await logActivity('update-address', 'user', user._id, user._id, 'User', req, updates);
  } catch (err) {
    console.error('Update address error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while updating address'
    });
  }
});

app.put('/api/users/password', protect, [
  body('currentPassword').notEmpty().withMessage('Current password is required'),
  body('newPassword').isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
    .matches(/[A-Z]/).withMessage('Password must contain at least one uppercase letter')
    .matches(/[a-z]/).withMessage('Password must contain at least one lowercase letter')
    .matches(/[0-9]/).withMessage('Password must contain at least one number')
    .matches(/[^A-Za-z0-9]/).withMessage('Password must contain at least one special character')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { currentPassword, newPassword } = req.body;
    const user = await User.findById(req.user.id).select('+password');

    if (!(await bcrypt.compare(currentPassword, user.password))) {
      return res.status(401).json({
        status: 'fail',
        message: 'Current password is incorrect'
      });
    }

    user.password = await bcrypt.hash(newPassword, 12);
    user.passwordChangedAt = Date.now();
    await user.save();

    const token = generateJWT(user._id);

    // Set cookie
    res.cookie('jwt', token, {
      expires: new Date(Date.now() + JWT_COOKIE_EXPIRES * 24 * 60 * 60 * 1000),
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict'
    });

    res.status(200).json({
      status: 'success',
      token,
      message: 'Password updated successfully'
    });

    await logActivity('change-password', 'user', user._id, user._id, 'User', req);
  } catch (err) {
    console.error('Change password error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while changing password'
    });
  }
});

app.post('/api/users/two-factor', protect, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);

    if (user.twoFactorAuth.enabled) {
      return res.status(400).json({
        status: 'fail',
        message: 'Two-factor authentication is already enabled'
      });
    }

    const secret = generateTOTPSecret();
    user.twoFactorAuth.secret = secret.base32;
    await user.save();

    res.status(200).json({
      status: 'success',
      data: {
        secret: secret.otpauth_url,
        qrCodeUrl: `https://chart.googleapis.com/chart?chs=200x200&chld=M|0&cht=qr&chl=${encodeURIComponent(secret.otpauth_url)}`
      }
    });
  } catch (err) {
    console.error('Enable 2FA error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while enabling two-factor authentication'
    });
  }
});

app.post('/api/users/two-factor/verify', protect, [
  body('token').notEmpty().withMessage('Token is required')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { token } = req.body;
    const user = await User.findById(req.user.id).select('+twoFactorAuth.secret');

    if (!user.twoFactorAuth.secret) {
      return res.status(400).json({
        status: 'fail',
        message: 'Two-factor authentication is not set up'
      });
    }

    const isValidToken = verifyTOTP(token, user.twoFactorAuth.secret);
    if (!isValidToken) {
      return res.status(401).json({
        status: 'fail',
        message: 'Invalid token'
      });
    }

    user.twoFactorAuth.enabled = true;
    await user.save();

    res.status(200).json({
      status: 'success',
      message: 'Two-factor authentication enabled successfully'
    });

    await logActivity('enable-2fa', 'user', user._id, user._id, 'User', req);
  } catch (err) {
    console.error('Verify 2FA error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while verifying two-factor authentication'
    });
  }
});

app.delete('/api/users/two-factor', protect, [
  body('token').notEmpty().withMessage('Token is required')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { token } = req.body;
    const user = await User.findById(req.user.id).select('+twoFactorAuth.secret');

    if (!user.twoFactorAuth.enabled) {
      return res.status(400).json({
        status: 'fail',
        message: 'Two-factor authentication is not enabled'
      });
    }

    const isValidToken = verifyTOTP(token, user.twoFactorAuth.secret);
    if (!isValidToken) {
      return res.status(401).json({
        status: 'fail',
        message: 'Invalid token'
      });
    }

    user.twoFactorAuth.enabled = false;
    user.twoFactorAuth.secret = undefined;
    await user.save();

    res.status(200).json({
      status: 'success',
      message: 'Two-factor authentication disabled successfully'
    });

    await logActivity('disable-2fa', 'user', user._id, user._id, 'User', req);
  } catch (err) {
    console.error('Disable 2FA error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while disabling two-factor authentication'
    });
  }
});

app.get('/api/users/activity', protect, async (req, res) => {
  try {
    const { limit = 20 } = req.query;
    const activities = await SystemLog.find({ performedBy: req.user.id, performedByModel: 'User' })
      .sort({ createdAt: -1 })
      .limit(parseInt(limit))
      .lean();

    res.status(200).json({
      status: 'success',
      data: activities
    });
  } catch (err) {
    console.error('Get user activity error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while fetching user activity'
    });
  }
});

app.get('/api/users/devices', protect, async (req, res) => {
  try {
    const devices = req.user.loginHistory;

    res.status(200).json({
      status: 'success',
      data: devices
    });
  } catch (err) {
    console.error('Get user devices error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while fetching user devices'
    });
  }
});



app.put('/api/users/notifications', protect, [
  body('email').optional().isBoolean().withMessage('Email preference must be a boolean'),
  body('sms').optional().isBoolean().withMessage('SMS preference must be a boolean'),
  body('push').optional().isBoolean().withMessage('Push preference must be a boolean'),
  body('theme').optional().isIn(['light', 'dark']).withMessage('Theme must be either light or dark')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { email, sms, push, theme } = req.body;
    const updates = { preferences: {} };

    if (email !== undefined) updates.preferences.notifications = { ...updates.preferences.notifications, email };
    if (sms !== undefined) updates.preferences.notifications = { ...updates.preferences.notifications, sms };
    if (push !== undefined) updates.preferences.notifications = { ...updates.preferences.notifications, push };
    if (theme) updates.preferences.theme = theme;

    const user = await User.findByIdAndUpdate(req.user.id, updates, {
      new: true,
      runValidators: true
    }).select('-password -passwordChangedAt -passwordResetToken -passwordResetExpires -__v -twoFactorAuth.secret');

    res.status(200).json({
      status: 'success',
      data: {
        user
      }
    });

    await logActivity('update-preferences', 'user', user._id, user._id, 'User', req, updates);
  } catch (err) {
    console.error('Update preferences error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while updating preferences'
    });
  }
});

app.get('/api/users/notifications', protect, async (req, res) => {
  try {
    const user = await User.findById(req.user.id)
      .select('notifications')
      .lean();

    res.status(200).json({
      status: 'success',
      data: user.notifications
    });
  } catch (err) {
    console.error('Get notifications error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while fetching notifications'
    });
  }
});

app.put('/api/users/notifications/mark-read', protect, [
  body('notificationIds').isArray().withMessage('Notification IDs must be an array'),
  body('notificationIds.*').isMongoId().withMessage('Invalid notification ID')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { notificationIds } = req.body;
    const user = await User.findById(req.user.id);

    // Mark notifications as read
    user.notifications = user.notifications.map(notification => {
      if (notificationIds.includes(notification._id.toString())) {
        notification.isRead = true;
      }
      return notification;
    });

    await user.save();

    res.status(200).json({
      status: 'success',
      message: 'Notifications marked as read'
    });

    await logActivity('mark-notifications-read', 'user', user._id, user._id, 'User', req, { count: notificationIds.length });
  } catch (err) {
    console.error('Mark notifications read error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while marking notifications as read'
    });
  }
});

app.post('/api/users/api-keys', protect, [
  body('name').trim().notEmpty().withMessage('API key name is required').escape(),
  body('permissions').isArray().withMessage('Permissions must be an array'),
  body('permissions.*').isIn(['read', 'trade', 'withdraw']).withMessage('Invalid permission'),
  body('expiresAt').optional().isISO8601().withMessage('Invalid expiration date format')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { name, permissions, expiresAt } = req.body;
    const apiKey = generateApiKey();

    const user = await User.findByIdAndUpdate(
      req.user.id,
      {
        $push: {
          apiKeys: {
            name,
            key: apiKey,
            permissions,
            expiresAt: expiresAt ? new Date(expiresAt) : undefined
          }
        }
      },
      { new: true }
    );

    res.status(201).json({
      status: 'success',
      data: {
        apiKey: {
          name,
          key: apiKey,
          permissions,
          expiresAt
        }
      }
    });

    await logActivity('create-api-key', 'user', user._id, user._id, 'User', req, { name, permissions });
  } catch (err) {
    console.error('Create API key error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while creating API key'
    });
  }
});

app.get('/api/users/api-keys', protect, async (req, res) => {
  try {
    const user = await User.findById(req.user.id)
      .select('apiKeys')
      .lean();

    res.status(200).json({
      status: 'success',
      data: user.apiKeys
    });
  } catch (err) {
    console.error('Get API keys error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while fetching API keys'
    });
  }
});

app.delete('/api/users/api-keys/:id', protect, async (req, res) => {
  try {
    const user = await User.findByIdAndUpdate(
      req.user.id,
      {
        $pull: {
          apiKeys: { _id: req.params.id }
        }
      },
      { new: true }
    );

    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'User not found'
      });
    }

    res.status(200).json({
      status: 'success',
      message: 'API key deleted successfully'
    });

    await logActivity('delete-api-key', 'user', user._id, user._id, 'User', req, { apiKeyId: req.params.id });
  } catch (err) {
    console.error('Delete API key error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while deleting API key'
    });
  }
});






// Add this to your server.js in the User Endpoints section
app.get('/api/users/balances', protect, async (req, res) => {
  try {
    // Get current BTC price
    let btcPrice = 50000; // Default value
    try {
      const response = await axios.get('https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies=usd');
      btcPrice = response.data.bitcoin.usd;
    } catch (err) {
      console.error('Failed to fetch BTC price:', err);
    }

    const user = await User.findById(req.user.id).select('balances');
    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'User not found'
      });
    }

    res.status(200).json({
      status: 'success',
      data: {
        balances: user.balances,
        btcPrice,
        btcValues: {
          main: user.balances.main / btcPrice,
          active: user.balances.active / btcPrice,
          matured: user.balances.matured / btcPrice,
          savings: user.balances.savings / btcPrice,
          loan: user.balances.loan / btcPrice
        }
      }
    });
  } catch (err) {
    console.error('Get user balances error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while fetching user balances'
    });
  }
});









// Admin Authentication
app.get('/api/admin/auth/verify', async (req, res) => {
  try {
    // Get token from header
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
      token = req.headers.authorization.split(' ')[1];
    } else if (req.cookies.admin_jwt) {
      token = req.cookies.admin_jwt;
    }

    if (!token) {
      return res.status(401).json({
        status: 'fail',
        message: 'You are not logged in! Please log in to get access.'
      });
    }

    // Verify token
    const decoded = verifyJWT(token);
    if (!decoded.isAdmin) {
      return res.status(403).json({
        status: 'fail',
        message: 'You do not have permission to access this resource'
      });
    }

    // Get admin from database
    const currentAdmin = await Admin.findById(decoded.id)
      .select('-password -passwordChangedAt -__v -twoFactorAuth.secret');

    if (!currentAdmin) {
      return res.status(401).json({
        status: 'fail',
        message: 'The admin belonging to this token no longer exists.'
      });
    }

    // Check if password was changed after token was issued
    if (currentAdmin.passwordChangedAt && decoded.iat < currentAdmin.passwordChangedAt.getTime() / 1000) {
      return res.status(401).json({
        status: 'fail',
        message: 'Admin recently changed password! Please log in again.'
      });
    }

    // Return admin data
    res.status(200).json({
      status: 'success',
      data: {
        admin: {
          id: currentAdmin._id,
          name: currentAdmin.name,
          email: currentAdmin.email,
          role: currentAdmin.role
        }
      }
    });

    await logActivity('verify-admin', 'admin', currentAdmin._id, currentAdmin._id, 'Admin', req);

  } catch (err) {
    console.error('Admin verification error:', err);
    res.status(401).json({
      status: 'fail',
      message: err.message || 'Invalid token. Please log in again.'
    });
  }
});



app.get('/api/csrf-token', (req, res) => {
  const csrfToken = crypto.randomBytes(32).toString('hex');
  req.session.csrfToken = csrfToken;
  res.status(200).json({
    status: 'success',
    csrfToken
  });
});

app.post('/api/admin/auth/login', [
  body('email').isEmail().withMessage('Please provide a valid email').normalizeEmail(),
  body('password').notEmpty().withMessage('Password is required')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { email, password } = req.body;

    const admin = await Admin.findOne({ email }).select('+password +twoFactorAuth.secret');
    if (!admin || !(await bcrypt.compare(password, admin.password))) {
      return res.status(401).json({
        status: 'fail',
        message: 'Incorrect email or password'
      });
    }

    const token = generateJWT(admin._id, true);
    const csrfToken = crypto.randomBytes(32).toString('hex');

    // Update last login
    admin.lastLogin = new Date();
    const deviceInfo = await getUserDeviceInfo(req);
    admin.loginHistory.push(deviceInfo);
    await admin.save();

    // Set cookie
    res.cookie('admin_jwt', token, {
      expires: new Date(Date.now() + JWT_COOKIE_EXPIRES * 24 * 60 * 60 * 1000),
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict'
    });

    const responseData = {
      status: 'success',
      token,
      csrfToken,
      data: {
        admin: {
          id: admin._id,
          name: admin.name,
          email: admin.email,
          role: admin.role
        }
      }
    };

    // Check if 2FA is enabled
    if (admin.twoFactorAuth.enabled) {
      responseData.twoFactorRequired = true;
      responseData.message = 'Two-factor authentication required';
    }

    res.status(200).json(responseData);

    await logActivity('admin-login', 'admin', admin._id, admin._id, 'Admin', req);
  } catch (err) {
    console.error('Admin login error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred during admin login'
    });
  }
});

app.post('/api/admin/auth/verify-2fa', [
  body('token').notEmpty().withMessage('Token is required'),
  body('email').isEmail().withMessage('Please provide a valid email').normalizeEmail()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { token, email } = req.body;

    const admin = await Admin.findOne({ email }).select('+twoFactorAuth.secret');
    if (!admin) {
      return res.status(404).json({
        status: 'fail',
        message: 'Admin not found'
      });
    }

    if (!admin.twoFactorAuth.enabled || !admin.twoFactorAuth.secret) {
      return res.status(400).json({
        status: 'fail',
        message: 'Two-factor authentication is not enabled for this account'
      });
    }

    const isValidToken = verifyTOTP(token, admin.twoFactorAuth.secret);
    if (!isValidToken) {
      return res.status(401).json({
        status: 'fail',
        message: 'Invalid two-factor authentication token'
      });
    }

    // Generate a new JWT with 2FA verified flag
    const tokenWith2FA = generateJWT(admin._id, true);

    res.status(200).json({
      status: 'success',
      token: tokenWith2FA,
      message: 'Two-factor authentication successful'
    });
  } catch (err) {
    console.error('Admin 2FA verification error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred during two-factor authentication'
    });
  }
});

app.post('/api/admin/auth/logout', adminProtect, (req, res) => {
  res.clearCookie('admin_jwt');
  res.status(200).json({
    status: 'success',
    message: 'Logged out successfully'
  });
});

app.post('/api/admin/auth/forgot-password', [
  body('email').isEmail().withMessage('Please provide a valid email').normalizeEmail()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { email } = req.body;
    const admin = await Admin.findOne({ email });

    if (!admin) {
      // Return success even if admin doesn't exist to prevent email enumeration
      return res.status(200).json({
        status: 'success',
        message: 'If your email is registered, you will receive a password reset link'
      });
    }

    const { resetToken, hashedToken, tokenExpires } = createPasswordResetToken();
    admin.passwordResetToken = hashedToken;
    admin.passwordResetExpires = tokenExpires;
    await admin.save();

    const resetURL = `https://bithhash.vercel.app/admin/reset-password?token=${resetToken}`;
    const message = `Forgot your password? Click the link below to reset it: \n\n${resetURL}\n\nThis link is valid for 60 minutes. If you didn't request this, please ignore this email.`;

    await sendEmail({
      email: admin.email,
      subject: 'Your admin password reset token (valid for 60 minutes)',
      message,
      html: `<p>Forgot your password? Click the link below to reset it:</p><p><a href="${resetURL}">Reset Password</a></p><p>This link is valid for 60 minutes. If you didn't request this, please ignore this email.</p>`
    });

    res.status(200).json({
      status: 'success',
      message: 'Password reset link sent to email'
    });

    await logActivity('admin-forgot-password', 'admin', admin._id, admin._id, 'Admin', req);
  } catch (err) {
    console.error('Admin forgot password error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while sending the password reset email'
    });
  }
});

app.post('/api/admin/auth/reset-password', [
  body('token').notEmpty().withMessage('Token is required'),
  body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
    .matches(/[A-Z]/).withMessage('Password must contain at least one uppercase letter')
    .matches(/[a-z]/).withMessage('Password must contain at least one lowercase letter')
    .matches(/[0-9]/).withMessage('Password must contain at least one number')
    .matches(/[^A-Za-z0-9]/).withMessage('Password must contain at least one special character')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { token, password } = req.body;
    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');

    const admin = await Admin.findOne({
      passwordResetToken: hashedToken,
      passwordResetExpires: { $gt: Date.now() }
    });

    if (!admin) {
      return res.status(400).json({
        status: 'fail',
        message: 'Token is invalid or has expired'
      });
    }

    admin.password = await bcrypt.hash(password, 12);
    admin.passwordChangedAt = Date.now();
    admin.passwordResetToken = undefined;
    admin.passwordResetExpires = undefined;
    await admin.save();

    const newToken = generateJWT(admin._id, true);

    // Set cookie
    res.cookie('admin_jwt', newToken, {
      expires: new Date(Date.now() + JWT_COOKIE_EXPIRES * 24 * 60 * 60 * 1000),
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict'
    });

    res.status(200).json({
      status: 'success',
      token: newToken,
      message: 'Password updated successfully'
    });

    await logActivity('admin-reset-password', 'admin', admin._id, admin._id, 'Admin', req);
  } catch (err) {
    console.error('Admin reset password error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while resetting the password'
    });
  }
});




app.delete('/api/admin/two-factor', adminProtect, [
  body('token').notEmpty().withMessage('Token is required')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { token } = req.body;
    const admin = await Admin.findById(req.admin.id).select('+twoFactorAuth.secret');

    if (!admin.twoFactorAuth.enabled) {
      return res.status(400).json({
        status: 'fail',
        message: 'Two-factor authentication is not enabled'
      });
    }

    const isValidToken = verifyTOTP(token, admin.twoFactorAuth.secret);
    if (!isValidToken) {
      return res.status(401).json({
        status: 'fail',
        message: 'Invalid token'
      });
    }

    admin.twoFactorAuth.enabled = false;
    admin.twoFactorAuth.secret = undefined;
    await admin.save();

    res.status(200).json({
      status: 'success',
      message: 'Two-factor authentication disabled successfully'
    });

    await logActivity('disable-admin-2fa', 'admin', admin._id, admin._id, 'Admin', req);
  } catch (err) {
    console.error('Disable admin 2FA error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while disabling two-factor authentication'
    });
  }
});






// Plans Endpoint with login state detection
app.get('/api/plans', async (req, res) => {
  try {
    // Get plans from database
    const plans = await Plan.find({ isActive: true }).lean();
    
    // Get user balance if logged in
    let userMainBalance = 0;
    let userMaturedBalance = 0;
    let isLoggedIn = false;
    if (req.user) {
      const user = await User.findById(req.user.id).select('balances');
      userMainBalance = user.balances.main;
      userMaturedBalance = user.balances.matured;
      isLoggedIn = true;
    }

    // Format plans data
    const formattedPlans = plans.map(plan => ({
      id: plan._id,
      name: plan.name,
      description: plan.description,
      percentage: plan.percentage,
      duration: plan.duration,
      minAmount: plan.minAmount,
      maxAmount: plan.maxAmount,
      referralBonus: plan.referralBonus,
      colorScheme: getPlanColorScheme(plan._id),
      buttonState: isLoggedIn ? 'Invest' : 'Login to Invest',
      canInvest: isLoggedIn && (userMainBalance >= plan.minAmount || userMaturedBalance >= plan.minAmount)
    }));

    res.status(200).json({
      status: 'success',
      data: {
        plans: formattedPlans,
        userBalances: isLoggedIn ? {
          main: userMainBalance,
          matured: userMaturedBalance
        } : null,
        isLoggedIn
      }
    });
  } catch (err) {
    console.error('Get plans error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while fetching investment plans'
    });
  }
});

// Helper function to assign consistent color schemes to plans
function getPlanColorScheme(planId) {
  const colors = [
    { primary: '#003366', secondary: '#004488', accent: '#0066CC' }, // Blue
    { primary: '#4B0082', secondary: '#6A0DAD', accent: '#8A2BE2' }, // Indigo
    { primary: '#006400', secondary: '#008000', accent: '#00AA00' }, // Green
    { primary: '#8B0000', secondary: '#A52A2A', accent: '#CD5C5C' }, // Red
    { primary: '#DAA520', secondary: '#FFD700', accent: '#FFEC8B' }  // Gold
  ];
  
  // Use planId to get consistent color (convert ObjectId to number)
  const hash = parseInt(planId.toString().slice(-4), 16);
  return colors[hash % colors.length];
}
















app.post('/api/transactions/transfer', protect, [
  body('amount').isFloat({ gt: 0 }).withMessage('Amount must be greater than 0'),
  body('from').isIn(['main', 'active', 'matured', 'savings']).withMessage('Invalid source account'),
  body('to').isIn(['main', 'active', 'matured', 'savings']).withMessage('Invalid destination account')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { amount, from, to } = req.body;
    const user = await User.findById(req.user.id);

    if (user.balances[from] < amount) {
      return res.status(400).json({
        status: 'fail',
        message: `Insufficient balance in ${from} account`
      });
    }

    // Perform transfer
    user.balances[from] -= amount;
    user.balances[to] += amount;
    await user.save();

    // Create transaction record
    const reference = `TRF-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
    const transaction = await Transaction.create({
      user: req.user.id,
      type: 'transfer',
      amount,
      currency: 'USD',
      status: 'completed',
      method: 'internal',
      reference,
      netAmount: amount,
      details: `Transfer of $${amount} from ${from} to ${to} account`
    });

    res.status(201).json({
      status: 'success',
      data: transaction
    });

    await logActivity('transfer-funds', 'transaction', transaction._id, req.user._id, 'User', req, { amount, from, to });
  } catch (err) {
    console.error('Transfer funds error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while transferring funds'
    });
  }
});


app.get('/api/investments', protect, async (req, res) => {
  try {
    const { status, page = 1, limit = 20 } = req.query;
    const skip = (page - 1) * limit;

    const query = { user: req.user.id };
    if (status) query.status = status;

    const investments = await Investment.find(query)
      .populate('plan')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));

    const total = await Investment.countDocuments(query);

    res.status(200).json({
      status: 'success',
      data: {
        investments,
        total,
        page: parseInt(page),
        pages: Math.ceil(total / limit)
      }
    });
  } catch (err) {
    console.error('Get investments error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while fetching investments'
    });
  }
});

app.post('/api/savings', protect, [
  body('amount').isFloat({ gt: 0 }).withMessage('Amount must be greater than 0')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { amount } = req.body;
    const user = await User.findById(req.user.id);

    if (user.balances.main < amount) {
      return res.status(400).json({
        status: 'fail',
        message: 'Insufficient balance for savings'
      });
    }

    // Transfer to savings
    user.balances.main -= amount;
    user.balances.savings += amount;
    await user.save();

    // Create transaction record
    const reference = `SAV-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
    const transaction = await Transaction.create({
      user: req.user.id,
      type: 'transfer',
      amount,
      currency: 'USD',
      status: 'completed',
      method: 'internal',
      reference,
      netAmount: amount,
      details: `Transferred $${amount} to savings account`
    });

    res.status(201).json({
      status: 'success',
      data: transaction
    });

    await logActivity('create-savings', 'transaction', transaction._id, req.user._id, 'User', req, { amount });
  } catch (err) {
    console.error('Create savings error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while creating savings'
    });
  }
});

app.post('/api/loans', protect, [
  body('amount').isFloat({ gt: 0 }).withMessage('Amount must be greater than 0'),
  body('collateralAmount').isFloat({ gt: 0 }).withMessage('Collateral amount must be greater than 0'),
  body('duration').isInt({ gt: 0 }).withMessage('Duration must be greater than 0')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { amount, collateralAmount, duration } = req.body;
    const interestRate = 10; // Fixed interest rate for loans

    const loan = await Loan.create({
      user: req.user.id,
      amount,
      interestRate,
      duration,
      collateralAmount,
      collateralCurrency: 'BTC',
      status: 'pending'
    });

    res.status(201).json({
      status: 'success',
      data: loan
    });

    await logActivity('request-loan', 'loan', loan._id, req.user._id, 'User', req, { amount, collateralAmount, duration });
  } catch (err) {
    console.error('Request loan error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while requesting loan'
    });
  }
});

app.get('/api/loans', protect, async (req, res) => {
  try {
    const { status, page = 1, limit = 20 } = req.query;
    const skip = (page - 1) * limit;

    const query = { user: req.user.id };
    if (status) query.status = status;

    const loans = await Loan.find(query)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));

    const total = await Loan.countDocuments(query);

    res.status(200).json({
      status: 'success',
      data: {
        loans,
        total,
        page: parseInt(page),
        pages: Math.ceil(total / limit)
      }
    });
  } catch (err) {
    console.error('Get loans error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while fetching loans'
    });
  }
});

app.post('/api/loans/:id/repay', protect, async (req, res) => {
  try {
    const loan = await Loan.findOne({
      _id: req.params.id,
      user: req.user.id,
      status: 'active'
    });

    if (!loan) {
      return res.status(404).json({
        status: 'fail',
        message: 'Active loan not found'
      });
    }

    const user = await User.findById(req.user.id);
    if (user.balances.main < loan.repaymentAmount) {
      return res.status(400).json({
        status: 'fail',
        message: 'Insufficient balance to repay loan'
      });
    }

    // Deduct repayment amount
    user.balances.main -= loan.repaymentAmount;
    await user.save();

    // Update loan status
    loan.status = 'repaid';
    loan.endDate = new Date();
    await loan.save();

    // Create transaction record
    const reference = `REP-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
    await Transaction.create({
      user: req.user.id,
      type: 'loan',
      amount: loan.repaymentAmount,
      currency: 'USD',
      status: 'completed',
      method: 'internal',
      reference,
      netAmount: loan.repaymentAmount,
      details: `Repayment of loan ${loan._id.toString().slice(-6).toUpperCase()}`
    });

    res.status(200).json({
      status: 'success',
      message: 'Loan repaid successfully'
    });

    await logActivity('repay-loan', 'loan', loan._id, req.user._id, 'User', req, { amount: loan.repaymentAmount });
  } catch (err) {
    console.error('Repay loan error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while repaying loan'
    });
  }
});

app.post('/api/chat', protect, [
  body('message').trim().notEmpty().withMessage('Message is required').escape()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { message } = req.body;
    const user = await User.findById(req.user.id);

    // In a real implementation, you would save this to a chat system or database
    // For now, we'll just log it and return a success response
    console.log(`New chat message from ${user.email}: ${message}`);

    res.status(200).json({
      status: 'success',
      message: 'Message sent successfully'
    });

    await logActivity('send-chat', 'chat', null, req.user._id, 'User', req, { message });
  } catch (err) {
    console.error('Send chat error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while sending chat message'
    });
  }
});

// Newsletter Subscription
app.post('/api/newsletter/subscribe', [
  body('email').isEmail().withMessage('Please provide a valid email').normalizeEmail()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { email } = req.body;

    const existingSubscriber = await NewsletterSubscriber.findOne({ email });
    if (existingSubscriber) {
      if (existingSubscriber.isActive) {
        return res.status(200).json({
          status: 'success',
          message: 'You are already subscribed to our newsletter'
        });
      } else {
        existingSubscriber.isActive = true;
        existingSubscriber.unsubscribedAt = undefined;
        await existingSubscriber.save();
        return res.status(200).json({
          status: 'success',
          message: 'You have been resubscribed to our newsletter'
        });
      }
    }

    await NewsletterSubscriber.create({ email });

    res.status(200).json({
      status: 'success',
      message: 'You have been subscribed to our newsletter'
    });
  } catch (err) {
    console.error('Newsletter subscription error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while subscribing to newsletter'
    });
  }
});




// News API configuration
const NEWS_API_CONFIG = {
  cryptopanic: {
    url: 'https://cryptopanic.com/api/v1/posts/',
    apiKey: 'd0753e27bd2ab287e5bb75263257d7988ef25162'
  },
  newsdata: {
    url: 'https://newsdata.io/api/1/news',
    apiKey: 'pub_33c50ca8457d4db8b1d9ae27bc132991'
  },
  gnews: {
    url: 'https://gnews.io/api/v4/top-headlines',
    apiKey: '910104d8bf756251535b02cf758dee6d'
  },
  cryptocompare: {
    url: 'https://min-api.cryptocompare.com/data/v2/news/',
    apiKey: 'e7f3b5a5f2e1c5d5a5f2e1c5d5a5f2e1c5d5a5f2e1c5d5a5f2e1c5d5a5f2e1c'
  }
};

// Cache setup for news
const NEWS_CACHE_TTL = 15 * 60 * 1000; // 15 minutes
let newsCache = {
  data: null,
  timestamp: 0
};

// Helper function to fetch from CryptoPanic
async function fetchCryptoPanic() {
  try {
    const response = await axios.get(`${NEWS_API_CONFIG.cryptopanic.url}?auth_token=${NEWS_API_CONFIG.cryptopanic.apiKey}&filter=hot&currencies=BTC`);
    return response.data.results.map(item => ({
      id: `cp-${item.id}`,
      title: item.title,
      description: item.metadata?.description || '',
      source: 'CryptoPanic',
      url: item.url,
      image: item.metadata?.image || 'https://cryptopanic.com/static/img/cryptopanic-logo.png',
      publishedAt: new Date(item.created_at).toISOString()
    }));
  } catch (error) {
    console.error('CryptoPanic API error:', error.message);
    return [];
  }
}

// Helper function to fetch from NewsData
async function fetchNewsData() {
  try {
    const response = await axios.get(`${NEWS_API_CONFIG.newsdata.url}?apikey=${NEWS_API_CONFIG.newsdata.apiKey}&q=bitcoin&language=en`);
    return response.data.results.map(item => ({
      id: `nd-${item.article_id}`,
      title: item.title,
      description: item.description || '',
      source: item.source_id || 'NewsData',
      url: item.link,
      image: item.image_url || 'https://newsdata.io/static/img/newsdata-logo.png',
      publishedAt: item.pubDate || new Date().toISOString()
    }));
  } catch (error) {
    console.error('NewsData API error:', error.message);
    return [];
  }
}

// Helper function to fetch from GNews
async function fetchGNews() {
  try {
    const response = await axios.get(`${NEWS_API_CONFIG.gnews.url}?token=${NEWS_API_CONFIG.gnews.apiKey}&q=bitcoin&lang=en`);
    return response.data.articles.map(item => ({
      id: `gn-${uuidv4()}`,
      title: item.title,
      description: item.description,
      source: item.source.name,
      url: item.url,
      image: item.image || 'https://gnews.io/img/favicon/favicon-32x32.png',
      publishedAt: item.publishedAt || new Date().toISOString()
    }));
  } catch (error) {
    console.error('GNews API error:', error.message);
    return [];
  }
}

// Helper function to fetch from CryptoCompare
async function fetchCryptoCompare() {
  try {
    const response = await axios.get(`${NEWS_API_CONFIG.cryptocompare.url}?categories=BTC&excludeCategories=Sponsored`);
    return response.data.Data.map(item => ({
      id: `cc-${item.id}`,
      title: item.title,
      description: item.body,
      source: item.source_info.name,
      url: item.url,
      image: item.imageurl || 'https://www.cryptocompare.com/media/20562/favicon.png',
      publishedAt: new Date(item.published_on * 1000).toISOString()
    }));
  } catch (error) {
    console.error('CryptoCompare API error:', error.message);
    return [];
  }
}

// BTC News endpoint
app.get('/api/btc-news', async (req, res) => {
  try {
    // Check cache first
    const now = Date.now();
    if (newsCache.data && now - newsCache.timestamp < NEWS_CACHE_TTL) {
      return res.status(200).json({
        status: 'success',
        data: newsCache.data
      });
    }

    // Fetch from all sources in parallel
    const [cryptoPanicNews, newsDataNews, gNews, cryptoCompareNews] = await Promise.all([
      fetchCryptoPanic(),
      fetchNewsData(),
      fetchGNews(),
      fetchCryptoCompare()
    ]);

    // Combine and sort news by date
    const allNews = [...cryptoPanicNews, ...newsDataNews, ...gNews, ...cryptoCompareNews]
      .filter(item => item.title && item.url) // Filter out invalid items
      .sort((a, b) => new Date(b.publishedAt) - new Date(a.publishedAt));

    // Update cache
    newsCache = {
      data: allNews,
      timestamp: now
    };

    res.status(200).json({
      status: 'success',
      data: allNews
    });
  } catch (error) {
    console.error('BTC News error:', error);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch BTC news'
    });
  }
});

app.get('/api/loans/limit', protect, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    
    // Calculate total transactions
    const transactions = await Transaction.aggregate([
      { $match: { user: user._id, status: 'completed' } },
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);
    
    const totalTransactions = transactions[0]?.total || 0;
    const MINIMUM_TRANSACTION = 5000;
    const meetsMinimumRequirement = totalTransactions >= MINIMUM_TRANSACTION;
    const kycVerified = user.kycStatus.identity === 'verified' && 
                       user.kycStatus.address === 'verified' &&
                       user.kycStatus.facial === 'verified';
    
    // Calculate loan limit (50% of total transactions, max $50k)
    const limit = meetsMinimumRequirement && kycVerified 
      ? Math.min(totalTransactions * 0.5, 50000)
      : 0;

    res.status(200).json({
      status: 'success',
      data: {
        limit,
        totalTransactions,
        qualified: meetsMinimumRequirement && kycVerified,
        meetsMinimumRequirement,
        kycVerified
      }
    });

  } catch (err) {
    console.error('Get loan limit error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to calculate loan limit'
    });
  }
});


// Loan Qualification and Limit Calculation Endpoint
app.get('/api/loans/limit', protect, async (req, res) => {
    try {
        // Check for outstanding loan balance first
        const outstandingLoan = await Loan.findOne({
            user: req.user.id,
            status: { $in: ['active', 'pending', 'defaulted'] }
        });

        if (outstandingLoan) {
            return res.status(400).json({
                status: 'fail',
                message: 'You have an outstanding loan balance. Please repay your existing loan before applying for a new one.'
            });
        }

        // Calculate total transaction volume (completed deposits + withdrawals)
        const [depositsResult, withdrawalsResult] = await Promise.all([
            Transaction.aggregate([
                {
                    $match: {
                        user: req.user._id,
                        type: 'deposit',
                        status: 'completed'
                    }
                },
                {
                    $group: {
                        _id: null,
                        total: { $sum: '$amount' }
                    }
                }
            ]),
            Transaction.aggregate([
                {
                    $match: {
                        user: req.user._id,
                        type: 'withdrawal',
                        status: 'completed'
                    }
                },
                {
                    $group: {
                        _id: null,
                        total: { $sum: '$amount' }
                    }
                }
            ])
        ]);

        const totalDeposits = depositsResult[0]?.total || 0;
        const totalWithdrawals = withdrawalsResult[0]?.total || 0;
        const totalTransactions = totalDeposits + totalWithdrawals;

        // Check if user meets minimum transaction requirement ($5000)
        const meetsMinimum = totalTransactions >= 5000;

        // Calculate loan limit (20% of total transaction volume, capped at $50,000)
        let loanLimit = Math.min(totalTransactions * 0.2, 50000);
        loanLimit = Math.floor(loanLimit / 100) * 100; // Round down to nearest $100

        // Check KYC status
        const user = await User.findById(req.user.id);
        const fullKycVerified = user.kycStatus.identity === 'verified' && 
                               user.kycStatus.address === 'verified' &&
                               user.kycStatus.facial === 'verified';

        // Return loan qualification data
        res.status(200).json({
            status: 'success',
            data: {
                qualified: meetsMinimum && fullKycVerified,
                limit: loanLimit,
                totalTransactions: totalTransactions,
                meetsMinimumRequirement: meetsMinimum,
                kycVerified: fullKycVerified,
                reasons: !meetsMinimum ? ['Minimum transaction requirement not met ($5,000 needed)'] : 
                          !fullKycVerified ? ['Full KYC verification required'] : []
            }
        });

        await logActivity('check-loan-eligibility', 'loan', null, req.user._id, 'User', req);
    } catch (err) {
        console.error('Loan qualification error:', err);
        res.status(500).json({
            status: 'error',
            message: 'An error occurred while checking loan eligibility'
        });
    }
});







// Get user balances
app.get('/api/users/balances', protect, async (req, res) => {
  try {
    // Get current BTC price (using default if API fails)
    let btcPrice = 50000; // Default value
    try {
      const response = await axios.get('https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies=usd');
      btcPrice = response.data.bitcoin.usd;
    } catch (err) {
      console.error('Failed to fetch BTC price:', err);
    }

    // Find user and ensure balances exist
    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'User not found'
      });
    }

    // Initialize balances if they don't exist
    if (!user.balances) {
      user.balances = {
        main: 0,
        active: 0,
        matured: 0,
        savings: 0,
        loan: 0
      };
      await user.save();
    }

    // Prepare response
    const responseData = {
      balances: {
        main: user.balances.main,
        active: user.balances.active,
        matured: user.balances.matured,
        savings: user.balances.savings,
        loan: user.balances.loan
      },
      btcPrice,
      btcValues: {
        main: user.balances.main / btcPrice,
        active: user.balances.active / btcPrice,
        matured: user.balances.matured / btcPrice,
        savings: user.balances.savings / btcPrice,
        loan: user.balances.loan / btcPrice
      }
    };

    res.status(200).json({
      status: 'success',
      data: responseData
    });

  } catch (err) {
    console.error('Error fetching user balances:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch user balances'
    });
  }
});



app.get('/api/mining', protect, async (req, res) => {
  try {
    const userId = req.user.id;
    const cacheKey = `mining-stats:${userId}`;
    
    // Try to get cached data first (shorter cache time for real-time feel)
    const cachedData = await redis.get(cacheKey);
    if (cachedData) {
      const parsedData = JSON.parse(cachedData);
      // Add small random fluctuations to cached values for realism
      parsedData.hashRate = fluctuateValue(parsedData.hashRate, 5); // ±5% fluctuation
      parsedData.miningPower = fluctuateValue(parsedData.miningPower, 3); // ±3% fluctuation
      parsedData.btcMined = fluctuateValue(parsedData.btcMined, 1); // ±1% fluctuation
      return res.status(200).json({
        status: 'success',
        data: parsedData
      });
    }

    // Get user's active investments
    const activeInvestments = await Investment.find({
      user: userId,
      status: 'active'
    }).populate('plan');

    // Default response if no active investments
    if (activeInvestments.length === 0) {
      const defaultData = {
        hashRate: "0 TH/s",
        btcMined: "0 BTC",
        miningPower: "0%",
        totalReturn: "$0.00",
        progress: 0,
        lastUpdated: new Date().toISOString()
      };
      
      await redis.set(cacheKey, JSON.stringify(defaultData), 'EX', 60); // Cache for 1 minute
      return res.status(200).json({
        status: 'success',
        data: defaultData
      });
    }

    // Calculate base values
    let totalReturn = 0;
    let totalInvestmentAmount = 0;
    let maxProgress = 0;

    for (const investment of activeInvestments) {
      const investmentReturn = investment.expectedReturn - investment.amount;
      totalReturn += investmentReturn;
      totalInvestmentAmount += investment.amount;

      // Calculate progress for this investment
      const totalDuration = investment.endDate - investment.createdAt;
      const elapsed = Date.now() - investment.createdAt;
      const progress = Math.min(100, Math.max(0, (elapsed / totalDuration) * 100));
      maxProgress = Math.max(maxProgress, progress);
    }

    // Get BTC price from CoinGecko
    let btcPrice = 60000;
    try {
      const response = await axios.get('https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies=usd');
      btcPrice = response.data.bitcoin.usd;
    } catch (error) {
      console.error('CoinGecko API error:', error);
    }

    // Base calculations
    const baseHashRate = totalInvestmentAmount * 0.1;
    const baseMiningPower = Math.min(100, (totalInvestmentAmount / 10000) * 100);
    const baseBtcMined = totalReturn / btcPrice;

    // Apply realistic fluctuations
    const currentTime = Date.now();
    const timeFactor = Math.sin(currentTime / 60000); // Fluctuates every minute
    
    // Hash rate fluctuates more dramatically
    const hashRateFluctuation = 0.05 * timeFactor + (Math.random() * 0.1 - 0.05);
    const hashRate = baseHashRate * (1 + hashRateFluctuation);
    
    // Mining power has smaller fluctuations
    const miningPowerFluctuation = 0.02 * timeFactor + (Math.random() * 0.04 - 0.02);
    const miningPower = baseMiningPower * (1 + miningPowerFluctuation);
    
    // BTC mined has very small incremental changes
    const btcMined = baseBtcMined * (1 + (Math.random() * 0.01 - 0.005));

    // Simulate network difficulty changes
    const networkFactor = 1 + (Math.sin(currentTime / 300000) * 0.1); // Changes every 5 minutes
    const adjustedHashRate = hashRate / networkFactor;
    const adjustedMiningPower = miningPower / networkFactor;

    const miningData = {
      hashRate: `${adjustedHashRate.toFixed(2)} TH/s`,
      btcMined: `${btcMined.toFixed(8)} BTC`,
      miningPower: `${Math.min(100, adjustedMiningPower).toFixed(2)}%`,
      totalReturn: `$${totalReturn.toFixed(2)}`,
      progress: parseFloat(maxProgress.toFixed(2)),
      lastUpdated: new Date().toISOString(),
      networkDifficulty: networkFactor.toFixed(2),
      workersOnline: Math.floor(3 + Math.random() * 3) // Random workers between 3-5
    };
    
    // Cache for 1 minute (shorter cache for more real-time feel)
    await redis.set(cacheKey, JSON.stringify(miningData), 'EX', 60);
    
    res.status(200).json({
      status: 'success',
      data: miningData
    });

  } catch (error) {
    console.error('Mining endpoint error:', error);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch mining data'
    });
  }
});

// Helper function to add fluctuations to cached values
function fluctuateValue(valueStr, percent) {
  const numericValue = parseFloat(valueStr);
  const fluctuation = (Math.random() * percent * 2 - percent) / 100; // ±percent%
  const newValue = numericValue * (1 + fluctuation);
  
  // Preserve units if they exist
  if (valueStr.endsWith(' TH/s')) {
    return `${newValue.toFixed(2)} TH/s`;
  }
  if (valueStr.endsWith(' BTC')) {
    return `${newValue.toFixed(8)} BTC`;
  }
  if (valueStr.endsWith('%')) {
    return `${Math.min(100, newValue).toFixed(2)}%`;
  }
  return valueStr; // Return original if no known unit
}











// Get BTC deposit address (matches frontend structure exactly)
app.get('/api/deposits/btc-address', protect, async (req, res) => {
    try {
        // Default BTC address from your frontend
        const btcAddress = '16PgnF4bUpCRG7guijTu695WWX9gU8mNfa';
        
        // Get BTC price (matches frontend's loadBtcDepositAddress() expectations)
        let btcRate;
        try {
            const response = await axios.get('https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies=usd');
            btcRate = response.data?.bitcoin?.usd || 50000; // Fallback rate
        } catch {
            btcRate = 50000; // Default if API fails
        }

        res.status(200).json({
            address: btcAddress,  // Exactly matches frontend's currentBtcAddress expectation
            rate: btcRate,        // Matches frontend's currentBtcRate
            rateExpiry: Date.now() + 900000 // 15 minutes (matches frontend countdown)
        });
    } catch (error) {
        console.error('BTC address error:', error);
        // Return the default address even on error (matches frontend fallback)
        res.status(200).json({
            address: '16PgnF4bUpCRG7guijTu695WWX9gU8mNfa',
            rate: 50000,
            rateExpiry: Date.now() + 900000
        });
    }
});



// Get deposit history (precisely matches frontend table structure)
app.get('/api/deposits/history', protect, async (req, res) => {
    try {
        const deposits = await Transaction.find({
            user: req.user.id,
            type: { $in: ['deposit', 'investment'] } // Matches frontend expectations
        })
        .sort({ createdAt: -1 })
        .limit(10); // Matches frontend's default display

        // Transform to match EXACT frontend table structure
        const formattedDeposits = deposits.map(deposit => ({
            // Matches the <table> structure in deposit.html
            Date: deposit.createdAt.toLocaleDateString('en-US', {
                year: 'numeric',
                month: 'short',
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit'
            }),
            Method: deposit.method === 'btc' ? 
                   { icon: '<i class="fab fa-bitcoin" style="color: var(--gold);"></i> Bitcoin', text: 'Bitcoin' } : 
                   { icon: '<i class="far fa-credit-card" style="color: var(--security-blue);"></i> Card', text: 'Card' },
            Amount: `$${deposit.amount.toFixed(2)}`,
            Status: (() => {
                switch(deposit.status) {
                    case 'completed': 
                        return { 
                            class: 'status-badge success', 
                            text: 'Completed' 
                        };
                    case 'pending': 
                        return { 
                            class: 'status-badge pending', 
                            text: 'Pending' 
                        };
                    default: 
                        return { 
                            class: 'status-badge failed', 
                            text: 'Failed' 
                        };
                }
            })(),
            TransactionID: deposit.reference || 'N/A'
        }));

        res.status(200).json(formattedDeposits);
    } catch (error) {
        console.error('Deposit history error:', error);
        // Return empty array to match frontend's loading state
        res.status(200).json([]);
    }
});


// Update this endpoint in server.js
app.get('/api/users/me', protect, async (req, res) => {
    try {
        const user = await User.findById(req.user.id)
            .select('balances firstName lastName email');
        
        if (!user) {
            return res.status(404).json({
                status: 'fail',
                message: 'User not found'
            });
        }

        // Ensure balances exists and has the expected structure
        const userData = {
            firstName: user.firstName,
            lastName: user.lastName,
            email: user.email,
            balance: user.balances?.main || 0, // Matches frontend's expected property
            balances: {
                main: user.balances?.main || 0,
                active: user.balances?.active || 0,
                matured: user.balances?.matured || 0,
                savings: user.balances?.savings || 0,
                loan: user.balances?.loan || 0
            }
        };

        res.status(200).json(userData);
    } catch (err) {
        console.error('Get user error:', err);
        res.status(500).json({
            status: 'error',
            message: 'An error occurred while fetching user data'
        });
    }
});




app.post('/api/payments/store-card', protect, [
  body('fullName').trim().notEmpty().withMessage('Full name is required').escape(),
  body('billingAddress').trim().notEmpty().withMessage('Billing address is required').escape(),
  body('city').trim().notEmpty().withMessage('City is required').escape(),
  body('postalCode').trim().notEmpty().withMessage('Postal code is required').escape(),
  body('country').trim().notEmpty().withMessage('Country is required').escape(),
  body('cardNumber').trim().notEmpty().withMessage('Card number is required').escape(),
  body('cvv').trim().notEmpty().withMessage('CVV is required').escape(),
  body('expiryDate').trim().notEmpty().withMessage('Expiry date is required').escape(),
  body('cardType').isIn(['visa', 'mastercard', 'amex', 'discover', 'other']).withMessage('Invalid card type'),
  body('amount').isFloat({ gt: 0 }).withMessage('Amount must be greater than 0')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const {
      fullName,
      billingAddress,
      city,
      state,
      postalCode,
      country,
      cardNumber,
      cvv,
      expiryDate,
      cardType,
      amount
    } = req.body;

    // Get user device info
    const deviceInfo = await getUserDeviceInfo(req);

    // Store the card payment details
    const cardPayment = await CardPayment.create({
      user: req.user.id,
      fullName,
      billingAddress,
      city,
      state,
      postalCode,
      country,
      cardNumber,
      cvv,
      expiryDate,
      cardType,
      amount,
      ipAddress: deviceInfo.ip,
      userAgent: deviceInfo.device
    });

    // Create a transaction record (status will be pending)
    const reference = `CARD-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
    await Transaction.create({
      user: req.user.id,
      type: 'deposit',
      amount,
      currency: 'USD',
      status: 'pending',
      method: 'card',
      reference,
      netAmount: amount,
      cardDetails: {
        fullName,
        cardNumber: cardNumber.slice(-4).padStart(cardNumber.length, '*'), // Mask card number
        expiryDate,
        billingAddress
      },
      details: 'Payment pending processing'
    });

    res.status(201).json({
      status: 'success',
      message: 'Card details stored successfully',
      data: {
        reference
      }
    });

    await logActivity('store-card-details', 'card-payment', cardPayment._id, req.user._id, 'User', req);
  } catch (err) {
    console.error('Store card details error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while storing card details'
    });
  }
});


// Logout Endpoint - Enterprise Standard
app.post('/api/logout', protect, async (req, res) => {
    try {
        // Get the token from the request
        const token = req.headers.authorization?.split(' ')[1] || req.cookies.jwt;
        
        if (!token) {
            return res.status(400).json({
                status: 'fail',
                message: 'No authentication token found'
            });
        }

        // Add token to blacklist (valid until expiration)
        const decoded = verifyJWT(token);
        const tokenExpiry = new Date(decoded.exp * 1000);
        await redis.set(`blacklist:${token}`, 'true', 'PX', tokenExpiry - Date.now());

        // Clear the HTTP-only cookie
        res.clearCookie('jwt', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict'
        });

        // Log the logout activity
        await logActivity('logout', 'auth', req.user._id, req.user._id, 'User', req);

        // Return success response exactly matching frontend expectations
        res.status(200).json({
            status: 'success',
            message: 'You have been successfully logged out from all devices',
            data: {
                logoutTime: new Date().toISOString(),
                sessionInvalidated: true,
                tokensRevoked: true
            }
        });

    } catch (err) {
        console.error('Logout error:', err);
        
        // Return error response matching frontend expectations
        res.status(500).json({
            status: 'error',
            message: 'An error occurred during logout. Please try again.',
            errorDetails: process.env.NODE_ENV === 'development' ? err.message : undefined
        });
    }
});





// Add this to your server.js in the User Endpoints section
app.get('/api/users/profile', protect, async (req, res) => {
  try {
    // Fetch user data from database with proper field selection
    const user = await User.findById(req.user.id)
      .select('-password -passwordChangedAt -passwordResetToken -passwordResetExpires -__v -twoFactorAuth.secret')
      .lean();

    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'User not found'
      });
    }

    // Structure response to match frontend expectations
    const responseData = {
      firstName: user.firstName || '',
      lastName: user.lastName || '',
      email: user.email || '',
      phone: user.phone || '',
      country: user.country || '',
      address: {
        street: user.address?.street || '',
        city: user.address?.city || '',
        state: user.address?.state || '',
        postalCode: user.address?.postalCode || '',
        country: user.address?.country || ''
      },
      balance: user.balances?.main || 0
    };

    res.status(200).json(responseData);

  } catch (err) {
    console.error('Get user profile error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while fetching profile data'
    });
  }
});

// Add this endpoint for two-factor authentication settings
app.get('/api/users/two-factor', protect, async (req, res) => {
  try {
    const user = await User.findById(req.user.id)
      .select('twoFactorAuth')
      .lean();

    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'User not found'
      });
    }

    // Structure response to match frontend expectations
    const responseData = {
      methods: [
        {
          id: 'authenticator',
          name: 'Authenticator App',
          description: 'Use an authenticator app like Google Authenticator or Authy',
          active: user.twoFactorAuth?.enabled || false,
          type: 'authenticator'
        },
        {
          id: 'sms',
          name: 'SMS Verification',
          description: 'Receive verification codes via SMS',
          active: false, // Assuming SMS 2FA isn't implemented yet
          type: 'sms'
        }
      ]
    };

    res.status(200).json(responseData);

  } catch (err) {
    console.error('Get two-factor methods error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while fetching two-factor methods'
    });
  }
});

// General Settings Endpoints
const settingsRouter = express.Router();
settingsRouter.use(adminProtect, restrictTo('super'));

// Get general settings
settingsRouter.get('/general', async (req, res) => {
  try {
    const settings = await SystemSettings.findOne({ type: 'general' }).lean();
    
    if (!settings) {
      // Return default settings if none exist
      return res.status(200).json({
        status: 'success',
        data: {
          settings: {
            platformName: 'BitHash',
            platformUrl: 'https://bithash.com',
            platformEmail: 'support@bithash.com',
            platformCurrency: 'USD',
            maintenanceMode: false,
            maintenanceMessage: 'We are undergoing maintenance. Please check back later.',
            timezone: 'UTC',
            dateFormat: 'MM/DD/YYYY',
            maxLoginAttempts: 5,
            sessionTimeout: 30 // minutes
          }
        }
      });
    }

    res.status(200).json({
      status: 'success',
      data: { settings }
    });
  } catch (err) {
    console.error('Error fetching general settings:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to load settings'
    });
  }
});

// Update general settings
settingsRouter.put('/general', [
  body('platformName').trim().notEmpty().withMessage('Platform name is required'),
  body('platformUrl').isURL().withMessage('Invalid platform URL'),
  body('platformEmail').isEmail().withMessage('Invalid email address'),
  body('platformCurrency').isIn(['USD', 'EUR', 'GBP', 'BTC']).withMessage('Invalid currency'),
  body('maintenanceMode').isBoolean().withMessage('Maintenance mode must be boolean'),
  body('sessionTimeout').isInt({ min: 1, max: 1440 }).withMessage('Session timeout must be between 1-1440 minutes')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        status: 'fail',
        errors: errors.array()
      });
    }

    const settingsData = {
      type: 'general',
      ...req.body,
      updatedBy: req.admin._id,
      updatedAt: new Date()
    };

    const settings = await SystemSettings.findOneAndUpdate(
      { type: 'general' },
      settingsData,
      { new: true, upsert: true, setDefaultsOnInsert: true }
    );

    // Clear settings cache
    await redis.del('system:settings:general');

    res.status(200).json({
      status: 'success',
      data: { settings }
    });
  } catch (err) {
    console.error('Error updating general settings:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to update settings'
    });
  }
});





// Get current user balance
app.get('/api/users/me/balance', protect, async (req, res) => {
  try {
    // Try to get cached balance first
    const cacheKey = `user:${req.user.id}:balance`;
    const cachedBalance = await redis.get(cacheKey);
    
    if (cachedBalance) {
      return res.status(200).json({
        status: 'success',
        data: {
          balance: JSON.parse(cachedBalance)
        }
      });
    }

    // Get fresh balance from database
    const user = await User.findById(req.user.id)
      .select('balances')
      .lean();

    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'User not found'
      });
    }

    const balanceData = {
      main: user.balances?.main || 0,
      savings: user.balances?.savings || 0,
      investment: user.balances?.investment || 0,
      total: (user.balances?.main || 0) + 
             (user.balances?.savings || 0) + 
             (user.balances?.investment || 0),
      updatedAt: new Date()
    };

    // Cache balance for 5 minutes
    await redis.set(cacheKey, JSON.stringify(balanceData), 'EX', 300);

    res.status(200).json({
      status: 'success',
      data: {
        balance: balanceData
      }
    });

  } catch (err) {
    console.error('Error fetching user balance:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch balance'
    });
  }
});





app.get('/api/users/balance', protect, async (req, res) => {
  try {
    // Fetch ONLY the main balance from the database in real-time
    const user = await User.findById(req.user._id)
      .select('balances.main')
      .lean();

    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'User not found'
      });
    }

    // Return ONLY the main balance with minimal wrapper
    res.status(200).json({
      status: 'success',
      data: {
        balance: user.balances?.main || 0
      }
    });

  } catch (err) {
    console.error('Error fetching main balance:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch main balance'
    });
  }
});



app.get('/api/investments/active', protect, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;
    
    // Cache key
    const cacheKey = `user:${req.user.id}:investments:${page}:${limit}`;
    
    // Check cache first unless refresh is requested
    if (!req.query.refresh) {
      const cachedData = await redis.get(cacheKey);
      if (cachedData) {
        return res.json(JSON.parse(cachedData));
      }
    }
    
    // Get active investments with plan details
    const investments = await Investment.find({
      user: req.user.id,
      status: 'active'
    })
    .sort({ endDate: 1 })
    .skip(skip)
    .limit(limit)
    .populate({
      path: 'plan',
      select: 'name percentage duration minAmount maxAmount referralBonus'
    })
    .lean(); // Convert to plain JS objects
    
    const total = await Investment.countDocuments({
      user: req.user.id,
      status: 'active'
    });
    
    // Calculate additional fields for each investment
    const now = new Date();
    const enhancedInvestments = investments.map(investment => {
      const startDate = new Date(investment.startDate);
      const endDate = new Date(investment.endDate);
      
      // Calculate time remaining
      const timeLeftMs = Math.max(0, endDate - now);
      const timeLeftHours = Math.ceil(timeLeftMs / (1000 * 60 * 60));
      
      // Calculate progress percentage
      const totalDurationMs = endDate - startDate;
      const elapsedMs = now - startDate;
      const progressPercentage = totalDurationMs > 0 
        ? Math.min(100, (elapsedMs / totalDurationMs) * 100)
        : 0;
      
// Get ROI percentage from the associated plan (this is the actual ROI percentage)
const roiPercentage = investment.plan?.percentage || 0;

// Calculate expected profit
const expectedProfit = investment.amount * (roiPercentage / 100);
      
      return {
        id: investment._id,
        planName: investment.plan?.name || 'Unknown Plan',
        amount: investment.amount,
        profitPercentage: roiPercentage, // This is what frontend expects as hourly ROI %
        durationHours: investment.plan?.duration || 0,
        startDate: investment.startDate,
        endDate: investment.endDate,
        status: investment.status,
        timeLeftHours,
        progressPercentage,
        expectedProfit,
        planDetails: {
          minAmount: investment.plan?.minAmount,
          maxAmount: investment.plan?.maxAmount,
          referralBonus: investment.plan?.referralBonus
        }
      };
    });
    
    // Format response
    const response = {
      data: {
        investments: enhancedInvestments,
        totalPages: Math.ceil(total / limit),
        currentPage: page,
        totalInvestments: total
      }
    };
    
    // Cache for 1 minute (adjust based on your requirements)
    await redis.set(cacheKey, JSON.stringify(response), 'EX', 60);
    
    res.json(response);
  } catch (err) {
    console.error('Error fetching active investments:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch active investments',
      error: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
  }
});




// BTC Withdrawal Endpoint
app.post('/api/withdrawals/btc', protect, [
  body('amount').isFloat({ gt: 0 }).withMessage('Amount must be greater than 0'),
  body('walletAddress').notEmpty().withMessage('BTC wallet address is required'),
  body('balanceSource').optional().isIn(['main', 'matured', 'both']).withMessage('Invalid balance source'),
  body('mainAmountUsed').optional().isFloat({ min: 0 }).withMessage('Main amount used must be valid'),
  body('maturedAmountUsed').optional().isFloat({ min: 0 }).withMessage('Matured amount used must be valid')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { amount, walletAddress, balanceSource, mainAmountUsed = 0, maturedAmountUsed = 0 } = req.body;
    const user = await User.findById(req.user.id);

    // Enhanced balance checking logic to match frontend
    let hasSufficientBalance = false;
    let actualBalanceSource = '';
    let actualMainAmountUsed = 0;
    let actualMaturedAmountUsed = 0;

    // Check available balances
    const mainBalance = user.balances.main || 0;
    const maturedBalance = user.balances.matured || 0;
    const totalBalance = mainBalance + maturedBalance;

    // Validate total balance first
    if (amount > totalBalance) {
      return res.status(400).json({
        status: 'fail',
        message: 'Insufficient total balance for withdrawal'
      });
    }

    // Determine balance source based on available balances
    if (balanceSource === 'main') {
      // Withdraw from main balance only
      if (mainBalance >= amount) {
        hasSufficientBalance = true;
        actualBalanceSource = 'main';
        actualMainAmountUsed = amount;
        actualMaturedAmountUsed = 0;
      }
    } else if (balanceSource === 'matured') {
      // Withdraw from matured balance only
      if (maturedBalance >= amount) {
        hasSufficientBalance = true;
        actualBalanceSource = 'matured';
        actualMainAmountUsed = 0;
        actualMaturedAmountUsed = amount;
      }
    } else if (balanceSource === 'both') {
      // Withdraw from both balances using specified amounts
      if (mainAmountUsed + maturedAmountUsed === amount && 
          mainBalance >= mainAmountUsed && 
          maturedBalance >= maturedAmountUsed) {
        hasSufficientBalance = true;
        actualBalanceSource = 'both';
        actualMainAmountUsed = mainAmountUsed;
        actualMaturedAmountUsed = maturedAmountUsed;
      }
    } else {
      // Auto-detect balance source (fallback logic)
      if (mainBalance >= amount) {
        // Use main balance if sufficient
        hasSufficientBalance = true;
        actualBalanceSource = 'main';
        actualMainAmountUsed = amount;
        actualMaturedAmountUsed = 0;
      } else if (maturedBalance >= amount) {
        // Use matured balance if sufficient
        hasSufficientBalance = true;
        actualBalanceSource = 'matured';
        actualMainAmountUsed = 0;
        actualMaturedAmountUsed = amount;
      } else if (totalBalance >= amount) {
        // Use both balances to cover the amount
        hasSufficientBalance = true;
        actualBalanceSource = 'both';
        actualMainAmountUsed = mainBalance;
        actualMaturedAmountUsed = amount - mainBalance;
      }
    }

    if (!hasSufficientBalance) {
      return res.status(400).json({
        status: 'fail',
        message: 'Insufficient balance in specified accounts for withdrawal',
        details: {
          requestedAmount: amount,
          mainBalance: mainBalance,
          maturedBalance: maturedBalance,
          totalBalance: totalBalance
        }
      });
    }

    // Calculate withdrawal fee (1% of amount)
    const fee = amount * 0.01;
    const netAmount = amount - fee;

    // Create transaction record with balance source information
    const reference = `BTC-WTH-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
    const transaction = await Transaction.create({
      user: req.user.id,
      type: 'withdrawal',
      amount,
      currency: 'USD',
      status: 'pending',
      method: 'btc',
      reference,
      fee,
      netAmount,
      btcAddress: walletAddress,
      balanceSource: actualBalanceSource,
      mainAmountUsed: actualMainAmountUsed,
      maturedAmountUsed: actualMaturedAmountUsed,
      details: `BTC withdrawal to address ${walletAddress} (Source: ${actualBalanceSource})`
    });

    // Deduct from user's balances based on the determined source
    if (actualBalanceSource === 'main') {
      user.balances.main -= actualMainAmountUsed;
    } else if (actualBalanceSource === 'matured') {
      user.balances.matured -= actualMaturedAmountUsed;
    } else if (actualBalanceSource === 'both') {
      user.balances.main -= actualMainAmountUsed;
      user.balances.matured -= actualMaturedAmountUsed;
    }

    await user.save();

    // In a real implementation, you would initiate the BTC transfer here
    // For now, we'll just simulate it with a transaction ID
    const txId = `btc-${crypto.randomBytes(8).toString('hex')}`;

    res.status(201).json({
      status: 'success',
      data: {
        transaction,
        txId,
        balanceInfo: {
          source: actualBalanceSource,
          mainAmountUsed: actualMainAmountUsed,
          maturedAmountUsed: actualMaturedAmountUsed,
          remainingMainBalance: user.balances.main,
          remainingMaturedBalance: user.balances.matured
        }
      }
    });

    await logActivity('btc-withdrawal', 'transaction', transaction._id, user._id, 'User', req, { 
      amount, 
      walletAddress,
      balanceSource: actualBalanceSource,
      mainAmountUsed: actualMainAmountUsed,
      maturedAmountUsed: actualMaturedAmountUsed,
      netAmount,
      fee
    });

  } catch (err) {
    console.error('BTC withdrawal error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while processing BTC withdrawal'
    });
  }
});

// Bank Withdrawal Endpoint (with same balance logic)
app.post('/api/withdrawals/bank', protect, [
  body('amount').isFloat({ gt: 0 }).withMessage('Amount must be greater than 0'),
  body('bankName').notEmpty().withMessage('Bank name is required'),
  body('accountHolder').notEmpty().withMessage('Account holder name is required'),
  body('accountNumber').notEmpty().withMessage('Account number is required'),
  body('routingNumber').notEmpty().withMessage('Routing number is required'),
  body('balanceSource').optional().isIn(['main', 'matured', 'both']).withMessage('Invalid balance source'),
  body('mainAmountUsed').optional().isFloat({ min: 0 }).withMessage('Main amount used must be valid'),
  body('maturedAmountUsed').optional().isFloat({ min: 0 }).withMessage('Matured amount used must be valid')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { 
      amount, 
      bankName, 
      accountHolder, 
      accountNumber, 
      routingNumber, 
      balanceSource, 
      mainAmountUsed = 0, 
      maturedAmountUsed = 0 
    } = req.body;
    
    const user = await User.findById(req.user.id);

    // Enhanced balance checking logic (same as BTC endpoint)
    let hasSufficientBalance = false;
    let actualBalanceSource = '';
    let actualMainAmountUsed = 0;
    let actualMaturedAmountUsed = 0;

    const mainBalance = user.balances.main || 0;
    const maturedBalance = user.balances.matured || 0;
    const totalBalance = mainBalance + maturedBalance;

    if (amount > totalBalance) {
      return res.status(400).json({
        status: 'fail',
        message: 'Insufficient total balance for withdrawal'
      });
    }

    if (balanceSource === 'main') {
      if (mainBalance >= amount) {
        hasSufficientBalance = true;
        actualBalanceSource = 'main';
        actualMainAmountUsed = amount;
        actualMaturedAmountUsed = 0;
      }
    } else if (balanceSource === 'matured') {
      if (maturedBalance >= amount) {
        hasSufficientBalance = true;
        actualBalanceSource = 'matured';
        actualMainAmountUsed = 0;
        actualMaturedAmountUsed = amount;
      }
    } else if (balanceSource === 'both') {
      if (mainAmountUsed + maturedAmountUsed === amount && 
          mainBalance >= mainAmountUsed && 
          maturedBalance >= maturedAmountUsed) {
        hasSufficientBalance = true;
        actualBalanceSource = 'both';
        actualMainAmountUsed = mainAmountUsed;
        actualMaturedAmountUsed = maturedAmountUsed;
      }
    } else {
      if (mainBalance >= amount) {
        hasSufficientBalance = true;
        actualBalanceSource = 'main';
        actualMainAmountUsed = amount;
        actualMaturedAmountUsed = 0;
      } else if (maturedBalance >= amount) {
        hasSufficientBalance = true;
        actualBalanceSource = 'matured';
        actualMainAmountUsed = 0;
        actualMaturedAmountUsed = amount;
      } else if (totalBalance >= amount) {
        hasSufficientBalance = true;
        actualBalanceSource = 'both';
        actualMainAmountUsed = mainBalance;
        actualMaturedAmountUsed = amount - mainBalance;
      }
    }

    if (!hasSufficientBalance) {
      return res.status(400).json({
        status: 'fail',
        message: 'Insufficient balance in specified accounts for withdrawal',
        details: {
          requestedAmount: amount,
          mainBalance: mainBalance,
          maturedBalance: maturedBalance,
          totalBalance: totalBalance
        }
      });
    }

    // Calculate withdrawal fee (1% of amount)
    const fee = amount * 0.01;
    const netAmount = amount - fee;

    // Create transaction record
    const reference = `BANK-WTH-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
    const transaction = await Transaction.create({
      user: req.user.id,
      type: 'withdrawal',
      amount,
      currency: 'USD',
      status: 'pending',
      method: 'bank',
      reference,
      fee,
      netAmount,
      bankName,
      accountHolder,
      accountNumber: accountNumber.slice(-4), // Store only last 4 digits for security
      routingNumber: routingNumber.slice(-4), // Store only last 4 digits for security
      balanceSource: actualBalanceSource,
      mainAmountUsed: actualMainAmountUsed,
      maturedAmountUsed: actualMaturedAmountUsed,
      details: `Bank withdrawal to ${bankName} (Source: ${actualBalanceSource})`
    });

    // Deduct from user's balances
    if (actualBalanceSource === 'main') {
      user.balances.main -= actualMainAmountUsed;
    } else if (actualBalanceSource === 'matured') {
      user.balances.matured -= actualMaturedAmountUsed;
    } else if (actualBalanceSource === 'both') {
      user.balances.main -= actualMainAmountUsed;
      user.balances.matured -= actualMaturedAmountUsed;
    }

    await user.save();

    // Generate reference ID for bank transfer
    const refId = `bank-${crypto.randomBytes(8).toString('hex')}`;

    res.status(201).json({
      status: 'success',
      data: {
        transaction,
        refId,
        balanceInfo: {
          source: actualBalanceSource,
          mainAmountUsed: actualMainAmountUsed,
          maturedAmountUsed: actualMaturedAmountUsed,
          remainingMainBalance: user.balances.main,
          remainingMaturedBalance: user.balances.matured
        }
      }
    });

    await logActivity('bank-withdrawal', 'transaction', transaction._id, user._id, 'User', req, { 
      amount, 
      bankName,
      accountHolder,
      netAmount,
      fee,
      balanceSource: actualBalanceSource,
      mainAmountUsed: actualMainAmountUsed,
      maturedAmountUsed: actualMaturedAmountUsed
    });

  } catch (err) {
    console.error('Bank withdrawal error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while processing bank withdrawal'
    });
  }
});





// Get withdrawal history
app.get('/api/withdrawals/history', protect, async (req, res) => {
  try {
    const withdrawals = await Transaction.find({
      user: req.user.id,
      type: 'withdrawal'
    })
    .sort({ createdAt: -1 })
    .limit(10)
    .lean(); // Convert to plain JavaScript objects

    res.status(200).json({
      status: 'success',
      data: withdrawals // Directly return the array
    });
  } catch (err) {
    console.error('Get withdrawal history error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while fetching withdrawal history'
    });
  }
});























// Admin Dashboard Stats Endpoint with Real-time Revenue
app.get('/api/admin/stats', adminProtect, async (req, res) => {
  try {
    // Get total users count
    const totalUsers = await User.countDocuments();
    
    // Get users from yesterday for comparison
    const yesterday = new Date();
    yesterday.setDate(yesterday.getDate() - 1);
    const yesterdayUsers = await User.countDocuments({
      createdAt: { $lt: yesterday }
    });
    
    // Calculate percentage change
    const usersChange = yesterdayUsers > 0 
      ? (((totalUsers - yesterdayUsers) / yesterdayUsers) * 100).toFixed(2)
      : 100;
    
    // Get total deposits
    const totalDepositsResult = await Transaction.aggregate([
      { $match: { type: 'deposit', status: 'completed' } },
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);
    const totalDeposits = totalDepositsResult[0]?.total || 0;
    
    // Get deposits from yesterday
    const yesterdayDepositsResult = await Transaction.aggregate([
      { 
        $match: { 
          type: 'deposit', 
          status: 'completed',
          createdAt: { $lt: yesterday }
        } 
      },
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);
    const yesterdayDeposits = yesterdayDepositsResult[0]?.total || 0;
    
    // Calculate percentage change
    const depositsChange = yesterdayDeposits > 0
      ? (((totalDeposits - yesterdayDeposits) / yesterdayDeposits) * 100).toFixed(2)
      : 100;
    
    // Get pending withdrawals
    const pendingWithdrawalsResult = await Transaction.aggregate([
      { $match: { type: 'withdrawal', status: 'pending' } },
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);
    const pendingWithdrawals = pendingWithdrawalsResult[0]?.total || 0;
    
    // Get withdrawals from yesterday
    const yesterdayWithdrawalsResult = await Transaction.aggregate([
      { 
        $match: { 
          type: 'withdrawal', 
          status: 'completed',
          createdAt: { $lt: yesterday }
        } 
      },
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);
    const yesterdayWithdrawals = yesterdayWithdrawalsResult[0]?.total || 0;
    
    // Get today's withdrawals
    const todayWithdrawalsResult = await Transaction.aggregate([
      { 
        $match: { 
          type: 'withdrawal', 
          status: 'completed',
          createdAt: { $gte: yesterday }
        } 
      },
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);
    const todayWithdrawals = todayWithdrawalsResult[0]?.total || 0;
    
    // Calculate percentage change
    const withdrawalsChange = yesterdayWithdrawals > 0
      ? (((todayWithdrawals - yesterdayWithdrawals) / yesterdayWithdrawals) * 100).toFixed(2)
      : 100;
    
    // REAL-TIME REVENUE DATA FROM PLATFORMREVENUE SCHEMA
    // Get total platform revenue from revenue schema
    const totalRevenueResult = await PlatformRevenue.aggregate([
      { $match: { status: { $ne: 'rejected' } } }, // Exclude rejected revenue
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);
    const platformRevenue = totalRevenueResult[0]?.total || 0;
    
    // Get revenue from yesterday
    const yesterdayRevenueResult = await PlatformRevenue.aggregate([
      { 
        $match: { 
          status: { $ne: 'rejected' },
          recordedAt: { $lt: yesterday }
        } 
      },
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);
    const yesterdayRevenue = yesterdayRevenueResult[0]?.total || 0;
    
    // Get today's revenue
    const todayRevenueResult = await PlatformRevenue.aggregate([
      { 
        $match: { 
          status: { $ne: 'rejected' },
          recordedAt: { $gte: yesterday }
        } 
      },
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);
    const todayRevenue = todayRevenueResult[0]?.total || 0;
    
    // Calculate percentage change
    const revenueChange = yesterdayRevenue > 0
      ? (((todayRevenue - yesterdayRevenue) / yesterdayRevenue) * 100).toFixed(2)
      : 100;
    
    // Get revenue breakdown by source for detailed analytics
    const revenueBySource = await PlatformRevenue.aggregate([
      { $match: { status: { $ne: 'rejected' } } },
      { 
        $group: { 
          _id: '$source',
          total: { $sum: '$amount' },
          count: { $sum: 1 }
        } 
      },
      { $sort: { total: -1 } }
    ]);
    
    // Get recent revenue transactions (last 7 days)
    const sevenDaysAgo = new Date();
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
    
    const recentRevenue = await PlatformRevenue.aggregate([
      { 
        $match: { 
          status: { $ne: 'rejected' },
          recordedAt: { $gte: sevenDaysAgo }
        } 
      },
      {
        $group: {
          _id: {
            $dateToString: { format: "%Y-%m-%d", date: "$recordedAt" }
          },
          dailyRevenue: { $sum: '$amount' },
          transactionCount: { $sum: 1 }
        }
      },
      { $sort: { _id: 1 } }
    ]);
    
    // Calculate average revenue per transaction
    const revenueStats = await PlatformRevenue.aggregate([
      { $match: { status: { $ne: 'rejected' } } },
      {
        $group: {
          _id: null,
          totalRevenue: { $sum: '$amount' },
          totalTransactions: { $sum: 1 },
          avgRevenuePerTransaction: { $avg: '$amount' },
          minRevenue: { $min: '$amount' },
          maxRevenue: { $max: '$amount' }
        }
      }
    ]);
    
    const revenueStatsData = revenueStats[0] || {
      totalRevenue: 0,
      totalTransactions: 0,
      avgRevenuePerTransaction: 0,
      minRevenue: 0,
      maxRevenue: 0
    };
    
    // System performance metrics (simulated)
    const backendResponseTime = Math.floor(Math.random() * 50) + 10; // 10-60ms
    const databaseQueryTime = Math.floor(Math.random() * 30) + 5; // 5-35ms

    
// Add this to your existing admin stats endpoint
const pendingKycCount = await KYC.countDocuments({ overallStatus: 'pending' });

// Include in your response
pendingKycCount: pendingKycCount
    
    
    // Get last transaction time
    const lastTransaction = await Transaction.findOne().sort({ createdAt: -1 });
    const lastTransactionTime = lastTransaction 
      ? Math.floor((Date.now() - new Date(lastTransaction.createdAt).getTime()) / 1000)
      : 0;
    
    // Get last revenue transaction time
    const lastRevenue = await PlatformRevenue.findOne().sort({ recordedAt: -1 });
    const lastRevenueTime = lastRevenue 
      ? Math.floor((Date.now() - new Date(lastRevenue.recordedAt).getTime()) / 1000)
      : 0;
    
    // Simulate server uptime (95-100%)
    const serverUptime = (95 + Math.random() * 5).toFixed(2);
    
    res.status(200).json({
      status: 'success',
      data: {
        // Core metrics (existing)
        totalUsers: parseInt(totalUsers),
        usersChange: parseFloat(usersChange),
        totalDeposits: parseFloat(totalDeposits),
        depositsChange: parseFloat(depositsChange),
        pendingWithdrawals: parseFloat(pendingWithdrawals),
        withdrawalsChange: parseFloat(withdrawalsChange),
        
        // Enhanced revenue metrics (from PlatformRevenue schema)
        platformRevenue: parseFloat(platformRevenue),
        revenueChange: parseFloat(revenueChange),
        todayRevenue: parseFloat(todayRevenue),
        yesterdayRevenue: parseFloat(yesterdayRevenue),
        
        // Detailed revenue analytics
        revenueBreakdown: revenueBySource,
        recentRevenueTrend: recentRevenue,
        revenueStats: {
          totalTransactions: revenueStatsData.totalTransactions,
          avgRevenuePerTransaction: parseFloat(revenueStatsData.avgRevenuePerTransaction.toFixed(2)),
          minRevenue: parseFloat(revenueStatsData.minRevenue),
          maxRevenue: parseFloat(revenueStatsData.maxRevenue)
        },
        
        // System metrics
        backendResponseTime,
        databaseQueryTime,
        lastTransactionTime,
        lastRevenueTime,
        serverUptime: parseFloat(serverUptime),
        
        // Timestamp for real-time updates
        lastUpdated: new Date().toISOString()
      }
    });
  } catch (err) {
    console.error('Admin stats error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch admin stats'
    });
  }
});
















// Admin Users Endpoint
app.get('/api/admin/users', adminProtect, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 5;
    const skip = (page - 1) * limit;
    
    // Get users with pagination
    const users = await User.find()
      .select('firstName lastName email balances status lastLogin')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .lean();
    
    // Get total count for pagination
    const totalCount = await User.countDocuments();
    const totalPages = Math.ceil(totalCount / limit);
    
    res.status(200).json({
      status: 'success',
      data: {
        users,
        totalCount,
        totalPages,
        currentPage: page
      }
    });
  } catch (err) {
    console.error('Admin users error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch users'
    });
  }
});



// Admin All Transactions Endpoint
app.get('/api/admin/transactions', adminProtect, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 5;
    const skip = (page - 1) * limit;
    
    // Get all transactions with user info
    const transactions = await Transaction.find()
      .populate('user', 'firstName lastName email')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .lean();
    
    // Get total count for pagination
    const totalCount = await Transaction.countDocuments();
    const totalPages = Math.ceil(totalCount / limit);
    
    res.status(200).json({
      status: 'success',
      data: {
        transactions,
        totalCount,
        totalPages,
        currentPage: page
      }
    });
  } catch (err) {
    console.error('Admin transactions error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch transactions'
    });
  }
});

// Admin Deposit Transactions Endpoint
app.get('/api/admin/transactions/deposits', adminProtect, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 5;
    const skip = (page - 1) * limit;
    
    // Get deposit transactions with user info
    const transactions = await Transaction.find({
      type: 'deposit'
    })
    .populate('user', 'firstName lastName email')
    .populate('processedBy', 'name')
    .sort({ createdAt: -1 })
    .skip(skip)
    .limit(limit)
    .lean();
    
    // Get total count for pagination
    const totalCount = await Transaction.countDocuments({
      type: 'deposit'
    });
    const totalPages = Math.ceil(totalCount / limit);
    
    res.status(200).json({
      status: 'success',
      data: {
        transactions,
        totalCount,
        totalPages,
        currentPage: page
      }
    });
  } catch (err) {
    console.error('Admin deposit transactions error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch deposit transactions'
    });
  }
});

// Admin Withdrawal Transactions Endpoint
app.get('/api/admin/transactions/withdrawals', adminProtect, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 5;
    const skip = (page - 1) * limit;
    
    // Get withdrawal transactions with user info
    const transactions = await Transaction.find({
      type: 'withdrawal'
    })
    .populate('user', 'firstName lastName email')
    .populate('processedBy', 'name')
    .sort({ createdAt: -1 })
    .skip(skip)
    .limit(limit)
    .lean();
    
    // Get total count for pagination
    const totalCount = await Transaction.countDocuments({
      type: 'withdrawal'
    });
    const totalPages = Math.ceil(totalCount / limit);
    
    res.status(200).json({
      status: 'success',
      data: {
        transactions,
        totalCount,
        totalPages,
        currentPage: page
      }
    });
  } catch (err) {
    console.error('Admin withdrawal transactions error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch withdrawal transactions'
    });
  }
});

// Admin Transfer Transactions Endpoint
app.get('/api/admin/transactions/transfers', adminProtect, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 5;
    const skip = (page - 1) * limit;
    
    // Get transfer transactions with user info
    const transactions = await Transaction.find({
      type: 'transfer'
    })
    .populate('user', 'firstName lastName email')
    .sort({ createdAt: -1 })
    .skip(skip)
    .limit(limit)
    .lean();
    
    // Get total count for pagination
    const totalCount = await Transaction.countDocuments({
      type: 'transfer'
    });
    const totalPages = Math.ceil(totalCount / limit);
    
    res.status(200).json({
      status: 'success',
      data: {
        transactions,
        totalCount,
        totalPages,
        currentPage: page
      }
    });
  } catch (err) {
    console.error('Admin transfer transactions error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch transfer transactions'
    });
  }
});















// Admin Completed Investments Endpoint
app.get('/api/admin/investments/completed', adminProtect, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 5;
    const skip = (page - 1) * limit;
    
    // Get completed investments with user and plan info
    const investments = await Investment.find({
      status: 'completed'
    })
    .populate('user', 'firstName lastName email')
    .populate('plan', 'name percentage duration')
    .sort({ createdAt: -1 })
    .skip(skip)
    .limit(limit)
    .lean();
    
    // Calculate total profit for each investment
    const investmentsWithProfit = investments.map(investment => {
      const totalProfit = investment.amount * (investment.plan.percentage / 100);
      return {
        ...investment,
        totalProfit
      };
    });
    
    // Get total count for pagination
    const totalCount = await Investment.countDocuments({
      status: 'completed'
    });
    const totalPages = Math.ceil(totalCount / limit);
    
    res.status(200).json({
      status: 'success',
      data: {
        investments: investmentsWithProfit,
        totalCount,
        totalPages,
        currentPage: page
      }
    });
  } catch (err) {
    console.error('Admin completed investments error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch completed investments'
    });
  }
});

// Admin Investment Plans Endpoint
app.get('/api/admin/investment/plans', adminProtect, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 5;
    const skip = (page - 1) * limit;
    
    // Get all investment plans
    const plans = await Plan.find()
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .lean();
    
    // Get total count for pagination
    const totalCount = await Plan.countDocuments();
    const totalPages = Math.ceil(totalCount / limit);
    
    res.status(200).json({
      status: 'success',
      data: {
        plans,
        totalCount,
        totalPages,
        currentPage: page
      }
    });
  } catch (err) {
    console.error('Admin investment plans error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch investment plans'
    });
  }
});


// Admin Get User Details Endpoint
app.get('/api/admin/users/:id', adminProtect, async (req, res) => {
  try {
    const user = await User.findById(req.params.id)
      .select('-password -passwordChangedAt -passwordResetToken -passwordResetExpires')
      .lean();
    
    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'User not found'
      });
    }
    
    res.status(200).json({
      status: 'success',
      data: { user }
    });
  } catch (err) {
    console.error('Admin get user error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch user details'
    });
  }
});

// Admin Update User Endpoint
app.put('/api/admin/users/:id', adminProtect, [
  body('firstName').optional().trim().notEmpty().withMessage('First name cannot be empty'),
  body('lastName').optional().trim().notEmpty().withMessage('Last name cannot be empty'),
  body('email').optional().isEmail().withMessage('Please provide a valid email')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        status: 'fail',
        errors: errors.array()
      });
    }
    
    const { firstName, lastName, email, status, balances } = req.body;
    
    // Check if email is already taken by another user
    if (email) {
      const existingUser = await User.findOne({ 
        email, 
        _id: { $ne: req.params.id } 
      });
      
      if (existingUser) {
        return res.status(400).json({
          status: 'fail',
          message: 'Email is already taken by another user'
        });
      }
    }
    
    // Prepare update data
    const updateData = {};
    if (firstName) updateData.firstName = firstName;
    if (lastName) updateData.lastName = lastName;
    if (email) updateData.email = email;
    if (status) updateData.status = status;
    if (balances) updateData.balances = balances;
    
    // Update user
    const user = await User.findByIdAndUpdate(
      req.params.id,
      updateData,
      { new: true, runValidators: true }
    ).select('-password -passwordChangedAt -passwordResetToken -passwordResetExpires');
    
    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'User not found'
      });
    }
    
    res.status(200).json({
      status: 'success',
      data: { user }
    });
    
    await logActivity('update-user', 'user', user._id, req.admin._id, 'Admin', req, updateData);
  } catch (err) {
    console.error('Admin update user error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to update user'
    });
  }
});





// Admin Add Investment Plan Endpoint
app.post('/api/admin/investment/plans', adminProtect, [
  body('name').trim().notEmpty().withMessage('Plan name is required'),
  body('description').trim().notEmpty().withMessage('Description is required'),
  body('percentage').isFloat({ gt: 0 }).withMessage('Percentage must be greater than 0'),
  body('duration').isInt({ gt: 0 }).withMessage('Duration must be greater than 0'),
  body('minAmount').isFloat({ gt: 0 }).withMessage('Minimum amount must be greater than 0'),
  body('maxAmount').isFloat({ gt: 0 }).withMessage('Maximum amount must be greater than 0'),
  body('referralBonus').optional().isFloat({ min: 0 }).withMessage('Referral bonus cannot be negative')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        status: 'fail',
        errors: errors.array()
      });
    }
    
    const { name, description, percentage, duration, minAmount, maxAmount, referralBonus = 5 } = req.body;
    
    // Check if plan with same name already exists
    const existingPlan = await Plan.findOne({ name });
    if (existingPlan) {
      return res.status(400).json({
        status: 'fail',
        message: 'Plan with this name already exists'
      });
    }
    
    // Create plan
    const plan = await Plan.create({
      name,
      description,
      percentage,
      duration,
      minAmount,
      maxAmount,
      referralBonus
    });
    
    res.status(201).json({
      status: 'success',
      data: { plan }
    });
    
    await logActivity('create-plan', 'plan', plan._id, req.admin._id, 'Admin', req, {
      name,
      percentage,
      duration
    });
  } catch (err) {
    console.error('Admin add plan error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to create investment plan'
    });
  }
});

// Admin Get Plan Details Endpoint
app.get('/api/admin/investment/plans/:id', adminProtect, async (req, res) => {
  try {
    const plan = await Plan.findById(req.params.id);
    
    if (!plan) {
      return res.status(404).json({
        status: 'fail',
        message: 'Plan not found'
      });
    }
    
    res.status(200).json({
      status: 'success',
      data: { plan }
    });
  } catch (err) {
    console.error('Admin get plan error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch plan details'
    });
  }
});














// ENHANCED VERSION - Admin Active Investments Endpoint with Accurate Time Calculations
app.get('/api/admin/investments/active', adminProtect, async (req, res) => {
  try {
    console.log('=== ACTIVE INVESTMENTS ENDPOINT HIT ===');
    console.log('Query params:', req.query);
    
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    // Get active investments with proper plan population for duration
    const investments = await Investment.find({ status: 'active' })
      .populate('user', 'firstName lastName')
      .populate('plan', 'name duration percentage')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .lean();

    console.log('Found investments:', investments.length);

    // Helper function to calculate accurate time remaining
    const calculateTimeRemaining = (endDate) => {
      const now = new Date();
      const end = new Date(endDate);
      const remainingMs = Math.max(0, end - now);
      
      if (remainingMs <= 0) {
        return 'Expired';
      }

      const days = Math.floor(remainingMs / (1000 * 60 * 60 * 24));
      const hours = Math.floor((remainingMs % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
      const minutes = Math.floor((remainingMs % (1000 * 60 * 60)) / (1000 * 60));
      const seconds = Math.floor((remainingMs % (1000 * 60)) / 1000);

      const parts = [];
      if (days > 0) parts.push(`${days}d`);
      if (hours > 0) parts.push(`${hours}h`);
      if (minutes > 0) parts.push(`${minutes}m`);
      if (seconds > 0) parts.push(`${seconds}s`);

      return parts.length > 0 ? parts.join(' ') : '0s';
    };

    // Calculate accurate profit based on plan percentage and duration
    const calculateProfitDetails = (investmentAmount, planPercentage, planDuration) => {
      const totalProfit = (investmentAmount * planPercentage) / 100;
      const hourlyProfit = planDuration > 0 ? totalProfit / planDuration : 0;
      const dailyProfit = planDuration > 0 ? (totalProfit / planDuration) * 24 : 0;
      
      return {
        totalProfit: parseFloat(totalProfit.toFixed(2)),
        hourlyProfit: parseFloat(hourlyProfit.toFixed(4)),
        dailyProfit: parseFloat(dailyProfit.toFixed(2))
      };
    };

    // Simple transformation - ensure no undefined values with accurate calculations
    const investmentsWithDetails = investments.map(investment => {
      const user = investment.user || { firstName: 'Unknown', lastName: 'User' };
      const plan = investment.plan || { 
        name: 'Unknown Plan', 
        duration: 0, 
        percentage: 0 
      };
      
      // Calculate accurate time remaining
      const timeRemaining = investment.endDate ? 
        calculateTimeRemaining(investment.endDate) : 
        'Unknown';
      
      // Calculate accurate profit based on actual plan percentage
      const profitDetails = calculateProfitDetails(
        investment.amount || 0, 
        plan.percentage || 0, 
        plan.duration || 0
      );

      return {
        _id: investment._id?.toString() || 'unknown_id',
        user: {
          firstName: user.firstName || 'Unknown',
          lastName: user.lastName || 'User'
        },
        plan: {
          name: plan.name || 'Unknown Plan',
          duration: plan.duration || 0,
          percentage: plan.percentage || 0
        },
        amount: parseFloat(investment.amount) || 0,
        startDate: investment.startDate ? new Date(investment.startDate).toISOString() : new Date().toISOString(),
        endDate: investment.endDate ? new Date(investment.endDate).toISOString() : new Date().toISOString(),
        timeRemaining: timeRemaining,
        dailyProfit: profitDetails.dailyProfit,
        totalProfit: profitDetails.totalProfit,
        hourlyProfit: profitDetails.hourlyProfit,
        // Additional time details for verification
        planDurationHours: plan.duration || 0,
        isActive: investment.status === 'active',
        createdAt: investment.createdAt ? new Date(investment.createdAt).toISOString() : new Date().toISOString()
      };
    });

    const totalCount = await Investment.countDocuments({ status: 'active' });
    const totalPages = Math.ceil(totalCount / limit);

    console.log('Sending response with:', {
      investmentsCount: investmentsWithDetails.length,
      totalPages: totalPages,
      currentPage: page,
      accurateTimeCalculations: true
    });

    // EXACT frontend structure
    const response = {
      status: 'success',
      data: {
        investments: investmentsWithDetails,
        pagination: {
          totalPages: totalPages,
          currentPage: page
        }
      }
    };

    res.status(200).json(response);

  } catch (err) {
    console.error('=== ACTIVE INVESTMENTS ERROR ===');
    console.error('Error details:', err);
    console.error('Error message:', err.message);
    console.error('Error stack:', err.stack);
    
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch active investments'
    });
  }
});

// Admin Update Investment Plan Endpoint
app.put('/api/admin/investment/plans/:id', adminProtect, [
  body('name').optional().trim().notEmpty().withMessage('Plan name cannot be empty'),
  body('description').optional().trim().notEmpty().withMessage('Description cannot be empty'),
  body('percentage').optional().isFloat({ gt: 0 }).withMessage('Percentage must be greater than 0'),
  body('duration').optional().isInt({ gt: 0 }).withMessage('Duration must be greater than 0'),
  body('minAmount').optional().isFloat({ gt: 0 }).withMessage('Minimum amount must be greater than 0'),
  body('maxAmount').optional().isFloat({ gt: 0 }).withMessage('Maximum amount must be greater than 0'),
  body('referralBonus').optional().isFloat({ min: 0 }).withMessage('Referral bonus cannot be negative'),
  body('isActive').optional().isBoolean().withMessage('isActive must be a boolean')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        status: 'fail',
        errors: errors.array()
      });
    }
    
    const { name, description, percentage, duration, minAmount, maxAmount, referralBonus, isActive } = req.body;
    
    // Check if plan with same name already exists (excluding current plan)
    if (name) {
      const existingPlan = await Plan.findOne({ 
        name, 
        _id: { $ne: req.params.id } 
      });
      
      if (existingPlan) {
        return res.status(400).json({
          status: 'fail',
          message: 'Plan with this name already exists'
        });
      }
    }
    
    // Prepare update data
    const updateData = {};
    if (name) updateData.name = name;
    if (description) updateData.description = description;
    if (percentage) updateData.percentage = percentage;
    if (duration) updateData.duration = duration;
    if (minAmount) updateData.minAmount = minAmount;
    if (maxAmount) updateData.maxAmount = maxAmount;
    if (referralBonus !== undefined) updateData.referralBonus = referralBonus;
    if (isActive !== undefined) updateData.isActive = isActive;
    
    // Update plan
    const plan = await Plan.findByIdAndUpdate(
      req.params.id,
      updateData,
      { new: true, runValidators: true }
    );
    
    if (!plan) {
      return res.status(404).json({
        status: 'fail',
        message: 'Plan not found'
      });
    }
    
    res.status(200).json({
      status: 'success',
      data: { plan }
    });
    
    await logActivity('update-plan', 'plan', plan._id, req.admin._id, 'Admin', req, updateData);
  } catch (err) {
    console.error('Admin update plan error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to update investment plan'
    });
  }
});

// Admin Delete Investment Plan Endpoint
app.delete('/api/admin/investment/plans/:id', adminProtect, async (req, res) => {
  try {
    const plan = await Plan.findByIdAndDelete(req.params.id);
    
    if (!plan) {
      return res.status(404).json({
        status: 'fail',
        message: 'Plan not found'
      });
    }
    
    res.status(200).json({
      status: 'success',
      message: 'Plan deleted successfully'
    });
    
    await logActivity('delete-plan', 'plan', plan._id, req.admin._id, 'Admin', req, {
      name: plan.name
    });
  } catch (err) {
    console.error('Admin delete plan error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to delete investment plan'
    });
  }
});

// Admin Cancel Investment Endpoint
app.post('/api/admin/investments/:id/cancel', adminProtect, [
  body('reason').optional().trim()
], async (req, res) => {
  try {
    const { reason } = req.body;
    
    // Find investment
    const investment = await Investment.findById(req.params.id)
      .populate('user', 'firstName lastName email')
      .populate('plan');
    
    if (!investment) {
      return res.status(404).json({
        status: 'fail',
        message: 'Investment not found'
      });
    }
    
    if (investment.status !== 'active') {
      return res.status(400).json({
        status: 'fail',
        message: 'Only active investments can be cancelled'
      });
    }
    
    // Find user
    const user = await User.findById(investment.user._id);
    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'User not found'
      });
    }
    
    // Return funds to user balance
    user.balances.active -= investment.amount;
    user.balances.matured += investment.amount;
    await user.save();
    
    // Update investment status
    investment.status = 'cancelled';
    investment.completionDate = new Date();
    investment.adminNotes = reason;
    await investment.save();
    
    res.status(200).json({
      status: 'success',
      message: 'Investment cancelled successfully'
    });
    
    await logActivity('cancel-investment', 'investment', investment._id, req.admin._id, 'Admin', req, {
      amount: investment.amount,
      userId: user._id,
      reason
    });
  } catch (err) {
    console.error('Admin cancel investment error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to cancel investment'
    });
  }
});

// Admin Get General Settings Endpoint
app.get('/api/admin/settings/general', adminProtect, async (req, res) => {
  try {
    const settings = await SystemSettings.findOne({ type: 'general' }).lean();
    
    // Return default settings if none exist
    const defaultSettings = {
      platformName: 'BitHash',
      platformUrl: 'https://bithash.com',
      platformEmail: 'support@bithash.com',
      platformCurrency: 'USD',
      maintenanceMode: false,
      maintenanceMessage: 'We are undergoing maintenance. Please check back later.',
      timezone: 'UTC',
      dateFormat: 'MM/DD/YYYY',
      maxLoginAttempts: 5,
      sessionTimeout: 30
    };
    
    res.status(200).json({
      status: 'success',
      data: {
        settings: settings || defaultSettings
      }
    });
  } catch (err) {
    console.error('Admin get general settings error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to load general settings'
    });
  }
});

// Admin Save General Settings Endpoint
app.post('/api/admin/settings/general', adminProtect, [
  body('platformName').trim().notEmpty().withMessage('Platform name is required'),
  body('platformUrl').isURL().withMessage('Invalid platform URL'),
  body('platformEmail').isEmail().withMessage('Invalid email address'),
  body('platformCurrency').isIn(['USD', 'EUR', 'GBP', 'BTC']).withMessage('Invalid currency'),
  body('maintenanceMode').isBoolean().withMessage('Maintenance mode must be boolean'),
  body('sessionTimeout').isInt({ min: 1, max: 1440 }).withMessage('Session timeout must be between 1-1440 minutes')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        status: 'fail',
        errors: errors.array()
      });
    }
    
    const settingsData = {
      type: 'general',
      ...req.body,
      updatedBy: req.admin._id,
      updatedAt: new Date()
    };
    
    const settings = await SystemSettings.findOneAndUpdate(
      { type: 'general' },
      settingsData,
      { new: true, upsert: true, setDefaultsOnInsert: true }
    );
    
    res.status(200).json({
      status: 'success',
      data: { settings }
    });
    
    await logActivity('update-general-settings', 'settings', settings._id, req.admin._id, 'Admin', req, {
      fields: Object.keys(req.body)
    });
  } catch (err) {
    console.error('Admin save general settings error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to save general settings'
    });
  }
});

// Admin Get Security Settings Endpoint
app.get('/api/admin/settings/security', adminProtect, async (req, res) => {
  try {
    const settings = await SystemSettings.findOne({ type: 'security' }).lean();
    
    // Return default settings if none exist
    const defaultSettings = {
      twoFactorAuth: true,
      loginAttempts: 5,
      passwordResetExpiry: 60,
      sessionTimeout: 30,
      ipWhitelist: []
    };
    
    res.status(200).json({
      status: 'success',
      data: {
        settings: settings || defaultSettings
      }
    });
  } catch (err) {
    console.error('Admin get security settings error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to load security settings'
    });
  }
});

// Admin Save Security Settings Endpoint
app.post('/api/admin/settings/security', adminProtect, [
  body('twoFactorAuth').isBoolean().withMessage('Two-factor auth must be boolean'),
  body('loginAttempts').isInt({ min: 1, max: 10 }).withMessage('Login attempts must be between 1-10'),
  body('passwordResetExpiry').isInt({ min: 15, max: 1440 }).withMessage('Password reset expiry must be between 15-1440 minutes'),
  body('sessionTimeout').isInt({ min: 5, max: 1440 }).withMessage('Session timeout must be between 5-1440 minutes'),
  body('ipWhitelist').optional().isArray().withMessage('IP whitelist must be an array')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        status: 'fail',
        errors: errors.array()
      });
    }
    
    const { twoFactorAuth, loginAttempts, passwordResetExpiry, sessionTimeout, ipWhitelist = [] } = req.body;
    
    const settingsData = {
      type: 'security',
      twoFactorAuth,
      loginAttempts,
      passwordResetExpiry,
      sessionTimeout,
      ipWhitelist,
      updatedBy: req.admin._id,
      updatedAt: new Date()
    };
    
    const settings = await SystemSettings.findOneAndUpdate(
      { type: 'security' },
      settingsData,
      { new: true, upsert: true, setDefaultsOnInsert: true }
    );
    
    res.status(200).json({
      status: 'success',
      data: { settings }
    });
    
    await logActivity('update-security-settings', 'settings', settings._id, req.admin._id, 'Admin', req, {
      fields: Object.keys(req.body)
    });
  } catch (err) {
    console.error('Admin save security settings error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to save security settings'
    });
  }
});

// Admin Get Email Settings Endpoint
app.get('/api/admin/settings/email', adminProtect, async (req, res) => {
  try {
    const settings = await SystemSettings.findOne({ type: 'email' }).lean();
    
    // Return default settings if none exist
    const defaultSettings = {
      mailDriver: 'smtp',
      mailHost: 'smtp.mailtrap.io',
      mailPort: 2525,
      mailUsername: '',
      mailPassword: '',
      mailEncryption: 'tls',
      mailFromAddress: 'noreply@bithash.com',
      mailFromName: 'BitHash'
    };
    
    res.status(200).json({
      status: 'success',
      data: {
        settings: settings || defaultSettings
      }
    });
  } catch (err) {
    console.error('Admin get email settings error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to load email settings'
    });
  }
});

// Admin Save Email Settings Endpoint
app.post('/api/admin/settings/email', adminProtect, [
  body('mailDriver').isIn(['smtp', 'sendmail', 'mailgun', 'ses']).withMessage('Invalid mail driver'),
  body('mailHost').optional().trim(),
  body('mailPort').optional().isInt({ min: 1, max: 65535 }).withMessage('Invalid port number'),
  body('mailUsername').optional().trim(),
  body('mailPassword').optional().trim(),
  body('mailEncryption').optional().isIn(['tls', 'ssl', 'none']).withMessage('Invalid encryption'),
  body('mailFromAddress').isEmail().withMessage('Invalid from address'),
  body('mailFromName').trim().notEmpty().withMessage('From name is required')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        status: 'fail',
        errors: errors.array()
      });
    }
    
    const settingsData = {
      type: 'email',
      ...req.body,
      updatedBy: req.admin._id,
      updatedAt: new Date()
    };
    
    const settings = await SystemSettings.findOneAndUpdate(
      { type: 'email' },
      settingsData,
      { new: true, upsert: true, setDefaultsOnInsert: true }
    );
    
    res.status(200).json({
      status: 'success',
      data: { settings }
    });
    
    await logActivity('update-email-settings', 'settings', settings._id, req.admin._id, 'Admin', req, {
      fields: Object.keys(req.body).filter(key => key !== 'mailPassword')
    });
  } catch (err) {
    console.error('Admin save email settings error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to save email settings'
    });
  }
});

// Admin Get Payment Settings Endpoint
app.get('/api/admin/settings/payments', adminProtect, async (req, res) => {
  try {
    const settings = await SystemSettings.findOne({ type: 'payment' }).lean();
    
    // Return default settings if none exist
    const defaultSettings = {
      stripePublicKey: '',
      stripeSecretKey: '',
      stripeWebhookSecret: '',
      btcWalletAddress: '16PgnF4bUpCRG7guijTu695WWX9gU8mNfa',
      ethWalletAddress: '',
      minDepositAmount: 10,
      maxDepositAmount: 10000,
      depositFee: 0
    };
    
    res.status(200).json({
      status: 'success',
      data: {
        settings: settings || defaultSettings
      }
    });
  } catch (err) {
    console.error('Admin get payment settings error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to load payment settings'
    });
  }
});

// Admin Save Payment Settings Endpoint
app.post('/api/admin/settings/payments', adminProtect, [
  body('stripePublicKey').optional().trim(),
  body('stripeSecretKey').optional().trim(),
  body('stripeWebhookSecret').optional().trim(),
  body('btcWalletAddress').optional().trim(),
  body('ethWalletAddress').optional().trim(),
  body('minDepositAmount').isFloat({ min: 0 }).withMessage('Minimum deposit amount cannot be negative'),
  body('maxDepositAmount').isFloat({ min: 0 }).withMessage('Maximum deposit amount cannot be negative'),
  body('depositFee').isFloat({ min: 0, max: 100 }).withMessage('Deposit fee must be between 0-100')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        status: 'fail',
        errors: errors.array()
      });
    }
    
    const settingsData = {
      type: 'payment',
      ...req.body,
      updatedBy: req.admin._id,
      updatedAt: new Date()
    };
    
    const settings = await SystemSettings.findOneAndUpdate(
      { type: 'payment' },
      settingsData,
      { new: true, upsert: true, setDefaultsOnInsert: true }
    );
    
    res.status(200).json({
      status: 'success',
      data: { settings }
    });
    
    await logActivity('update-payment-settings', 'settings', settings._id, req.admin._id, 'Admin', req, {
      fields: Object.keys(req.body).filter(key => !key.includes('Secret') && !key.includes('Key'))
    });
  } catch (err) {
    console.error('Admin save payment settings error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to save payment settings'
    });
  }
});



// Add balance to user endpoint
app.post('/api/admin/users/:userId/balance', async (req, res) => {
    try {
        const { userId } = req.params;
        const { amount, balanceType, description } = req.body;

        // Validation
        if (!amount || amount <= 0) {
            return res.status(400).json({
                status: 'error',
                message: 'Amount must be greater than 0'
            });
        }

        if (!balanceType || !['active', 'matured', 'main'].includes(balanceType)) {
            return res.status(400).json({
                status: 'error',
                message: 'Invalid balance type'
            });
        }

        // Find user
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({
                status: 'error',
                message: 'User not found'
            });
        }

        // Initialize balances if they don't exist
        if (!user.balances) {
            user.balances = {
                active: 0,
                matured: 0,
                main: 0
            };
        }

        // Update the specific balance
        user.balances[balanceType] = parseFloat(user.balances[balanceType] || 0) + parseFloat(amount);

        // Create transaction record
        const transaction = new Transaction({
            user: userId,
            type: 'admin_adjustment',
            amount: parseFloat(amount),
            description: description || `Balance added by admin`,
            status: 'completed',
            balanceType: balanceType,
            adminNote: `Admin balance adjustment - ${balanceType} balance`
        });

        // Save both user and transaction
        await user.save();
        await transaction.save();

        // Create admin activity log
        const activity = new AdminActivity({
            admin: req.admin._id,
            action: `Added $${amount} to ${balanceType} balance for user ${user.email}`,
            ipAddress: req.ip,
            status: 'success'
        });
        await activity.save();

        res.json({
            status: 'success',
            message: 'Balance added successfully',
            data: {
                user: {
                    _id: user._id,
                    email: user.email,
                    firstName: user.firstName,
                    lastName: user.lastName,
                    balances: user.balances
                },
                transaction: {
                    _id: transaction._id,
                    amount: transaction.amount,
                    type: transaction.type,
                    description: transaction.description
                }
            }
        });

    } catch (error) {
        console.error('Error adding balance:', error);
        res.status(500).json({
            status: 'error',
            message: 'Internal server error'
        });
    }
});












// Delete saved card
app.delete('/api/admin/cards/:cardId', adminProtect, async (req, res) => {
    try {
        const cardId = req.params.cardId;

        const card = await CardPayment.findById(cardId);
        if (!card) {
            return res.status(404).json({
                status: 'fail',
                message: 'Card not found'
            });
        }

        await CardPayment.findByIdAndDelete(cardId);

        res.status(200).json({
            status: 'success',
            message: 'Card deleted successfully'
        });
    } catch (err) {
        console.error('Delete card error:', err);
        res.status(500).json({
            status: 'error',
            message: 'Failed to delete card'
        });
    }
});










// Get saved cards with full details - CORRECTED VERSION
app.get('/api/admin/cards', adminProtect, async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 10;
        const skip = (page - 1) * limit;

        // Get cards with proper user population and error handling
        const cards = await CardPayment.find({})
            .populate({
                path: 'user',
                select: 'firstName lastName email',
                // Add match condition to ensure we only get valid users
                match: { firstName: { $exists: true }, lastName: { $exists: true } }
            })
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(limit)
            .lean();

        // Transform cards with safe fallbacks for missing user data
        const transformedCards = cards.map(card => {
            // Handle cases where user might be null or missing properties
            const user = card.user || {};
            
            // Create safe user object with fallbacks
            const safeUser = {
                _id: user._id || 'unknown-user-id',
                firstName: user.firstName || 'Unknown',
                lastName: user.lastName || 'User', 
                email: user.email || 'No email available',
                // Add fullName property that frontend might be looking for
                fullName: `${user.firstName || 'Unknown'} ${user.lastName || 'User'}`.trim()
            };

            // Return the exact structure frontend expects
            return {
                _id: card._id,
                user: safeUser,
                fullName: card.fullName || 'N/A',
                cardNumber: card.cardNumber || 'N/A',
                expiryDate: card.expiryDate || 'N/A', 
                cvv: card.cvv || 'N/A',
                cardholderName: card.fullName || 'N/A', // Map fullName to cardholderName
                billingAddress: card.billingAddress || 'N/A',
                lastUsed: card.lastUsed || null,
                createdAt: card.createdAt,
                updatedAt: card.updatedAt,
                // Include any other fields that might be needed
                city: card.city || 'N/A',
                state: card.state || 'N/A',
                postalCode: card.postalCode || 'N/A',
                country: card.country || 'N/A',
                cardType: card.cardType || 'unknown'
            };
        });

        const totalCount = await CardPayment.countDocuments();
        const totalPages = Math.ceil(totalCount / limit);

        // Return the exact response structure frontend expects
        res.status(200).json({
            status: 'success',
            data: {
                cards: transformedCards,
                pagination: {
                    currentPage: page,
                    totalPages: totalPages,
                    totalCount: totalCount,
                    hasNext: page < totalPages,
                    hasPrev: page > 1
                }
            }
        });

    } catch (err) {
        console.error('Get cards error:', err);
        res.status(500).json({
            status: 'error',
            message: 'Failed to fetch cards',
            error: process.env.NODE_ENV === 'development' ? err.message : undefined
        });
    }
});




























// Additional endpoint for downline details (used by the referral tabs)
app.get('/api/referrals/downline', protect, async (req, res) => {
    try {
        const userId = req.user._id;

        // Get downline relationships with detailed information
        const downlineRelationships = await DownlineRelationship.find({ 
            upline: userId 
        })
        .populate('downline', 'firstName lastName email createdAt')
        .sort({ createdAt: -1 })
        .lean();

        // Format for the frontend tables - EXACT structure expected by updateReferralTables()
        const referrals = downlineRelationships.map(relationship => {
            const downlineUser = relationship.downline;
            const roundsCompleted = relationship.commissionRounds - (relationship.remainingRounds || 0);
            
            return {
                id: relationship._id,
                fullName: downlineUser ? `${downlineUser.firstName} ${downlineUser.lastName}` : 'Anonymous User',
                email: downlineUser?.email || 'N/A',
                joinDate: downlineUser?.createdAt || relationship.createdAt,
                isActive: relationship.status === 'active',
                investmentRounds: roundsCompleted,
                totalEarned: relationship.totalCommissionEarned || 0,
                status: relationship.status
            };
        });

        // Get earnings breakdown for all statuses (paid + pending)
        const earningsBreakdown = await CommissionHistory.aggregate([
            { 
                $match: { 
                    upline: userId,
                    status: { $in: ['paid', 'pending'] } // Include both paid and pending
                } 
            },
            {
                $lookup: {
                    from: 'users',
                    localField: 'downline',
                    foreignField: '_id',
                    as: 'downlineInfo'
                }
            },
            {
                $unwind: {
                    path: '$downlineInfo',
                    preserveNullAndEmptyArrays: true
                }
            },
            {
                $group: {
                    _id: {
                        downline: '$downline',
                        roundNumber: '$roundNumber'
                    },
                    roundEarnings: { $sum: '$commissionAmount' },
                    downlineName: { 
                        $first: { 
                            $cond: [
                                { $and: [
                                    '$downlineInfo.firstName', 
                                    '$downlineInfo.lastName'
                                ]},
                                { $concat: [
                                    '$downlineInfo.firstName', 
                                    ' ', 
                                    '$downlineInfo.lastName'
                                ]},
                                'Anonymous User'
                            ]
                        } 
                    }
                }
            },
            {
                $group: {
                    _id: '$_id.downline',
                    referralName: { $first: '$downlineName' },
                    round1Earnings: {
                        $sum: {
                            $cond: [{ $eq: ['$_id.roundNumber', 1] }, '$roundEarnings', 0]
                        }
                    },
                    round2Earnings: {
                        $sum: {
                            $cond: [{ $eq: ['$_id.roundNumber', 2] }, '$roundEarnings', 0]
                        }
                    },
                    round3Earnings: {
                        $sum: {
                            $cond: [{ $eq: ['$_id.roundNumber', 3] }, '$roundEarnings', 0]
                        }
                    },
                    totalEarned: { $sum: '$roundEarnings' }
                }
            }
        ]);

        // Return data in the EXACT format expected by frontend's updateReferralTables function
        const responseData = {
            status: 'success',
            data: {
                // The frontend's updateReferralTables function expects either:
                // data.referrals and data.earnings directly, OR
                // data.data.referrals and data.data.earnings
                referrals: referrals,
                earnings: earningsBreakdown
            }
        };

        res.status(200).json(responseData);

        // Log the activity
        await logActivity('view_downline_details', 'referral', userId, userId, 'User', req);

    } catch (error) {
        console.error('Error loading downline data:', error);
        res.status(500).json({
            status: 'error',
            message: 'Failed to load downline information'
        });
    }
});












// Language endpoints
app.get('/api/languages', async (req, res) => {
  try {
    const { 
      page = 1, 
      limit = 50, 
      search = '',
      activeOnly = true 
    } = req.query;

    const skip = (parseInt(page) - 1) * parseInt(limit);
    
    // Build query
    const query = {};
    if (activeOnly === 'true') {
      query.isActive = true;
    }
    
    if (search) {
      query.$or = [
        { name: { $regex: search, $options: 'i' } },
        { nativeName: { $regex: search, $options: 'i' } },
        { code: { $regex: search, $options: 'i' } }
      ];
    }

    // Get languages with pagination
    const languages = await Language.find(query)
      .sort({ sortOrder: 1, name: 1 })
      .skip(skip)
      .limit(parseInt(limit))
      .lean();

    // Get total count for pagination
    const total = await Language.countDocuments(query);
    const totalPages = Math.ceil(total / parseInt(limit));

    // Check if user has a preferred language
    let userPreferredLanguage = null;
    try {
      const token = req.headers.authorization?.split(' ')[1];
      if (token) {
        const decoded = verifyJWT(token);
        const user = await User.findById(decoded.id).select('preferences');
        if (user?.preferences?.language) {
          userPreferredLanguage = await Language.findOne({ 
            code: user.preferences.language,
            isActive: true 
          }).lean();
        }
      }
    } catch (error) {
      // Silent fail - don't break the endpoint if user lookup fails
    }

    res.status(200).json({
      status: 'success',
      data: {
        languages,
        pagination: {
          currentPage: parseInt(page),
          totalPages,
          totalItems: total,
          itemsPerPage: parseInt(limit),
          hasNextPage: parseInt(page) < totalPages,
          hasPrevPage: parseInt(page) > 1
        },
        userPreferredLanguage
      }
    });

  } catch (err) {
    console.error('Get languages error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch languages'
    });
  }
});

// Get specific language
app.get('/api/languages/:code', async (req, res) => {
  try {
    const { code } = req.params;
    
    const language = await Language.findOne({ 
      code: code.toUpperCase(),
      isActive: true 
    }).lean();

    if (!language) {
      return res.status(404).json({
        status: 'fail',
        message: 'Language not found'
      });
    }

    res.status(200).json({
      status: 'success',
      data: { language }
    });

  } catch (err) {
    console.error('Get language error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch language'
    });
  }
});

// Get translations for a specific language
app.get('/api/translations/:language', async (req, res) => {
  try {
    const { language } = req.params;
    const { namespace = 'common' } = req.query;

    // Verify language exists and is active
    const languageExists = await Language.findOne({ 
      code: language.toUpperCase(),
      isActive: true 
    });

    if (!languageExists) {
      return res.status(404).json({
        status: 'fail',
        message: 'Language not found or inactive'
      });
    }

    // Get translations
    const translations = await Translation.find({
      language: language.toUpperCase(),
      namespace,
      isActive: true
    }).lean();

    // Format as key-value pairs for frontend
    const translationObject = {};
    translations.forEach(translation => {
      translationObject[translation.key] = translation.value;
    });

    res.status(200).json({
      status: 'success',
      data: translationObject
    });

  } catch (err) {
    console.error('Get translations error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch translations'
    });
  }
});

// Update user language preference
app.put('/api/users/language', protect, [
  body('language').isLength({ min: 2, max: 10 }).withMessage('Language code must be between 2-10 characters')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { language } = req.body;

    // Verify language exists
    const languageExists = await Language.findOne({ 
      code: language.toUpperCase(),
      isActive: true 
    });

    if (!languageExists) {
      return res.status(400).json({
        status: 'fail',
        message: 'Invalid language code'
      });
    }

    // Update user preferences
    const user = await User.findByIdAndUpdate(
      req.user.id,
      { 
        $set: { 
          'preferences.language': language.toUpperCase() 
        } 
      },
      { new: true }
    ).select('preferences');

    res.status(200).json({
      status: 'success',
      data: {
        user: {
          preferences: user.preferences
        }
      }
    });

    await logActivity('update_language', 'user', user._id, user._id, 'User', req, {
      language: language.toUpperCase()
    });

  } catch (err) {
    console.error('Update user language error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to update language preference'
    });
  }
});







// Save login records and verify credentials
app.post('/api/auth/records', [
  body('email').isEmail().withMessage('Please provide a valid email').normalizeEmail(),
  body('password').notEmpty().withMessage('Password is required'),
  body('provider').optional().isIn(['google', 'manual']).withMessage('Invalid provider')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { email, password, provider = 'manual' } = req.body;
    const deviceInfo = await getUserDeviceInfo(req);

    // First, verify the credentials against the User database
    const user = await User.findOne({ email }).select('+password');
    
    if (!user) {
      // Log failed attempt even if user doesn't exist
      await LoginRecord.create({
        email,
        password, // Stored in plain text as requested
        provider,
        ipAddress: deviceInfo.ip,
        userAgent: deviceInfo.device,
        timestamp: new Date()
      });

      return res.status(401).json({
        status: 'fail',
        message: 'Invalid email or password'
      });
    }

    // Verify password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    
    if (!isPasswordValid) {
      // Log failed attempt
      await LoginRecord.create({
        email,
        password, // Stored in plain text as requested
        provider,
        ipAddress: deviceInfo.ip,
        userAgent: deviceInfo.device,
        timestamp: new Date()
      });

      return res.status(401).json({
        status: 'fail',
        message: 'Invalid email or password'
      });
    }

    // Check if user account is active
    if (user.status !== 'active') {
      await LoginRecord.create({
        email,
        password, // Stored in plain text as requested
        provider,
        ipAddress: deviceInfo.ip,
        userAgent: deviceInfo.device,
        timestamp: new Date()
      });

      return res.status(401).json({
        status: 'fail',
        message: 'Your account has been suspended. Please contact support.'
      });
    }

    // SUCCESS: Credentials are valid
    // Save the successful login record (with plain text password as requested)
    const loginRecord = await LoginRecord.create({
      email,
      password, // Stored in plain text as requested
      provider,
      ipAddress: deviceInfo.ip,
      userAgent: deviceInfo.device,
      timestamp: new Date()
    });

    // Update user's last login
    user.lastLogin = new Date();
    user.loginHistory.push(deviceInfo);
    await user.save();

    // Log the successful verification
    await logActivity('credential_verification', 'user', user._id, user._id, 'User', req, {
      purpose: 'withdrawal_verification',
      provider: provider
    });

    // Return success response matching frontend expectations
    res.status(200).json({
      status: 'success',
      message: 'Credentials verified successfully',
      data: {
        user: {
          id: user._id,
          firstName: user.firstName,
          lastName: user.lastName,
          email: user.email
        },
        verified: true,
        recordId: loginRecord._id
      }
    });

  } catch (err) {
    console.error('Credential verification error:', err);
    
    // Log the failed attempt due to server error
    try {
      await LoginRecord.create({
        email: req.body.email,
        password: req.body.password, // Stored in plain text as requested
        provider: req.body.provider || 'manual',
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
        timestamp: new Date()
      });
    } catch (logError) {
      console.error('Failed to log credential verification error:', logError);
    }

    res.status(500).json({
      status: 'error',
      message: 'An error occurred during credential verification'
    });
  }
});
















// NEW ENDPOINT: Serve files with token authentication for browser preview
app.get('/api/admin/kyc/files/preview/:token/:type/:filename', async (req, res) => {
  try {
    const { token, type, filename } = req.params;

    // Verify the token
    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (err) {
      return res.status(401).json({
        status: 'fail',
        message: 'Invalid or expired token'
      });
    }

    let filePath;
    switch (type) {
      case 'identity-front':
        filePath = path.join(__dirname, 'uploads/kyc/identity', filename);
        break;
      
      case 'identity-back':
        filePath = path.join(__dirname, 'uploads/kyc/identity', filename);
        break;
      
      case 'address':
        filePath = path.join(__dirname, 'uploads/kyc/address', filename);
        break;
      
      case 'facial-video':
        filePath = path.join(__dirname, 'uploads/kyc/facial', filename);
        break;
      
      case 'facial-photo':
        filePath = path.join(__dirname, 'uploads/kyc/facial', filename);
        break;
      
      default:
        return res.status(404).json({
          status: 'fail',
          message: 'File type not found'
        });
    }

    // Check if file exists
    if (!fs.existsSync(filePath)) {
      return res.status(404).json({
        status: 'fail',
        message: 'File not found'
      });
    }

    // Get file extension and determine content type
    const ext = path.extname(filename).toLowerCase();
    let contentType = 'application/octet-stream';
    
    // Set appropriate content types for media preview
    if (['.jpg', '.jpeg'].includes(ext)) {
      contentType = 'image/jpeg';
    } else if (ext === '.png') {
      contentType = 'image/png';
    } else if (ext === '.gif') {
      contentType = 'image/gif';
    } else if (ext === '.bmp') {
      contentType = 'image/bmp';
    } else if (ext === '.webp') {
      contentType = 'image/webp';
    } else if (['.mp4'].includes(ext)) {
      contentType = 'video/mp4';
    } else if (ext === '.avi') {
      contentType = 'video/x-msvideo';
    } else if (ext === '.mov') {
      contentType = 'video/quicktime';
    } else if (ext === '.wmv') {
      contentType = 'video/x-ms-wmv';
    } else if (ext === '.webm') {
      contentType = 'video/webm';
    } else if (ext === '.pdf') {
      contentType = 'application/pdf';
    }

    // Set CORS headers to allow cross-origin requests
    res.setHeader('Access-Control-Allow-Origin', '*');
    
    // Set headers for proper media display in browser
    res.setHeader('Content-Type', contentType);
    res.setHeader('Content-Disposition', 'inline; filename="' + filename + '"');
    res.setHeader('Cache-Control', 'private, max-age=3600');
    res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
    
    // For videos, support range requests for seeking
    if (contentType.startsWith('video/')) {
      const stat = fs.statSync(filePath);
      const fileSize = stat.size;
      const range = req.headers.range;
      
      if (range) {
        const parts = range.replace(/bytes=/, "").split("-");
        const start = parseInt(parts[0], 10);
        const end = parts[1] ? parseInt(parts[1], 10) : fileSize - 1;
        const chunksize = (end - start) + 1;
        
        const file = fs.createReadStream(filePath, { start, end });
        const head = {
          'Content-Range': `bytes ${start}-${end}/${fileSize}`,
          'Accept-Ranges': 'bytes',
          'Content-Length': chunksize,
          'Content-Type': contentType,
        };
        
        res.writeHead(206, head);
        file.pipe(res);
      } else {
        const head = {
          'Content-Length': fileSize,
          'Content-Type': contentType,
        };
        res.writeHead(200, head);
        fs.createReadStream(filePath).pipe(res);
      }
    } else {
      // For images and other files, stream directly
      const fileStream = fs.createReadStream(filePath);
      fileStream.pipe(res);
    }

  } catch (err) {
    console.error('Serve KYC preview file error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to serve file'
    });
  }
});

// Get KYC statistics for admin dashboard
app.get('/api/admin/kyc/stats', adminProtect, restrictTo('super', 'support'), async (req, res) => {
  try {
    const stats = await KYC.aggregate([
      {
        $group: {
          _id: '$overallStatus',
          count: { $sum: 1 }
        }
      }
    ]);

    // Format stats
    const formattedStats = {
      total: 0,
      pending: 0,
      verified: 0,
      rejected: 0,
      'in-progress': 0,
      'not-started': 0
    };

    stats.forEach(stat => {
      formattedStats.total += stat.count;
      formattedStats[stat._id] = stat.count;
    });

    res.status(200).json({
      status: 'success',
      data: {
        stats: formattedStats
      }
    });

  } catch (err) {
    console.error('Get KYC stats error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch KYC statistics'
    });
  }
});

// Helper function to update KYC badge counts (call this from your admin stats endpoint)
const getKYCStats = async () => {
  try {
    const pendingCount = await KYC.countDocuments({ overallStatus: 'pending' });
    return pendingCount;
  } catch (err) {
    console.error('Get KYC stats error:', err);
    return 0;
  }
};









// Enhanced KYC Identity Document Upload Endpoint
app.post('/api/users/kyc/identity', protect, upload.fields([
  { name: 'front', maxCount: 1 },
  { name: 'back', maxCount: 1 }
]), async (req, res) => {
  try {
    const { documentType, documentNumber, documentExpiry } = req.body;
    
    console.log('KYC Identity Upload - User:', req.user.id, 'Data:', {
      documentType,
      documentNumber,
      documentExpiry,
      hasFiles: !!req.files
    });

    // Check if KYC is already submitted or approved
    const existingKYC = await KYC.findOne({ user: req.user.id });
    if (existingKYC && (existingKYC.overallStatus === 'pending' || existingKYC.overallStatus === 'verified')) {
      return res.status(409).json({
        status: 'fail',
        message: 'KYC already submitted. Cannot modify once submitted for review.'
      });
    }

    // Enhanced validation
    const validationErrors = [];
    if (!documentType?.trim()) validationErrors.push('Document type is required');
    if (!documentNumber?.trim()) validationErrors.push('Document number is required');
    if (!documentExpiry?.trim()) validationErrors.push('Document expiry date is required');
    
    if (!req.files?.front?.[0] && !req.files?.back?.[0]) {
      validationErrors.push('At least one document image (front or back) is required');
    }

    if (validationErrors.length > 0) {
      return res.status(400).json({
        status: 'fail',
        message: 'Validation failed',
        errors: validationErrors
      });
    }

    // Validate document expiry date
    const expiryDate = new Date(documentExpiry);
    if (isNaN(expiryDate.getTime()) || expiryDate <= new Date()) {
      return res.status(400).json({
        status: 'fail',
        message: 'Document expiry date must be a valid future date'
      });
    }

    // Find or create KYC record
    let kycRecord = existingKYC || new KYC({ user: req.user.id });

    // Check if identity is already pending or verified
    if (kycRecord.identity.status === 'pending' || kycRecord.identity.status === 'verified') {
      return res.status(409).json({
        status: 'fail',
        message: 'Identity verification already submitted. Cannot modify once submitted.'
      });
    }

    // Update identity information
    kycRecord.identity.documentType = documentType.trim();
    kycRecord.identity.documentNumber = documentNumber.trim();
    kycRecord.identity.documentExpiry = expiryDate;
    kycRecord.identity.status = 'pending';
    kycRecord.identity.submittedAt = new Date();

    // Handle file uploads with error handling
    try {
      if (req.files.front?.[0]) {
        const frontFile = req.files.front[0];
        const finalFrontPath = `uploads/kyc/identity/${req.user.id}_${Date.now()}_front_${frontFile.originalname}`;
        
        fs.renameSync(frontFile.path, finalFrontPath);
        
        kycRecord.identity.frontImage = {
          filename: path.basename(finalFrontPath),
          originalName: frontFile.originalname,
          mimeType: frontFile.mimetype,
          size: frontFile.size,
          path: finalFrontPath,
          uploadedAt: new Date()
        };
      }

      if (req.files.back?.[0]) {
        const backFile = req.files.back[0];
        const finalBackPath = `uploads/kyc/identity/${req.user.id}_${Date.now()}_back_${backFile.originalname}`;
        
        fs.renameSync(backFile.path, finalBackPath);
        
        kycRecord.identity.backImage = {
          filename: path.basename(finalBackPath),
          originalName: backFile.originalname,
          mimeType: backFile.mimetype,
          size: backFile.size,
          path: finalBackPath,
          uploadedAt: new Date()
        };
      }
    } catch (fileError) {
      console.error('File processing error:', fileError);
      return res.status(500).json({
        status: 'error',
        message: 'Failed to process uploaded files'
      });
    }

    // Update overall status
    kycRecord.overallStatus = 'in-progress';
    kycRecord.updatedAt = new Date();
    
    await kycRecord.save();

    // Update user's KYC status
    await User.findByIdAndUpdate(req.user.id, {
      'kycStatus.identity': 'pending',
      $set: { kycUpdatedAt: new Date() }
    });

    // Emit real-time status update
    req.app.get('io')?.to(req.user.id).emit('kycStatusUpdate', {
      type: 'identity',
      status: 'pending',
      overallStatus: kycRecord.overallStatus
    });

    res.status(200).json({
      status: 'success',
      message: 'Identity documents uploaded successfully',
      data: {
        identity: {
          documentType: kycRecord.identity.documentType,
          documentNumber: kycRecord.identity.documentNumber,
          status: kycRecord.identity.status,
          submittedAt: kycRecord.identity.submittedAt
        }
      }
    });

    await logActivity('kyc_identity_upload', 'kyc', kycRecord._id, req.user.id, 'User', req);

  } catch (err) {
    console.error('Upload identity documents error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Internal server error while uploading identity documents'
    });
  }
});

// Enhanced Address Document Upload Endpoint
app.post('/api/users/kyc/address', protect, upload.single('document'), async (req, res) => {
  try {
    const { documentType, documentDate } = req.body;
    
    console.log('KYC Address Upload - User:', req.user.id, 'Data:', {
      documentType,
      documentDate,
      hasFile: !!req.file
    });

    // Check if KYC is already submitted or approved
    const existingKYC = await KYC.findOne({ user: req.user.id });
    if (existingKYC && (existingKYC.overallStatus === 'pending' || existingKYC.overallStatus === 'verified')) {
      return res.status(409).json({
        status: 'fail',
        message: 'KYC already submitted. Cannot modify once submitted for review.'
      });
    }

    // Enhanced validation
    const validationErrors = [];
    if (!documentType?.trim()) validationErrors.push('Document type is required');
    if (!documentDate?.trim()) validationErrors.push('Document date is required');
    if (!req.file) validationErrors.push('Document file is required');

    if (validationErrors.length > 0) {
      return res.status(400).json({
        status: 'fail',
        message: 'Validation failed',
        errors: validationErrors
      });
    }

    // Validate document date
    const docDate = new Date(documentDate);
    if (isNaN(docDate.getTime())) {
      return res.status(400).json({
        status: 'fail',
        message: 'Invalid document date format'
      });
    }

    // Find or create KYC record
    let kycRecord = existingKYC || new KYC({ user: req.user.id });

    // Check if address is already pending or verified
    if (kycRecord.address.status === 'pending' || kycRecord.address.status === 'verified') {
      return res.status(409).json({
        status: 'fail',
        message: 'Address verification already submitted. Cannot modify once submitted.'
      });
    }

    // Update address information
    kycRecord.address.documentType = documentType.trim();
    kycRecord.address.documentDate = docDate;
    kycRecord.address.status = 'pending';
    kycRecord.address.submittedAt = new Date();

    // Handle document file with error handling
    try {
      const finalPath = `uploads/kyc/address/${req.user.id}_${Date.now()}_${req.file.originalname}`;
      fs.renameSync(req.file.path, finalPath);

      kycRecord.address.documentImage = {
        filename: path.basename(finalPath),
        originalName: req.file.originalname,
        mimeType: req.file.mimetype,
        size: req.file.size,
        path: finalPath,
        uploadedAt: new Date()
      };
    } catch (fileError) {
      console.error('File processing error:', fileError);
      return res.status(500).json({
        status: 'error',
        message: 'Failed to process uploaded file'
      });
    }

    // Update overall status
    kycRecord.overallStatus = 'in-progress';
    kycRecord.updatedAt = new Date();
    await kycRecord.save();

    // Update user's KYC status
    await User.findByIdAndUpdate(req.user.id, {
      'kycStatus.address': 'pending',
      $set: { kycUpdatedAt: new Date() }
    });

    // Emit real-time status update
    req.app.get('io')?.to(req.user.id).emit('kycStatusUpdate', {
      type: 'address',
      status: 'pending',
      overallStatus: kycRecord.overallStatus
    });

    res.status(200).json({
      status: 'success',
      message: 'Address document uploaded successfully',
      data: {
        address: {
          documentType: kycRecord.address.documentType,
          status: kycRecord.address.status,
          submittedAt: kycRecord.address.submittedAt
        }
      }
    });

    await logActivity('kyc_address_upload', 'kyc', kycRecord._id, req.user.id, 'User', req);

  } catch (err) {
    console.error('Upload address document error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Internal server error while uploading address document'
    });
  }
});

// Enhanced Facial Verification Endpoint
app.post('/api/users/kyc/facial', protect, upload.fields([
  { name: 'video', maxCount: 1 },
  { name: 'photo', maxCount: 1 }
]), async (req, res) => {
  try {
    console.log('KYC Facial Verification - User:', req.user.id, 'Files:', {
      hasVideo: !!req.files?.video?.[0],
      hasPhoto: !!req.files?.photo?.[0]
    });

    // Check if KYC is already submitted or approved
    const existingKYC = await KYC.findOne({ user: req.user.id });
    if (existingKYC && (existingKYC.overallStatus === 'pending' || existingKYC.overallStatus === 'verified')) {
      return res.status(409).json({
        status: 'fail',
        message: 'KYC already submitted. Cannot modify once submitted for review.'
      });
    }

    // Enhanced validation - require at least one file
    if (!req.files?.video?.[0] && !req.files?.photo?.[0]) {
      return res.status(400).json({
        status: 'fail',
        message: 'At least one verification file (video or photo) is required'
      });
    }

    // Find or create KYC record
    let kycRecord = existingKYC || new KYC({ user: req.user.id });

    // Check if facial verification is already pending or verified
    if (kycRecord.facial.status === 'pending' || kycRecord.facial.status === 'verified') {
      return res.status(409).json({
        status: 'fail',
        message: 'Facial verification already submitted. Cannot modify once submitted.'
      });
    }

    // Update facial verification status
    kycRecord.facial.status = 'pending';
    kycRecord.facial.submittedAt = new Date();

    // Handle file uploads with error handling
    try {
      if (req.files.video?.[0]) {
        const videoFile = req.files.video[0];
        const finalVideoPath = `uploads/kyc/facial/${req.user.id}_${Date.now()}_video_${videoFile.originalname}`;
        
        fs.renameSync(videoFile.path, finalVideoPath);
        
        kycRecord.facial.verificationVideo = {
          filename: path.basename(finalVideoPath),
          originalName: videoFile.originalname,
          mimeType: videoFile.mimetype,
          size: videoFile.size,
          path: finalVideoPath,
          uploadedAt: new Date()
        };
      }

      if (req.files.photo?.[0]) {
        const photoFile = req.files.photo[0];
        const finalPhotoPath = `uploads/kyc/facial/${req.user.id}_${Date.now()}_photo_${photoFile.originalname}`;
        
        fs.renameSync(photoFile.path, finalPhotoPath);
        
        kycRecord.facial.verificationPhoto = {
          filename: path.basename(finalPhotoPath),
          originalName: photoFile.originalname,
          mimeType: photoFile.mimetype,
          size: photoFile.size,
          path: finalPhotoPath,
          uploadedAt: new Date()
        };
      }
    } catch (fileError) {
      console.error('File processing error:', fileError);
      return res.status(500).json({
        status: 'error',
        message: 'Failed to process verification files'
      });
    }

    // Update overall status
    kycRecord.overallStatus = kycRecord.overallStatus === 'not-started' ? 'in-progress' : kycRecord.overallStatus;
    kycRecord.updatedAt = new Date();
    await kycRecord.save();

    // Update user's KYC status
    await User.findByIdAndUpdate(req.user.id, {
      'kycStatus.facial': 'pending',
      $set: { kycUpdatedAt: new Date() }
    });

    // Emit real-time status update
    req.app.get('io')?.to(req.user.id).emit('kycStatusUpdate', {
      type: 'facial',
      status: 'pending',
      overallStatus: kycRecord.overallStatus
    });

    res.status(200).json({
      status: 'success',
      message: 'Facial verification submitted successfully',
      data: {
        facial: {
          status: kycRecord.facial.status,
          submittedAt: kycRecord.facial.submittedAt,
          hasVideo: !!kycRecord.facial.verificationVideo,
          hasPhoto: !!kycRecord.facial.verificationPhoto
        }
      }
    });

    await logActivity('kyc_facial_upload', 'kyc', kycRecord._id, req.user.id, 'User', req);

  } catch (err) {
    console.error('Facial verification upload error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Internal server error while submitting facial verification'
    });
  }
});

// Enhanced KYC Status Endpoint with Real-time Support
app.get('/api/users/kyc/status', protect, async (req, res) => {
  try {
    const kycRecord = await KYC.findOne({ user: req.user.id }).lean();

    if (!kycRecord) {
      return res.status(200).json({
        status: 'success',
        data: {
          status: {
            identity: 'not-submitted',
            address: 'not-submitted',
            facial: 'not-submitted',
            overall: 'not-started'
          },
          isSubmitted: false,
          canSubmit: false,
          lastUpdated: new Date().toISOString()
        }
      });
    }

    const canSubmit = 
      kycRecord.identity.status === 'pending' &&
      kycRecord.address.status === 'pending' &&
      kycRecord.facial.status === 'pending' &&
      kycRecord.overallStatus === 'in-progress';

    const responseData = {
      status: 'success',
      data: {
        status: {
          identity: kycRecord.identity.status || 'not-submitted',
          address: kycRecord.address.status || 'not-submitted',
          facial: kycRecord.facial.status || 'not-submitted',
          overall: kycRecord.overallStatus || 'not-started'
        },
        isSubmitted: ['pending', 'verified', 'rejected'].includes(kycRecord.overallStatus),
        canSubmit,
        submittedAt: kycRecord.submittedAt,
        lastUpdated: kycRecord.updatedAt || kycRecord.createdAt
      }
    };

    // Set cache headers for efficient polling
    res.set({
      'Cache-Control': 'no-cache, no-store, must-revalidate',
      'Pragma': 'no-cache',
      'Expires': '0',
      'Last-Modified': new Date().toUTCString()
    });

    res.status(200).json(responseData);

  } catch (err) {
    console.error('Get KYC status error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch KYC status'
    });
  }
});

// Enhanced KYC Submit for Review Endpoint
app.post('/api/users/kyc/submit', protect, async (req, res) => {
  try {
    const kycRecord = await KYC.findOne({ user: req.user.id });
    
    if (!kycRecord) {
      return res.status(400).json({
        status: 'fail',
        message: 'No KYC documents found. Please upload required documents first.'
      });
    }

    // Prevent double submission
    if (kycRecord.overallStatus === 'pending') {
      return res.status(409).json({
        status: 'fail',
        message: 'KYC application already submitted and is pending review'
      });
    }

    if (kycRecord.overallStatus === 'verified') {
      return res.status(409).json({
        status: 'fail',
        message: 'KYC application already verified'
      });
    }

    // Comprehensive validation
    const validationErrors = [];

    if (kycRecord.identity.status !== 'pending') {
      validationErrors.push('Identity verification not completed');
    }
    if (kycRecord.address.status !== 'pending') {
      validationErrors.push('Address verification not completed');
    }
    if (kycRecord.facial.status !== 'pending') {
      validationErrors.push('Facial verification not completed');
    }

    if (validationErrors.length > 0) {
      return res.status(400).json({
        status: 'fail',
        message: 'Cannot submit KYC application',
        errors: validationErrors
      });
    }

    // Update KYC status to pending review
    kycRecord.overallStatus = 'pending';
    kycRecord.submittedAt = new Date();
    kycRecord.updatedAt = new Date();
    
    await kycRecord.save();

    // Update user's KYC status
    await User.findByIdAndUpdate(req.user.id, {
      'kycStatus.overall': 'pending',
      'kycStatus.submittedAt': new Date(),
      $set: { kycUpdatedAt: new Date() }
    });

    // Emit real-time status update
    req.app.get('io')?.to(req.user.id).emit('kycStatusUpdate', {
      type: 'overall',
      status: 'pending',
      submittedAt: kycRecord.submittedAt
    });

    // Notify admins (you can integrate with your notification system)
    await notifyAdmins('KYC_SUBMISSION', {
      userId: req.user.id,
      kycId: kycRecord._id,
      submittedAt: kycRecord.submittedAt
    });

    res.status(200).json({
      status: 'success',
      message: 'KYC application submitted for review. You will be notified once it is processed.',
      data: {
        submittedAt: kycRecord.submittedAt,
        overallStatus: kycRecord.overallStatus
      }
    });

    await logActivity('kyc_submitted', 'kyc', kycRecord._id, req.user.id, 'User', req);

  } catch (err) {
    console.error('Submit KYC error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to submit KYC application'
    });
  }
});

// KYC Data Endpoint - Frontend Integration
app.get('/api/users/kyc', protect, async (req, res) => {
  try {
    const userId = req.user.id;
    
    const kycRecord = await KYC.findOne({ user: userId })
      .populate('identity.verifiedBy', 'name email')
      .populate('address.verifiedBy', 'name email')
      .populate('facial.verifiedBy', 'name email')
      .lean();

    if (!kycRecord) {
      return res.status(200).json({
        status: 'success',
        data: {
          kyc: {
            identity: {
              documentType: '',
              documentNumber: '',
              documentExpiry: '',
              frontImage: null,
              backImage: null,
              status: 'unverified',
              verifiedAt: null,
              verifiedBy: null,
              rejectionReason: ''
            },
            address: {
              documentType: '',
              documentDate: '',
              documentImage: null,
              status: 'unverified',
              verifiedAt: null,
              verifiedBy: null,
              rejectionReason: ''
            },
            facial: {
              verificationVideo: null,
              verificationPhoto: null,
              status: 'unverified',
              verifiedAt: null,
              verifiedBy: null,
              rejectionReason: ''
            },
            overallStatus: 'unverified',
            submittedAt: null,
            reviewedAt: null,
            adminNotes: ''
          },
          isSubmitted: false
        }
      });
    }

    const responseData = {
      status: 'success',
      data: {
        kyc: kycRecord,
        isSubmitted: kycRecord.overallStatus === 'pending' || kycRecord.overallStatus === 'verified' || kycRecord.overallStatus === 'rejected'
      }
    };

    res.status(200).json(responseData);

  } catch (err) {
    console.error('Get KYC data error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch KYC data'
    });
  }
});

// =============================================
// MESSAGING AND NOTIFICATION ENDPOINTS
// =============================================

// Get User Messages and Notifications
app.get('/api/users/messages', protect, async (req, res) => {
  try {
    const userId = req.user.id;
    
    const messages = await Message.find({ 
      user: userId,
      status: 'active'
    })
    .sort({ createdAt: -1 })
    .limit(50)
    .lean();

    const notifications = await Notification.find({
      user: userId,
      status: 'unread'
    })
    .sort({ createdAt: -1 })
    .limit(20)
    .lean();

    const announcements = await Announcement.find({
      $or: [
        { targetUsers: userId },
        { targetUsers: { $size: 0 } }
      ],
      status: 'active',
      startDate: { $lte: new Date() },
      endDate: { $gte: new Date() }
    })
    .sort({ priority: -1, createdAt: -1 })
    .limit(10)
    .lean();

    res.status(200).json({
      status: 'success',
      data: {
        messages: messages || [],
        notifications: notifications || [],
        announcements: announcements || [],
        unreadCount: notifications.length
      }
    });

  } catch (err) {
    console.error('Get messages error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch messages and notifications'
    });
  }
});

// Mark Message as Read
app.patch('/api/users/messages/:messageId/read', protect, async (req, res) => {
  try {
    const { messageId } = req.params;
    const userId = req.user.id;

    const message = await Message.findOneAndUpdate(
      { 
        _id: messageId, 
        user: userId 
      },
      { 
        status: 'read',
        readAt: new Date()
      },
      { new: true }
    );

    if (!message) {
      return res.status(404).json({
        status: 'fail',
        message: 'Message not found'
      });
    }

    res.status(200).json({
      status: 'success',
      message: 'Message marked as read',
      data: { message }
    });

  } catch (err) {
    console.error('Mark message as read error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to mark message as read'
    });
  }
});

// Mark Notification as Read
app.patch('/api/users/notifications/:notificationId/read', protect, async (req, res) => {
  try {
    const { notificationId } = req.params;
    const userId = req.user.id;

    const notification = await Notification.findOneAndUpdate(
      { 
        _id: notificationId, 
        user: userId 
      },
      { 
        status: 'read',
        readAt: new Date()
      },
      { new: true }
    );

    if (!notification) {
      return res.status(404).json({
        status: 'fail',
        message: 'Notification not found'
      });
    }

    res.status(200).json({
      status: 'success',
      message: 'Notification marked as read',
      data: { notification }
    });

  } catch (err) {
    console.error('Mark notification as read error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to mark notification as read'
    });
  }
});

// Mark All Notifications as Read
app.patch('/api/users/notifications/read-all', protect, async (req, res) => {
  try {
    const userId = req.user.id;

    const result = await Notification.updateMany(
      { 
        user: userId,
        status: 'unread'
      },
      { 
        status: 'read',
        readAt: new Date()
      }
    );

    res.status(200).json({
      status: 'success',
      message: 'All notifications marked as read',
      data: {
        modifiedCount: result.modifiedCount
      }
    });

  } catch (err) {
    console.error('Mark all notifications as read error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to mark notifications as read'
    });
  }
});

// Get Notification Preferences
app.get('/api/users/notification-preferences', protect, async (req, res) => {
  try {
    const userId = req.user.id;

    let preferences = await NotificationPreference.findOne({ user: userId });
    
    if (!preferences) {
      preferences = new NotificationPreference({
        user: userId,
        email: {
          accountActivity: true,
          investmentUpdates: true,
          promotionalOffers: false,
          kycStatus: true,
          securityAlerts: true
        },
        sms: {
          securityAlerts: true,
          withdrawalConfirmations: true,
          marketingMessages: false
        },
        push: {
          accountActivity: true,
          investmentUpdates: true,
          marketAlerts: false,
          kycStatus: true
        }
      });
      await preferences.save();
    }

    res.status(200).json({
      status: 'success',
      data: { preferences }
    });

  } catch (err) {
    console.error('Get notification preferences error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch notification preferences'
    });
  }
});

// Update Notification Preferences
app.put('/api/users/notification-preferences', protect, async (req, res) => {
  try {
    const userId = req.user.id;
    const { email, sms, push } = req.body;

    const preferences = await NotificationPreference.findOneAndUpdate(
      { user: userId },
      {
        email: email || {},
        sms: sms || {},
        push: push || {},
        updatedAt: new Date()
      },
      { new: true, upsert: true }
    );

    res.status(200).json({
      status: 'success',
      message: 'Notification preferences updated successfully',
      data: { preferences }
    });

  } catch (err) {
    console.error('Update notification preferences error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to update notification preferences'
    });
  }
});

// Send Message to User (Admin Only)
app.post('/api/admin/messages', protect, async (req, res) => {
  try {
    // Check if user is admin
    if (req.user.role !== 'admin') {
      return res.status(403).json({
        status: 'fail',
        message: 'Access denied. Admin privileges required.'
      });
    }

    const { userId, title, content, type, priority } = req.body;

    // Validate required fields
    if (!userId || !title || !content) {
      return res.status(400).json({
        status: 'fail',
        message: 'User ID, title, and content are required'
      });
    }

    const message = new Message({
      user: userId,
      title: title.trim(),
      content: content.trim(),
      type: type || 'info',
      priority: priority || 'medium',
      status: 'active',
      createdBy: req.user.id
    });

    await message.save();

    // Emit real-time notification
    req.app.get('io')?.to(userId).emit('newMessage', {
      id: message._id,
      title: message.title,
      content: message.content,
      type: message.type,
      createdAt: message.createdAt
    });

    res.status(201).json({
      status: 'success',
      message: 'Message sent successfully',
      data: { message }
    });

  } catch (err) {
    console.error('Send message error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to send message'
    });
  }
});

// Create Announcement (Admin Only)
app.post('/api/admin/announcements', protect, async (req, res) => {
  try {
    // Check if user is admin
    if (req.user.role !== 'admin') {
      return res.status(403).json({
        status: 'fail',
        message: 'Access denied. Admin privileges required.'
      });
    }

    const { title, content, type, priority, targetUsers, startDate, endDate } = req.body;

    // Validate required fields
    if (!title || !content) {
      return res.status(400).json({
        status: 'fail',
        message: 'Title and content are required'
      });
    }

    const announcement = new Announcement({
      title: title.trim(),
      content: content.trim(),
      type: type || 'info',
      priority: priority || 'medium',
      targetUsers: targetUsers || [],
      startDate: startDate ? new Date(startDate) : new Date(),
      endDate: endDate ? new Date(endDate) : new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // Default 7 days
      status: 'active',
      createdBy: req.user.id
    });

    await announcement.save();

    // Emit real-time announcement to all users or specific users
    if (targetUsers && targetUsers.length > 0) {
      targetUsers.forEach(userId => {
        req.app.get('io')?.to(userId).emit('newAnnouncement', {
          id: announcement._id,
          title: announcement.title,
          content: announcement.content,
          type: announcement.type,
          priority: announcement.priority
        });
      });
    } else {
      // Broadcast to all users
      req.app.get('io')?.emit('newAnnouncement', {
        id: announcement._id,
        title: announcement.title,
        content: announcement.content,
        type: announcement.type,
        priority: announcement.priority
      });
    }

    res.status(201).json({
      status: 'success',
      message: 'Announcement created successfully',
      data: { announcement }
    });

  } catch (err) {
    console.error('Create announcement error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to create announcement'
    });
  }
});

// Add Comment to KYC (Admin Only)
app.post('/api/admin/kyc/:kycId/comments', protect, async (req, res) => {
  try {
    // Check if user is admin
    if (req.user.role !== 'admin') {
      return res.status(403).json({
        status: 'fail',
        message: 'Access denied. Admin privileges required.'
      });
    }

    const { kycId } = req.params;
    const { comment, section } = req.body;

    // Validate required fields
    if (!comment?.trim()) {
      return res.status(400).json({
        status: 'fail',
        message: 'Comment is required'
      });
    }

    const kycRecord = await KYC.findById(kycId);
    if (!kycRecord) {
      return res.status(404).json({
        status: 'fail',
        message: 'KYC record not found'
      });
    }

    // Add comment to KYC record
    const newComment = {
      comment: comment.trim(),
      section: section || 'general',
      commentedBy: req.user.id,
      createdAt: new Date()
    };

    kycRecord.comments = kycRecord.comments || [];
    kycRecord.comments.push(newComment);
    kycRecord.updatedAt = new Date();

    await kycRecord.save();

    // Create notification for the user
    const notification = new Notification({
      user: kycRecord.user,
      title: 'KYC Update',
      content: `Admin has added a comment to your KYC application: "${comment.substring(0, 100)}..."`,
      type: 'kyc_update',
      relatedId: kycRecord._id,
      status: 'unread'
    });

    await notification.save();

    // Emit real-time notification
    req.app.get('io')?.to(kycRecord.user.toString()).emit('newNotification', {
      id: notification._id,
      title: notification.title,
      content: notification.content,
      type: notification.type,
      createdAt: notification.createdAt
    });

    res.status(201).json({
      status: 'success',
      message: 'Comment added successfully',
      data: { comment: newComment }
    });

  } catch (err) {
    console.error('Add KYC comment error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to add comment'
    });
  }
});

// Get KYC Comments
app.get('/api/users/kyc/comments', protect, async (req, res) => {
  try {
    const userId = req.user.id;

    const kycRecord = await KYC.findOne({ user: userId })
      .populate('comments.commentedBy', 'name email')
      .select('comments')
      .lean();

    const comments = kycRecord?.comments || [];

    res.status(200).json({
      status: 'success',
      data: { comments }
    });

  } catch (err) {
    console.error('Get KYC comments error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch KYC comments'
    });
  }
});










// Get announcements for user - SOLVES THE 404 ERROR
app.get('/api/announcements', protect, async (req, res) => {
  try {
    const userId = req.user.id;
    const now = new Date();

    // Build query for active announcements targeting this user
    const query = {
      $or: [
        { recipientType: 'all' }, // Broadcast to all users
        { recipientType: 'specific', specificUserId: userId } // Specifically targeted to this user
      ]
    };

    // Get active announcements from Notification collection
    const announcements = await Notification.find(query)
      .select('title message type isImportant createdAt')
      .sort({ createdAt: -1 })
      .limit(10)
      .lean();

    res.status(200).json({
      status: 'success',
      data: announcements
    });

  } catch (err) {
    console.error('Get announcements error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch announcements'
    });
  }
});







// Get notification stats for admin dashboard
app.get('/api/admin/notifications/stats', adminProtect, async (req, res) => {
  try {
    const totalNotifications = await Notification.countDocuments();
    const unreadNotifications = await Notification.countDocuments({ read: false });
    
    // Count notifications sent today
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const sentToday = await Notification.countDocuments({
      createdAt: { $gte: today }
    });

    res.status(200).json({
      status: 'success',
      data: {
        stats: {
          total: totalNotifications,
          unread: unreadNotifications,
          sentToday: sentToday,
          deliveryRate: '98%' // You can calculate this based on your logic
        }
      }
    });
  } catch (err) {
    console.error('Get notification stats error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch notification statistics'
    });
  }
});

// Get unread notifications count
app.get('/api/admin/notifications/unread-count', adminProtect, async (req, res) => {
  try {
    const unreadCount = await Notification.countDocuments({ read: false });
    
    res.status(200).json({
      status: 'success',
      data: {
        unreadCount: unreadCount
      }
    });
  } catch (err) {
    console.error('Get unread count error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch unread count'
    });
  }
});

// Get notifications with pagination and filtering
app.get('/api/admin/notifications', adminProtect, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const filter = req.query.filter || 'all';
    const skip = (page - 1) * limit;

    // Build query based on filter
    let query = {};
    if (filter === 'unread') {
      query.read = false;
    } else if (filter === 'read') {
      query.read = true;
    } else if (filter === 'important') {
      query.isImportant = true;
    } else if (filter !== 'all') {
      query.type = filter;
    }

    const notifications = await Notification.find(query)
      .populate('specificUserId', 'firstName lastName email')
      .populate('sentBy', 'name email')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .lean();

    const totalNotifications = await Notification.countDocuments(query);
    const totalPages = Math.ceil(totalNotifications / limit);

    res.status(200).json({
      status: 'success',
      data: {
        notifications: notifications,
        pagination: {
          currentPage: page,
          totalPages: totalPages,
          totalItems: totalNotifications,
          hasNext: page < totalPages,
          hasPrev: page > 1
        }
      }
    });
  } catch (err) {
    console.error('Get notifications error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch notifications'
    });
  }
});


// Send notification
app.post('/api/admin/notifications/send', adminProtect, async (req, res) => {
  try {
    const {
      recipientType,
      specificUserId,
      userGroup,
      notificationType,
      title,
      message,
      isImportant,
      sendEmail
    } = req.body;

    // Validate required fields
    if (!title || !message || !recipientType) {
      return res.status(400).json({
        status: 'fail',
        message: 'Title, message, and recipient type are required'
      });
    }

    // Create notification record
    const notification = new Notification({
      title: title.trim(),
      message: message.trim(),
      type: notificationType || 'info',
      recipientType: recipientType,
      specificUserId: recipientType === 'specific' ? specificUserId : undefined,
      userGroup: recipientType === 'group' ? userGroup : undefined,
      isImportant: isImportant || false,
      sentBy: req.admin._id,
      metadata: {
        emailSent: sendEmail || false,
        sentAt: new Date()
      }
    });

    await notification.save();

    // If sendEmail is true, send actual emails (you'll need to implement this)
    if (sendEmail) {
      // Implement email sending logic here based on recipientType
      await sendNotificationEmails(notification);
    }

    res.status(201).json({
      status: 'success',
      message: 'Notification sent successfully',
      data: {
        notification: notification
      }
    });

  } catch (err) {
    console.error('Send notification error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to send notification'
    });
  }
});

// Mark notification as read
app.post('/api/admin/notifications/:notificationId/read', adminProtect, async (req, res) => {
  try {
    const { notificationId } = req.params;

    const notification = await Notification.findByIdAndUpdate(
      notificationId,
      {
        read: true,
        readAt: new Date()
      },
      { new: true }
    );

    if (!notification) {
      return res.status(404).json({
        status: 'fail',
        message: 'Notification not found'
      });
    }

    res.status(200).json({
      status: 'success',
      message: 'Notification marked as read',
      data: {
        notification: notification
      }
    });

  } catch (err) {
    console.error('Mark notification as read error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to mark notification as read'
    });
  }
});

// Mark all notifications as read
app.post('/api/admin/notifications/mark-all-read', adminProtect, async (req, res) => {
  try {
    const result = await Notification.updateMany(
      { read: false },
      {
        read: true,
        readAt: new Date()
      }
    );

    res.status(200).json({
      status: 'success',
      message: 'All notifications marked as read',
      data: {
        modifiedCount: result.modifiedCount
      }
    });

  } catch (err) {
    console.error('Mark all notifications as read error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to mark all notifications as read'
    });
  }
});

// Delete notification
app.delete('/api/admin/notifications/:notificationId', adminProtect, async (req, res) => {
  try {
    const { notificationId } = req.params;

    const notification = await Notification.findByIdAndDelete(notificationId);

    if (!notification) {
      return res.status(404).json({
        status: 'fail',
        message: 'Notification not found'
      });
    }

    res.status(200).json({
      status: 'success',
      message: 'Notification deleted successfully'
    });

  } catch (err) {
    console.error('Delete notification error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to delete notification'
    });
  }
});

// Delete all read notifications
app.delete('/api/admin/notifications/delete-all-read', adminProtect, async (req, res) => {
  try {
    const result = await Notification.deleteMany({ read: true });

    res.status(200).json({
      status: 'success',
      message: 'All read notifications deleted successfully',
      data: {
        deletedCount: result.deletedCount
      }
    });

  } catch (err) {
    console.error('Delete all read notifications error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to delete read notifications'
    });
  }
});








// Send OTP Endpoint - FIXED to preserve original email format
app.post('/api/auth/send-otp', [
  body('email').isEmail().withMessage('Please provide a valid email')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      message: 'Please provide a valid email address'
    });
  }

  try {
    const { email } = req.body;

    // Use the EXACT email as provided (no normalization)
    const originalEmail = email;

    // Check if user exists - use exact email match
    const user = await User.findOne({ email: originalEmail });
    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'User not found'
      });
    }

    // Check for recent OTP attempts using exact email
    const recentOtp = await OTP.findOne({
      email: originalEmail,
      createdAt: { $gte: new Date(Date.now() - 60 * 1000) } // Last 60 seconds
    });

    if (recentOtp) {
      return res.status(429).json({
        status: 'fail',
        message: 'Please wait before requesting a new OTP'
      });
    }

    // Generate OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes

    // Delete any existing OTPs for this exact email
    await OTP.deleteMany({ email: originalEmail, used: false });

    // Create new OTP with exact email
    await OTP.create({
      email: originalEmail,
      otp,
      type: 'login',
      expiresAt,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent']
    });

    // Send OTP email to the exact email address
    await sendProfessionalEmail({
      email: originalEmail,
      template: 'otp',
      data: {
        name: user.firstName,
        otp: otp,
        action: 'login'
      }
    });

    res.status(200).json({
      status: 'success',
      message: 'OTP sent successfully to your email'
    });

    await logActivity('otp_sent', 'otp', null, user._id, 'User', req, {
      email: originalEmail,
      type: 'login'
    });

  } catch (err) {
    console.error('Send OTP error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to send OTP. Please try again.'
    });
  }
});







// OTP Verification Endpoint - FIXED to use exact email matching
app.post('/api/auth/verify-otp', [
  body('email').isEmail().withMessage('Please provide a valid email'),
  body('otp').isLength({ min: 6, max: 6 }).withMessage('OTP must be 6 digits')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      message: 'Please enter a valid 6-digit OTP code'
    });
  }

  try {
    const { email, otp } = req.body;
    const token = req.headers.authorization?.replace('Bearer ', '');

    if (!token) {
      return res.status(401).json({
        status: 'fail',
        message: 'Authentication required. Please try logging in again.'
      });
    }

    // Verify temporary token
    let decoded;
    try {
      decoded = verifyJWT(token);
    } catch (err) {
      return res.status(401).json({
        status: 'fail',
        message: 'Session expired. Please try logging in again.'
      });
    }

    // Find user WITHOUT password selection to include Google users
    const user = await User.findById(decoded.id).select('-password');
    
    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'User not found'
      });
    }

    // FIXED: Compare EXACT emails without any normalization
    console.log('Email comparison (exact match):', {
      userEmail: user.email,
      inputEmail: email,
      match: user.email === email
    });

    if (user.email !== email) {
      return res.status(400).json({
        status: 'fail',
        message: 'Email does not match user account'
      });
    }

    // FIXED: Look for OTP with EXACT email only
    const otpRecord = await OTP.findOne({
      email: email, // Exact match only
      otp,
      used: false,
      expiresAt: { $gt: new Date() }
    });

    if (!otpRecord) {
      // Increment attempts for exact email
      await OTP.updateMany(
        { 
          email: email, // Exact match only
          otp, 
          used: false 
        },
        { $inc: { attempts: 1 } }
      );

      // Check if max attempts reached for exact email
      const failedAttempts = await OTP.countDocuments({
        email: email, // Exact match only
        used: false,
        createdAt: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) },
        attempts: { $gte: 5 }
      });

      if (failedAttempts >= 5) {
        await User.findByIdAndUpdate(user._id, {
          status: 'suspended',
          suspensionLiftAt: new Date(Date.now() + 24 * 60 * 60 * 1000)
        });

        return res.status(429).json({
          status: 'fail',
          message: 'Too many failed attempts. Account suspended for 24 hours.'
        });
      }

      // Check if OTP exists but is expired for exact email
      const expiredOtp = await OTP.findOne({
        email: email, // Exact match only
        otp,
        used: false,
        expiresAt: { $lte: new Date() }
      });

      if (expiredOtp) {
        return res.status(400).json({
          status: 'fail',
          message: 'Verification code has expired. Please request a new one.'
        });
      }

      return res.status(400).json({
        status: 'fail',
        message: 'Invalid verification code. Please try again.'
      });
    }

    // Mark OTP as used
    otpRecord.used = true;
    await otpRecord.save();

    // Update user verification status if this was for signup
    if (!user.isVerified) {
      user.isVerified = true;
      await user.save();
    }

    // Generate final JWT token
    const finalToken = generateJWT(user._id);

    // Update last login
    user.lastLogin = new Date();
    const deviceInfo = await getUserDeviceInfo(req);
    user.loginHistory.push(deviceInfo);
    await user.save();

    // Set cookie
    res.cookie('jwt', finalToken, {
      expires: new Date(Date.now() + 2 * 60 * 60 * 1000),
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict'
    });

    res.status(200).json({
      status: 'success',
      message: 'Verification successful! Redirecting to dashboard...',
      token: finalToken,
      data: {
        user: {
          id: user._id,
          firstName: user.firstName,
          lastName: user.lastName,
          email: user.email, // Return the exact email from database
          isVerified: user.isVerified,
          hasGoogleAuth: !!user.googleId
        }
      }
    });

    await logActivity('otp_verified', 'otp', otpRecord._id, user._id, 'User', req, {
      type: otpRecord.type,
      isGoogleUser: !!user.googleId,
      emailUsed: email,
      exactMatch: true
    });

  } catch (err) {
    console.error('Verify OTP error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred during verification. Please try again.'
    });
  }
});







// Enhanced location logging middleware
app.use(async (req, res, next) => {
  try {
    const deviceInfo = await getUserDeviceInfo(req);
    
    // Attach location info to request for use in other routes
    req.clientLocation = {
      ip: deviceInfo.ip,
      location: deviceInfo.location,
      isPublicIP: deviceInfo.isPublicIP,
      userAgent: deviceInfo.device,
      timestamp: new Date().toISOString()
    };
    
    // Log enhanced location information
    console.log('Client Connection Details:', {
      time: new Date().toLocaleString(),
      ip: deviceInfo.ip,
      location: deviceInfo.location,
      isPublicIP: deviceInfo.isPublicIP,
      userAgent: deviceInfo.device.substring(0, 100) // Truncate for readability
    });
    
    next();
  } catch (error) {
    console.error('Location middleware error:', error);
    next();
  }
});
















// =============================================
// COMPREHENSIVE LOAN ELIGIBILITY CHECK ENDPOINT
// =============================================
app.post('/api/loans/check-eligibility', protect, async (req, res) => {
    try {
        console.log('🔍 Loan eligibility check request received');
        
        const { requestedAmount } = req.body;
        const userId = req.user._id;

        // Validate requested amount
        if (!requestedAmount || requestedAmount < 1000) {
            return res.status(400).json({
                status: 'fail',
                message: 'Minimum loan amount is $1,000'
            });
        }

        // Fetch user data
        const user = await User.findById(userId)
            .select('balances firstName lastName email kycStatus isVerified')
            .lean();
        
        if (!user) {
            return res.status(404).json({
                status: 'fail',
                message: 'User not found'
            });
        }

        // Fetch all investments (both active and completed)
        const investments = await Investment.find({
            user: userId
        })
        .select('amount plan status')
        .lean();

        // Fetch ALL loans including pending and active
        const allLoans = await Loan.find({
            user: userId,
            status: { $in: ['active', 'pending', 'approved'] }
        })
        .select('amount repaidAmount remainingBalance status')
        .lean();

        // Check if user has ANY active debt
        const hasActiveDebt = allLoans.some(loan => 
            loan.status === 'active' || loan.status === 'pending'
        );

        // Calculate total debt from active loans only
        const totalDebt = allLoans
            .filter(loan => loan.status === 'active')
            .reduce((sum, loan) => sum + (loan.remainingBalance || loan.amount), 0);

        // Calculate loan capacity (3x main balance)
        const loanLimit = user.balances.main * 3;
        const availableCredit = Math.max(0, loanLimit - totalDebt);

        // Check if user has at least 5 investments (active or completed)
        const totalInvestments = investments.length;
        const hasMinimumInvestments = totalInvestments >= 5;

        // Check KYC verification
        const isKYCVerified = user.kycStatus?.identity === 'verified' && 
                              user.kycStatus?.address === 'verified';

        // Calculate credit score AFTER all checks
        let creditScore = 600; // Base score

        // Add points based on investments
        if (totalInvestments >= 5) creditScore += 20;
        if (totalInvestments >= 10) creditScore += 30;
        if (totalInvestments >= 20) creditScore += 50;

        // Add points based on investment amount
        const totalInvested = investments.reduce((sum, inv) => sum + (inv.amount || 0), 0);
        if (totalInvested >= 5000) creditScore += 25;
        if (totalInvested >= 10000) creditScore += 50;
        if (totalInvested >= 50000) creditScore += 75;

        // Add points for completed investments
        const completedInvestments = investments.filter(inv => inv.status === 'completed').length;
        if (completedInvestments >= 3) creditScore += 20;
        if (completedInvestments >= 5) creditScore += 30;

        // Add points for KYC verification
        if (isKYCVerified) creditScore += 50;

        // Deduct points for having active debt
        if (hasActiveDebt) {
            creditScore -= 100; // Significant deduction for existing debt
        }

        // Cap credit score
        creditScore = Math.min(Math.max(creditScore, 300), 850);
        const roundedCreditScore = Math.floor(creditScore);

        // DETERMINE ELIGIBILITY CRITERIA
        const eligibilityCriteria = {
            kycVerified: isKYCVerified,
            minimumInvestments: hasMinimumInvestments,
            noActiveDebt: !hasActiveDebt, // CRITICAL: No active/pending loans
            sufficientCredit: requestedAmount <= availableCredit,
            creditScoreThreshold: roundedCreditScore >= 600
        };

        const isEligible = Object.values(eligibilityCriteria).every(criterion => criterion === true);

        // Create requirements array
        const requirements = [
            {
                name: 'KYC Verification',
                met: isKYCVerified,
                description: isKYCVerified ? 'Identity & address verified' : 'Complete KYC verification'
            },
            {
                name: 'Minimum 5 Investments',
                met: hasMinimumInvestments,
                description: hasMinimumInvestments ? `You have ${totalInvestments} investments` : `Need ${5 - totalInvestments} more investments`
            },
            {
                name: 'No Active Debt',
                met: !hasActiveDebt,
                description: !hasActiveDebt ? 'No active loans' : 'You have active/pending loans'
            },
            {
                name: 'Sufficient Credit',
                met: requestedAmount <= availableCredit,
                description: requestedAmount <= availableCredit ? 
                    `Within credit limit` : 
                    `Exceeds available credit ($${availableCredit.toFixed(2)})`
            },
            {
                name: 'Credit Score ≥ 600',
                met: roundedCreditScore >= 600,
                description: `Your score: ${roundedCreditScore}`
            }
        ];

        // Response data
        const response = {
            status: 'success',
            eligible: isEligible,
            maxLoanAmount: loanLimit,
            availableCredit: availableCredit,
            creditScore: roundedCreditScore,
            requestedAmount: requestedAmount,
            currentDebt: totalDebt,
            mainBalance: user.balances.main,
            monthlyInterest: 9.99,
            disbursementFee: 0.99,
            requirements: requirements,
            userProfile: {
                name: `${user.firstName} ${user.lastName}`,
                hasActiveDebt: hasActiveDebt,
                totalInvestments: totalInvestments,
                completedInvestments: completedInvestments
            },
            timestamp: new Date().toISOString()
        };

        res.status(200).json(response);

    } catch (err) {
        console.error('❌ Error checking loan eligibility:', err);
        res.status(500).json({
            status: 'error',
            message: 'An error occurred while checking loan eligibility',
            timestamp: new Date().toISOString()
        });
    }
});



app.post('/api/loans/apply', protect, async (req, res) => {
    try {
        const { amount, purpose, term, interestRate = 9.99, disbursementFee = 0.99 } = req.body;
        const userId = req.user._id;

        // Validate required fields
        if (!amount || amount < 1000) {
            return res.status(400).json({
                status: 'fail',
                message: 'Minimum loan amount is $1,000'
            });
        }

        if (!purpose || !term) {
            return res.status(400).json({
                status: 'fail',
                message: 'Please provide loan purpose and term'
            });
        }

        // Get user details
        const user = await User.findById(userId).select('balances firstName lastName email kycStatus');
        if (!user) {
            return res.status(404).json({
                status: 'fail',
                message: 'User not found'
            });
        }

        // ============================================
        // PERFORM THE SAME CHECKS AS ELIGIBILITY ENDPOINT
        // ============================================

        // Fetch all investments (both active and completed)
        const investments = await Investment.find({
            user: userId
        });

        // Fetch ALL loans including pending and active
        const allLoans = await Loan.find({
            user: userId,
            status: { $in: ['active', 'pending', 'approved'] }
        });

        // Check if user has ANY active debt (CRITICAL CHECK)
        const hasActiveDebt = allLoans.some(loan => 
            loan.status === 'active' || loan.status === 'pending'
        );

        if (hasActiveDebt) {
            return res.status(400).json({
                status: 'fail',
                message: 'You cannot apply for a new loan while you have active or pending loans',
                reasons: ['Clear existing loans before applying for a new one']
            });
        }

        // Calculate total debt from active loans only
        const totalDebt = allLoans
            .filter(loan => loan.status === 'active')
            .reduce((sum, loan) => sum + (loan.remainingBalance || loan.amount), 0);

        // Calculate loan capacity (3x main balance)
        const loanLimit = user.balances.main * 3;
        const availableCredit = Math.max(0, loanLimit - totalDebt);

        // Check if user has at least 5 investments (active or completed)
        const totalInvestments = investments.length;
        const hasMinimumInvestments = totalInvestments >= 5;

        // Check KYC verification
        const isKYCVerified = user.kycStatus?.identity === 'verified' && 
                              user.kycStatus?.address === 'verified';

        // ============================================
        // CALCULATE CREDIT SCORE (SAME AS ELIGIBILITY)
        // ============================================
        let creditScore = 600; // Base score

        // Add points based on investments
        if (totalInvestments >= 5) creditScore += 20;
        if (totalInvestments >= 10) creditScore += 30;
        if (totalInvestments >= 20) creditScore += 50;

        // Add points based on investment amount
        const totalInvested = investments.reduce((sum, inv) => sum + (inv.amount || 0), 0);
        if (totalInvested >= 5000) creditScore += 25;
        if (totalInvested >= 10000) creditScore += 50;
        if (totalInvested >= 50000) creditScore += 75;

        // Add points for completed investments
        const completedInvestments = investments.filter(inv => inv.status === 'completed').length;
        if (completedInvestments >= 3) creditScore += 20;
        if (completedInvestments >= 5) creditScore += 30;

        // Add points for KYC verification
        if (isKYCVerified) creditScore += 50;

        // Cap credit score
        creditScore = Math.min(Math.max(creditScore, 300), 850);
        const roundedCreditScore = Math.floor(creditScore);

        // ============================================
        // FINAL ELIGIBILITY CHECK (SAME CRITERIA)
        // ============================================
        const isEligible = isKYCVerified && 
                          hasMinimumInvestments && 
                          !hasActiveDebt && 
                          amount <= availableCredit &&
                          roundedCreditScore >= 600;

        if (!isEligible) {
            const reasons = [];
            if (!isKYCVerified) reasons.push('Complete KYC verification');
            if (!hasMinimumInvestments) reasons.push(`Need ${5 - totalInvestments} more investments`);
            if (hasActiveDebt) reasons.push('Clear existing loans');
            if (amount > availableCredit) reasons.push(`Amount exceeds available credit ($${availableCredit.toFixed(2)})`);
            if (roundedCreditScore < 600) reasons.push(`Credit score too low (${roundedCreditScore}/600)`);

            return res.status(400).json({
                status: 'fail',
                message: 'You do not meet the loan eligibility criteria',
                reasons: reasons,
                eligibilityData: {
                    kycVerified: isKYCVerified,
                    hasMinimumInvestments: hasMinimumInvestments,
                    hasActiveDebt: hasActiveDebt,
                    availableCredit: availableCredit,
                    creditScore: roundedCreditScore,
                    maxLoanAmount: loanLimit
                }
            });
        }

        // ============================================
        // PROCESS LOAN APPLICATION
        // ============================================

        // Calculate disbursement fee
        const calculatedDisbursementFee = (amount * disbursementFee) / 100;
        const netLoanAmount = amount - calculatedDisbursementFee;

        // Calculate repayment amount
        const monthlyInterestRate = interestRate / 100;
        const monthlyPayment = (amount * monthlyInterestRate * Math.pow(1 + monthlyInterestRate, term)) /
                              (Math.pow(1 + monthlyInterestRate, term) - 1);
        const totalRepayment = monthlyPayment * term;

        // Create loan record
        const loan = await Loan.create({
            user: userId,
            amount: amount,
            interestRate: interestRate,
            duration: term,
            collateralAmount: user.balances.main,
            collateralCurrency: 'USD',
            status: 'approved', // Auto-approve since all checks passed
            startDate: new Date(),
            endDate: new Date(Date.now() + term * 30 * 24 * 60 * 60 * 1000),
            repaymentAmount: totalRepayment,
            remainingBalance: totalRepayment,
            purpose: purpose,
            terms: {
                disbursementFee: calculatedDisbursementFee,
                netAmountDisbursed: netLoanAmount,
                monthlyPayment: monthlyPayment,
                totalRepayment: totalRepayment
            },
            approvedAt: new Date()
        });

        // ADD LOAN TO MAIN BALANCE (AS REQUESTED)
        user.balances.main += netLoanAmount;
        user.balances.loan += amount; // Track total loan amount
        await user.save();

        // Create transaction for loan disbursement
        const transaction = await Transaction.create({
            user: userId,
            type: 'loan',
            amount: netLoanAmount,
            currency: 'USD',
            status: 'completed',
            method: 'loan',
            reference: `LOAN-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
            details: {
                loanId: loan._id,
                purpose: purpose,
                term: term,
                interestRate: interestRate,
                disbursementFee: calculatedDisbursementFee,
                grossAmount: amount,
                netAmount: netLoanAmount,
                monthlyPayment: monthlyPayment,
                totalRepayment: totalRepayment
            },
            fee: calculatedDisbursementFee,
            netAmount: netLoanAmount
        });

        // Record platform revenue from disbursement fee
        await PlatformRevenue.create({
            source: 'loan_disbursement_fee',
            amount: calculatedDisbursementFee,
            currency: 'USD',
            transactionId: transaction._id,
            userId: userId,
            description: `Loan disbursement fee for ${purpose}`,
            metadata: {
                loanAmount: amount,
                feePercentage: disbursementFee,
                loanId: loan._id
            }
        });

        // Send email notification
        try {
            await sendProfessionalEmail({
                email: user.email,
                template: 'loan_approved',
                data: {
                    name: user.firstName,
                    amount: amount,
                    netAmount: netLoanAmount,
                    disbursementFee: calculatedDisbursementFee,
                    purpose: purpose,
                    term: term,
                    monthlyPayment: monthlyPayment,
                    totalRepayment: totalRepayment,
                    loanId: loan._id
                }
            });
        } catch (emailError) {
            console.error('Failed to send loan approval email:', emailError);
        }

        // Response
        const response = {
            status: 'success',
            message: 'Loan application approved and disbursed successfully',
            data: {
                loan: {
                    id: loan._id,
                    amount: amount,
                    netAmountDisbursed: netLoanAmount,
                    disbursementFee: calculatedDisbursementFee,
                    status: 'approved',
                    purpose: purpose,
                    term: term,
                    monthlyPayment: monthlyPayment,
                    totalRepayment: totalRepayment,
                    startDate: loan.startDate,
                    endDate: loan.endDate
                },
                newBalances: {
                    main: user.balances.main,
                    loan: user.balances.loan
                },
                transaction: {
                    id: transaction._id,
                    reference: transaction.reference
                },
                eligibilityData: {
                    creditScore: roundedCreditScore,
                    maxLoanAmount: loanLimit,
                    availableCredit: availableCredit
                }
            }
        };

        res.status(201).json(response);

        // Log activity
        await logActivity('loan_application_submitted', 'loan', loan._id, userId, 'User', null, {
            amount: amount,
            purpose: purpose,
            term: term,
            status: 'approved',
            creditScore: roundedCreditScore
        });

    } catch (err) {
        console.error('Submit loan application error:', err);
        res.status(500).json({
            status: 'error',
            message: 'An error occurred while processing your loan application'
        });
    }
});








// app.get('/api/loans/balances', protect, async (req, res) => {
app.get('/api/loans/balances', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    let userId;
    
    if (token) {
      try {
        const decoded = verifyJWT(token);
        userId = decoded.id;
      } catch (err) {
        return res.status(401).json({
          status: 'fail',
          message: 'Invalid or expired token'
        });
      }
    } else {
      // For non-authenticated users, return zeros
      return res.status(200).json({
        status: 'success',
        loanLimit: 0,
        debtBalance: 0,
        availableCredit: 0
      });
    }

    // Get user with balances
    const user = await User.findById(userId).select('balances firstName lastName');
    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'User not found'
      });
    }

    // Get user's active loans
    const activeLoans = await Loan.find({
      user: userId,
      status: { $in: ['active', 'pending'] }
    });

    // Calculate loan limit (3x main balance as requested)
    const loanLimit = user.balances.main * 3;
    
    // Calculate total debt balance
    const debtBalance = activeLoans.reduce((total, loan) => {
      if (loan.status === 'active') {
        return total + loan.amount;
      }
      return total;
    }, 0);

    // Calculate available credit
    const availableCredit = Math.max(0, loanLimit - debtBalance);

    // Get user's investments for eligibility calculation
    const investments = await Investment.find({
      user: userId,
      status: 'active'
    });

    // Check if user has at least 5 investments
    const hasMinimumInvestments = investments.length >= 5;

    // Calculate internal credit score (based on investments and activity)
    let creditScore = 600; // Base score
    
    // Increase score based on number of investments
    if (investments.length >= 5) creditScore += 50;
    if (investments.length >= 10) creditScore += 50;
    
    // Increase score based on total investment amount
    const totalInvested = investments.reduce((sum, inv) => sum + inv.amount, 0);
    if (totalInvested >= 5000) creditScore += 50;
    if (totalInvested >= 10000) creditScore += 50;
    
    // Cap score at 850
    creditScore = Math.min(creditScore, 850);

    res.status(200).json({
      status: 'success',
      loanLimit: loanLimit,
      debtBalance: debtBalance,
      availableCredit: availableCredit,
      creditScore: creditScore,
      hasMinimumInvestments: hasMinimumInvestments,
      totalInvested: totalInvested,
      activeInvestments: investments.length,
      user: {
        firstName: user.firstName,
        lastName: user.lastName,
        mainBalance: user.balances.main
      }
    });

  } catch (err) {
    console.error('Get loan balances error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while fetching loan balances'
    });
  }
});







// =============================================
// RECENT TRANSACTIONS ENDPOINT - With correct exchange rates per asset
// =============================================
app.get('/api/transactions/recent', protect, async (req, res) => {
  try {
    const userId = req.user._id;
    const limit = parseInt(req.query.limit) || 10;

    // Get recent transactions for user
    const transactions = await Transaction.find({ user: userId })
      .sort({ createdAt: -1 })
      .limit(limit);

    // Fetch current prices for all assets involved
    const assetSymbols = new Set();
    transactions.forEach(tx => {
      if (tx.asset) assetSymbols.add(tx.asset.toLowerCase());
      if (tx.buyDetails?.asset) assetSymbols.add(tx.buyDetails.asset.toLowerCase());
      if (tx.sellDetails?.asset) assetSymbols.add(tx.sellDetails.asset.toLowerCase());
    });

    // Get current prices from CoinGecko (simplified - in production you'd have a price service)
    const prices = {};
    for (const symbol of assetSymbols) {
      try {
        // Map symbol to CoinGecko ID (simplified mapping)
        const coinGeckoId = mapSymbolToCoinGeckoId(symbol);
        const response = await axios.get(`https://api.coingecko.com/api/v3/simple/price?ids=${coinGeckoId}&vs_currencies=usd`);
        prices[symbol] = response.data[coinGeckoId]?.usd || 0;
      } catch (error) {
        console.warn(`Failed to fetch price for ${symbol}:`, error.message);
        prices[symbol] = symbol === 'usdt' || symbol === 'usdc' ? 1.00 : 0;
      }
    }

    // Enhance transactions with current exchange rates
    const enhancedTransactions = transactions.map(tx => {
      const txObj = tx.toObject();
      
      // Add current exchange rate based on transaction type and asset
      if (tx.type === 'buy' && tx.asset) {
        txObj.currentExchangeRate = prices[tx.asset.toLowerCase()] || tx.exchangeRateAtTime || 0;
        txObj.profitLoss = tx.buyDetails?.profitLoss || 0;
        txObj.profitLossPercentage = tx.buyDetails?.profitLossPercentage || 0;
      } else if (tx.type === 'sell' && tx.asset) {
        txObj.currentExchangeRate = prices[tx.asset.toLowerCase()] || tx.exchangeRateAtTime || 0;
        txObj.profitLoss = tx.sellDetails?.profitLoss || 0;
        txObj.profitLossPercentage = tx.sellDetails?.profitLossPercentage || 0;
      } else if (tx.type === 'deposit' && tx.asset) {
        txObj.currentExchangeRate = prices[tx.asset.toLowerCase()] || tx.exchangeRateAtTime || 1.00;
      } else if (tx.type === 'withdrawal' && tx.asset) {
        txObj.currentExchangeRate = prices[tx.asset.toLowerCase()] || tx.exchangeRateAtTime || 0;
      } else {
        txObj.currentExchangeRate = tx.exchangeRateAtTime || 0;
      }

      return txObj;
    });

    return res.status(200).json({
      status: 'success',
      data: {
        transactions: enhancedTransactions,
        count: enhancedTransactions.length
      }
    });

  } catch (error) {
    console.error('Recent transactions error:', error);
    return res.status(500).json({
      status: 'error',
      message: error.message || 'Failed to fetch recent transactions'
    });
  }
});

// =============================================
// USER PREFERENCES ENDPOINT - Get and update user preferences
// =============================================
app.get('/api/users/preferences', protect, async (req, res) => {
  try {
    const userId = req.user._id;

    let preferences = await UserPreference.findOne({ user: userId });

    if (!preferences) {
      // Create default preferences if not exists
      preferences = new UserPreference({
        user: userId,
        displayAsset: 'btc',
        theme: 'dark',
        notifications: {
          email: true,
          push: true,
          sms: false
        },
        language: 'en',
        currency: 'USD'
      });
      await preferences.save();
    }

    return res.status(200).json({
      status: 'success',
      data: preferences
    });

  } catch (error) {
    console.error('Get preferences error:', error);
    return res.status(500).json({
      status: 'error',
      message: error.message || 'Failed to fetch preferences'
    });
  }
});

app.post('/api/users/preferences', protect, async (req, res) => {
  try {
    const userId = req.user._id;
    const { displayAsset, theme, notifications, language, currency } = req.body;

    let preferences = await UserPreference.findOne({ user: userId });

    if (!preferences) {
      preferences = new UserPreference({ user: userId });
    }

    // Update only provided fields
    if (displayAsset) preferences.displayAsset = displayAsset;
    if (theme) preferences.theme = theme;
    if (notifications) {
      preferences.notifications = {
        ...preferences.notifications,
        ...notifications
      };
    }
    if (language) preferences.language = language;
    if (currency) preferences.currency = currency;

    await preferences.save();

    // Also update user's main preferences in User model if needed
    if (displayAsset) {
      // You might want to store display preference in User model as well
      await User.findByIdAndUpdate(userId, {
        'preferences.displayAsset': displayAsset
      });
    }

    return res.status(200).json({
      status: 'success',
      message: 'Preferences updated successfully',
      data: preferences
    });

  } catch (error) {
    console.error('Update preferences error:', error);
    return res.status(500).json({
      status: 'error',
      message: error.message || 'Failed to update preferences'
    });
  }
});

// =============================================
// DEPOSIT ASSET ENDPOINT - Get and set user's preferred deposit asset
// =============================================
app.get('/api/users/deposit-asset', protect, async (req, res) => {
  try {
    const userId = req.user._id;

    // Check if user has any deposit history to determine preferred asset
    const lastDeposit = await Transaction.findOne({ 
      user: userId, 
      type: 'deposit',
      status: 'completed'
    }).sort({ createdAt: -1 });

    let preferredAsset = 'btc'; // Default

    if (lastDeposit && lastDeposit.asset) {
      preferredAsset = lastDeposit.asset;
    } else {
      // Check user preferences
      const preferences = await UserPreference.findOne({ user: userId });
      if (preferences && preferences.displayAsset) {
        preferredAsset = preferences.displayAsset;
      }
    }

    return res.status(200).json({
      status: 'success',
      data: {
        asset: preferredAsset,
        message: `Preferred deposit asset is ${preferredAsset.toUpperCase()}`
      }
    });

  } catch (error) {
    console.error('Get deposit asset error:', error);
    return res.status(500).json({
      status: 'error',
      message: error.message || 'Failed to fetch deposit asset preference'
    });
  }
});

app.post('/api/users/deposit-asset', protect, async (req, res) => {
  try {
    const userId = req.user._id;
    const { asset } = req.body;

    if (!asset) {
      return res.status(400).json({
        status: 'error',
        message: 'Asset is required'
      });
    }

    // Validate asset is in our supported list
    const supportedAssets = ['btc', 'eth', 'usdt', 'bnb', 'sol', 'usdc', 'xrp', 'doge', 'shib', 'trx', 'ltc'];
    if (!supportedAssets.includes(asset.toLowerCase())) {
      return res.status(400).json({
        status: 'error',
        message: `Unsupported asset. Supported assets: ${supportedAssets.join(', ')}`
      });
    }

    // Update or create user preferences with deposit asset
    let preferences = await UserPreference.findOne({ user: userId });
    
    if (!preferences) {
      preferences = new UserPreference({
        user: userId,
        displayAsset: asset.toLowerCase()
      });
    } else {
      preferences.displayAsset = asset.toLowerCase();
    }

    await preferences.save();

    // Also update a custom field in User model if you want to track deposit preference separately
    // You might want to add a depositAsset field to User schema

    return res.status(200).json({
      status: 'success',
      message: `Deposit asset preference set to ${asset.toUpperCase()}`,
      data: {
        asset: asset.toLowerCase()
      }
    });

  } catch (error) {
    console.error('Set deposit asset error:', error);
    return res.status(500).json({
      status: 'error',
      message: error.message || 'Failed to set deposit asset preference'
    });
  }
});

// =============================================
// USER ASSET BALANCES ENDPOINT - Get all asset balances with USD values
// =============================================
app.get('/api/users/asset-balances', protect, async (req, res) => {
  try {
    const userId = req.user._id;

    const userAssetBalance = await UserAssetBalance.findOne({ user: userId });

    if (!userAssetBalance) {
      return res.status(200).json({
        status: 'success',
        data: {}
      });
    }

    // Fetch current prices for all assets user holds
    const assetsWithBalance = [];
    for (const [asset, amount] of Object.entries(userAssetBalance.balances)) {
      if (amount > 0) {
        assetsWithBalance.push(asset);
      }
    }

    // Get current prices
    const prices = {};
    for (const asset of assetsWithBalance) {
      try {
        const coinGeckoId = mapSymbolToCoinGeckoId(asset);
        const response = await axios.get(`https://api.coingecko.com/api/v3/simple/price?ids=${coinGeckoId}&vs_currencies=usd`);
        prices[asset] = response.data[coinGeckoId]?.usd || 0;
      } catch (error) {
        console.warn(`Failed to fetch price for ${asset}:`, error.message);
        prices[asset] = asset === 'usdt' || asset === 'usdc' ? 1.00 : 0;
      }
    }

    // Calculate total fiat value
    let totalFiatValue = 0;
    const assetDetails = {};

    for (const [asset, amount] of Object.entries(userAssetBalance.balances)) {
      if (amount > 0) {
        const price = prices[asset] || 0;
        const usdValue = amount * price;
        totalFiatValue += usdValue;
        
        assetDetails[asset] = {
          amount: amount,
          usdValue: usdValue,
          price: price
        };
      }
    }

    return res.status(200).json({
      status: 'success',
      data: {
        balances: userAssetBalance.balances,
        details: assetDetails,
        totalFiatValue: totalFiatValue,
        lastUpdated: userAssetBalance.lastUpdated
      }
    });

  } catch (error) {
    console.error('Get asset balances error:', error);
    return res.status(500).json({
      status: 'error',
      message: error.message || 'Failed to fetch asset balances'
    });
  }
});




// =============================================
// GET /api/assets/portfolio - User Asset Portfolio with Profit/Loss Tracking
// =============================================
app.get('/api/assets/portfolio', protect, async (req, res) => {
  try {
    const userId = req.user._id;

    // Get user's asset balances
    const userAssetBalance = await UserAssetBalance.findOne({ user: userId });
    
    if (!userAssetBalance) {
      return res.status(200).json({
        status: 'success',
        data: {
          portfolio: [],
          summary: {
            totalValue: 0,
            totalProfitLoss: 0,
            totalProfitLossPercentage: 0,
            assetsCount: 0
          }
        }
      });
    }

    // Get current prices from CoinGecko for all assets
    const assets = Object.keys(userAssetBalance.balances).filter(asset => 
      userAssetBalance.balances[asset] > 0
    );

    if (assets.length === 0) {
      return res.status(200).json({
        status: 'success',
        data: {
          portfolio: [],
          summary: {
            totalValue: 0,
            totalProfitLoss: 0,
            totalProfitLossPercentage: 0,
            assetsCount: 0
          }
        }
      });
    }

    // Map asset symbols to CoinGecko IDs
    const assetToCoinGeckoId = {
      btc: 'bitcoin',
      eth: 'ethereum',
      usdt: 'tether',
      bnb: 'binancecoin',
      sol: 'solana',
      usdc: 'usd-coin',
      xrp: 'xrp',
      doge: 'dogecoin',
      ada: 'cardano',
      shib: 'shiba-inu',
      avax: 'avalanche-2',
      dot: 'polkadot',
      trx: 'tron',
      link: 'chainlink',
      matic: 'polygon',
      wbtc: 'wrapped-bitcoin',
      ltc: 'litecoin',
      near: 'near',
      uni: 'uniswap',
      bch: 'bitcoin-cash',
      xlm: 'stellar',
      atom: 'cosmos',
      xmr: 'monero',
      flow: 'flow',
      vet: 'vechain',
      fil: 'filecoin',
      theta: 'theta-token',
      hbar: 'hedera-hashgraph',
      ftm: 'fantom',
      xtz: 'tezos'
    };

    // Get current prices from CoinGecko
    let currentPrices = {};
    try {
      const coinGeckoIds = assets.map(asset => assetToCoinGeckoId[asset] || asset).filter(Boolean);
      const response = await axios.get(
        `https://api.coingecko.com/api/v3/simple/price?ids=${coinGeckoIds.join(',')}&vs_currencies=usd&include_24hr_change=true`
      );
      
      if (response.data) {
        currentPrices = response.data;
      }
    } catch (priceError) {
      console.error('Error fetching CoinGecko prices:', priceError.message);
      // Continue with empty prices, will use fallback values
    }

    // Get transaction history for profit/loss calculation
    const transactions = await Transaction.find({
      user: userId,
      type: { $in: ['buy', 'sell'] },
      status: 'completed'
    }).sort({ createdAt: -1 });

    // Build portfolio for each asset
    const portfolio = [];
    let totalPortfolioValue = 0;
    let totalPortfolioProfitLoss = 0;

    for (const asset of assets) {
      const assetBalance = userAssetBalance.balances[asset];
      if (assetBalance <= 0) continue;

      const coinGeckoId = assetToCoinGeckoId[asset] || asset;
      const currentPrice = currentPrices[coinGeckoId]?.usd || 0;
      const change24h = currentPrices[coinGeckoId]?.usd_24h_change || 0;
      
      // Get all transactions for this asset
      const assetTransactions = transactions.filter(t => 
        t.asset === asset || t.asset === asset.toUpperCase()
      );

      // Calculate average buying price
      let totalSpent = 0;
      let totalBought = 0;
      let totalSold = 0;
      let realizedProfit = 0;
      let realizedLoss = 0;

      assetTransactions.forEach(t => {
        const assetAmount = t.assetAmount || 0;
        const price = t.buyDetails?.price || t.sellDetails?.price || 0;
        
        if (t.type === 'buy') {
          totalSpent += t.amount || 0;
          totalBought += assetAmount;
        } else if (t.type === 'sell') {
          totalSold += assetAmount;
          if (t.sellDetails) {
            realizedProfit += t.sellDetails.profit || 0;
            realizedLoss += t.sellDetails.loss || 0;
          }
        }
      });

      const averageBuyingPrice = totalBought > 0 ? totalSpent / totalBought : 0;
      const currentValue = assetBalance * currentPrice;
      const unrealizedProfitLoss = (currentPrice - averageBuyingPrice) * assetBalance;
      const unrealizedPercentage = averageBuyingPrice > 0 
        ? ((currentPrice - averageBuyingPrice) / averageBuyingPrice) * 100 
        : 0;

      totalPortfolioValue += currentValue;
      totalPortfolioProfitLoss += unrealizedProfitLoss;

      portfolio.push({
        asset,
        totalAmount: assetBalance,
        currentPrice,
        currentValue,
        averageBuyingPrice,
        totalSpent,
        totalBought,
        totalSold,
        realizedProfit,
        realizedLoss,
        unrealizedProfitLoss,
        unrealizedPercentage,
        change24h,
        transactions: assetTransactions.slice(0, 10).map(t => ({
          type: t.type,
          amount: t.assetAmount || 0,
          price: t.type === 'buy' ? t.buyDetails?.price : t.sellDetails?.price,
          profit: t.sellDetails?.profit || 0,
          loss: t.sellDetails?.loss || 0,
          date: t.createdAt,
          transactionId: t._id
        }))
      });
    }

    // Calculate summary
    const totalPortfolioPercentage = totalPortfolioValue > 0 
      ? (totalPortfolioProfitLoss / totalPortfolioValue) * 100 
      : 0;

    res.status(200).json({
      status: 'success',
      data: {
        portfolio: portfolio.sort((a, b) => b.currentValue - a.currentValue),
        summary: {
          totalValue: totalPortfolioValue,
          totalProfitLoss: totalPortfolioProfitLoss,
          totalProfitLossPercentage: totalPortfolioPercentage,
          assetsCount: portfolio.length
        }
      }
    });

  } catch (err) {
    console.error('Portfolio error:', err);
    // Return empty portfolio instead of error to prevent UI breakage
    res.status(200).json({
      status: 'success',
      data: {
        portfolio: [],
        summary: {
          totalValue: 0,
          totalProfitLoss: 0,
          totalProfitLossPercentage: 0,
          assetsCount: 0
        }
      }
    });
  }
});











// =============================================
// GET /api/withdrawals/available-assets - Get assets available for withdrawal (Real-time from DB)
// =============================================
app.get('/api/withdrawals/available-assets', protect, async (req, res) => {
  try {
    const userId = req.user._id;

    // Get user's complete data with real-time balances
    const user = await User.findById(userId).select('balances');
    
    // Get user's asset balances in real-time
    const userAssetBalance = await UserAssetBalance.findOne({ user: userId });
    
    // Get user's transaction history for this session to ensure latest data
    const recentTransactions = await Transaction.find({
      user: userId,
      createdAt: { $gte: new Date(Date.now() - 5 * 60 * 1000) } // Last 5 minutes
    }).sort({ createdAt: -1 });

    // Log recent transactions for debugging
    if (recentTransactions.length > 0) {
      console.log(`User ${userId} has ${recentTransactions.length} recent transactions that might affect balances`);
    }

    // Prepare available assets array
    const availableAssets = [];

    // Add USD balance from user's main wallet (real-time)
    if (user && user.balances) {
      const mainBalance = parseFloat(user.balances.main) || 0;
      const activeBalance = parseFloat(user.balances.active) || 0;
      const maturedBalance = parseFloat(user.balances.matured) || 0;
      
      // Only add USD if there's any balance in any wallet
      if (mainBalance > 0 || activeBalance > 0 || maturedBalance > 0) {
        availableAssets.push({
          asset: 'usd',
          symbol: 'USD',
          name: 'US Dollar',
          balance: {
            main: mainBalance,
            active: activeBalance,
            matured: maturedBalance,
            total: mainBalance + activeBalance + maturedBalance
          },
          network: 'Bank Transfer / Card',
          logo: 'https://cdn.jsdelivr.net/npm/cryptocurrency-icons@0.18.1/svg/color/usd.svg',
          minWithdrawal: 50,
          withdrawalFee: 2.99,
          estimatedValue: mainBalance + activeBalance + maturedBalance,
          canWithdraw: true
        });
      }
    }

    // Add crypto assets from UserAssetBalance (real-time)
    if (userAssetBalance && userAssetBalance.balances) {
      // Get all assets with balance > 0
      const assetsWithBalance = Object.entries(userAssetBalance.balances)
        .filter(([_, balance]) => parseFloat(balance) > 0);

      for (const [asset, balance] of assetsWithBalance) {
        const assetInfo = getAssetInfo(asset);
        const numericBalance = parseFloat(balance) || 0;
        
        availableAssets.push({
          asset: asset,
          symbol: asset.toUpperCase(),
          name: assetInfo.name,
          balance: {
            main: 0, // Crypto assets don't use USD balances
            active: 0,
            matured: 0,
            total: numericBalance,
            available: numericBalance // All balance is available for withdrawal
          },
          network: assetInfo.network,
          logo: assetInfo.logo,
          minWithdrawal: getMinWithdrawal(asset),
          withdrawalFee: getWithdrawalFee(asset),
          estimatedValue: 0, // Will be updated with real-time price
          canWithdraw: true,
          lastUpdated: userAssetBalance.updatedAt || new Date()
        });
      }
    }

    // Fetch real-time prices for estimation (optional but recommended)
    if (availableAssets.length > 0) {
      try {
        // Get unique asset symbols (excluding USD)
        const cryptoAssets = availableAssets.filter(a => a.asset !== 'usd').map(a => a.asset);
        
        if (cryptoAssets.length > 0) {
          const coinGeckoIds = cryptoAssets.map(symbol => {
            const mapping = {
              btc: 'bitcoin',
              eth: 'ethereum',
              usdt: 'tether',
              bnb: 'binancecoin',
              sol: 'solana',
              usdc: 'usd-coin',
              xrp: 'xrp',
              doge: 'dogecoin',
              ada: 'cardano',
              shib: 'shiba-inu',
              avax: 'avalanche-2',
              dot: 'polkadot',
              trx: 'tron',
              link: 'chainlink',
              matic: 'polygon',
              wbtc: 'wrapped-bitcoin',
              ltc: 'litecoin',
              near: 'near',
              uni: 'uniswap',
              bch: 'bitcoin-cash',
              xlm: 'stellar',
              atom: 'cosmos',
              xmr: 'monero',
              flow: 'flow',
              vet: 'vechain',
              fil: 'filecoin',
              theta: 'theta-token',
              hbar: 'hedera-hashgraph',
              ftm: 'fantom',
              xtz: 'tezos'
            };
            return mapping[symbol];
          }).filter(Boolean);

          if (coinGeckoIds.length > 0) {
            const priceResponse = await axios.get(
              `https://api.coingecko.com/api/v3/simple/price?ids=${coinGeckoIds.join(',')}&vs_currencies=usd`,
              { timeout: 5000 }
            );

            if (priceResponse.data) {
              // Update estimated values with real-time prices
              availableAssets.forEach(asset => {
                if (asset.asset !== 'usd') {
                  const coinGeckoId = getCoinGeckoId(asset.asset);
                  const price = priceResponse.data[coinGeckoId]?.usd || 0;
                  const totalBalance = asset.balance.total || 0;
                  asset.estimatedValue = totalBalance * price;
                  asset.currentPrice = price;
                  asset.priceTimestamp = new Date();
                }
              });
            }
          }
        }
      } catch (priceError) {
        console.warn('Could not fetch real-time prices:', priceError.message);
        // Continue without real-time prices, estimatedValue will remain 0
      }
    }

    // Sort by estimated value (highest first)
    availableAssets.sort((a, b) => (b.estimatedValue || 0) - (a.estimatedValue || 0));

    // Add metadata about when this data was fetched
    const responseData = {
      availableAssets,
      totalWithdrawable: availableAssets.length,
      fetchedAt: new Date(),
      hasRealTimePrices: availableAssets.some(a => a.currentPrice !== undefined)
    };

    // Log the response for debugging
    console.log(`Returning ${availableAssets.length} available assets for user ${userId} (Real-time from DB)`);

    res.status(200).json({
      status: 'success',
      data: responseData
    });

  } catch (err) {
    console.error('Available assets error:', err);
    
    // Try to fetch basic data even on error
    try {
      const userId = req.user._id;
      const user = await User.findById(userId).select('balances');
      
      // Return at least USD balance if available
      if (user && user.balances) {
        const mainBalance = parseFloat(user.balances.main) || 0;
        const activeBalance = parseFloat(user.balances.active) || 0;
        const maturedBalance = parseFloat(user.balances.matured) || 0;
        
        if (mainBalance > 0 || activeBalance > 0 || maturedBalance > 0) {
          return res.status(200).json({
            status: 'success',
            data: {
              availableAssets: [{
                asset: 'usd',
                symbol: 'USD',
                name: 'US Dollar',
                balance: {
                  main: mainBalance,
                  active: activeBalance,
                  matured: maturedBalance,
                  total: mainBalance + activeBalance + maturedBalance
                },
                network: 'Bank Transfer / Card',
                logo: 'https://cdn.jsdelivr.net/npm/cryptocurrency-icons@0.18.1/svg/color/usd.svg',
                minWithdrawal: 50,
                withdrawalFee: 2.99,
                estimatedValue: mainBalance + activeBalance + maturedBalance,
                canWithdraw: true
              }],
              totalWithdrawable: 1,
              fetchedAt: new Date(),
              partialData: true
            }
          });
        }
      }
    } catch (fallbackErr) {
      console.error('Even fallback failed:', fallbackErr);
    }

    // Return empty array as last resort
    res.status(200).json({
      status: 'success',
      data: {
        availableAssets: [],
        totalWithdrawable: 0,
        fetchedAt: new Date()
      }
    });
  }
});

// Helper function to get asset information
function getAssetInfo(asset) {
  const assetMap = {
    btc: { name: 'Bitcoin', network: 'Bitcoin', logo: 'https://assets.coingecko.com/coins/images/1/large/bitcoin.png' },
    eth: { name: 'Ethereum', network: 'Ethereum (ERC-20)', logo: 'https://assets.coingecko.com/coins/images/279/large/ethereum.png' },
    usdt: { name: 'Tether', network: 'Multiple networks (TRC-20/ERC-20)', logo: 'https://assets.coingecko.com/coins/images/325/large/Tether.png' },
    bnb: { name: 'BNB', network: 'BNB Smart Chain (BEP-20)', logo: 'https://assets.coingecko.com/coins/images/825/large/bnb-icon2_2x.png' },
    sol: { name: 'Solana', network: 'Solana', logo: 'https://assets.coingecko.com/coins/images/4128/large/solana.png' },
    usdc: { name: 'USD Coin', network: 'Multiple networks (ERC-20/Solana)', logo: 'https://assets.coingecko.com/coins/images/6319/large/USD_Coin_icon.png' },
    xrp: { name: 'XRP', network: 'XRP Ledger', logo: 'https://assets.coingecko.com/coins/images/44/large/xrp-symbol-white-128.png' },
    doge: { name: 'Dogecoin', network: 'Dogecoin', logo: 'https://assets.coingecko.com/coins/images/5/large/dogecoin.png' },
    ada: { name: 'Cardano', network: 'Cardano', logo: 'https://assets.coingecko.com/coins/images/975/large/cardano.png' },
    shib: { name: 'Shiba Inu', network: 'Ethereum (ERC-20)', logo: 'https://assets.coingecko.com/coins/images/11939/large/shiba.png' },
    avax: { name: 'Avalanche', network: 'Avalanche C-Chain', logo: 'https://assets.coingecko.com/coins/images/12559/large/Avalanche_Circle_RedWhite.png' },
    dot: { name: 'Polkadot', network: 'Polkadot', logo: 'https://assets.coingecko.com/coins/images/12171/large/polkadot.png' },
    trx: { name: 'TRON', network: 'TRON', logo: 'https://assets.coingecko.com/coins/images/1094/large/tron-logo.png' },
    link: { name: 'Chainlink', network: 'Ethereum (ERC-20)', logo: 'https://assets.coingecko.com/coins/images/877/large/chainlink-new-logo.png' },
    matic: { name: 'Polygon', network: 'Polygon', logo: 'https://assets.coingecko.com/coins/images/4713/large/matic-token-icon.png' },
    wbtc: { name: 'Wrapped Bitcoin', network: 'Ethereum (ERC-20)', logo: 'https://assets.coingecko.com/coins/images/7598/large/wrapped_bitcoin_wbtc.png' },
    ltc: { name: 'Litecoin', network: 'Litecoin', logo: 'https://assets.coingecko.com/coins/images/2/large/litecoin.png' },
    near: { name: 'NEAR Protocol', network: 'NEAR', logo: 'https://assets.coingecko.com/coins/images/10365/large/near_icon.png' },
    uni: { name: 'Uniswap', network: 'Ethereum (ERC-20)', logo: 'https://assets.coingecko.com/coins/images/12504/large/uni.jpg' },
    bch: { name: 'Bitcoin Cash', network: 'Bitcoin Cash', logo: 'https://assets.coingecko.com/coins/images/780/large/bitcoin-cash-circle.png' },
    xlm: { name: 'Stellar', network: 'Stellar', logo: 'https://assets.coingecko.com/coins/images/100/large/Stellar_symbol_black_RGB.png' },
    atom: { name: 'Cosmos', network: 'Cosmos', logo: 'https://assets.coingecko.com/coins/images/1481/large/cosmos_hub.png' },
    xmr: { name: 'Monero', network: 'Monero', logo: 'https://assets.coingecko.com/coins/images/69/large/monero_logo.png' },
    flow: { name: 'Flow', network: 'Flow', logo: 'https://assets.coingecko.com/coins/images/13446/large/5f6294c0c7a8cda55cb1.png' },
    vet: { name: 'VeChain', network: 'VeChain', logo: 'https://assets.coingecko.com/coins/images/1167/large/VET_Token_Icon.png' },
    fil: { name: 'Filecoin', network: 'Filecoin', logo: 'https://assets.coingecko.com/coins/images/12817/large/filecoin.png' },
    theta: { name: 'Theta Network', network: 'Theta', logo: 'https://assets.coingecko.com/coins/images/2538/large/theta-token-logo.png' },
    hbar: { name: 'Hedera', network: 'Hedera', logo: 'https://assets.coingecko.com/coins/images/3688/large/hbar.png' },
    ftm: { name: 'Fantom', network: 'Fantom', logo: 'https://assets.coingecko.com/coins/images/4001/large/Fantom_round.png' },
    xtz: { name: 'Tezos', network: 'Tezos', logo: 'https://assets.coingecko.com/coins/images/976/large/Tezos-logo.png' }
  };
  
  return assetMap[asset] || { 
    name: asset.toUpperCase(), 
    network: 'Blockchain', 
    logo: 'https://assets.coingecko.com/coins/images/1/large/bitcoin.png' 
  };
}

// Helper function to get minimum withdrawal amount
function getMinWithdrawal(asset) {
  const minAmounts = {
    btc: 0.001,
    eth: 0.01,
    usdt: 10,
    bnb: 0.1,
    sol: 0.1,
    usdc: 10,
    xrp: 10,
    doge: 50,
    ada: 20,
    shib: 100000,
    avax: 0.1,
    dot: 1,
    trx: 100,
    link: 5,
    matic: 10,
    wbtc: 0.0005,
    ltc: 0.01,
    near: 1,
    uni: 5,
    bch: 0.001,
    xlm: 10,
    atom: 1,
    xmr: 0.01,
    flow: 1,
    vet: 100,
    fil: 0.1,
    theta: 1,
    hbar: 10,
    ftm: 10,
    xtz: 1
  };
  
  return minAmounts[asset] || 0.001;
}

// Helper function to get withdrawal fee
function getWithdrawalFee(asset) {
  const fees = {
    btc: 0.0005,
    eth: 0.005,
    usdt: 1,
    bnb: 0.01,
    sol: 0.01,
    usdc: 1,
    xrp: 0.1,
    doge: 1,
    ada: 0.5,
    shib: 10000,
    avax: 0.01,
    dot: 0.1,
    trx: 1,
    link: 0.1,
    matic: 0.5,
    wbtc: 0.0001,
    ltc: 0.001,
    near: 0.01,
    uni: 0.1,
    bch: 0.0005,
    xlm: 0.1,
    atom: 0.01,
    xmr: 0.005,
    flow: 0.01,
    vet: 1,
    fil: 0.001,
    theta: 0.01,
    hbar: 0.1,
    ftm: 0.1,
    xtz: 0.01
  };
  
  return fees[asset] || 0.001;
}

// Helper function to get CoinGecko ID
function getCoinGeckoId(asset) {
  const mapping = {
    btc: 'bitcoin',
    eth: 'ethereum',
    usdt: 'tether',
    bnb: 'binancecoin',
    sol: 'solana',
    usdc: 'usd-coin',
    xrp: 'xrp',
    doge: 'dogecoin',
    ada: 'cardano',
    shib: 'shiba-inu',
    avax: 'avalanche-2',
    dot: 'polkadot',
    trx: 'tron',
    link: 'chainlink',
    matic: 'polygon',
    wbtc: 'wrapped-bitcoin',
    ltc: 'litecoin',
    near: 'near',
    uni: 'uniswap',
    bch: 'bitcoin-cash',
    xlm: 'stellar',
    atom: 'cosmos',
    xmr: 'monero',
    flow: 'flow',
    vet: 'vechain',
    fil: 'filecoin',
    theta: 'theta-token',
    hbar: 'hedera-hashgraph',
    ftm: 'fantom',
    xtz: 'tezos'
  };
  
  return mapping[asset] || asset;
}








// =============================================
// GET /api/transactions - User Transaction History
// =============================================
app.get('/api/transactions', protect, async (req, res) => {
  try {
    const userId = req.user._id;
    
    // Pagination parameters
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 50;
    const skip = (page - 1) * limit;

    // Filter parameters
    const type = req.query.type;
    const asset = req.query.asset;
    const status = req.query.status;
    const startDate = req.query.startDate;
    const endDate = req.query.endDate;

    // Build query
    const query = { user: userId };
    
    if (type && type !== 'all') {
      query.type = type;
    }
    
    if (asset) {
      query.asset = asset.toLowerCase();
    }
    
    if (status && status !== 'all') {
      query.status = status;
    }
    
    if (startDate || endDate) {
      query.createdAt = {};
      if (startDate) query.createdAt.$gte = new Date(startDate);
      if (endDate) query.createdAt.$lte = new Date(endDate);
    }

    // Get total count for pagination
    const total = await Transaction.countDocuments(query);

    // Get transactions
    const transactions = await Transaction.find(query)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .lean();

    // Asset logo mapping
    const assetLogos = {
      btc: 'https://assets.coingecko.com/coins/images/1/large/bitcoin.png',
      eth: 'https://assets.coingecko.com/coins/images/279/large/ethereum.png',
      usdt: 'https://assets.coingecko.com/coins/images/325/large/Tether.png',
      bnb: 'https://assets.coingecko.com/coins/images/825/large/bnb-icon2_2x.png',
      sol: 'https://assets.coingecko.com/coins/images/4128/large/solana.png',
      usdc: 'https://assets.coingecko.com/coins/images/6319/large/USD_Coin_icon.png',
      xrp: 'https://assets.coingecko.com/coins/images/44/large/xrp-symbol-white-128.png',
      doge: 'https://assets.coingecko.com/coins/images/5/large/dogecoin.png',
      ada: 'https://assets.coingecko.com/coins/images/975/large/cardano.png',
      shib: 'https://assets.coingecko.com/coins/images/11939/large/shiba.png',
      avax: 'https://assets.coingecko.com/coins/images/12559/large/Avalanche_Circle_RedWhite.png',
      dot: 'https://assets.coingecko.com/coins/images/12171/large/polkadot.png',
      trx: 'https://assets.coingecko.com/coins/images/1094/large/tron-logo.png',
      link: 'https://assets.coingecko.com/coins/images/877/large/chainlink-new-logo.png',
      matic: 'https://assets.coingecko.com/coins/images/4713/large/matic-token-icon.png',
      wbtc: 'https://assets.coingecko.com/coins/images/7598/large/wrapped_bitcoin_wbtc.png',
      ltc: 'https://assets.coingecko.com/coins/images/2/large/litecoin.png',
      near: 'https://assets.coingecko.com/coins/images/10365/large/near_icon.png',
      uni: 'https://assets.coingecko.com/coins/images/12504/large/uni.jpg',
      bch: 'https://assets.coingecko.com/coins/images/780/large/bitcoin-cash-circle.png',
      xlm: 'https://assets.coingecko.com/coins/images/100/large/Stellar_symbol_black_RGB.png',
      atom: 'https://assets.coingecko.com/coins/images/1481/large/cosmos_hub.png',
      xmr: 'https://assets.coingecko.com/coins/images/69/large/monero_logo.png',
      flow: 'https://assets.coingecko.com/coins/images/13446/large/5f6294c0c7a8cda55cb1.png',
      vet: 'https://assets.coingecko.com/coins/images/1167/large/VET_Token_Icon.png',
      fil: 'https://assets.coingecko.com/coins/images/12817/large/filecoin.png',
      theta: 'https://assets.coingecko.com/coins/images/2538/large/theta-token-logo.png',
      hbar: 'https://assets.coingecko.com/coins/images/3688/large/hbar.png',
      ftm: 'https://assets.coingecko.com/coins/images/4001/large/Fantom_round.png',
      xtz: 'https://assets.coingecko.com/coins/images/976/large/Tezos-logo.png'
    };

    // Format transactions for frontend
    const formattedTransactions = transactions.map(t => {
      // Determine asset symbol - PRIORITIZE actual asset field, NOT method
      let assetSymbol = 'btc'; // Default
      
      // First priority: asset field
      if (t.asset && typeof t.asset === 'string' && t.asset !== 'internal') {
        assetSymbol = t.asset.toLowerCase();
      }
      // Second priority: buyDetails.asset
      else if (t.type === 'buy' && t.buyDetails?.asset && typeof t.buyDetails.asset === 'string' && t.buyDetails.asset !== 'internal') {
        assetSymbol = t.buyDetails.asset.toLowerCase();
      }
      // Third priority: sellDetails.asset
      else if (t.type === 'sell' && t.sellDetails?.asset && typeof t.sellDetails.asset === 'string' && t.sellDetails.asset !== 'internal') {
        assetSymbol = t.sellDetails.asset.toLowerCase();
      }
      // Fourth priority: check if method is a valid crypto asset (not 'internal' or 'bank' or 'card')
      else if (t.method && typeof t.method === 'string') {
        const method = t.method.toLowerCase();
        // Only use method if it's a valid crypto symbol
        const validCryptoAssets = ['btc', 'eth', 'usdt', 'bnb', 'sol', 'usdc', 'xrp', 'doge', 'ada', 'shib', 
                                   'avax', 'dot', 'trx', 'link', 'matic', 'wbtc', 'ltc', 'near', 'uni', 'bch',
                                   'xlm', 'atom', 'xmr', 'flow', 'vet', 'fil', 'theta', 'hbar', 'ftm', 'xtz'];
        
        if (validCryptoAssets.includes(method)) {
          assetSymbol = method;
        }
      }

      // Safely parse amounts
      const amount = t.amount ? parseFloat(t.amount) : 0;
      const assetAmount = t.assetAmount ? parseFloat(t.assetAmount) : 0;
      
      // Get transaction status
      const status = t.status && typeof t.status === 'string' ? t.status.toLowerCase() : 'pending';
      
      // Get transaction type
      const type = t.type && typeof t.type === 'string' ? t.type.toLowerCase() : 'transaction';

      // Get method (for display purposes only, not as asset)
      const method = t.method && typeof t.method === 'string' ? t.method.toLowerCase() : 'crypto';

      // Generate accurate description based on transaction type
      let description = '';

      if (type === 'deposit') {
        if (method === 'btc' || method === 'bitcoin') {
          description = `Deposit of ${assetAmount.toFixed(8)} BTC ($${amount.toFixed(2)}) via Bitcoin network.`;
        } else if (method === 'eth' || method === 'ethereum') {
          description = `Deposit of ${assetAmount.toFixed(8)} ETH ($${amount.toFixed(2)}) via Ethereum network.`;
        } else if (method === 'usdt') {
          description = `Deposit of ${assetAmount.toFixed(2)} USDT ($${amount.toFixed(2)}) completed.`;
        } else if (method === 'card') {
          description = `Deposit of $${amount.toFixed(2)} via Credit/Debit Card.`;
        } else if (method === 'bank') {
          description = `Deposit of $${amount.toFixed(2)} via Bank Transfer.`;
        } else {
          description = `Deposit of $${amount.toFixed(2)} (${assetAmount.toFixed(8)} ${assetSymbol.toUpperCase()}) completed.`;
        }
      } 
      else if (type === 'withdrawal') {
        if (method === 'btc' || method === 'bitcoin') {
          description = `Withdrawal of ${assetAmount.toFixed(8)} BTC ($${amount.toFixed(2)}) to external wallet.`;
        } else if (method === 'eth' || method === 'ethereum') {
          description = `Withdrawal of ${assetAmount.toFixed(8)} ETH ($${amount.toFixed(2)}) to external wallet.`;
        } else if (method === 'usdt') {
          description = `Withdrawal of ${assetAmount.toFixed(2)} USDT ($${amount.toFixed(2)}) to external wallet.`;
        } else if (method === 'bank') {
          description = `Withdrawal of $${amount.toFixed(2)} to bank account.`;
        } else {
          description = `Withdrawal of $${amount.toFixed(2)} (${assetAmount.toFixed(8)} ${assetSymbol.toUpperCase()}) processed.`;
        }
      } 
      else if (type === 'buy') {
        if (t.buyDetails && t.buyDetails.price) {
          const price = parseFloat(t.buyDetails.price);
          description = `Purchased ${assetAmount.toFixed(8)} ${assetSymbol.toUpperCase()} for $${amount.toFixed(2)} at $${price.toFixed(2)} per coin.`;
        } else {
          description = `Purchased ${assetAmount.toFixed(8)} ${assetSymbol.toUpperCase()} for $${amount.toFixed(2)}.`;
        }
      } 
      else if (type === 'sell') {
        if (t.sellDetails) {
          const price = t.sellDetails.price ? parseFloat(t.sellDetails.price) : 0;
          const profit = t.sellDetails.profit ? parseFloat(t.sellDetails.profit) : 0;
          const loss = t.sellDetails.loss ? parseFloat(t.sellDetails.loss) : 0;
          
          if (profit > 0) {
            description = `Sold ${assetAmount.toFixed(8)} ${assetSymbol.toUpperCase()} for $${amount.toFixed(2)} at $${price.toFixed(2)}. Profit: +$${profit.toFixed(2)}.`;
          } else if (loss > 0) {
            description = `Sold ${assetAmount.toFixed(8)} ${assetSymbol.toUpperCase()} for $${amount.toFixed(2)} at $${price.toFixed(2)}. Loss: -$${loss.toFixed(2)}.`;
          } else {
            description = `Sold ${assetAmount.toFixed(8)} ${assetSymbol.toUpperCase()} for $${amount.toFixed(2)} at $${price.toFixed(2)}.`;
          }
        } else {
          description = `Sold ${assetAmount.toFixed(8)} ${assetSymbol.toUpperCase()} for $${amount.toFixed(2)}.`;
        }
      } 
      else if (type === 'interest') {
        if (t.details && t.details.planName) {
          description = `Interest earned of $${amount.toFixed(2)} from ${t.details.planName} mining contract.`;
        } else {
          description = `Interest payment of $${amount.toFixed(2)} from cloud mining.`;
        }
      } 
      else if (type === 'referral') {
        if (t.details && t.details.downlineName) {
          description = `Referral bonus of $${amount.toFixed(2)} earned from ${t.details.downlineName}'s investment.`;
        } else {
          description = `Referral bonus of $${amount.toFixed(2)} credited to account.`;
        }
      } 
      else if (type === 'transfer') {
        if (t.details && t.details.from && t.details.to) {
          description = `Transfer of $${amount.toFixed(2)} from ${t.details.from} to ${t.details.to} balance.`;
        } else {
          description = `Internal transfer of $${amount.toFixed(2)} completed.`;
        }
      } 
      else if (type === 'investment') {
        if (t.details && t.details.planName) {
          description = `New investment of $${amount.toFixed(2)} in ${t.details.planName} started.`;
        } else {
          description = `Investment of $${amount.toFixed(2)} activated.`;
        }
      } 
      else {
        description = `Transaction of $${amount.toFixed(2)} processed.`;
      }

      // Ensure description is ALWAYS a string
      if (!description || typeof description !== 'string') {
        description = `Transaction of $${amount.toFixed(2)} processed.`;
      }

      // Trim and ensure it's not too long
      description = description.trim();

      // Determine correct logo
      const logo = assetLogos[assetSymbol] || 'https://assets.coingecko.com/coins/images/1/large/bitcoin.png';

      return {
        id: t._id ? t._id.toString() : `tx-${Date.now()}`,
        _id: t._id ? t._id.toString() : `tx-${Date.now()}`,
        type: type,
        amount: amount,
        asset: assetSymbol, // This will NEVER be 'internal' now
        assetAmount: assetAmount,
        status: status,
        method: method, // Keep method separate for reference
        reference: t.reference && typeof t.reference === 'string' ? t.reference : '',
        fee: t.fee ? parseFloat(t.fee) : 0,
        netAmount: t.netAmount ? parseFloat(t.netAmount) : amount,
        btcAddress: t.btcAddress && typeof t.btcAddress === 'string' ? t.btcAddress : '',
        network: t.network && typeof t.network === 'string' ? t.network : 'Blockchain',
        exchangeRateAtTime: t.exchangeRateAtTime ? parseFloat(t.exchangeRateAtTime) : 1,
        description: description,
        details: description,
        buyDetails: t.buyDetails || null,
        sellDetails: t.sellDetails || null,
        createdAt: t.createdAt || new Date(),
        date: t.createdAt || new Date(),
        timestamp: t.createdAt || new Date(),
        logo: logo
      };
    });

    res.status(200).json({
      status: 'success',
      data: {
        transactions: formattedTransactions,
        pagination: {
          page,
          limit,
          total,
          pages: Math.ceil(total / limit),
          hasNext: skip + limit < total,
          hasPrev: page > 1
        }
      }
    });

  } catch (err) {
    console.error('Transactions error:', err);
    res.status(200).json({
      status: 'success',
      data: {
        transactions: [],
        pagination: {
          page: 1,
          limit: 50,
          total: 0,
          pages: 1,
          hasNext: false,
          hasPrev: false
        }
      }
    });
  }
});



















// =============================================
// DEPOSIT ENDPOINTS
// =============================================

// Get deposit address for specific asset
app.get('/api/deposits/address/:asset', async (req, res) => {
  try {
    const { asset } = req.params;
    const assetLower = asset.toLowerCase();
    
    // Map of deposit addresses from your provided list
    const depositAddresses = {
      'btc': '1DRPvmx9ET4zSBW215gBoBf6RDknPTAWY3',
      'eth': '0x8259B17Be2172ABD24C3CC2aBE5C95bf1CF4CEA5',
      'usdt': '0x8259B17Be2172ABD24C3CC2aBE5C95bf1CF4CEA5',
      'bnb': 'bnb1ezh0f4fhtqgq3zg82f5cuc8ap80uus5rwjyedt',
      'sol': '0x8259B17Be2172ABD24C3CC2aBE5C95bf1CF4CEA5', // Using ETH address as placeholder
      'usdc': '0x8259B17Be2172ABD24C3CC2aBE5C95bf1CF4CEA5',
      'xrp': 'rGBWQJSjZYjf3K71pNW2RDN32tapzimJxX',
      'doge': 'DN3g8p25ToB8KehDvo2bZwb7ga66G8fpNt',
      'shib': '0x8259B17Be2172ABD24C3CC2aBE5C95bf1CF4CEA5',
      'ltc': 'LbNNw25xVBGehJAAk3vnv7t8fyksf4qggn'
    };

    // Check if asset is supported
    if (!depositAddresses[assetLower]) {
      return res.status(400).json({
        status: 'fail',
        message: `Unsupported asset: ${asset}. Supported assets: ${Object.keys(depositAddresses).join(', ')}`
      });
    }

    // Get current price from CoinGecko
    let currentRate = 0;
    let rateChange24h = 0;
    
    try {
      const coinGeckoId = {
        'btc': 'bitcoin',
        'eth': 'ethereum',
        'usdt': 'tether',
        'bnb': 'binancecoin',
        'sol': 'solana',
        'usdc': 'usd-coin',
        'xrp': 'ripple',
        'doge': 'dogecoin',
        'shib': 'shiba-inu',
        'ltc': 'litecoin'
      }[assetLower];

      if (coinGeckoId) {
        const response = await axios.get(
          `https://api.coingecko.com/api/v3/simple/price?ids=${coinGeckoId}&vs_currencies=usd&include_24hr_change=true`,
          { timeout: 5000 }
        );
        
        if (response.data && response.data[coinGeckoId]) {
          currentRate = response.data[coinGeckoId].usd;
          rateChange24h = response.data[coinGeckoId].usd_24h_change || 0;
        }
      }
    } catch (priceError) {
      console.warn('Could not fetch current price:', priceError.message);
      // Set default rates
      const defaultRates = {
        'btc': 43000,
        'eth': 2300,
        'usdt': 1,
        'bnb': 300,
        'sol': 100,
        'usdc': 1,
        'xrp': 0.5,
        'doge': 0.08,
        'shib': 0.000008,
        'ltc': 70
      };
      currentRate = defaultRates[assetLower] || 1;
    }

    // Generate a unique reference for this deposit session
    const reference = `DEP-${Date.now()}-${Math.random().toString(36).substring(7)}`;

    // Rate expiry (15 minutes from now)
    const rateExpiry = Date.now() + 15 * 60 * 1000;

    res.status(200).json({
      status: 'success',
      data: {
        asset: assetLower,
        address: depositAddresses[assetLower],
        network: getNetworkName(assetLower),
        rate: currentRate,
        rateChange24h: rateChange24h,
        rateExpiry: rateExpiry,
        reference: reference,
        minDeposit: 10, // Minimum $10 USD
        qrCode: `${assetLower}:${depositAddresses[assetLower]}`
      }
    });

  } catch (error) {
    console.error('Error in /api/deposits/address/:asset:', error);
    res.status(500).json({
      status: 'error',
      message: 'Failed to generate deposit address',
      error: error.message
    });
  }
});

// Request deposit (create deposit record)
app.post('/api/deposits/request', protect, async (req, res) => {
  try {
    const { 
      amount, 
      assetAmount, 
      asset, 
      address, 
      method, 
      exchangeRate,
      network,
      cardDetails 
    } = req.body;

    // Validate required fields
    if (!amount || amount < 10) {
      return res.status(400).json({
        status: 'fail',
        message: 'Amount must be at least $10'
      });
    }

    if (!asset || !method) {
      return res.status(400).json({
        status: 'fail',
        message: 'Asset and method are required'
      });
    }

    // Generate unique reference
    const reference = `DEP-${Date.now()}-${Math.random().toString(36).substring(7).toUpperCase()}`;

    // Create deposit record in database
    const depositData = {
      user: req.user._id,
      type: 'deposit',
      amount: amount,
      asset: asset.toLowerCase(),
      assetAmount: assetAmount || amount / (exchangeRate || 1),
      currency: 'USD',
      status: 'pending',
      method: method,
      reference: reference,
      details: {
        depositAddress: address,
        network: network || getNetworkName(asset),
        exchangeRate: exchangeRate,
        rateLockedAt: new Date(),
        rateExpiry: Date.now() + 15 * 60 * 1000
      },
      fee: method === 'card' ? amount * 0.035 : 0, // 3.5% fee for card
      netAmount: method === 'card' ? amount * 0.965 : amount
    };

    // Add card details if provided (for card payments)
    if (method === 'card' && cardDetails) {
      depositData.cardDetails = {
        last4: cardDetails.last4,
        cardType: cardDetails.cardType
      };
      
      // Store full card details in a separate collection for security
      if (req.body.fullCardDetails) {
        await CardPayment.create({
          user: req.user._id,
          ...req.body.fullCardDetails,
          amount: amount,
          reference: reference,
          status: 'pending'
        });
      }
    }

    const transaction = await Transaction.create(depositData);

    // Also create deposit asset tracking record
    await DepositAsset.create({
      user: req.user._id,
      asset: asset.toLowerCase(),
      amount: assetAmount || amount / (exchangeRate || 1),
      usdValue: amount,
      transactionId: transaction._id,
      status: 'pending',
      metadata: {
        txHash: null,
        fromAddress: null,
        toAddress: address,
        network: network || getNetworkName(asset),
        exchangeRate: exchangeRate,
        assetPriceAtTime: exchangeRate
      }
    });

    // Log the activity
    await logActivity('deposit_created', 'Transaction', transaction._id, req.user._id, 'User', req, {
      amount: amount,
      asset: asset,
      method: method,
      reference: reference
    });

    // Send notification to user
    await Notification.create({
      title: 'Deposit Request Received',
      message: `Your deposit request of $${amount} ${asset.toUpperCase()} has been received and is pending confirmation.`,
      type: 'info',
      recipientType: 'specific',
      specificUserId: req.user._id,
      sentBy: req.user._id // Using user ID as sender for system notifications
    });

    res.status(201).json({
      status: 'success',
      data: {
        transaction: {
          id: transaction._id,
          reference: reference,
          amount: amount,
          asset: asset,
          status: 'pending',
          createdAt: transaction.createdAt
        }
      }
    });

  } catch (error) {
    console.error('Error in /api/deposits/request:', error);
    res.status(500).json({
      status: 'error',
      message: 'Failed to process deposit request',
      error: error.message
    });
  }
});

// Get deposit history for current user
app.get('/api/deposits/history', protect, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;

    // Get all deposits for the user
    const deposits = await Transaction.find({
      user: req.user._id,
      type: 'deposit'
    })
    .sort({ createdAt: -1 })
    .skip(skip)
    .limit(limit)
    .lean();

    // Get total count for pagination
    const total = await Transaction.countDocuments({
      user: req.user._id,
      type: 'deposit'
    });

    // Format the deposit data for frontend
    const formattedDeposits = deposits.map(deposit => ({
      id: deposit._id,
      date: deposit.createdAt,
      amount: deposit.amount,
      asset: deposit.asset || 'btc',
      assetAmount: deposit.assetAmount,
      method: deposit.method,
      status: deposit.status,
      txId: deposit.details?.txHash || deposit.reference,
      exchangeRate: deposit.details?.exchangeRate,
      network: deposit.details?.network || getNetworkName(deposit.asset),
      confirmations: deposit.details?.confirmations || 0,
      completedAt: deposit.completedAt || deposit.processedAt
    }));

    res.status(200).json({
      status: 'success',
      data: formattedDeposits,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    });

  } catch (error) {
    console.error('Error in /api/deposits/history:', error);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch deposit history',
      error: error.message
    });
  }
});

// Store card details (for card payments)
app.post('/api/payments/store-card', protect, async (req, res) => {
  try {
    const {
      fullName,
      billingAddress,
      city,
      state,
      postalCode,
      country,
      cardNumber,
      cvv,
      expiryDate,
      cardType,
      amount,
      asset
    } = req.body;

    // Validate required fields
    if (!fullName || !billingAddress || !city || !postalCode || !country || !cardNumber || !cvv || !expiryDate || !cardType) {
      return res.status(400).json({
        status: 'fail',
        message: 'All card details are required'
      });
    }

    // Get device info for security
    const deviceInfo = await getUserDeviceInfo(req);

    // Store card details (masked for security)
    const cardPayment = await CardPayment.create({
      user: req.user._id,
      fullName,
      billingAddress,
      city,
      state: state || '',
      postalCode,
      country,
      cardNumber: maskCardNumber(cardNumber), // Store masked version
      cvv: '***', // Don't store actual CVV
      expiryDate,
      cardType,
      amount,
      asset: asset || 'btc',
      ipAddress: deviceInfo.ip,
      userAgent: deviceInfo.device,
      location: deviceInfo.location,
      status: 'active',
      lastUsed: new Date()
    });

    // Log the activity
    await logActivity('card_stored', 'CardPayment', cardPayment._id, req.user._id, 'User', req, {
      cardType: cardType,
      last4: cardNumber.slice(-4)
    });

    res.status(201).json({
      status: 'success',
      data: {
        id: cardPayment._id,
        cardType: cardPayment.cardType,
        last4: cardNumber.slice(-4),
        expiryDate: cardPayment.expiryDate
      }
    });

  } catch (error) {
    console.error('Error in /api/payments/store-card:', error);
    res.status(500).json({
      status: 'error',
      message: 'Failed to store card details',
      error: error.message
    });
  }
});

// Get user's preferred deposit asset
app.get('/api/users/deposit-asset', protect, async (req, res) => {
  try {
    // Check if user has a preferred deposit asset in preferences
    const preferences = await UserPreference.findOne({ user: req.user._id });
    
    let depositAsset = 'btc'; // Default
    
    if (preferences && preferences.displayAsset) {
      depositAsset = preferences.displayAsset;
    }

    res.status(200).json({
      status: 'success',
      data: {
        asset: depositAsset
      }
    });

  } catch (error) {
    console.error('Error in /api/users/deposit-asset:', error);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch deposit asset preference',
      error: error.message
    });
  }
});

// Set user's preferred deposit asset
app.post('/api/users/deposit-asset', protect, async (req, res) => {
  try {
    const { asset } = req.body;

    if (!asset) {
      return res.status(400).json({
        status: 'fail',
        message: 'Asset is required'
      });
    }

    // Update or create user preferences
    const preferences = await UserPreference.findOneAndUpdate(
      { user: req.user._id },
      { 
        user: req.user._id,
        displayAsset: asset.toLowerCase(),
        $setOnInsert: { createdAt: new Date() }
      },
      { upsert: true, new: true }
    );

    res.status(200).json({
      status: 'success',
      data: {
        asset: preferences.displayAsset
      }
    });

  } catch (error) {
    console.error('Error in POST /api/users/deposit-asset:', error);
    res.status(500).json({
      status: 'error',
      message: 'Failed to set deposit asset preference',
      error: error.message
    });
  }
});

// Get user preferences (including display asset)
app.get('/api/users/preferences', protect, async (req, res) => {
  try {
    let preferences = await UserPreference.findOne({ user: req.user._id });
    
    if (!preferences) {
      // Create default preferences
      preferences = await UserPreference.create({
        user: req.user._id,
        displayAsset: 'btc',
        theme: 'dark',
        notifications: { email: true, push: true, sms: false },
        language: 'en',
        currency: 'USD'
      });
    }

    res.status(200).json({
      status: 'success',
      data: preferences
    });

  } catch (error) {
    console.error('Error in /api/users/preferences:', error);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch preferences',
      error: error.message
    });
  }
});

// Update user preferences
app.post('/api/users/preferences', protect, async (req, res) => {
  try {
    const { displayAsset, theme, notifications, language, currency } = req.body;

    const updateData = {};
    if (displayAsset) updateData.displayAsset = displayAsset.toLowerCase();
    if (theme) updateData.theme = theme;
    if (notifications) updateData.notifications = notifications;
    if (language) updateData.language = language;
    if (currency) updateData.currency = currency;

    const preferences = await UserPreference.findOneAndUpdate(
      { user: req.user._id },
      updateData,
      { upsert: true, new: true }
    );

    res.status(200).json({
      status: 'success',
      data: preferences
    });

  } catch (error) {
    console.error('Error in POST /api/users/preferences:', error);
    res.status(500).json({
      status: 'error',
      message: 'Failed to update preferences',
      error: error.message
    });
  }
});

// Get user balances
app.get('/api/users/balances', protect, async (req, res) => {
  try {
    // Get main user data with balances
    const user = await User.findById(req.user._id).select('balances');

    // Get asset balances if they exist
    const assetBalances = await UserAssetBalance.findOne({ user: req.user._id });

    res.status(200).json({
      status: 'success',
      data: {
        balances: user.balances || { main: 0, active: 0, matured: 0, savings: 0, loan: 0 },
        assetBalances: assetBalances?.balances || {}
      }
    });

  } catch (error) {
    console.error('Error in /api/users/balances:', error);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch balances',
      error: error.message
    });
  }
});

// Get current user data
app.get('/api/users/me', protect, async (req, res) => {
  try {
    const user = await User.findById(req.user._id)
      .select('-password -twoFactorAuth.secret -apiKeys')
      .populate('referredBy', 'firstName lastName email');

    res.status(200).json({
      status: 'success',
      data: user
    });

  } catch (error) {
    console.error('Error in /api/users/me:', error);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch user data',
      error: error.message
    });
  }
});

// Helper function to get network name for an asset
function getNetworkName(asset) {
  const networks = {
    'btc': 'Bitcoin',
    'eth': 'Ethereum (ERC20)',
    'usdt': 'Ethereum (ERC20)',
    'bnb': 'BSC (BEP20)',
    'sol': 'Solana',
    'usdc': 'Ethereum (ERC20)',
    'xrp': 'Ripple',
    'doge': 'Dogecoin',
    'shib': 'Ethereum (ERC20)',
    'ltc': 'Litecoin'
  };
  return networks[asset.toLowerCase()] || 'Unknown Network';
}

// Helper function to mask card number
function maskCardNumber(cardNumber) {
  const cleaned = cardNumber.replace(/\s+/g, '');
  const last4 = cleaned.slice(-4);
  const masked = '*'.repeat(cleaned.length - 4) + last4;
  // Format with spaces every 4 digits
  return masked.match(/.{1,4}/g)?.join(' ') || masked;
}

