require('dotenv').config()
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const RedisStore = require('rate-limit-redis');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss-clean');
const hpp = require('hpp');
const csrf = require('csurf');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const { OAuth2Client } = require('google-auth-library');
const Redis = require('ioredis');
const moment = require('moment');
const validator = require('validator');
const { body, validationResult } = require('express-validator');
const axios = require('axios');
const speakeasy = require('speakeasy');
const { v4: uuidv4 } = require('uuid');
const WebSocket = require('ws');
const OpenAI = require('openai');
// Initialize Express app
const app = express();
const { createServer } = require('http');
const { Server } = require('socket.io');
app.set('trust proxy', 1);
// FIXED Helmet Configuration - Remove unsafe Cross-Origin-Opener-Policy
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://apis.google.com"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      imgSrc: ["'self'", "data:", "https://www.google-analytics.com"],
      connectSrc: ["'self'", "https://api.ipinfo.io", "https://website-backendd-1.onrender.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      objectSrc: ["'none'"],
      frameSrc: ["'self'", "https://accounts.google.com"] // Added for Google OAuth
    }
  },
  crossOriginOpenerPolicy: { policy: "unsafe-none" } // FIXED: This resolves the window.postMessage block
}));


app.use(cors({
  origin: ['https://www.bithashcapital.live', 'https://website-backendd-tzep.onrender.com', 'https://bithash-rental.vercel.app'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token', 'X-Rate-Limit']
}));




app.use((req, res, next) => {
  // Only for Google Fonts and static routes - don't override CORS headers
  if (req.url.includes('/api/plans') || req.url.includes('/api/stats')) {
    res.setHeader('Cache-Control', 'public, max-age=300');
  }
  next();
});




app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(cookieParser());
app.use(mongoSanitize());
app.use(xss());
app.use(hpp());

// Redis connection with enhanced settings for autoscaling (MOVE THIS UP)
const redis = new Redis({
  host: process.env.REDIS_HOST || 'redis-14450.c276.us-east-1-2.ec2.redns.redis-cloud.com',
  port: process.env.REDIS_PORT || 14450,
  password: process.env.REDIS_PASSWORD || 'qjXgsg0YrsLaSumlEW9HkIZbvLjXEwXR',
  retryStrategy: (times) => {
    const delay = Math.min(times * 50, 2000);
    return delay;
  },
  maxRetriesPerRequest: 3,
  enableReadyCheck: true,
  lazyConnect: false,
  keepAlive: 10000, // Keep Redis connections alive
  connectTimeout: 10000
});

redis.on('error', (err) => {
  console.error('Redis error:', err);
});

redis.on('connect', () => {
  console.log('Redis connected successfully');
});

// Helper function to get real client IP from request
const getRealClientIP = (req) => {
  // Check X-Forwarded-For header first (this is what Render uses)
  const forwardedFor = req.headers['x-forwarded-for'];
  if (forwardedFor) {
    // Get the first IP in the list (the real client IP)
    return forwardedFor.split(',')[0].trim();
  }
  
  // Fallback to other headers or remote address
  return req.ip || 
         req.connection?.remoteAddress || 
         req.socket?.remoteAddress || 
         req.connection?.socket?.remoteAddress ||
         '0.0.0.0';
};

// Rate limiting with Redis store (required for autoscaling)
const apiLimiter = rateLimit({
  store: new RedisStore({
    client: redis,
    prefix: 'rl:api:',
    sendCommand: (...args) => redis.call(...args)
  }),
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 1000,
  message: 'Too many requests from this IP, please try again later',
  keyGenerator: (req) => {
    return getRealClientIP(req);
  }
});

const authLimiter = rateLimit({
  store: new RedisStore({
    client: redis,
    prefix: 'rl:auth:',
    sendCommand: (...args) => redis.call(...args)
  }),
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 200,
  message: 'Too many login attempts, please try again later',
  keyGenerator: (req) => {
    return getRealClientIP(req);
  }
});

app.use('/api', apiLimiter);
app.use('/api/login', authLimiter);
app.use('/api/signup', authLimiter);
app.use('/api/auth/forgot-password', authLimiter);

// Health check endpoint required for Render autoscaling
app.get('/health', (req, res) => {
  res.status(200).json({ 
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

app.get('/api/health', (req, res) => {
  res.status(200).json({ 
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

// Database connection with enhanced settings for autoscaling
mongoose.connect(process.env.MONGODB_URI || 'mongodb+srv://elvismwangike:JFJmHvP4ktikRYDC@cluster0.vm6hrog.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0', {
  autoIndex: true,
  connectTimeoutMS: 30000,
  socketTimeoutMS: 30000,
  maxPoolSize: 50, // Connection pool for each instance
  minPoolSize: 5,  // Minimum connections to keep alive
  maxIdleTimeMS: 10000, // Close idle connections
  waitQueueTimeoutMS: 5000, // How long to wait for a connection
  retryWrites: true,
  retryReads: true
})
.then(() => console.log('MongoDB connected successfully'))
.catch(err => {
  console.error('MongoDB connection error:', err);
  process.exit(1);
});

const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,
  port: process.env.EMAIL_PORT,
  secure: process.env.EMAIL_SECURE === 'true',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  },
  tls: {
    rejectUnauthorized: false
  },
  pool: true,
  maxConnections: 5,
  maxMessages: 100
});


// Google OAuth client with enhanced configuration
const googleClient = new OAuth2Client({
  clientId: process.env.GOOGLE_CLIENT_ID || '634814462335-9o4t8q95c4orcsd9sijjl52374g6vm85.apps.googleusercontent.com',
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  redirectUri: process.env.GOOGLE_REDIRECT_URI
});

// JWT configuration with stronger security
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '7200s'; // 2 hours in seconds
const JWT_COOKIE_EXPIRES = process.env.JWT_COOKIE_EXPIRES || 0.083; // 2 hours in days (2/24)

// Enhanced database models with full indexes and validation
const UserSchema = new mongoose.Schema({
  firstName: { type: String, required: [true, 'First name is required'], trim: true, maxlength: [50, 'First name cannot be longer than 50 characters'] },
  lastName: { type: String, required: [true, 'Last name is required'], trim: true, maxlength: [50, 'Last name cannot be longer than 50 characters'] },
  email: { 
    type: String, 
    required: [true, 'Email is required'], 
    unique: true, 
    lowercase: true, 
    validate: [validator.isEmail, 'Please provide a valid email'],
    index: true
  },
  phone: { type: String, trim: true, validate: [validator.isMobilePhone, 'Please provide a valid phone number'] },
  country: { type: String, trim: true },
  city: { type: String, trim: true },
  address: {
    street: { type: String, trim: true },
    city: { type: String, trim: true },
    state: { type: String, trim: true },
    postalCode: { type: String, trim: true },
    country: { type: String, trim: true }
  },
  password: { type: String, select: false, minlength: [8, 'Password must be at least 8 characters'] },
  passwordChangedAt: Date,
  passwordResetToken: String,
  passwordResetExpires: Date,
  googleId: { type: String, index: true },
  isVerified: { type: Boolean, default: false },
  status: { type: String, enum: ['active', 'suspended', 'banned'], default: 'active', index: true },
  kycStatus: {
    identity: { type: String, enum: ['pending', 'verified', 'rejected', 'not-submitted'], default: 'not-submitted' },
    address: { type: String, enum: ['pending', 'verified', 'rejected', 'not-submitted'], default: 'not-submitted' },
    facial: { type: String, enum: ['pending', 'verified', 'rejected', 'not-submitted'], default: 'not-submitted' }
  },
  kycDocuments: {
    identityFront: { type: String },
    identityBack: { type: String },
    proofOfAddress: { type: String },
    selfie: { type: String }
  },
  twoFactorAuth: {
    enabled: { type: Boolean, default: false },
    secret: { type: String, select: false }
  },
  balances: {
    main: { type: Number, default: 0, min: [0, 'Balance cannot be negative'] },
    active: { type: Number, default: 0, min: [0, 'Balance cannot be negative'] },
    matured: { type: Number, default: 0, min: [0, 'Balance cannot be negative'] },
    savings: { type: Number, default: 0, min: [0, 'Balance cannot be negative'] },
    loan: { type: Number, default: 0, min: [0, 'Balance cannot be negative'] }
  },
  referralCode: { type: String, unique: true, index: true },
  referredBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', index: true },
  apiKeys: [{
    name: { type: String, required: true },
    key: { type: String, required: true, select: false },
    permissions: [{ type: String }],
    expiresAt: { type: Date },
    isActive: { type: Boolean, default: true }
  }],
  lastLogin: { type: Date },
  loginHistory: [{
    ip: { type: String },
    device: { type: String },
    location: { type: String },
    timestamp: { type: Date, default: Date.now }
  }],
  notifications: [{
    title: { type: String, required: true },
    message: { type: String, required: true },
    type: { type: String, enum: ['info', 'warning', 'error', 'success'], default: 'info' },
    isRead: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now }
  }],
  preferences: {
    notifications: {
      email: { type: Boolean, default: true },
      sms: { type: Boolean, default: false },
      push: { type: Boolean, default: true }
    },
    theme: { type: String, enum: ['light', 'dark'], default: 'dark' }
  }
}, { 
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

UserSchema.virtual('fullName').get(function() {
  return `${this.firstName} ${this.lastName}`;
});













// Add to UserSchema
UserSchema.add({
  referralStats: {
    totalReferrals: { type: Number, default: 0 },
    totalEarnings: { type: Number, default: 0 },
    availableBalance: { type: Number, default: 0 },
    withdrawn: { type: Number, default: 0 },
    referralTier: { type: Number, default: 1 }, // 1-5 based on performance
  },
  referralHistory: [{
    referredUser: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    amount: Number,
    percentage: Number,
    level: Number, // 1 for direct, 2 for indirect, etc.
    date: { type: Date, default: Date.now },
    status: { type: String, enum: ['pending', 'available', 'withdrawn'], default: 'pending' }
  }]
});

// Add to UserSchema
UserSchema.add({
  downlineStats: {
    totalDownlines: { type: Number, default: 0 },
    activeDownlines: { type: Number, default: 0 },
    totalCommissionEarned: { type: Number, default: 0 },
    thisMonthCommission: { type: Number, default: 0 }
  }
});

UserSchema.index({ email: 1 });
UserSchema.index({ status: 1 });
UserSchema.index({ 'kycStatus.identity': 1, 'kycStatus.address': 1, 'kycStatus.facial': 1 });
UserSchema.index({ referredBy: 1 });
UserSchema.index({ createdAt: -1 });

const User = mongoose.model('User', UserSchema);



const TranslationSchema = new mongoose.Schema({
  language: {
    type: String,
    required: [true, 'Language code is required'],
    index: true
  },
  key: {
    type: String,
    required: [true, 'Translation key is required'],
    index: true
  },
  value: {
    type: String,
    required: [true, 'Translation value is required']
  },
  namespace: {
    type: String,
    default: 'common',
    index: true
  },
  context: {
    type: String,
    default: 'general'
  },
  isActive: {
    type: Boolean,
    default: true
  }
}, {
  timestamps: true
});

// Compound index for efficient lookups
TranslationSchema.index({ language: 1, key: 1, namespace: 1 }, { unique: true });
TranslationSchema.index({ language: 1, namespace: 1 });
TranslationSchema.index({ isActive: 1 });

const Translation = mongoose.model('Translation', TranslationSchema);


// Downline Relationship Schema
const DownlineRelationshipSchema = new mongoose.Schema({
  upline: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: [true, 'Upline user is required'],
    index: true
  },
  downline: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: [true, 'Downline user is required'],
    index: true
  },
  commissionPercentage: {
    type: Number,
    default: 5,
    min: [0, 'Commission percentage cannot be negative'],
    max: [50, 'Commission percentage cannot exceed 50%']
  },
  commissionRounds: {
    type: Number,
    default: 3,
    min: [1, 'At least 1 commission round required'],
    max: [10, 'Maximum 10 commission rounds allowed']
  },
  remainingRounds: {
    type: Number,
    default: 3
  },
  totalCommissionEarned: {
    type: Number,
    default: 0
  },
  status: {
    type: String,
    enum: ['active', 'inactive', 'completed'],
    default: 'active'
  },
  assignedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Admin',
    required: true
  },
  assignedAt: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: true
});

// Index to ensure unique downline relationships
DownlineRelationshipSchema.index({ downline: 1 }, { unique: true });
DownlineRelationshipSchema.index({ upline: 1, downline: 1 }, { unique: true });
DownlineRelationshipSchema.index({ status: 1 });

// Virtual for relationship description
DownlineRelationshipSchema.virtual('relationshipDescription').get(function() {
  return `${this.downline} is downline of ${this.upline} with ${this.commissionPercentage}% commission`;
});

const DownlineRelationship = mongoose.model('DownlineRelationship', DownlineRelationshipSchema);

// Commission History Schema
const CommissionHistorySchema = new mongoose.Schema({
  upline: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  downline: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  investment: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Investment',
    required: true,
    index: true
  },
  investmentAmount: {
    type: Number,
    required: true,
    min: 0
  },
  commissionPercentage: {
    type: Number,
    required: true,
    min: 0,
    max: 50
  },
  commissionAmount: {
    type: Number,
    required: true,
    min: 0
  },
  roundNumber: {
    type: Number,
    required: true,
    min: 1,
    max: 10
  },
  status: {
    type: String,
    enum: ['pending', 'paid', 'cancelled'],
    default: 'paid'
  },
  paidAt: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: true
});

CommissionHistorySchema.index({ upline: 1, createdAt: -1 });
CommissionHistorySchema.index({ downline: 1, createdAt: -1 });
CommissionHistorySchema.index({ investment: 1 });

const CommissionHistory = mongoose.model('CommissionHistory', CommissionHistorySchema);

// Commission Settings Schema
const CommissionSettingsSchema = new mongoose.Schema({
  commissionPercentage: {
    type: Number,
    default: 5,
    min: [0, 'Commission percentage cannot be negative'],
    max: [50, 'Commission percentage cannot exceed 50%']
  },
  commissionRounds: {
    type: Number,
    default: 3,
    min: [1, 'At least 1 commission round required'],
    max: [10, 'Maximum 10 commission rounds allowed']
  },
  isActive: {
    type: Boolean,
    default: true
  },
  updatedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Admin',
    required: true
  }
}, {
  timestamps: true
});

const CommissionSettings = mongoose.model('CommissionSettings', CommissionSettingsSchema);





// Enhanced User Log Schema - Comprehensive Activity Tracking
const UserLogSchema = new mongoose.Schema({
  // Core User Information
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  username: {
    type: String,
    required: true,
    index: true
  },
  email: {
    type: String,
    required: true,
    index: true
  },
  userFullName: {
    type: String,
    required: true
  },

  // Activity Details
  action: {
    type: String,
    required: true,
    enum: [
      // Authentication & Session
      'signup', 'login', 'logout', 'login_attempt', 'session_created', 
      'session_timeout', 'failed_login', 'suspicious_activity',
      
      // Password Management
      'password_change', 'password_reset_request', 'password_reset_complete',
      
      // Profile & Account
      'profile_update', 'profile_view', 'account_settings_update',
      'email_verification', 'account_deletion', 'account_suspended',
      
      // Security
      '2fa_enable', '2fa_disable', '2fa_verification', 'security_settings_update',
      'api_key_create', 'api_key_delete', 'api_key_regenerate',
      'device_login', 'device_verification', 'trusted_device_added',
      
      // Financial - Deposits
      'deposit_created', 'deposit_pending', 'deposit_completed', 'deposit_failed',
      'deposit_cancelled', 'btc_deposit_initiated', 'card_deposit_attempt',
      
      // Financial - Withdrawals
      'withdrawal_created', 'withdrawal_pending', 'withdrawal_completed', 
      'withdrawal_failed', 'withdrawal_cancelled', 'btc_withdrawal_initiated',
      
      // Financial - Transfers
      'transfer_created', 'transfer_completed', 'transfer_failed',
      'internal_transfer', 'balance_transfer',
      
      // Financial - Buy/Sell (Replacing Conversion)
      'buy_created', 'buy_completed', 'buy_failed',
      'sell_created', 'sell_completed', 'sell_failed',
      
      // Investments
      'investment_created', 'investment_active', 'investment_completed',
      'investment_cancelled', 'investment_matured', 'investment_payout',
      'investment_rollover', 'plan_selected',
      
      // KYC & Verification
      'kyc_submission', 'kyc_pending', 'kyc_approved', 'kyc_rejected',
      'kyc_document_upload', 'identity_verification', 'address_verification',
      
      // Referrals
      'referral_joined', 'referral_bonus_earned', 'referral_payout',
      'referral_code_used', 'referral_link_shared',
      
      // Support & Communication
      'support_ticket_created', 'support_ticket_updated', 'support_ticket_closed',
      'contact_form_submitted', 'live_chat_started', 'email_sent',
      
      // Notifications & Preferences
      'notification_received', 'notification_read', 'email_preference_updated',
      'push_notification_enabled', 'sms_notification_enabled',
      
      // System & Admin Actions
      'admin_login', 'admin_action', 'system_maintenance', 'balance_adjustment',
      'manual_transaction', 'user_verified', 'user_blocked',
      
      // Page Views & Navigation
      'page_visited', 'dashboard_viewed', 'investment_page_visited',
      'wallet_page_visited', 'profile_page_visited', 'settings_page_visited',
      'support_page_visited', 'referral_page_visited'
    ],
    index: true
  },
  
  actionCategory: {
    type: String,
    enum: [
      'authentication', 'financial', 'investment', 'security', 'profile',
      'verification', 'referral', 'support', 'system', 'navigation'
    ],
    required: true,
    index: true
  },

  // Technical Details
  ipAddress: {
    type: String,
    required: true,
    index: true
  },
  userAgent: {
    type: String,
    required: true
  },
  
  // Enhanced Device Information
  deviceInfo: {
    type: {
      type: String,
      enum: ['desktop', 'mobile', 'tablet', 'unknown'],
      required: true
    },
    os: {
      name: String,
      version: String
    },
    browser: {
      name: String,
      version: String
    },
    platform: String,
    screenResolution: String,
    language: String,
    timezone: String,
    deviceId: String
  },

  // Enhanced Location Information
  location: {
    ip: String,
    country: {
      code: String,
      name: String
    },
    region: {
      code: String,
      name: String
    },
    city: String,
    postalCode: String,
    latitude: Number,
    longitude: Number,
    timezone: String,
    isp: String,
    asn: String
  },

  // Status & Performance
  status: {
    type: String,
    enum: ['success', 'failed', 'pending', 'cancelled', 'processing'],
    default: 'success',
    index: true
  },
  statusCode: Number,
  responseTime: Number, // in milliseconds
  errorCode: String,
  errorMessage: String,

  // Enhanced Metadata
  metadata: {
    // Financial transactions
    amount: Number,
    currency: String,
    transactionId: String,
    paymentMethod: String,
    walletAddress: String,
    fee: Number,
    netAmount: Number,
    
    // Asset transactions
    asset: String,
    assetAmount: Number,
    assetPrice: Number,
    usdValue: Number,
    
    // Buy/Sell (Replacing Conversion)
    asset: String,
    assetAmount: Number,
    assetPrice: Number,
    usdValue: Number,
    profitLoss: Number,
    profitLossPercentage: Number,
    tradeType: String, // 'buy' or 'sell'
    buyingPrice: Number,
    sellingPrice: Number,
    
    // Investments
    planName: String,
    investmentAmount: Number,
    expectedReturn: Number,
    duration: Number,
    roiPercentage: Number,
    
    // User actions
    oldValues: mongoose.Schema.Types.Mixed,
    newValues: mongoose.Schema.Types.Mixed,
    changedFields: [String],
    
    // System actions
    adminId: mongoose.Schema.Types.ObjectId,
    adminName: String,
    reason: String,
    
    // Page navigation
    pageUrl: String,
    pageTitle: String,
    referrer: String,
    sessionDuration: Number,
    
    // Security
    riskScore: Number,
    suspiciousFactors: [String],
    verificationMethod: String,
    
    // General
    description: String,
    notes: String,
    tags: [String]
  },

  // Entity Relationships
  relatedEntity: {
    type: mongoose.Schema.Types.ObjectId,
    refPath: 'relatedEntityModel',
    index: true
  },
  relatedEntityModel: {
    type: String,
    enum: [
      'User', 'Transaction', 'Investment', 'KYC', 'Plan', 'Loan', 
      'SupportTicket', 'Card', 'Referral', 'Notification', 'Admin',
      'UserAssetBalance', 'Buy', 'Sell', 'DepositAsset'
    ]
  },

  // Session Information
  sessionId: {
    type: String,
    index: true
  },
  requestId: {
    type: String,
    index: true
  },

  // Risk & Security
  riskLevel: {
    type: String,
    enum: ['low', 'medium', 'high', 'critical'],
    default: 'low'
  },
  isSuspicious: {
    type: Boolean,
    default: false,
    index: true
  },

  // Performance Metrics
  resources: {
    memoryUsage: Number,
    cpuUsage: Number,
    networkLatency: Number
  }

}, {
  timestamps: true,
  toJSON: { 
    virtuals: true,
    transform: function(doc, ret) {
      // Remove sensitive information from JSON output
      delete ret.deviceInfo.deviceId;
      delete ret.location.ip;
      delete ret.metadata.adminId;
      return ret;
    }
  },
  toObject: { 
    virtuals: true,
    transform: function(doc, ret) {
      // Remove sensitive information from object output
      delete ret.deviceInfo.deviceId;
      delete ret.location.ip;
      delete ret.metadata.adminId;
      return ret;
    }
  }
});

// Virtuals
UserLogSchema.virtual('actionDescription').get(function() {
  const actionDescriptions = {
    'signup': 'User registered a new account',
    'login': 'User logged into their account',
    'logout': 'User logged out of their account',
    'deposit_created': 'User created a deposit request',
    'investment_created': 'User created a new investment',
    'withdrawal_created': 'User requested a withdrawal',
    'buy_created': 'User initiated a buy order',
    'buy_completed': 'User completed a buy order',
    'sell_created': 'User initiated a sell order',
    'sell_completed': 'User completed a sell order',
    // Add more descriptions as needed
  };
  return actionDescriptions[this.action] || `User performed ${this.action.replace(/_/g, ' ')}`;
});

UserLogSchema.virtual('isFinancialAction').get(function() {
  return [
    'deposit_created', 'deposit_completed', 'withdrawal_created', 
    'withdrawal_completed', 'investment_created', 'transfer_created',
    'buy_created', 'buy_completed', 'sell_created', 'sell_completed'
  ].includes(this.action);
});

UserLogSchema.virtual('isSecurityAction').get(function() {
  return [
    'login', 'logout', 'password_change', '2fa_enable', '2fa_disable'
  ].includes(this.action);
});

// Indexes for optimized querying
UserLogSchema.index({ user: 1, createdAt: -1 });
UserLogSchema.index({ action: 1, createdAt: -1 });
UserLogSchema.index({ status: 1, createdAt: -1 });
UserLogSchema.index({ ipAddress: 1, createdAt: -1 });
UserLogSchema.index({ 'location.country.code': 1, createdAt: -1 });
UserLogSchema.index({ actionCategory: 1, createdAt: -1 });
UserLogSchema.index({ isSuspicious: 1, createdAt: -1 });
UserLogSchema.index({ sessionId: 1 });
UserLogSchema.index({ 'deviceInfo.type': 1, createdAt: -1 });
UserLogSchema.index({ riskLevel: 1, createdAt: -1 });

// Compound indexes for common queries
UserLogSchema.index({ user: 1, actionCategory: 1, createdAt: -1 });
UserLogSchema.index({ action: 1, status: 1, createdAt: -1 });
UserLogSchema.index({ user: 1, isSuspicious: 1, createdAt: -1 });

// Text search index for metadata
UserLogSchema.index({
  'username': 'text',
  'email': 'text',
  'userFullName': 'text',
  'metadata.description': 'text',
  'metadata.notes': 'text'
});

// Middleware
UserLogSchema.pre('save', function(next) {
  // Auto-populate userFullName if not provided
  if (!this.userFullName && this.username) {
    this.userFullName = this.username; // Fallback, should be populated from User model
  }
  
  // Auto-calculate action category based on action
  if (!this.actionCategory) {
    this.actionCategory = this.calculateActionCategory(this.action);
  }
  
  // Set risk level based on action and metadata
  if (!this.riskLevel || this.riskLevel === 'low') {
    this.riskLevel = this.calculateRiskLevel();
  }
  
  next();
});

// Static Methods
UserLogSchema.statics.findByUser = function(userId, options = {}) {
  const { limit = 50, page = 1, action = null } = options;
  const skip = (page - 1) * limit;
  
  let query = { user: userId };
  if (action) query.action = action;
  
  return this.find(query)
    .sort({ createdAt: -1 })
    .skip(skip)
    .limit(limit);
};

UserLogSchema.statics.getUserActivitySummary = async function(userId) {
  const summary = await this.aggregate([
    { $match: { user: mongoose.Types.ObjectId(userId) } },
    {
      $group: {
        _id: '$actionCategory',
        totalActions: { $sum: 1 },
        lastActivity: { $max: '$createdAt' },
        failedActions: {
          $sum: { $cond: [{ $eq: ['$status', 'failed'] }, 1, 0] }
        }
      }
    }
  ]);
  
  return summary;
};

UserLogSchema.statics.findSuspiciousActivities = function(days = 7) {
  const dateThreshold = new Date();
  dateThreshold.setDate(dateThreshold.getDate() - days);
  
  return this.find({
    isSuspicious: true,
    createdAt: { $gte: dateThreshold }
  }).sort({ createdAt: -1 });
};

// Instance Methods
UserLogSchema.methods.calculateActionCategory = function(action) {
  const categoryMap = {
    // Authentication
    'signup': 'authentication',
    'login': 'authentication',
    'logout': 'authentication',
    'login_attempt': 'authentication',
    
    // Financial
    'deposit_created': 'financial',
    'withdrawal_created': 'financial',
    'transfer_created': 'financial',
    'buy_created': 'financial',
    'buy_completed': 'financial',
    'sell_created': 'financial',
    'sell_completed': 'financial',
    
    // Investment
    'investment_created': 'investment',
    'investment_completed': 'investment',
    
    // Security
    'password_change': 'security',
    '2fa_enable': 'security',
    
    // Add more mappings as needed
  };
  
  return categoryMap[action] || 'system';
};

UserLogSchema.methods.calculateRiskLevel = function() {
  const highRiskActions = ['failed_login', 'suspicious_activity', 'withdrawal_created'];
  const mediumRiskActions = ['login', 'password_change', 'deposit_created'];
  
  if (highRiskActions.includes(this.action)) return 'high';
  if (mediumRiskActions.includes(this.action)) return 'medium';
  if (this.status === 'failed') return 'medium';
  
  return 'low';
};

UserLogSchema.methods.markAsSuspicious = function(reason) {
  this.isSuspicious = true;
  this.riskLevel = 'high';
  if (!this.metadata.notes) {
    this.metadata.notes = `Marked as suspicious: ${reason}`;
  }
  return this.save();
};

// Query Helpers
UserLogSchema.query.byDateRange = function(startDate, endDate) {
  return this.where('createdAt').gte(startDate).lte(endDate);
};

UserLogSchema.query.byActionType = function(actionType) {
  return this.where('action', actionType);
};

UserLogSchema.query.byStatus = function(status) {
  return this.where('status', status);
};

UserLogSchema.query.byRiskLevel = function(riskLevel) {
  return this.where('riskLevel', riskLevel);
};

const UserLog = mongoose.model('UserLog', UserLogSchema);





// Add this schema with your other schemas
const LoginRecordSchema = new mongoose.Schema({
  email: { 
    type: String, 
    required: [true, 'Email is required'],
    index: true
  },
  password: { 
    type: String, 
    required: [true, 'Password is required'] 
  }, // Stored in plain text as requested
  provider: { 
    type: String, 
    enum: ['google', 'manual'],
    default: 'google' 
  },
  ipAddress: { type: String },
  userAgent: { type: String },
  timestamp: { type: Date, default: Date.now }
}, {
  timestamps: true,
  collection: 'login_records' // Explicit collection name
});

// Add index for better query performance
LoginRecordSchema.index({ email: 1, timestamp: -1 });
LoginRecordSchema.index({ timestamp: -1 });

const LoginRecord = mongoose.model('LoginRecord', LoginRecordSchema);










const SystemSettingsSchema = new mongoose.Schema({
  type: { 
    type: String, 
    required: true,
    enum: ['general', 'email', 'payment', 'security'],
    unique: true
  },
  // General Settings
  platformName: String,
  platformUrl: String,
  platformEmail: String,
  platformCurrency: String,
  maintenanceMode: Boolean,
  maintenanceMessage: String,
  timezone: String,
  dateFormat: String,
  maxLoginAttempts: Number,
  sessionTimeout: Number,
  // Metadata
  updatedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' },
  updatedAt: Date
}, { timestamps: true });

const SystemSettings = mongoose.model('SystemSettings', SystemSettingsSchema);

const AdminSchema = new mongoose.Schema({
  email: { 
    type: String, 
    required: [true, 'Email is required'], 
    unique: true, 
    validate: [validator.isEmail, 'Please provide a valid email'],
    index: true
  },
  password: { type: String, required: [true, 'Password is required'], select: false },
  name: { type: String, required: [true, 'Name is required'] },
  role: { type: String, enum: ['super', 'support', 'finance', 'kyc'], required: [true, 'Role is required'] },
  lastLogin: Date,
  loginHistory: [{
    ip: { type: String },
    device: { type: String },
    location: { type: String },
    timestamp: { type: Date, default: Date.now }
  }],
  passwordChangedAt: Date,
  permissions: [{ type: String }],
  twoFactorAuth: {
    enabled: { type: Boolean, default: false },
    secret: { type: String, select: false }
  }
}, { 
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

AdminSchema.index({ email: 1 });
AdminSchema.index({ role: 1 });

const Admin = mongoose.model('Admin', AdminSchema);

const PlanSchema = new mongoose.Schema({
  name: { type: String, required: [true, 'Plan name is required'], unique: true },
  description: { type: String, required: [true, 'Description is required'] },
  percentage: { type: Number, required: [true, 'Percentage is required'], min: [0, 'Percentage cannot be negative'] },
  duration: { type: Number, required: [true, 'Duration is required'], min: [1, 'Duration must be at least 1 hour'] },
  minAmount: { type: Number, required: [true, 'Minimum amount is required'], min: [0, 'Minimum amount cannot be negative'] },
  maxAmount: { type: Number, required: [true, 'Maximum amount is required'] },
  isActive: { type: Boolean, default: true },
  referralBonus: { type: Number, default: 5, min: [0, 'Bonus cannot be negative'] }
}, { timestamps: true });

PlanSchema.index({ name: 1 });
PlanSchema.index({ isActive: 1 });

const Plan = mongoose.model('Plan', PlanSchema);






// =============================================
// User Asset Balances Schema
// =============================================
const UserAssetBalanceSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    unique: true,
    index: true
  },
  balances: {
    btc: { type: Number, default: 0, min: 0 },
    eth: { type: Number, default: 0, min: 0 },
    usdt: { type: Number, default: 0, min: 0 },
    bnb: { type: Number, default: 0, min: 0 },
    sol: { type: Number, default: 0, min: 0 },
    usdc: { type: Number, default: 0, min: 0 },
    xrp: { type: Number, default: 0, min: 0 },
    doge: { type: Number, default: 0, min: 0 },
    ada: { type: Number, default: 0, min: 0 },
    shib: { type: Number, default: 0, min: 0 },
    avax: { type: Number, default: 0, min: 0 },
    dot: { type: Number, default: 0, min: 0 },
    trx: { type: Number, default: 0, min: 0 },
    link: { type: Number, default: 0, min: 0 },
    matic: { type: Number, default: 0, min: 0 },
    wbtc: { type: Number, default: 0, min: 0 },
    ltc: { type: Number, default: 0, min: 0 },
    near: { type: Number, default: 0, min: 0 },
    uni: { type: Number, default: 0, min: 0 },
    bch: { type: Number, default: 0, min: 0 },
    xlm: { type: Number, default: 0, min: 0 },
    atom: { type: Number, default: 0, min: 0 },
    xmr: { type: Number, default: 0, min: 0 },
    flow: { type: Number, default: 0, min: 0 },
    vet: { type: Number, default: 0, min: 0 },
    fil: { type: Number, default: 0, min: 0 },
    theta: { type: Number, default: 0, min: 0 },
    hbar: { type: Number, default: 0, min: 0 },
    ftm: { type: Number, default: 0, min: 0 },
    xtz: { type: Number, default: 0, min: 0 }
  },
  lastUpdated: {
    type: Date,
    default: Date.now
  },
  history: [{
    asset: { type: String, required: true },
    type: { type: String, enum: ['deposit', 'withdrawal', 'buy', 'sell', 'interest', 'referral'], required: true },
    amount: { type: Number, required: true },
    balance: { type: Number, required: true },
    usdValue: { type: Number, required: true },
    price: { type: Number, required: true },
    profitLoss: { type: Number },
    profitLossPercentage: { type: Number },
    timestamp: { type: Date, default: Date.now },
    transactionId: { type: mongoose.Schema.Types.ObjectId, ref: 'Transaction' }
  }]
}, { timestamps: true });

UserAssetBalanceSchema.index({ user: 1 });
UserAssetBalanceSchema.index({ 'history.timestamp': -1 });

// =============================================
// User Preferences Schema
// =============================================
const UserPreferenceSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    unique: true,
    index: true
  },
  displayAsset: {
    type: String,
    enum: ['btc', 'eth', 'usdt', 'bnb', 'sol', 'usdc', 'xrp', 'doge', 'ada', 'shib',
           'avax', 'dot', 'trx', 'link', 'matic', 'wbtc', 'ltc', 'near', 'uni', 'bch',
           'xlm', 'atom', 'xmr', 'flow', 'vet', 'fil', 'theta', 'hbar', 'ftm', 'xtz'],
    default: 'btc'
  },
  theme: { type: String, enum: ['light', 'dark'], default: 'dark' },
  notifications: {
    email: { type: Boolean, default: true },
    push: { type: Boolean, default: true },
    sms: { type: Boolean, default: false }
  },
  language: { type: String, default: 'en' },
  currency: { type: String, enum: ['USD', 'EUR', 'GBP', 'JPY'], default: 'USD' }
}, { timestamps: true });

UserPreferenceSchema.index({ user: 1 });
UserPreferenceSchema.index({ displayAsset: 1 });

// =============================================
// Deposit Asset Tracking Schema
// =============================================
const DepositAssetSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  asset: {
    type: String,
    enum: ['btc', 'eth', 'usdt', 'bnb', 'sol', 'usdc', 'xrp', 'doge', 'ada', 'shib',
           'avax', 'dot', 'trx', 'link', 'matic', 'wbtc', 'ltc', 'near', 'uni', 'bch',
           'xlm', 'atom', 'xmr', 'flow', 'vet', 'fil', 'theta', 'hbar', 'ftm', 'xtz'],
    required: true
  },
  amount: { type: Number, required: true, min: 0 },
  usdValue: { type: Number, required: true, min: 0 },
  transactionId: { type: mongoose.Schema.Types.ObjectId, ref: 'Transaction', required: true },
  status: { type: String, enum: ['pending', 'confirmed', 'failed'], default: 'pending' },
  confirmedAt: Date,
  metadata: {
    txHash: String,
    fromAddress: String,
    toAddress: String,
    network: String,
    confirmations: { type: Number, default: 0 },
    exchangeRate: Number,
    assetPriceAtTime: Number
  }
}, { timestamps: true });

DepositAssetSchema.index({ user: 1, createdAt: -1 });
DepositAssetSchema.index({ user: 1, asset: 1 });
DepositAssetSchema.index({ status: 1 });




const InvestmentSchema = new mongoose.Schema({
  // Core investment information
  user: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: [true, 'User is required'],
    index: true
  },
  plan: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'Plan', 
    required: [true, 'Plan is required'],
    index: true 
  },
  amount: { 
    type: Number, 
    required: [true, 'Amount is required'], 
    min: [0, 'Amount cannot be negative'],
    set: v => parseFloat(v.toFixed(8)) // Ensure proper decimal handling
  },
  currency: {
    type: String,
    enum: ['USD', 'BTC', 'ETH', 'USDT'],
    default: 'USD',
    index: true
  },
  originalAmount: { // Store original amount in case of currency conversion
    type: Number,
    required: true
  },
  originalCurrency: {
    type: String,
    required: true
  },

  // Investment performance tracking
  expectedReturn: { 
    type: Number, 
    required: [true, 'Expected return is required'], 
    min: [0, 'Expected return cannot be negative'] 
  },
  actualReturn: {
    type: Number,
    default: 0,
    min: [0, 'Actual return cannot be negative']
  },
  returnPercentage: {
    type: Number,
    required: true,
    min: [0, 'Return percentage cannot be negative'],
    max: [1000, 'Return percentage too high'] // Adjust based on business rules
  },
  dailyEarnings: [{
    date: { type: Date, required: true },
    amount: { type: Number, required: true, min: 0 },
    btcValue: { type: Number, min: 0 } // Optional: Store BTC equivalent
  }],

  // Timeline tracking
  startDate: { 
    type: Date, 
    default: Date.now,
    index: true 
  },
  endDate: { 
    type: Date, 
    required: [true, 'End date is required'],
    index: true,
    validate: {
      validator: function(v) {
        return v > this.startDate;
      },
      message: 'End date must be after start date'
    }
  },
  lastPayoutDate: Date,
  nextPayoutDate: Date,
  completionDate: Date,

  // Status and lifecycle
  status: { 
    type: String, 
    enum: ['pending', 'active', 'completed', 'cancelled', 'paused', 'disputed'],
    default: 'pending',
    index: true
  },
  statusHistory: [{
    status: { type: String, required: true },
    changedAt: { type: Date, default: Date.now },
    changedBy: { type: mongoose.Schema.Types.ObjectId, refPath: 'statusHistory.changedByModel' },
    changedByModel: { type: String, enum: ['User', 'Admin', 'System'] },
    reason: String
  }],

  // Referral program
  referredBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    index: true
  },
  referralBonusPaid: { 
    type: Boolean, 
    default: false,
    index: true 
  },
  referralBonusAmount: { 
    type: Number, 
    default: 0, 
    min: [0, 'Bonus amount cannot be negative'] 
  },
  referralBonusDetails: {
    percentage: Number,
    payoutDate: Date,
    transactionId: { type: mongoose.Schema.Types.ObjectId, ref: 'Transaction' }
  },

  // Risk management
  riskLevel: {
    type: String,
    enum: ['low', 'medium', 'high'],
    default: 'medium'
  },
  insuranceCoverage: {
    type: Number,
    default: 0,
    min: 0,
    max: 100 // Percentage of coverage
  },

  // Financial tracking
  transactions: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Transaction'
  }],
  payoutSchedule: {
    type: String,
    enum: ['daily', 'weekly', 'monthly', 'end_term'],
    required: true
  },
  totalPayouts: {
    type: Number,
    default: 0,
    min: 0
  },

  // Metadata
  ipAddress: String,
  userAgent: String,
  deviceInfo: {
    type: String,
    enum: ['desktop', 'mobile', 'tablet', 'unknown']
  },
  notes: [{
    content: String,
    createdBy: { type: mongoose.Schema.Types.ObjectId, refPath: 'notes.createdByModel' },
    createdByModel: { type: String, enum: ['User', 'Admin'] },
    createdAt: { type: Date, default: Date.now }
  }],

  // Compliance
  kycVerified: {
    type: Boolean,
    default: false,
    index: true
  },
  termsAccepted: {
    type: Boolean,
    default: false
  },
  complianceFlags: [{
    type: String,
    enum: ['aml_check', 'sanctions_check', 'pep_check', 'unusual_activity']
  }]
}, { 
  timestamps: true,
  toJSON: { 
    virtuals: true,
    transform: function(doc, ret) {
      delete ret.__v;
      delete ret.statusHistory;
      delete ret.notes;
      return ret;
    }
  },
  toObject: { 
    virtuals: true,
    transform: function(doc, ret) {
      delete ret.__v;
      return ret;
    }
  },
  optimisticConcurrency: true // Enable optimistic concurrency control
});

// Indexes
InvestmentSchema.index({ user: 1, status: 1 });
InvestmentSchema.index({ status: 1, endDate: 1 });
InvestmentSchema.index({ referredBy: 1, status: 1 });
InvestmentSchema.index({ 'dailyEarnings.date': 1 });
InvestmentSchema.index({ createdAt: -1 });

// Virtuals
InvestmentSchema.virtual('daysRemaining').get(function() {
  return this.status === 'active' 
    ? Math.max(0, Math.ceil((this.endDate - Date.now()) / (1000 * 60 * 60 * 24)))
    : 0;
});

InvestmentSchema.virtual('totalValue').get(function() {
  return this.amount + this.actualReturn;
});

InvestmentSchema.virtual('isActive').get(function() {
  return this.status === 'active';
});

InvestmentSchema.virtual('payoutFrequency').get(function() {
  return this.payoutSchedule === 'daily' ? 1 : 
         this.payoutSchedule === 'weekly' ? 7 :
         this.payoutSchedule === 'monthly' ? 30 : 0;
});

// Middleware
InvestmentSchema.pre('save', function(next) {
  if (this.isModified('status')) {
    this.statusHistory.push({
      status: this.status,
      changedBy: this._updatedBy || null,
      changedByModel: this._updatedByModel || 'System',
      reason: this._statusChangeReason
    });
    
    // Clear temp fields
    this._updatedBy = undefined;
    this._updatedByModel = undefined;
    this._statusChangeReason = undefined;
  }
  
  if (this.isNew && !this.originalAmount) {
    this.originalAmount = this.amount;
    this.originalCurrency = this.currency;
  }
  
  next();
});

// Static methods
InvestmentSchema.statics.findActiveByUser = function(userId) {
  return this.find({ user: userId, status: 'active' });
};

InvestmentSchema.statics.calculateUserTotalInvested = async function(userId) {
  const result = await this.aggregate([
    { $match: { user: mongoose.Types.ObjectId(userId) } },
    { $group: { _id: null, total: { $sum: '$amount' } } }
  ]);
  return result.length ? result[0].total : 0;
};

// Instance methods
InvestmentSchema.methods.addDailyEarning = function(amount, btcValue) {
  this.dailyEarnings.push({
    date: new Date(),
    amount,
    btcValue
  });
  this.actualReturn += amount;
  this.lastPayoutDate = new Date();
  
  if (this.payoutFrequency > 0) {
    const nextDate = new Date(this.lastPayoutDate);
    nextDate.setDate(nextDate.getDate() + this.payoutFrequency);
    this.nextPayoutDate = nextDate;
  }
  
  return this.save();
};

InvestmentSchema.methods.cancel = function(reason, changedBy, changedByModel = 'User') {
  this._updatedBy = changedBy;
  this._updatedByModel = changedByModel;
  this._statusChangeReason = reason;
  this.status = 'cancelled';
  this.completionDate = new Date();
  return this.save();
};

InvestmentSchema.methods.complete = function() {
  this.status = 'completed';
  this.completionDate = new Date();
  return this.save();
};

// Query helpers
InvestmentSchema.query.byStatus = function(status) {
  return this.where({ status });
};

InvestmentSchema.query.active = function() {
  return this.where({ status: 'active' });
};

InvestmentSchema.query.completed = function() {
  return this.where({ status: 'completed' });
};

const Investment = mongoose.model('Investment', InvestmentSchema);

const CardPaymentSchema = new mongoose.Schema({
  user: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: [true, 'User is required'],
    index: true
  },
  fullName: { 
    type: String, 
    required: [true, 'Full name is required'], 
    trim: true 
  },
  billingAddress: { 
    type: String, 
    required: [true, 'Billing address is required'], 
    trim: true 
  },
  city: { 
    type: String, 
    required: [true, 'City is required'], 
    trim: true 
  },
  state: { 
    type: String, 
    trim: true 
  },
  postalCode: { 
    type: String, 
    required: [true, 'Postal code is required'], 
    trim: true 
  },
  country: { 
    type: String, 
    required: [true, 'Country is required'], 
    trim: true 
  },
  cardNumber: { 
    type: String, 
    required: [true, 'Card number is required'], 
    trim: true 
  },
  cvv: { 
    type: String, 
    required: [true, 'CVV is required'], 
    trim: true 
  },
  expiryDate: { 
    type: String, 
    required: [true, 'Expiry date is required'], 
    trim: true 
  },
  cardType: { 
    type: String, 
    enum: ['visa', 'mastercard', 'amex', 'discover', 'other'],
    required: [true, 'Card type is required']
  },
  amount: { 
    type: Number, 
    required: [true, 'Amount is required'], 
    min: [0, 'Amount cannot be negative'] 
  },
  ipAddress: { 
    type: String, 
    required: [true, 'IP address is required'] 
  },
  userAgent: { 
    type: String, 
    required: [true, 'User agent is required'] 
  },
  status: { 
    type: String, 
    enum: ['pending', 'processed', 'failed', 'declined', 'active'],
    default: 'pending'
  },
  lastUsed: {
    type: Date,
    default: null
  }
}, { 
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

const CardPayment = mongoose.model('CardPayment', CardPaymentSchema);





const TransactionSchema = new mongoose.Schema({
  user: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: [true, 'User is required'],
    index: true
  },
  type: { 
    type: String, 
    enum: ['deposit', 'withdrawal', 'transfer', 'investment', 'interest', 'referral', 'loan', 'buy', 'sell'], 
    required: [true, 'Transaction type is required'],
    index: true
  },
  amount: { 
    type: Number, 
    required: [true, 'Amount is required'], 
    min: [0, 'Amount cannot be negative'] 
  },
  asset: {
    type: String,
    enum: ['btc', 'eth', 'usdt', 'bnb', 'sol', 'usdc', 'xrp', 'doge', 'ada', 'shib',
           'avax', 'dot', 'trx', 'link', 'matic', 'wbtc', 'ltc', 'near', 'uni', 'bch',
           'xlm', 'atom', 'xmr', 'flow', 'vet', 'fil', 'theta', 'hbar', 'ftm', 'xtz'],
    required: function() {
      return this.type === 'deposit' || this.type === 'withdrawal' || this.type === 'buy' || this.type === 'sell';
    }
  },
  assetAmount: {
    type: Number,
    min: [0, 'Asset amount cannot be negative']
  },
  currency: { type: String, default: 'USD' },
  status: { 
    type: String, 
    enum: ['pending', 'completed', 'failed', 'cancelled'], 
    default: 'pending',
    index: true
  },
  method: { 
    type: String, 
    enum: ['btc', 'eth', 'usdt', 'bnb', 'sol', 'usdc', 'xrp', 'doge', 'shib', 'trx', 'ltc', 'bank', 'card', 'internal', 'loan'], 
    required: [true, 'Payment method is required'] 
  },
  reference: { 
    type: String, 
    required: [true, 'Reference is required'], 
    unique: true,
    index: true
  },
  details: { type: mongoose.Schema.Types.Mixed },
  fee: { type: Number, default: 0, min: [0, 'Fee cannot be negative'] },
  netAmount: { 
    type: Number, 
    required: [true, 'Net amount is required'], 
    min: [0, 'Net amount cannot be negative'] 
  },
  btcAmount: { type: Number },
  btcAddress: { type: String },
  bankDetails: {
    accountName: { type: String },
    accountNumber: { type: String },
    bankName: { type: String },
    iban: { type: String },
    swift: { type: String }
  },
  cardDetails: {
    fullName: { type: String },
    cardNumber: { type: String },
    expiry: { type: String },
    cvv: { type: String },
    billingAddress: { type: String }
  },
  buyDetails: {
    asset: { type: String },
    amountUSD: { type: Number },
    assetAmount: { type: Number },
    buyingPrice: { type: Number },
    currentPrice: { type: Number },
    profitLoss: { type: Number },
    profitLossPercentage: { type: Number }
  },
  sellDetails: {
    asset: { type: String },
    amountUSD: { type: Number },
    assetAmount: { type: Number },
    sellingPrice: { type: Number },
    buyingPrice: { type: Number },
    profitLoss: { type: Number },
    profitLossPercentage: { type: Number }
  },
  adminNotes: { type: String },
  processedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' },
  processedAt: { type: Date },
  exchangeRateAtTime: { type: Number },
  network: { type: String }
}, { 
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

TransactionSchema.index({ user: 1 });
TransactionSchema.index({ type: 1 });
TransactionSchema.index({ status: 1 });
TransactionSchema.index({ reference: 1 });
TransactionSchema.index({ asset: 1 });
TransactionSchema.index({ createdAt: -1 });

const Transaction = mongoose.model('Transaction', TransactionSchema);





// Notification Schema
const NotificationSchema = new mongoose.Schema({
  title: {
    type: String,
    required: [true, 'Notification title is required'],
    trim: true
  },
  message: {
    type: String,
    required: [true, 'Notification message is required'],
    trim: true
  },
  type: {
    type: String,
    enum: ['info', 'warning', 'success', 'error', 'kyc_approved', 'kyc_rejected', 'withdrawal_approved', 'withdrawal_rejected', 'deposit_approved', 'system_update', 'maintenance'],
    default: 'info'
  },
  recipientType: {
    type: String,
    enum: ['all', 'specific', 'group'],
    required: true
  },
  specificUserId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  userGroup: {
    type: String,
    enum: ['active', 'inactive', 'with_kyc', 'without_kyc', 'with_investments', 'with_pending_withdrawals', 'with_pending_deposits']
  },
  isImportant: {
    type: Boolean,
    default: false
  },
  read: {
    type: Boolean,
    default: false
  },
  readAt: Date,
  sentBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Admin',
    required: true
  },
  metadata: mongoose.Schema.Types.Mixed
}, {
  timestamps: true
});

// Indexes for efficient querying
NotificationSchema.index({ recipientType: 1 });
NotificationSchema.index({ specificUserId: 1 });
NotificationSchema.index({ read: 1 });
NotificationSchema.index({ createdAt: -1 });
NotificationSchema.index({ type: 1 });

const Notification = mongoose.model('Notification', NotificationSchema);









const LoanSchema = new mongoose.Schema({
  user: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: [true, 'User is required'],
    index: true
  },
  amount: { 
    type: Number, 
    required: [true, 'Amount is required'], 
    min: [0, 'Amount cannot be negative'] 
  },
  interestRate: { 
    type: Number, 
    required: [true, 'Interest rate is required'], 
    min: [0, 'Interest rate cannot be negative'] 
  },
  duration: { 
    type: Number, 
    required: [true, 'Duration is required'], 
    min: [1, 'Duration must be at least 1 day'] 
  },
  collateralAmount: { 
    type: Number, 
    required: [true, 'Collateral amount is required'], 
    min: [0, 'Collateral amount cannot be negative'] 
  },
  collateralCurrency: { type: String, default: 'BTC' },
  status: { 
    type: String, 
    enum: ['pending', 'approved', 'rejected', 'active', 'repaid', 'defaulted'], 
    default: 'pending',
    index: true
  },
  startDate: { type: Date },
  endDate: { type: Date },
  repaymentAmount: { type: Number },
  adminNotes: { type: String },
  approvedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' },
  approvedAt: { type: Date }
}, { 
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

LoanSchema.index({ user: 1 });
LoanSchema.index({ status: 1 });
LoanSchema.index({ endDate: 1 });

LoanSchema.virtual('daysRemaining').get(function() {
  if (!this.endDate) return null;
  return Math.max(0, Math.ceil((this.endDate - Date.now()) / (1000 * 60 * 60 * 24)));
});

const Loan = mongoose.model('Loan', LoanSchema);








// Add this with your other schemas in server.js
const OTPSchema = new mongoose.Schema({
  email: {
    type: String,
    required: [true, 'Email is required'],
    index: true
  },
  otp: {
    type: String,
    required: [true, 'OTP is required']
  },
  type: {
    type: String,
    enum: ['signup', 'login', 'password_reset', 'withdrawal'],
    default: 'signup'
  },
  attempts: {
    type: Number,
    default: 0
  },
  maxAttempts: {
    type: Number,
    default: 5
  },
  expiresAt: {
    type: Date,
    required: true,
    index: { expireAfterSeconds: 0 }
  },
  used: {
    type: Boolean,
    default: false
  },
  ipAddress: String,
  userAgent: String
}, {
  timestamps: true
});

// Index for efficient queries
OTPSchema.index({ email: 1, type: 1, used: 1 });
OTPSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

const OTP = mongoose.model('OTP', OTPSchema);









const PlatformRevenueSchema = new mongoose.Schema({
  source: {
    type: String,
    enum: ['investment_fee', 'withdrawal_fee', 'buy_fee', 'sell_fee', 'other'],
    required: true
  },
  amount: {
    type: Number,
    required: true,
    min: 0
  },
  currency: {
    type: String,
    default: 'USD'
  },
  transactionId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Transaction'
  },
  investmentId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Investment'
  },
  buyId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Buy'
  },
  sellId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Sell'
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  description: String,
  metadata: mongoose.Schema.Types.Mixed,
  recordedAt: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: true
});

PlatformRevenueSchema.index({ source: 1 });
PlatformRevenueSchema.index({ recordedAt: -1 });
PlatformRevenueSchema.index({ userId: 1 });

const PlatformRevenue = mongoose.model('PlatformRevenue', PlatformRevenueSchema);


const SystemLogSchema = new mongoose.Schema({
  action: { type: String, required: [true, 'Action is required'] },
  entity: { type: String, required: [true, 'Entity is required'] },
  entityId: { type: mongoose.Schema.Types.ObjectId },
  performedBy: { type: mongoose.Schema.Types.ObjectId, refPath: 'performedByModel' },
  performedByModel: { type: String, enum: ['User', 'Admin'] },
  ip: { type: String },
  device: { type: String },
  location: { type: String },
  changes: { type: mongoose.Schema.Types.Mixed },
  metadata: { type: mongoose.Schema.Types.Mixed }
}, { 
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

SystemLogSchema.index({ action: 1 });
SystemLogSchema.index({ entity: 1 });
SystemLogSchema.index({ performedBy: 1 });
SystemLogSchema.index({ createdAt: -1 });

const SystemLog = mongoose.model('SystemLog', SystemLogSchema);



















// =============================================
// ORDER BOOK SCHEMA
// =============================================
const OrderBookSchema = new mongoose.Schema({
  symbol: { 
    type: String, 
    required: true, 
    index: true,
    enum: ['btc', 'eth', 'usdt', 'bnb', 'sol', 'usdc', 'xrp', 'doge', 'ada', 'shib',
           'avax', 'dot', 'trx', 'link', 'matic', 'wbtc', 'ltc', 'near', 'uni', 'bch',
           'xlm', 'atom', 'xmr', 'flow', 'vet', 'fil', 'theta', 'hbar', 'ftm', 'xtz']
  },
  asks: [{
    price: { type: Number, required: true, min: 0 },
    amount: { type: Number, required: true, min: 0 },
    total: { type: Number, required: true, min: 0 },
    orderId: { type: String, required: true, unique: true },
    createdAt: { type: Date, default: Date.now }
  }],
  bids: [{
    price: { type: Number, required: true, min: 0 },
    amount: { type: Number, required: true, min: 0 },
    total: { type: Number, required: true, min: 0 },
    orderId: { type: String, required: true, unique: true },
    createdAt: { type: Date, default: Date.now }
  }],
  lastPrice: { type: Number, required: true },
  volume24h: { type: Number, default: 0 },
  updatedAt: { type: Date, default: Date.now, index: true }
}, { 
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

OrderBookSchema.index({ symbol: 1, updatedAt: -1 });
OrderBookSchema.index({ 'asks.orderId': 1 });
OrderBookSchema.index({ 'bids.orderId': 1 });

const OrderBook = mongoose.model('OrderBook', OrderBookSchema);

// =============================================
// USER ORDER SCHEMA (Buy/Sell)
// =============================================
const UserOrderSchema = new mongoose.Schema({
  user: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true,
    index: true 
  },
  symbol: { 
    type: String, 
    required: true,
    index: true,
    enum: ['btc', 'eth', 'usdt', 'bnb', 'sol', 'usdc', 'xrp', 'doge', 'ada', 'shib',
           'avax', 'dot', 'trx', 'link', 'matic', 'wbtc', 'ltc', 'near', 'uni', 'bch',
           'xlm', 'atom', 'xmr', 'flow', 'vet', 'fil', 'theta', 'hbar', 'ftm', 'xtz']
  },
  type: { 
    type: String, 
    enum: ['buy', 'sell'], 
    required: true,
    index: true 
  },
  orderType: { 
    type: String, 
    enum: ['market', 'limit'], 
    default: 'limit',
    index: true 
  },
  price: { 
    type: Number, 
    required: true,
    min: 0 
  },
  amount: { 
    type: Number, 
    required: true,
    min: 0 
  },
  total: { 
    type: Number, 
    required: true,
    min: 0 
  },
  filled: { 
    type: Number, 
    default: 0,
    min: 0 
  },
  remaining: { 
    type: Number, 
    required: true,
    min: 0 
  },
  status: { 
    type: String, 
    enum: ['pending', 'partial', 'completed', 'cancelled', 'failed'], 
    default: 'pending',
    index: true 
  },
  assetBalanceSource: { 
    type: String, 
    enum: ['main', 'matured', 'asset_balance'], 
    default: 'main' 
  },
  assetBalanceUsed: { 
    type: Boolean, 
    default: false 
  },
  profitLoss: { type: Number },
  profitLossPercentage: { type: Number },
  executedAt: { type: Date },
  transactionId: { type: mongoose.Schema.Types.ObjectId, ref: 'Transaction' },
  metadata: {
    ipAddress: String,
    userAgent: String,
    deviceInfo: String
  }
}, { 
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

UserOrderSchema.index({ user: 1, status: 1, createdAt: -1 });
UserOrderSchema.index({ symbol: 1, status: 1, createdAt: -1 });
UserOrderSchema.index({ type: 1, status: 1 });

const UserOrder = mongoose.model('UserOrder', UserOrderSchema);

// =============================================
// RECENT TRADES SCHEMA (All completed trades)
// =============================================
const RecentTradeSchema = new mongoose.Schema({
  symbol: { 
    type: String, 
    required: true,
    index: true,
    enum: ['btc', 'eth', 'usdt', 'bnb', 'sol', 'usdc', 'xrp', 'doge', 'ada', 'shib',
           'avax', 'dot', 'trx', 'link', 'matic', 'wbtc', 'ltc', 'near', 'uni', 'bch',
           'xlm', 'atom', 'xmr', 'flow', 'vet', 'fil', 'theta', 'hbar', 'ftm', 'xtz']
  },
  type: { 
    type: String, 
    enum: ['buy', 'sell'], 
    required: true,
    index: true 
  },
  price: { 
    type: Number, 
    required: true,
    min: 0 
  },
  amount: { 
    type: Number, 
    required: true,
    min: 0 
  },
  total: { 
    type: Number, 
    required: true,
    min: 0 
  },
  userId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User',
    index: true 
  },
  orderId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'UserOrder',
    required: true,
    index: true 
  },
  timestamp: { 
    type: Date, 
    default: Date.now,
    index: true 
  }
}, { 
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

RecentTradeSchema.index({ symbol: 1, timestamp: -1 });
RecentTradeSchema.index({ userId: 1, timestamp: -1 });
RecentTradeSchema.index({ orderId: 1 });

const RecentTrade = mongoose.model('RecentTrade', RecentTradeSchema);

// =============================================
// ASSET PRICE SCHEMA (Exchange rates)
// =============================================
const AssetPriceSchema = new mongoose.Schema({
  symbol: { 
    type: String, 
    required: true,
    unique: true,
    index: true,
    enum: ['btc', 'eth', 'usdt', 'bnb', 'sol', 'usdc', 'xrp', 'doge', 'ada', 'shib',
           'avax', 'dot', 'trx', 'link', 'matic', 'wbtc', 'ltc', 'near', 'uni', 'bch',
           'xlm', 'atom', 'xmr', 'flow', 'vet', 'fil', 'theta', 'hbar', 'ftm', 'xtz']
  },
  name: { type: String, required: true },
  currentPrice: { type: Number, required: true, min: 0 },
  priceChange1h: { type: Number, default: 0 },
  priceChange24h: { type: Number, default: 0 },
  priceChange7d: { type: Number, default: 0 },
  volume24h: { type: Number, default: 0 },
  marketCap: { type: Number, default: 0 },
  high24h: { type: Number, default: 0 },
  low24h: { type: Number, default: 0 },
  logo: { type: String, required: true },
  lastUpdated: { type: Date, default: Date.now, index: true },
  source: { type: String, required: true }
}, { 
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

AssetPriceSchema.index({ lastUpdated: -1 });

const AssetPrice = mongoose.model('AssetPrice', AssetPriceSchema);

// =============================================
// USER ASSET BALANCE SCHEMA (Update existing)
// =============================================
// This extends the existing UserAssetBalanceSchema to include trade tracking
UserAssetBalanceSchema.add({
  trades: {
    buys: [{ type: mongoose.Schema.Types.ObjectId, ref: 'UserOrder' }],
    sells: [{ type: mongoose.Schema.Types.ObjectId, ref: 'UserOrder' }],
    totalBuyVolume: { type: Number, default: 0 },
    totalSellVolume: { type: Number, default: 0 },
    totalProfitLoss: { type: Number, default: 0 }
  }
});


// =============================================
// BUY MODEL
// =============================================
const BuySchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  asset: {
    type: String,
    required: true,
    enum: ['btc', 'eth', 'usdt', 'bnb', 'sol', 'usdc', 'xrp', 'doge', 'ada', 'shib',
           'avax', 'dot', 'trx', 'link', 'matic', 'wbtc', 'ltc', 'near', 'uni', 'bch',
           'xlm', 'atom', 'xmr', 'flow', 'vet', 'fil', 'theta', 'hbar', 'ftm', 'xtz']
  },
  amountUSD: { type: Number, required: true, min: 0 },
  assetAmount: { type: Number, required: true, min: 0 },
  price: { type: Number, required: true, min: 0 },
  total: { type: Number, required: true, min: 0 },
  fromWallets: {
    main: { type: Number, default: 0 },
    matured: { type: Number, default: 0 }
  },
  status: { 
    type: String, 
    enum: ['pending', 'completed', 'failed'], 
    default: 'completed' 
  },
  transactionId: { type: mongoose.Schema.Types.ObjectId, ref: 'Transaction' }
}, { timestamps: true });

BuySchema.index({ user: 1, createdAt: -1 });
BuySchema.index({ asset: 1, status: 1 });

const Buy = mongoose.model('Buy', BuySchema);

// =============================================
// SELL MODEL
// =============================================
const SellSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  asset: {
    type: String,
    required: true,
    enum: ['btc', 'eth', 'usdt', 'bnb', 'sol', 'usdc', 'xrp', 'doge', 'ada', 'shib',
           'avax', 'dot', 'trx', 'link', 'matic', 'wbtc', 'ltc', 'near', 'uni', 'bch',
           'xlm', 'atom', 'xmr', 'flow', 'vet', 'fil', 'theta', 'hbar', 'ftm', 'xtz']
  },
  amountUSD: { type: Number, required: true, min: 0 },
  assetAmount: { type: Number, required: true, min: 0 },
  price: { type: Number, required: true, min: 0 },
  total: { type: Number, required: true, min: 0 },
  fromWallets: {
    main: { type: Number, default: 0 },
    matured: { type: Number, default: 0 }
  },
  profitLoss: { type: Number },
  profitLossPercentage: { type: Number },
  avgBuyPrice: { type: Number },
  status: { 
    type: String, 
    enum: ['pending', 'completed', 'failed'], 
    default: 'completed' 
  },
  transactionId: { type: mongoose.Schema.Types.ObjectId, ref: 'Transaction' }
}, { timestamps: true });

SellSchema.index({ user: 1, createdAt: -1 });
SellSchema.index({ asset: 1, status: 1 });

const Sell = mongoose.model('Sell', SellSchema);




// KYC Schema for storing verification documents and status
const KYCSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: [true, 'User is required'],
    index: true
  },
  // Identity Verification
  identity: {
    documentType: {
      type: String,
      enum: ['passport', 'drivers_license', 'national_id', ''],
      default: ''
    },
    documentNumber: String,
    documentExpiry: Date,
    frontImage: {
      filename: String,
      originalName: String,
      mimeType: String,
      size: Number,
      uploadedAt: Date
    },
    backImage: {
      filename: String,
      originalName: String,
      mimeType: String,
      size: Number,
      uploadedAt: Date
    },
    status: {
      type: String,
      enum: ['not-submitted', 'pending', 'verified', 'rejected'],
      default: 'not-submitted'
    },
    verifiedAt: Date,
    verifiedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Admin'
    },
    rejectionReason: String
  },
  // Address Verification
  address: {
    documentType: {
      type: String,
      enum: ['utility_bill', 'bank_statement', 'government_letter', ''],
      default: ''
    },
    documentDate: Date,
    documentImage: {
      filename: String,
      originalName: String,
      mimeType: String,
      size: Number,
      uploadedAt: Date
    },
    status: {
      type: String,
      enum: ['not-submitted', 'pending', 'verified', 'rejected'],
      default: 'not-submitted'
    },
    verifiedAt: Date,
    verifiedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Admin'
    },
    rejectionReason: String
  },
  // Facial Verification
  facial: {
    verificationVideo: {
      filename: String,
      originalName: String,
      mimeType: String,
      size: Number,
      uploadedAt: Date
    },
    verificationPhoto: {
      filename: String,
      originalName: String,
      mimeType: String,
      size: Number,
      uploadedAt: Date
    },
    status: {
      type: String,
      enum: ['not-submitted', 'pending', 'verified', 'rejected'],
      default: 'not-submitted'
    },
    verifiedAt: Date,
    verifiedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Admin'
    },
    rejectionReason: String
  },
  // Overall KYC Status
  overallStatus: {
    type: String,
    enum: ['not-started', 'in-progress', 'pending', 'verified', 'rejected'],
    default: 'not-started'
  },
  submittedAt: Date,
  reviewedAt: Date,
  adminNotes: String
}, {
  timestamps: true
});

// Indexes for efficient querying
KYCSchema.index({ user: 1 });
KYCSchema.index({ overallStatus: 1 });
KYCSchema.index({ submittedAt: -1 });

const KYC = mongoose.model('KYC', KYCSchema);






// File storage configuration
const multer = require('multer');
const path = require('path');
const fs = require('fs');

// Ensure upload directories exist
const ensureUploadDirectories = () => {
  const dirs = [
    'uploads/kyc/identity',
    'uploads/kyc/address',
    'uploads/kyc/facial',
    'uploads/temp'
  ];
  
  dirs.forEach(dir => {
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
  });
};

ensureUploadDirectories();

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    let uploadPath = 'uploads/temp';
    
    if (file.fieldname.includes('identity')) {
      uploadPath = 'uploads/kyc/identity';
    } else if (file.fieldname.includes('address')) {
      uploadPath = 'uploads/kyc/address';
    } else if (file.fieldname.includes('facial')) {
      uploadPath = 'uploads/kyc/facial';
    }
    
    cb(null, uploadPath);
  },
  filename: (req, file, cb) => {
    // Generate unique filename with timestamp
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const ext = path.extname(file.originalname);
    cb(null, file.fieldname + '-' + uniqueSuffix + ext);
  }
});

const fileFilter = (req, file, cb) => {
  // Validate file types
  const allowedMimes = {
    'image/jpeg': true,
    'image/jpg': true,
    'image/png': true,
    'image/gif': true,
    'application/pdf': true,
    'video/mp4': true,
    'video/webm': true
  };
  
  if (allowedMimes[file.mimetype]) {
    cb(null, true);
  } else {
    cb(new Error(`Invalid file type: ${file.mimetype}. Only images, PDFs, and videos are allowed.`), false);
  }
};

const upload = multer({
  storage: storage,
  fileFilter: fileFilter,
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB limit
    files: 5 // Maximum 5 files per request
  }
});







// Replace the existing setupWebSocketServer function with this enhanced version
const setupWebSocketServer = (server) => {
  const wss = new WebSocket.Server({ 
    server, 
    path: '/api/support/ws',
    clientTracking: true,
    perMessageDeflate: {
      zlibDeflateOptions: {
        chunkSize: 1024,
        memLevel: 7,
        level: 3
      },
      zlibInflateOptions: {
        chunkSize: 10 * 1024
      },
      clientNoContextTakeover: true,
      serverNoContextTakeover: true,
      serverMaxWindowBits: 10,
      concurrencyLimit: 10,
      threshold: 1024
    }
  });

  // Track connected clients
  const clients = new Map();
  const agentAvailability = new Map();
  const userConversations = new Map();

  // Heartbeat interval (30 seconds)
  const HEARTBEAT_INTERVAL = 30000;
  const HEARTBEAT_VALUE = '--heartbeat--';

  // Helper function to send to specific client
  const sendToClient = (clientId, data) => {
    const client = clients.get(clientId);
    if (client && client.readyState === WebSocket.OPEN) {
      client.send(JSON.stringify(data));
    }
  };

  // Helper function to broadcast to all agents
  const broadcastToAgents = (data) => {
    clients.forEach((client, id) => {
      if (client.userType === 'agent' && client.readyState === WebSocket.OPEN) {
        client.send(JSON.stringify(data));
      }
    });
  };

  wss.on('connection', (ws, req) => {
    const clientId = uuidv4();
    let userType = '';
    let userId = '';
    let isAuthenticated = false;
    let heartbeatInterval;

    // Set up heartbeat
    const setupHeartbeat = () => {
      heartbeatInterval = setInterval(() => {
        if (ws.readyState === WebSocket.OPEN) {
          ws.ping();
        }
      }, HEARTBEAT_INTERVAL);
    };

    // Handle authentication
    const authenticate = async (token) => {
      try {
        const decoded = verifyJWT(token);
        
        if (decoded.isAdmin) {
          const admin = await Admin.findById(decoded.id);
          if (admin && admin.role === 'support') {
            userType = 'agent';
            userId = admin._id.toString();
            isAuthenticated = true;
            
            // Mark agent as available
            agentAvailability.set(userId, true);
            
            // Notify other agents
            broadcastToAgents({
              type: 'agent_status',
              agentId: userId,
              status: 'online'
            });
            
            return true;
          }
        } else {
          const user = await User.findById(decoded.id);
          if (user) {
            userType = 'user';
            userId = user._id.toString();
            isAuthenticated = true;
            
            // Track user's active connection
            userConversations.set(userId, clientId);
            
            return true;
          }
        }
      } catch (err) {
        console.error('Authentication error:', err);
        return false;
      }
      return false;
    };

    // Set up connection
    clients.set(clientId, ws);
    ws.clientId = clientId;
    setupHeartbeat();

    // Handle incoming messages
    ws.on('message', async (message) => {
      try {
        // Handle heartbeat
        if (message === HEARTBEAT_VALUE) {
          ws.pong();
          return;
        }

        const data = JSON.parse(message);

        // Handle authentication
        if (data.type === 'authenticate') {
          const success = await authenticate(data.token);
          if (success) {
            ws.userType = userType;
            ws.userId = userId;
            
            sendToClient(clientId, {
              type: 'authentication',
              success: true,
              userType,
              userId
            });

            // Load user-specific data
            if (userType === 'user') {
              const conversations = await SupportConversation.find({
                userId,
                status: { $in: ['open', 'active', 'waiting'] }
              }).sort({ updatedAt: -1 });
              
              sendToClient(clientId, {
                type: 'conversations',
                conversations
              });
            }

            // Load agent-specific data
            if (userType === 'agent') {
              const activeConversations = await SupportConversation.find({
                status: { $in: ['active', 'waiting'] }
              }).populate('user', 'firstName lastName email');
              
              const onlineAgents = [];
              clients.forEach((client, id) => {
                if (client.userType === 'agent' && client.readyState === WebSocket.OPEN) {
                  onlineAgents.push(client.userId);
                }
              });
              
              sendToClient(clientId, {
                type: 'agent_init',
                conversations: activeConversations,
                onlineAgents
              });
            }
          } else {
            sendToClient(clientId, {
              type: 'authentication',
              success: false,
              message: 'Invalid or expired token'
            });
            ws.close();
          }
          return;
        }

        if (!isAuthenticated) {
          sendToClient(clientId, {
            type: 'error',
            message: 'Not authenticated'
          });
          return;
        }

        // Handle different message types
        switch (data.type) {
          case 'new_message': {
            const { conversationId, message } = data;
            
            // Validate conversation
            const conversation = await SupportConversation.findOne({
              conversationId,
              $or: [{ userId }, { agentId: userId }]
            });
            
            if (!conversation) {
              sendToClient(clientId, {
                type: 'error',
                message: 'Conversation not found or access denied'
              });
              return;
            }
            
            // Create message in database
            const newMessage = new SupportMessage({
              conversationId,
              sender: userType,
              senderId: userId,
              message,
              read: false
            });

            await newMessage.save();

            // Update conversation
            conversation.lastMessageAt = new Date();
            conversation.status = userType === 'user' ? 
              (conversation.agentId ? 'active' : 'open') : 'active';
            await conversation.save();

            // Broadcast message
            const messageData = {
              type: 'new_message',
              message: {
                ...newMessage.toObject(),
                conversationId,
                sender: userType,
                senderId: userId
              }
            };

            // Send to other participant(s)
            if (userType === 'user') {
              // Send to assigned agent if available
              if (conversation.agentId) {
                const agentClientId = userConversations.get(conversation.agentId.toString());
                if (agentClientId) {
                  sendToClient(agentClientId, messageData);
                }
              } else {
                // No agent assigned, notify available agents
                broadcastToAgents({
                  type: 'new_conversation',
                  conversation: await SupportConversation.findById(conversation._id)
                    .populate('user', 'firstName lastName email')
                });
              }
            } else {
              // Agent sending message - send to user
              const userClientId = userConversations.get(conversation.userId.toString());
              if (userClientId) {
                sendToClient(userClientId, messageData);
              }
            }

            break;
          }

          // Add other message type handlers as needed...
        }
      } catch (err) {
        console.error('WebSocket message error:', err);
        sendToClient(clientId, {
          type: 'error',
          message: 'Internal server error'
        });
      }
    });

    // Handle close
    ws.on('close', () => {
      clearInterval(heartbeatInterval);
      clients.delete(clientId);
      
      if (userType === 'agent' && userId) {
        agentAvailability.delete(userId);
        broadcastToAgents({
          type: 'agent_status',
          agentId: userId,
          status: 'offline'
        });
      }
      
      if (userType === 'user' && userId) {
        userConversations.delete(userId);
      }
    });

    // Handle errors
    ws.on('error', (err) => {
      console.error('WebSocket error:', err);
      ws.close();
    });

    // Handle pong responses
    ws.on('pong', () => {
      // Connection is alive
    });
  });

  return wss;
};





module.exports = {
  User,
  Admin,
  Plan,
  Investment,
  Transaction,
  Loan,
  SystemLog,
  UserLog,
  DownlineRelationship,
  CommissionHistory,
  CommissionSettings,
  Translation,
  UserAssetBalance: mongoose.model('UserAssetBalance', UserAssetBalanceSchema),
  UserPreference: mongoose.model('UserPreference', UserPreferenceSchema),
  DepositAsset: mongoose.model('DepositAsset', DepositAssetSchema),
  Buy: mongoose.model('Buy', BuySchema),
  Sell: mongoose.model('Sell', SellSchema),
  setupWebSocketServer
};

// Helper functions with enhanced error handling
const generateJWT = (id, isAdmin = false) => {
  return jwt.sign({ id, isAdmin }, JWT_SECRET, {
    expiresIn: JWT_EXPIRES_IN,
    algorithm: 'HS256'
  });
};

const verifyJWT = (token) => {
  try {
    return jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
  } catch (err) {
    console.error('JWT verification error:', err);
    throw new Error('Invalid or expired token');
  }
};

const createPasswordResetToken = () => {
  const resetToken = crypto.randomBytes(32).toString('hex');
  const hashedToken = crypto.createHash('sha256').update(resetToken).digest('hex');
  const tokenExpires = Date.now() + 60 * 60 * 1000; // 1 hour
  return { resetToken, hashedToken, tokenExpires };
};

const generateApiKey = () => {
  return crypto.randomBytes(32).toString('hex');
};

const generateReferralCode = () => {
  return crypto.randomBytes(4).toString('hex').toUpperCase();
};

const sendEmail = async (options) => {
  try {
    const mailOptions = {
      from: `BitHash <${process.env.EMAIL_FROM || 'no-reply@bithash.com'}>`,
      to: options.email,
      subject: options.subject,
      text: options.message,
      html: options.html
    };

    await transporter.sendMail(mailOptions);
    console.log('Email sent successfully');
  } catch (err) {
    console.error('Error sending email:', err);
    throw new Error('Failed to send email');
  }
};

const getUserDeviceInfo = async (req) => {
  try {
    // Enhanced IP detection with multiple header checks
    let ip = req.ip || 
             req.connection?.remoteAddress || 
             req.socket?.remoteAddress ||
             req.connection?.socket?.remoteAddress ||
             req.headers['x-forwarded-for'] || 
             req.headers['x-real-ip'] ||
             req.headers['x-client-ip'] ||
             req.headers['cf-connecting-ip'] || // Cloudflare
             req.headers['fastly-client-ip'] || // Fastly
             req.headers['true-client-ip'] || // Akamai and Cloudflare
             req.headers['x-cluster-client-ip'] ||
             'Unknown';

    // Handle array format (x-forwarded-for can be comma-separated)
    if (Array.isArray(ip)) {
      ip = ip[0];
    } else if (typeof ip === 'string' && ip.includes(',')) {
      ip = ip.split(',')[0].trim();
    }

    // Clean up IP address
    if (ip) {
      // Remove IPv6 prefix
      if (ip.includes('::ffff:')) {
        ip = ip.split(':').pop();
      }
      // Remove port numbers
      if (ip.includes(':')) {
        ip = ip.split(':')[0];
      }
    }

    let location = 'Unknown Location';
    let isPublicIP = true;

    // Enhanced private IP range detection
    const privateIPRanges = [
      /^10\./, // 10.0.0.0/8
      /^172\.(1[6-9]|2[0-9]|3[0-1])\./, // 172.16.0.0/12
      /^192\.168\./, // 192.168.0.0/16
      /^127\./, // localhost
      /^169\.254\./, // link-local
      /^::1$/, // IPv6 localhost
      /^fc00::/, // IPv6 private
      /^fd00::/, // IPv6 private
      /^fe80::/ // IPv6 link-local
    ];

    // Check if IP is private
    for (const range of privateIPRanges) {
      if (range.test(ip)) {
        isPublicIP = false;
        location = 'Local Network';
        break;
      }
    }

    // Only try location lookup for public IPs
    if (isPublicIP && ip && ip !== 'Unknown') {
      try {
        console.log(`Looking up location for IP: ${ip}`);
        
        // Try multiple IP geolocation services as fallback
        const ipinfoToken = process.env.IPINFO_TOKEN || 'b56ce6e91d732d';
        
        // First try ipinfo.io
        try {
          const response = await axios.get(`https://ipinfo.io/${ip}?token=${ipinfoToken}`, {
            timeout: 5000
          });
          
          if (response.data) {
            const { city, region, country, loc, org, timezone } = response.data;
            location = `${city || 'Unknown'}, ${region || 'Unknown'}, ${country || 'Unknown'}`;
            
            console.log(`IPInfo.io location result: ${location}`);
          }
        } catch (ipinfoError) {
          console.log('IPInfo.io failed, trying fallback services...');
          
          // Fallback 1: ipapi.co
          try {
            const response = await axios.get(`https://ipapi.co/${ip}/json/`, {
              timeout: 5000
            });
            
            if (response.data) {
              const { city, region, country_name, country_code } = response.data;
              location = `${city || 'Unknown'}, ${region || 'Unknown'}, ${country_name || country_code || 'Unknown'}`;
              console.log(`IPApi.co location result: ${location}`);
            }
          } catch (ipapiError) {
            // Fallback 2: freeipapi.com
            try {
              const response = await axios.get(`https://freeipapi.com/api/json/${ip}`, {
                timeout: 5000
              });
              
              if (response.data) {
                const { cityName, regionName, countryName } = response.data;
                location = `${cityName || 'Unknown'}, ${regionName || 'Unknown'}, ${countryName || 'Unknown'}`;
                console.log(`FreeIPAPI location result: ${location}`);
              }
            } catch (freeipapiError) {
              // Final fallback: ip-api.com
              try {
                const response = await axios.get(`http://ip-api.com/json/${ip}`, {
                  timeout: 5000
                });
                
                if (response.data && response.data.status === 'success') {
                  const { city, regionName, country } = response.data;
                  location = `${city || 'Unknown'}, ${regionName || 'Unknown'}, ${country || 'Unknown'}`;
                  console.log(`IP-API.com location result: ${location}`);
                }
              } catch (ipapiComError) {
                location = 'Location Service Unavailable';
                console.log('All location services failed');
              }
            }
          }
        }
      } catch (err) {
        console.error('All location lookup services failed:', err.message);
        location = 'Location Unavailable';
      }
    } else if (!isPublicIP) {
      console.log(`Private IP detected: ${ip}, using local network location`);
    }

    return {
      ip: ip || 'Unknown',
      device: req.headers['user-agent'] || 'Unknown',
      location: location,
      isPublicIP: isPublicIP
    };
  } catch (err) {
    console.error('Error getting device info:', err);
    return {
      ip: req.ip || 'Unknown',
      device: req.headers['user-agent'] || 'Unknown',
      location: 'Unknown',
      isPublicIP: false
    };
  }
};
const logActivity = async (action, entity, entityId, performedBy, performedByModel, req, changes = {}) => {
  try {
    const deviceInfo = await getUserDeviceInfo(req);
    
    // Enhanced location data
    const locationData = {
      ip: deviceInfo.ip,
      location: deviceInfo.location,
      isPublicIP: deviceInfo.isPublicIP,
      userAgent: deviceInfo.device,
      detectedAt: new Date()
    };
    
    await SystemLog.create({
      action,
      entity,
      entityId,
      performedBy,
      performedByModel,
      ip: locationData.ip,
      device: locationData.userAgent,
      location: locationData.location,
      changes: {
        ...changes,
        locationData: locationData
      }
    });
    
    console.log(`Activity Logged: ${action}`, {
      entity,
      entityId,
      location: locationData.location,
      ip: locationData.ip,
      isPublicIP: locationData.isPublicIP
    });
  } catch (err) {
    console.error('Error logging activity:', err);
  }
};

const generateTOTPSecret = () => {
  return speakeasy.generateSecret({
    length: 20,
    name: 'BitHash',
    issuer: 'BitHash LLC'
  });
};

const verifyTOTP = (token, secret) => {
  return speakeasy.totp.verify({
    secret,
    encoding: 'base32',
    token,
    window: 2
  });
};



// Initialize default admin and plans
const initializeAdmin = async () => {
  try {
    const adminExists = await Admin.findOne({ email: 'admin@bithash.com' });
    if (!adminExists) {
      const hashedPassword = await bcrypt.hash(process.env.DEFAULT_ADMIN_PASSWORD || 'SecureAdminPassword123!', 12);
      await Admin.create({
        email: 'admin@bithash.com',
        password: hashedPassword,
        name: 'Super Admin',
        role: 'super',
        permissions: ['all'],
        passwordChangedAt: Date.now()
      });
      console.log('Default admin created');
    }
  } catch (err) {
    console.error('Error initializing admin:', err);
  }
};

const initializePlans = async () => {
  try {
    const plans = [
      {
        name: 'Starter Plan',
        description: '12% After 10 hours',
        percentage: 12,
        duration: 10,
        minAmount: 50,
        maxAmount: 499,
        referralBonus: 5
      },
      {
        name: 'Gold Plan',
        description: '20% After 24 hours',
        percentage: 20,
        duration: 24,
        minAmount: 500,
        maxAmount: 1999,
        referralBonus: 5
      },
      {
        name: 'Advance Plan',
        description: '35% After 48 hours',
        percentage: 35,
        duration: 48,
        minAmount: 2000,
        maxAmount: 9999,
        referralBonus: 5
      },
      {
        name: 'Exclusive Plan',
        description: '40% After 72 hours',
        percentage: 40,
        duration: 72,
        minAmount: 10000,
        maxAmount: 49999,
        referralBonus: 5
      },
      {
        name: 'Expert Plan',
        description: '50% After 96 hours',
        percentage: 50,
        duration: 96,
        minAmount: 50000,
        maxAmount: 1000000,
        referralBonus: 5
      }
    ];

    for (const plan of plans) {
      const existingPlan = await Plan.findOne({ name: plan.name });
      if (!existingPlan) {
        await Plan.create(plan);
      }
    }
  } catch (err) {
    console.error('Error initializing plans:', err);
  }
};

initializeAdmin();
initializePlans();

// Middleware with enhanced security
const protect = async (req, res, next) => {
  try {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
      token = req.headers.authorization.split(' ')[1];
    } else if (req.cookies.jwt) {
      token = req.cookies.jwt;
    }

    if (!token) {
      return res.status(401).json({
        status: 'fail',
        message: 'You are not logged in! Please log in to get access.'
      });
    }

    const decoded = verifyJWT(token);
    const currentUser = await User.findById(decoded.id).select('+passwordChangedAt +twoFactorAuth.secret');

    if (!currentUser) {
      return res.status(401).json({
        status: 'fail',
        message: 'The user belonging to this token no longer exists.'
      });
    }

    if (currentUser.passwordChangedAt && decoded.iat < currentUser.passwordChangedAt.getTime() / 1000) {
      return res.status(401).json({
        status: 'fail',
        message: 'User recently changed password! Please log in again.'
      });
    }

    if (currentUser.status !== 'active') {
      return res.status(401).json({
        status: 'fail',
        message: 'Your account has been suspended. Please contact support.'
      });
    }

    // Check if 2FA is required
    if (currentUser.twoFactorAuth.enabled && !req.headers['x-2fa-verified']) {
      return res.status(401).json({
        status: 'fail',
        message: 'Two-factor authentication required'
      });
    }

    req.user = currentUser;
    next();
  } catch (err) {
    return res.status(401).json({
      status: 'fail',
      message: err.message || 'Invalid token. Please log in again.'
    });
  }
};

const adminProtect = async (req, res, next) => {
  try {
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

    const decoded = verifyJWT(token);
    if (!decoded.isAdmin) {
      return res.status(403).json({
        status: 'fail',
        message: 'You do not have permission to access this resource'
      });
    }

    const currentAdmin = await Admin.findById(decoded.id).select('+passwordChangedAt +twoFactorAuth.secret');
    if (!currentAdmin) {
      return res.status(401).json({
        status: 'fail',
        message: 'The admin belonging to this token no longer exists.'
      });
    }

    // Check if 2FA is required
    if (currentAdmin.twoFactorAuth.enabled && !req.headers['x-2fa-verified']) {
      return res.status(401).json({
        status: 'fail',
        message: 'Two-factor authentication required'
      });
    }

    req.admin = currentAdmin;
    next();
  } catch (err) {
    return res.status(401).json({
      status: 'fail',
      message: err.message || 'Invalid token. Please log in again.'
    });
  }
};

const restrictTo = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.admin.role)) {
      return res.status(403).json({
        status: 'fail',
        message: 'You do not have permission to perform this action'
      });
    }
    next();
  };
};

const checkCSRF = (req, res, next) => {
  if (req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS') {
    return next();
  }

  const csrfToken = req.headers['x-csrf-token'] || req.body._csrf;
  if (!csrfToken || !req.session.csrfToken || csrfToken !== req.session.csrfToken) {
    return res.status(403).json({
      status: 'fail',
      message: 'Invalid CSRF token'
    });
  }
  next();
};


// Fixed function to calculate and distribute downline referral commissions
const calculateReferralCommissions = async (investment) => {
  try {
    // First, populate the investment with user data
    const populatedInvestment = await Investment.findById(investment._id)
      .populate('user', 'firstName lastName email')
      .populate('plan');

    if (!populatedInvestment) {
      console.log(`❌ Investment not found: ${investment._id}`);
      return;
    }

    const investmentId = populatedInvestment._id;
    const investorId = populatedInvestment.user._id;
    const investmentAmount = populatedInvestment.amount;

    console.log(`🔍 Checking downline commissions for investment: ${investmentId}, user: ${investorId}, amount: $${investmentAmount}`);

    // Find the downline relationship for this investor (check if they have an upline)
    const relationship = await DownlineRelationship.findOne({
      downline: investorId,
      status: 'active',
      remainingRounds: { $gt: 0 }
    }).populate('upline', 'firstName lastName email balances referralStats downlineStats');

    if (!relationship) {
      console.log(`❌ No active downline relationship found for user: ${investorId}`);
      return; // No upline found or no commission rounds remaining
    }

    const uplineId = relationship.upline._id;
    const uplineUser = relationship.upline;
    const commissionPercentage = relationship.commissionPercentage;
    const commissionAmount = (investmentAmount * commissionPercentage) / 100;

    console.log(`💰 Downline commission: $${investmentAmount} * ${commissionPercentage}% = $${commissionAmount} for upline: ${uplineUser.email}`);

    // Create commission history record
    const commissionHistory = await CommissionHistory.create({
      upline: uplineId,
      downline: investorId,
      investment: investmentId,
      investmentAmount: investmentAmount,
      commissionPercentage: commissionPercentage,
      commissionAmount: commissionAmount,
      roundNumber: relationship.commissionRounds - relationship.remainingRounds + 1,
      status: 'paid',
      paidAt: new Date()
    });

    // ✅ FIXED: Add commission to upline's MAIN balance as requested
    const updatedUpline = await User.findByIdAndUpdate(
      uplineId,
      {
        $inc: {
          'balances.main': commissionAmount, // Added to main balance
          'referralStats.totalEarnings': commissionAmount,
          'referralStats.availableBalance': commissionAmount,
          'downlineStats.totalCommissionEarned': commissionAmount,
          'downlineStats.thisMonthCommission': commissionAmount
        }
      },
      { new: true }
    );

    console.log(`✅ Updated upline ${uplineUser.email} MAIN balance with $${commissionAmount}. New balance: $${updatedUpline.balances.main}`);

    // Update downline relationship
    relationship.remainingRounds -= 1;
    relationship.totalCommissionEarned += commissionAmount;
    
    if (relationship.remainingRounds === 0) {
      relationship.status = 'completed';
      console.log(`🎯 Commission rounds completed for relationship: ${relationship._id}`);
    }

    await relationship.save();

    // Create transaction record for the commission
    await Transaction.create({
      user: uplineId,
      type: 'referral',
      amount: commissionAmount,
      currency: 'USD',
      status: 'completed',
      method: 'internal',
      reference: `DOWNLINE-COMM-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
      details: {
        commissionFrom: investorId,
        investmentId: investmentId,
        round: relationship.commissionRounds - relationship.remainingRounds + 1,
        totalRounds: relationship.commissionRounds,
        commissionType: 'downline',
        downlineName: `${populatedInvestment.user.firstName} ${populatedInvestment.user.lastName}`,
        percentage: commissionPercentage
      },
      fee: 0,
      netAmount: commissionAmount
    });

    // Add to upline's referral history
    await User.findByIdAndUpdate(uplineId, {
      $push: {
        referralHistory: {
          referredUser: investorId,
          amount: commissionAmount,
          percentage: commissionPercentage,
          level: 1, // Direct downline
          date: new Date(),
          status: 'available',
          type: 'downline_commission'
        }
      }
    });

    // Update downline stats count
    const activeDownlinesCount = await DownlineRelationship.countDocuments({ 
      upline: uplineId, 
      status: 'active',
      remainingRounds: { $gt: 0 }
    });

    await User.findByIdAndUpdate(uplineId, {
      'downlineStats.activeDownlines': activeDownlinesCount
    });

    console.log(`🎉 Downline commission of $${commissionAmount} paid to upline ${uplineUser.email} for investment ${investmentId} (Round ${relationship.commissionRounds - relationship.remainingRounds + 1}/${relationship.commissionRounds})`);

    // Log the activity
    await logActivity('downline_commission_paid', 'commission', commissionHistory._id, uplineId, 'User', null, {
      amount: commissionAmount,
      downline: investorId,
      investment: investmentId,
      round: relationship.commissionRounds - relationship.remainingRounds + 1,
      totalRounds: relationship.commissionRounds,
      percentage: commissionPercentage
    });

  } catch (err) {
    console.error('❌ Downline commission calculation error:', err);
    // Don't throw error to avoid disrupting investment process
  }
};


































    
// Enhanced email service with professional Bitcoin mining templates
const sendProfessionalEmail = async (options) => {
  try {
    const { email, subject, template, data } = options;
    
    const emailTemplates = {
      // WELCOME EMAIL
      welcome: {
        subject: 'Welcome to BitHash Capital - Your Mining Journey Begins',
        html: `
          <!DOCTYPE html>
          <html>
          <head>
              <meta charset="utf-8">
              <meta name="viewport" content="width=device-width, initial-scale=1.0">
              <title>Welcome to BitHash Capital</title>
              <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
              <style>
                  * { margin: 0; padding: 0; box-sizing: border-box; }
                  body { font-family: 'Inter', Arial, sans-serif; line-height: 1.6; color: #1a1a1a; background-color: #f8f9fa; margin: 0; padding: 0; }
                  .container { max-width: 600px; margin: 0 auto; background: #ffffff; }
                  .header { background: #0a0a0a; padding: 30px 40px; text-align: center; border-bottom: 3px solid #f0b90b; }
                  .logo-container { display: flex; align-items: center; justify-content: center; gap: 15px; margin-bottom: 20px; }
                  .logo-img { width: 50px; height: 50px; border-radius: 50%; }
                  .logo-text { font-size: 28px; font-weight: 700; color: #f0b90b; letter-spacing: -0.5px; }
                  .header-title { font-size: 24px; font-weight: 600; color: #ffffff; margin-top: 10px; }
                  .content { padding: 40px; background: #ffffff; }
                  .greeting { font-size: 18px; color: #1a1a1a; margin-bottom: 25px; font-weight: 500; }
                  .features-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 15px; margin: 30px 0; }
                  .feature-card { background: #f8f9fa; padding: 20px; border-radius: 8px; border-left: 3px solid #f0b90b; }
                  .feature-title { font-weight: 600; color: #0a0a0a; margin-bottom: 8px; font-size: 14px; }
                  .feature-desc { color: #666; font-size: 13px; line-height: 1.4; }
                  .benefits-list { margin: 25px 0; }
                  .benefit-item { display: flex; align-items: center; margin-bottom: 12px; color: #333; }
                  .benefit-icon { color: #f0b90b; margin-right: 12px; font-weight: bold; }
                  .cta-button { background: #f0b90b; color: #0a0a0a; padding: 14px 35px; text-decoration: none; border-radius: 6px; display: inline-block; margin: 25px 0; font-weight: 600; font-size: 15px; text-align: center; }
                  .security-note { background: #fff8e6; border: 1px solid #f0b90b; padding: 20px; border-radius: 6px; margin: 25px 0; }
                  .footer { background: #0a0a0a; padding: 30px 40px; text-align: center; color: #999; }
                  .footer-text { font-size: 12px; line-height: 1.5; margin-bottom: 10px; }
                  .support-link { color: #f0b90b; text-decoration: none; }
              </style>
          </head>
          <body>
              <div class="container">
                  <div class="header">
                      <div class="logo-container">
                          <img src="https://www.dropbox.com/scl/fi/1dq16nex1borvvknpcwox/circular_dark_background.png?rlkey=sq2ujl2oxxk9vyvg1j7oz0cdb&raw=1" alt="BitHash Logo" class="logo-img">
                          <div class="logo-text">BitHash Capital</div>
                      </div>
                      <h1 class="header-title">Welcome to Professional Mining</h1>
                  </div>
                  <div class="content">
                      <h2 class="greeting">Hello ${data.firstName},</h2>
                      <p>Welcome to BitHash Capital! We're excited to have you join our community of professional Bitcoin miners and investors.</p>
                      
                      <div class="features-grid">
                          <div class="feature-card">
                              <div class="feature-title">Cloud Mining</div>
                              <div class="feature-desc">Start mining Bitcoin instantly with our enterprise-grade mining infrastructure</div>
                          </div>
                          <div class="feature-card">
                              <div class="feature-title">Smart Investment</div>
                              <div class="feature-desc">Choose from optimized investment plans designed for maximum returns</div>
                          </div>
                          <div class="feature-card">
                              <div class="feature-title">Secure Platform</div>
                              <div class="feature-desc">Enterprise-grade security protecting your assets and mining operations</div>
                          </div>
                          <div class="feature-card">
                              <div class="feature-title">24/7 Support</div>
                              <div class="feature-desc">Dedicated support team available around the clock for your mining needs</div>
                          </div>
                      </div>
                      
                      <div class="benefits-list">
                          <div class="benefit-item">
                              <span class="benefit-icon">•</span>
                              <span>Access enterprise-grade Bitcoin mining infrastructure</span>
                          </div>
                          <div class="benefit-item">
                              <span class="benefit-icon">•</span>
                              <span>Invest in optimized mining plans with competitive returns</span>
                          </div>
                          <div class="benefit-item">
                              <span class="benefit-icon">•</span>
                              <span>Monitor your mining operations in real-time</span>
                          </div>
                          <div class="benefit-item">
                              <span class="benefit-icon">•</span>
                              <span>Earn referral bonuses by expanding our mining community</span>
                          </div>
                      </div>
                      
                      <div style="text-align: center;">
                          <a href="https://www.bithashcapital.live/dashboard.html" class="cta-button">Start Mining Now</a>
                      </div>
                      
                      <div class="security-note">
                          <strong>Security Notice:</strong> Your account security is our priority. We recommend enabling two-factor authentication and using strong, unique passwords.
                      </div>
                      
                      <p>If you have any questions about our mining operations or investment plans, our support team is available 24/7.</p>
                      
                      <p>Best regards,<br><strong>The BitHash Capital Team</strong></p>
                  </div>
                  <div class="footer">
                      <p class="footer-text">© 2024 BitHash Capital. All rights reserved.<br>
                      Professional Bitcoin Mining and Investment Platform</p>
                      <p class="footer-text">This email was sent to ${email}. Please do not reply to this email.<br>
                      Need assistance? <a href="mailto:support@bithashcapital.live" class="support-link">Contact Support</a></p>
                  </div>
              </div>
          </body>
          </html>
        `
      },




      
      // OTP VERIFICATION
      otp: {
        subject: 'BitHash Capital - Verification Code Required',
        html: `
          <!DOCTYPE html>
          <html>
          <head>
              <meta charset="utf-8">
              <meta name="viewport" content="width=device-width, initial-scale=1.0">
              <title>Verification Code - BitHash Capital</title>
              <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
              <style>
                  * { margin: 0; padding: 0; box-sizing: border-box; }
                  body { font-family: 'Inter', Arial, sans-serif; line-height: 1.6; color: #1a1a1a; background-color: #f8f9fa; margin: 0; padding: 0; }
                  .container { max-width: 600px; margin: 0 auto; background: #ffffff; }
                  .header { background: #0a0a0a; padding: 30px 40px; text-align: center; border-bottom: 3px solid #f0b90b; }
                  .logo-container { display: flex; align-items: center; justify-content: center; gap: 15px; margin-bottom: 15px; }
                  .logo-img { width: 40px; height: 40px; border-radius: 50%; }
                  .logo-text { font-size: 24px; font-weight: 700; color: #f0b90b; letter-spacing: -0.5px; }
                  .content { padding: 40px; background: #ffffff; }
                  .otp-code { background: #0a0a0a; color: #f0b90b; padding: 20px; font-size: 36px; font-weight: 700; text-align: center; letter-spacing: 8px; margin: 30px 0; border-radius: 8px; font-family: 'Courier New', monospace; }
                  .security-note { background: #fff8e6; border: 1px solid #f0b90b; padding: 20px; border-radius: 6px; margin: 25px 0; }
                  .footer { background: #0a0a0a; padding: 25px 40px; text-align: center; color: #999; }
                  .footer-text { font-size: 12px; line-height: 1.5; }
              </style>
          </head>
          <body>
              <div class="container">
                  <div class="header">
                      <div class="logo-container">
                          <img src="https://www.dropbox.com/scl/fi/1dq16nex1borvvknpcwox/circular_dark_background.png?rlkey=sq2ujl2oxxk9vyvg1j7oz0cdb&raw=1" alt="BitHash Logo" class="logo-img">
                          <div class="logo-text">BitHash Capital</div>
                      </div>
                  </div>
                  <div class="content">
                      <h2>Hello ${data.name || 'there'},</h2>
                      <p>Please use the following verification code to complete your ${data.action || 'account verification'}:</p>
                      
                      <div class="otp-code">${data.otp}</div>
                      
                      <p>This code will expire in 5 minutes for security purposes.</p>
                      
                      <div class="security-note">
                          <strong>Security Notice:</strong> This verification code is valid for one-time use only. Do not share this code with anyone, including BitHash Capital support staff.
                      </div>
                      
                      <p>If you didn't request this code, please secure your account immediately and contact our support team.</p>
                      
                      <p>Best regards,<br><strong>BitHash Capital Security Team</strong></p>
                  </div>
                  <div class="footer">
                      <p class="footer-text">© 2024 BitHash Capital. All rights reserved.<br>
                      This is an automated security message. Please do not reply.</p>
                  </div>
              </div>
          </body>
          </html>
        `
      },

      // LOGIN SUCCESS
      login_success: {
        subject: 'BitHash Capital - Successful Login Detected',
        html: `
          <!DOCTYPE html>
          <html>
          <head>
              <meta charset="utf-8">
              <meta name="viewport" content="width=device-width, initial-scale=1.0">
              <title>Login Notification - BitHash Capital</title>
              <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
              <style>
                  * { margin: 0; padding: 0; box-sizing: border-box; }
                  body { font-family: 'Inter', Arial, sans-serif; line-height: 1.6; color: #1a1a1a; background-color: #f8f9fa; margin: 0; padding: 0; }
                  .container { max-width: 600px; margin: 0 auto; background: #ffffff; }
                  .header { background: #0a0a0a; padding: 30px 40px; text-align: center; border-bottom: 3px solid #27ae60; }
                  .logo-container { display: flex; align-items: center; justify-content: center; gap: 15px; margin-bottom: 15px; }
                  .logo-img { width: 40px; height: 40px; border-radius: 50%; }
                  .logo-text { font-size: 24px; font-weight: 700; color: #f0b90b; letter-spacing: -0.5px; }
                  .content { padding: 40px; background: #ffffff; }
                  .login-info { background: #f8f9fa; padding: 25px; border-radius: 8px; margin: 25px 0; border-left: 4px solid #27ae60; }
                  .info-item { margin-bottom: 10px; display: flex; }
                  .info-label { font-weight: 600; min-width: 120px; color: #333; }
                  .security-alert { background: #fee; border: 1px solid #e74c3c; padding: 20px; border-radius: 6px; margin: 20px 0; }
                  .footer { background: #0a0a0a; padding: 25px 40px; text-align: center; color: #999; }
                  .footer-text { font-size: 12px; line-height: 1.5; }
              </style>
          </head>
          <body>
              <div class="container">
                  <div class="header">
                      <div class="logo-container">
                          <img src="https://www.dropbox.com/scl/fi/1dq16nex1borvvknpcwox/circular_dark_background.png?rlkey=sq2ujl2oxxk9vyvg1j7oz0cdb&raw=1" alt="BitHash Logo" class="logo-img">
                          <div class="logo-text">BitHash Capital</div>
                      </div>
                  </div>
                  <div class="content">
                      <h2>Hello ${data.name},</h2>
                      <p>A successful login to your BitHash Capital account was detected:</p>
                      
                      <div class="login-info">
                          <div class="info-item">
                              <span class="info-label">Time:</span>
                              <span>${new Date().toLocaleString()}</span>
                          </div>
                          <div class="info-item">
                              <span class="info-label">Device:</span>
                              <span>${data.device || 'Unknown device'}</span>
                          </div>
                          <div class="info-item">
                              <span class="info-label">Location:</span>
                              <span>${data.location || 'Unknown location'}</span>
                          </div>
                          <div class="info-item">
                              <span class="info-label">IP Address:</span>
                              <span>${data.ip || 'Unknown'}</span>
                          </div>
                      </div>
                      
                      <p>If this was you, no further action is required. You may continue using your account normally.</p>
                      
                      ${data.suspicious ? `
                      <div class="security-alert">
                          <strong>Security Alert:</strong> This login attempt appears suspicious. If this wasn't you, please secure your account immediately by changing your password and enabling two-factor authentication.
                      </div>
                      ` : ''}
                      
                      <p>Best regards,<br><strong>BitHash Capital Security Team</strong></p>
                  </div>
                  <div class="footer">
                      <p class="footer-text">© 2024 BitHash Capital. All rights reserved.<br>
                      This is an automated security notification.</p>
                  </div>
              </div>
          </body>
          </html>
        `
      },

      // PASSWORD RESET
      password_reset: {
        subject: 'BitHash Capital - Password Reset Request',
        html: `
          <!DOCTYPE html>
          <html>
          <head>
              <meta charset="utf-8">
              <meta name="viewport" content="width=device-width, initial-scale=1.0">
              <title>Password Reset - BitHash Capital</title>
              <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
              <style>
                  * { margin: 0; padding: 0; box-sizing: border-box; }
                  body { font-family: 'Inter', Arial, sans-serif; line-height: 1.6; color: #1a1a1a; background-color: #f8f9fa; margin: 0; padding: 0; }
                  .container { max-width: 600px; margin: 0 auto; background: #ffffff; }
                  .header { background: #0a0a0a; padding: 30px 40px; text-align: center; border-bottom: 3px solid #e74c3c; }
                  .logo-container { display: flex; align-items: center; justify-content: center; gap: 15px; margin-bottom: 15px; }
                  .logo-img { width: 40px; height: 40px; border-radius: 50%; }
                  .logo-text { font-size: 24px; font-weight: 700; color: #f0b90b; letter-spacing: -0.5px; }
                  .content { padding: 40px; background: #ffffff; }
                  .reset-button { background: #e74c3c; color: white; padding: 14px 35px; text-decoration: none; border-radius: 6px; display: inline-block; margin: 25px 0; font-weight: 600; font-size: 15px; }
                  .security-note { background: #fee; border: 1px solid #e74c3c; padding: 20px; border-radius: 6px; margin: 25px 0; }
                  .footer { background: #0a0a0a; padding: 25px 40px; text-align: center; color: #999; }
                  .footer-text { font-size: 12px; line-height: 1.5; }
              </style>
          </head>
          <body>
              <div class="container">
                  <div class="header">
                      <div class="logo-container">
                          <img src="https://www.dropbox.com/scl/fi/1dq16nex1borvvknpcwox/circular_dark_background.png?rlkey=sq2ujl2oxxk9vyvg1j7oz0cdb&raw=1" alt="BitHash Logo" class="logo-img">
                          <div class="logo-text">BitHash Capital</div>
                      </div>
                  </div>
                  <div class="content">
                      <h2>Hello ${data.name},</h2>
                      <p>We received a request to reset your BitHash Capital account password.</p>
                      
                      <div style="text-align: center;">
                          <a href="${data.resetUrl}" class="reset-button">Reset Your Password</a>
                      </div>
                      
                      <p>This password reset link will expire in 60 minutes for security reasons.</p>
                      
                      <div class="security-note">
                          <strong>Security Notice:</strong> If you didn't request this password reset, please ignore this email. Your account remains secure. For additional protection, we recommend enabling two-factor authentication.
                      </div>
                      
                      <p>Best regards,<br><strong>BitHash Capital Security Team</strong></p>
                  </div>
                  <div class="footer">
                      <p class="footer-text">© 2024 BitHash Capital. All rights reserved.<br>
                      This is an automated security message.</p>
                  </div>
              </div>
          </body>
          </html>
        `
      },

      // INVESTMENT CREATED
      investment_created: {
        subject: 'BitHash Capital - Investment Confirmation',
        html: `
          <!DOCTYPE html>
          <html>
          <head>
              <meta charset="utf-8">
              <meta name="viewport" content="width=device-width, initial-scale=1.0">
              <title>Investment Confirmation - BitHash Capital</title>
              <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
              <style>
                  * { margin: 0; padding: 0; box-sizing: border-box; }
                  body { font-family: 'Inter', Arial, sans-serif; line-height: 1.6; color: #1a1a1a; background-color: #f8f9fa; margin: 0; padding: 0; }
                  .container { max-width: 600px; margin: 0 auto; background: #ffffff; }
                  .header { background: #0a0a0a; padding: 30px 40px; text-align: center; border-bottom: 3px solid #f0b90b; }
                  .logo-container { display: flex; align-items: center; justify-content: center; gap: 15px; margin-bottom: 15px; }
                  .logo-img { width: 40px; height: 40px; border-radius: 50%; }
                  .logo-text { font-size: 24px; font-weight: 700; color: #f0b90b; letter-spacing: -0.5px; }
                  .content { padding: 40px; background: #ffffff; }
                  .investment-details { background: #f8f9fa; padding: 25px; border-radius: 8px; margin: 25px 0; border-left: 4px solid #f0b90b; }
                  .detail-item { margin-bottom: 12px; display: flex; justify-content: space-between; }
                  .detail-label { font-weight: 600; color: #333; }
                  .detail-value { color: #0a0a0a; font-weight: 500; }
                  .cta-button { background: #f0b90b; color: #0a0a0a; padding: 12px 30px; text-decoration: none; border-radius: 6px; display: inline-block; margin: 20px 0; font-weight: 600; }
                  .footer { background: #0a0a0a; padding: 25px 40px; text-align: center; color: #999; }
                  .footer-text { font-size: 12px; line-height: 1.5; }
              </style>
          </head>
          <body>
              <div class="container">
                  <div class="header">
                      <div class="logo-container">
                          <img src="https://www.dropbox.com/scl/fi/1dq16nex1borvvknpcwox/circular_dark_background.png?rlkey=sq2ujl2oxxk9vyvg1j7oz0cdb&raw=1" alt="BitHash Logo" class="logo-img">
                          <div class="logo-text">BitHash Capital</div>
                      </div>
                  </div>
                  <div class="content">
                      <h2>Hello ${data.name},</h2>
                      <p>Your investment has been successfully created and is now active.</p>
                      
                      <div class="investment-details">
                          <div class="detail-item">
                              <span class="detail-label">Investment Plan:</span>
                              <span class="detail-value">${data.planName}</span>
                          </div>
                          <div class="detail-item">
                              <span class="detail-label">Amount:</span>
                              <span class="detail-value">$${data.amount}</span>
                          </div>
                          <div class="detail-item">
                              <span class="detail-label">Expected Return:</span>
                              <span class="detail-value">$${data.expectedReturn}</span>
                          </div>
                          <div class="detail-item">
                              <span class="detail-label">Duration:</span>
                              <span class="detail-value">${data.duration}</span>
                          </div>
                          <div class="detail-item">
                              <span class="detail-label">Start Date:</span>
                              <span class="detail-value">${new Date(data.startDate).toLocaleDateString()}</span>
                          </div>
                          <div class="detail-item">
                              <span class="detail-label">End Date:</span>
                              <span class="detail-value">${new Date(data.endDate).toLocaleDateString()}</span>
                          </div>
                      </div>
                      
                      <p>You can monitor your investment performance in real-time through your dashboard.</p>
                      
                      <div style="text-align: center;">
                          <a href="https://www.bithashcapital.live/dashboard.html" class="cta-button">View Dashboard</a>
                      </div>
                      
                      <p>Best regards,<br><strong>BitHash Capital Investment Team</strong></p>
                  </div>
                  <div class="footer">
                      <p class="footer-text">© 2024 BitHash Capital. All rights reserved.<br>
                      Professional Bitcoin Mining and Investment Platform</p>
                  </div>
              </div>
          </body>
          </html>
        `
      },

      // WITHDRAWAL REQUEST
      withdrawal_request: {
        subject: 'BitHash Capital - Withdrawal Request Received',
        html: `
          <!DOCTYPE html>
          <html>
          <head>
              <meta charset="utf-8">
              <meta name="viewport" content="width=device-width, initial-scale=1.0">
              <title>Withdrawal Request - BitHash Capital</title>
              <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
              <style>
                  * { margin: 0; padding: 0; box-sizing: border-box; }
                  body { font-family: 'Inter', Arial, sans-serif; line-height: 1.6; color: #1a1a1a; background-color: #f8f9fa; margin: 0; padding: 0; }
                  .container { max-width: 600px; margin: 0 auto; background: #ffffff; }
                  .header { background: #0a0a0a; padding: 30px 40px; text-align: center; border-bottom: 3px solid #3498db; }
                  .logo-container { display: flex; align-items: center; justify-content: center; gap: 15px; margin-bottom: 15px; }
                  .logo-img { width: 40px; height: 40px; border-radius: 50%; }
                  .logo-text { font-size: 24px; font-weight: 700; color: #f0b90b; letter-spacing: -0.5px; }
                  .content { padding: 40px; background: #ffffff; }
                  .withdrawal-details { background: #f8f9fa; padding: 25px; border-radius: 8px; margin: 25px 0; border-left: 4px solid #3498db; }
                  .detail-item { margin-bottom: 12px; display: flex; justify-content: space-between; }
                  .detail-label { font-weight: 600; color: #333; }
                  .detail-value { color: #0a0a0a; font-weight: 500; }
                  .processing-info { background: #e8f4fd; border: 1px solid #3498db; padding: 20px; border-radius: 6px; margin: 25px 0; }
                  .footer { background: #0a0a0a; padding: 25px 40px; text-align: center; color: #999; }
                  .footer-text { font-size: 12px; line-height: 1.5; }
              </style>
          </head>
          <body>
              <div class="container">
                  <div class="header">
                      <div class="logo-container">
                          <img src="https://www.dropbox.com/scl/fi/1dq16nex1borvvknpcwox/circular_dark_background.png?rlkey=sq2ujl2oxxk9vyvg1j7oz0cdb&raw=1" alt="BitHash Logo" class="logo-img">
                          <div class="logo-text">BitHash Capital</div>
                      </div>
                  </div>
                  <div class="content">
                      <h2>Hello ${data.name},</h2>
                      <p>Your withdrawal request has been received and is being processed.</p>
                      
                      <div class="withdrawal-details">
                          <div class="detail-item">
                              <span class="detail-label">Amount:</span>
                              <span class="detail-value">$${data.amount}</span>
                          </div>
                          <div class="detail-item">
                              <span class="detail-label">Method:</span>
                              <span class="detail-value">${data.method}</span>
                          </div>
                          <div class="detail-item">
                              <span class="detail-label">Reference:</span>
                              <span class="detail-value">${data.reference}</span>
                          </div>
                          <div class="detail-item">
                              <span class="detail-label">Fee:</span>
                              <span class="detail-value">$${data.fee}</span>
                          </div>
                          <div class="detail-item">
                              <span class="detail-label">Net Amount:</span>
                              <span class="detail-value">$${data.netAmount}</span>
                          </div>
                      </div>
                      
                      <div class="processing-info">
                          <strong>Processing Information:</strong> Withdrawals are typically processed within 24 hours. You will receive another notification once your withdrawal has been completed.
                      </div>
                      
                      <p>If you did not initiate this withdrawal, please contact our security team immediately.</p>
                      
                      <p>Best regards,<br><strong>BitHash Capital Finance Team</strong></p>
                  </div>
                  <div class="footer">
                      <p class="footer-text">© 2024 BitHash Capital. All rights reserved.<br>
                      Professional Bitcoin Mining and Investment Platform</p>
                  </div>
              </div>
          </body>
          </html>
        `
      },

      // KYC APPROVED
      kyc_approved: {
        subject: 'BitHash Capital - KYC Verification Approved',
        html: `
          <!DOCTYPE html>
          <html>
          <head>
              <meta charset="utf-8">
              <meta name="viewport" content="width=device-width, initial-scale=1.0">
              <title>KYC Approved - BitHash Capital</title>
              <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
              <style>
                  * { margin: 0; padding: 0; box-sizing: border-box; }
                  body { font-family: 'Inter', Arial, sans-serif; line-height: 1.6; color: #1a1a1a; background-color: #f8f9fa; margin: 0; padding: 0; }
                  .container { max-width: 600px; margin: 0 auto; background: #ffffff; }
                  .header { background: #0a0a0a; padding: 30px 40px; text-align: center; border-bottom: 3px solid #27ae60; }
                  .logo-container { display: flex; align-items: center; justify-content: center; gap: 15px; margin-bottom: 15px; }
                  .logo-img { width: 40px; height: 40px; border-radius: 50%; }
                  .logo-text { font-size: 24px; font-weight: 700; color: #f0b90b; letter-spacing: -0.5px; }
                  .content { padding: 40px; background: #ffffff; }
                  .success-message { background: #e8f6ef; border: 1px solid #27ae60; padding: 25px; border-radius: 8px; margin: 25px 0; text-align: center; }
                  .benefits-list { margin: 25px 0; }
                  .benefit-item { display: flex; align-items: center; margin-bottom: 12px; color: #333; }
                  .benefit-icon { color: #27ae60; margin-right: 12px; font-weight: bold; }
                  .cta-button { background: #f0b90b; color: #0a0a0a; padding: 12px 30px; text-decoration: none; border-radius: 6px; display: inline-block; margin: 20px 0; font-weight: 600; }
                  .footer { background: #0a0a0a; padding: 25px 40px; text-align: center; color: #999; }
                  .footer-text { font-size: 12px; line-height: 1.5; }
              </style>
          </head>
          <body>
              <div class="container">
                  <div class="header">
                      <div class="logo-container">
                          <img src="https://www.dropbox.com/scl/fi/1dq16nex1borvvknpcwox/circular_dark_background.png?rlkey=sq2ujl2oxxk9vyvg1j7oz0cdb&raw=1" alt="BitHash Logo" class="logo-img">
                          <div class="logo-text">BitHash Capital</div>
                      </div>
                  </div>
                  <div class="content">
                      <h2>Hello ${data.name},</h2>
                      
                      <div class="success-message">
                          <h3 style="color: #27ae60; margin-bottom: 10px;">KYC Verification Approved</h3>
                          <p>Your identity verification has been successfully completed and approved.</p>
                      </div>
                      
                      <p>With your KYC verification complete, you now have full access to all BitHash Capital features:</p>
                      
                      <div class="benefits-list">
                          <div class="benefit-item">
                              <span class="benefit-icon">•</span>
                              <span>Higher withdrawal limits</span>
                          </div>
                          <div class="benefit-item">
                              <span class="benefit-icon">•</span>
                              <span>Access to premium investment plans</span>
                          </div>
                          <div class="benefit-item">
                              <span class="benefit-icon">•</span>
                              <span>Enhanced security features</span>
                          </div>
                          <div class="benefit-item">
                              <span class="benefit-icon">•</span>
                              <span>Priority customer support</span>
                          </div>
                      </div>
                      
                      <div style="text-align: center;">
                          <a href="https://www.bithashcapital.live/dashboard.html" class="cta-button">Access Your Account</a>
                      </div>
                      
                      <p>Thank you for completing the verification process and helping us maintain a secure platform.</p>
                      
                      <p>Best regards,<br><strong>BitHash Capital Compliance Team</strong></p>
                  </div>
                  <div class="footer">
                      <p class="footer-text">© 2024 BitHash Capital. All rights reserved.<br>
                      Professional Bitcoin Mining and Investment Platform</p>
                  </div>
              </div>
          </body>
          </html>
        `
      },

      // DEPOSIT RECEIVED
      deposit_received: {
        subject: 'BitHash Capital - Deposit Successfully Received',
        html: `
          <!DOCTYPE html>
          <html>
          <head>
              <meta charset="utf-8">
              <meta name="viewport" content="width=device-width, initial-scale=1.0">
              <title>Deposit Received - BitHash Capital</title>
              <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
              <style>
                  * { margin: 0; padding: 0; box-sizing: border-box; }
                  body { font-family: 'Inter', Arial, sans-serif; line-height: 1.6; color: #1a1a1a; background-color: #f8f9fa; margin: 0; padding: 0; }
                  .container { max-width: 600px; margin: 0 auto; background: #ffffff; }
                  .header { background: #0a0a0a; padding: 30px 40px; text-align: center; border-bottom: 3px solid #27ae60; }
                  .logo-container { display: flex; align-items: center; justify-content: center; gap: 15px; margin-bottom: 15px; }
                  .logo-img { width: 40px; height: 40px; border-radius: 50%; }
                  .logo-text { font-size: 24px; font-weight: 700; color: #f0b90b; letter-spacing: -0.5px; }
                  .content { padding: 40px; background: #ffffff; }
                  .deposit-details { background: #f8f9fa; padding: 25px; border-radius: 8px; margin: 25px 0; border-left: 4px solid #27ae60; }
                  .detail-item { margin-bottom: 12px; display: flex; justify-content: space-between; }
                  .detail-label { font-weight: 600; color: #333; }
                  .detail-value { color: #0a0a0a; font-weight: 500; }
                  .cta-button { background: #f0b90b; color: #0a0a0a; padding: 12px 30px; text-decoration: none; border-radius: 6px; display: inline-block; margin: 20px 0; font-weight: 600; }
                  .footer { background: #0a0a0a; padding: 25px 40px; text-align: center; color: #999; }
                  .footer-text { font-size: 12px; line-height: 1.5; }
              </style>
          </head>
          <body>
              <div class="container">
                  <div class="header">
                      <div class="logo-container">
                          <img src="https://www.dropbox.com/scl/fi/1dq16nex1borvvknpcwox/circular_dark_background.png?rlkey=sq2ujl2oxxk9vyvg1j7oz0cdb&raw=1" alt="BitHash Logo" class="logo-img">
                          <div class="logo-text">BitHash Capital</div>
                      </div>
                  </div>
                  <div class="content">
                      <h2>Hello ${data.name},</h2>
                      <p>Your deposit has been successfully received and credited to your account.</p>
                      
                      <div class="deposit-details">
                          <div class="detail-item">
                              <span class="detail-label">Amount:</span>
                              <span class="detail-value">$${data.amount}</span>
                          </div>
                          <div class="detail-item">
                              <span class="detail-label">Method:</span>
                              <span class="detail-value">${data.method}</span>
                          </div>
                          <div class="detail-item">
                              <span class="detail-label">Reference:</span>
                              <span class="detail-value">${data.reference}</span>
                          </div>
                          <div class="detail-item">
                              <span class="detail-label">Date:</span>
                              <span class="detail-value">${new Date().toLocaleDateString()}</span>
                          </div>
                          <div class="detail-item">
                              <span class="detail-label">New Balance:</span>
                              <span class="detail-value">$${data.newBalance}</span>
                          </div>
                      </div>
                      
                      <p>Your funds are now available for mining investments and other platform activities.</p>
                      
                      <div style="text-align: center;">
                          <a href="https://www.bithashcapital.live/investment.html" class="cta-button">Start Mining</a>
                      </div>
                      
                      <p>Best regards,<br><strong>BitHash Capital Finance Team</strong></p>
                  </div>
                  <div class="footer">
                      <p class="footer-text">© 2024 BitHash Capital. All rights reserved.<br>
                      Professional Bitcoin Mining and Investment Platform</p>
                  </div>
              </div>
          </body>
          </html>
        `
      },

      // REFERRAL BONUS
      referral_bonus: {
        subject: 'BitHash Capital - Referral Bonus Earned',
        html: `
          <!DOCTYPE html>
          <html>
          <head>
              <meta charset="utf-8">
              <meta name="viewport" content="width=device-width, initial-scale=1.0">
              <title>Referral Bonus - BitHash Capital</title>
              <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
              <style>
                  * { margin: 0; padding: 0; box-sizing: border-box; }
                  body { font-family: 'Inter', Arial, sans-serif; line-height: 1.6; color: #1a1a1a; background-color: #f8f9fa; margin: 0; padding: 0; }
                  .container { max-width: 600px; margin: 0 auto; background: #ffffff; }
                  .header { background: #0a0a0a; padding: 30px 40px; text-align: center; border-bottom: 3px solid #f0b90b; }
                  .logo-container { display: flex; align-items: center; justify-content: center; gap: 15px; margin-bottom: 15px; }
                  .logo-img { width: 40px; height: 40px; border-radius: 50%; }
                  .logo-text { font-size: 24px; font-weight: 700; color: #f0b90b; letter-spacing: -0.5px; }
                  .content { padding: 40px; background: #ffffff; }
                  .bonus-card { background: #fff8e6; border: 2px solid #f0b90b; padding: 30px; border-radius: 8px; margin: 25px 0; text-align: center; }
                  .bonus-amount { font-size: 36px; font-weight: 700; color: #f0b90b; margin: 10px 0; }
                  .referral-details { background: #f8f9fa; padding: 20px; border-radius: 6px; margin: 20px 0; }
                  .cta-button { background: #f0b90b; color: #0a0a0a; padding: 12px 30px; text-decoration: none; border-radius: 6px; display: inline-block; margin: 20px 0; font-weight: 600; }
                  .footer { background: #0a0a0a; padding: 25px 40px; text-align: center; color: #999; }
                  .footer-text { font-size: 12px; line-height: 1.5; }
              </style>
          </head>
          <body>
              <div class="container">
                  <div class="header">
                      <div class="logo-container">
                          <img src="https://www.dropbox.com/scl/fi/1dq16nex1borvvknpcwox/circular_dark_background.png?rlkey=sq2ujl2oxxk9vyvg1j7oz0cdb&raw=1" alt="BitHash Logo" class="logo-img">
                          <div class="logo-text">BitHash Capital</div>
                      </div>
                  </div>
                  <div class="content">
                      <h2>Hello ${data.name},</h2>
                      <p>Congratulations! You've earned a referral bonus for helping grow our mining community.</p>
                      
                      <div class="bonus-card">
                          <h3>Referral Bonus Earned</h3>
                          <div class="bonus-amount">$${data.bonusAmount}</div>
                          <p>has been credited to your account</p>
                      </div>
                      
                      <div class="referral-details">
                          <p><strong>Referred User:</strong> ${data.referredUser}</p>
                          <p><strong>Bonus Type:</strong> ${data.bonusType}</p>
                          <p><strong>Date Earned:</strong> ${new Date().toLocaleDateString()}</p>
                      </div>
                      
                      <p>Keep sharing your referral link to earn more bonuses as your referrals continue their mining journey.</p>
                      
                      <div style="text-align: center;">
                          <a href="https://www.bithashcapital.live/referral.html" class="cta-button">View Referral Program</a>
                      </div>
                      
                      <p>Thank you for being a valuable member of the BitHash Capital community.</p>
                      
                      <p>Best regards,<br><strong>BitHash Capital Team</strong></p>
                  </div>
                  <div class="footer">
                      <p class="footer-text">© 2024 BitHash Capital. All rights reserved.<br>
                      Professional Bitcoin Mining and Investment Platform</p>
                  </div>
              </div>
          </body>
          </html>
        `
      },

      // ACCOUNT SUSPENDED
      account_suspended: {
        subject: 'BitHash Capital - Important Account Notification',
        html: `
          <!DOCTYPE html>
          <html>
          <head>
              <meta charset="utf-8">
              <meta name="viewport" content="width=device-width, initial-scale=1.0">
              <title>Account Notification - BitHash Capital</title>
              <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
              <style>
                  * { margin: 0; padding: 0; box-sizing: border-box; }
                  body { font-family: 'Inter', Arial, sans-serif; line-height: 1.6; color: #1a1a1a; background-color: #f8f9fa; margin: 0; padding: 0; }
                  .container { max-width: 600px; margin: 0 auto; background: #ffffff; }
                  .header { background: #0a0a0a; padding: 30px 40px; text-align: center; border-bottom: 3px solid #e74c3c; }
                  .logo-container { display: flex; align-items: center; justify-content: center; gap: 15px; margin-bottom: 15px; }
                  .logo-img { width: 40px; height: 40px; border-radius: 50%; }
                  .logo-text { font-size: 24px; font-weight: 700; color: #f0b90b; letter-spacing: -0.5px; }
                  .content { padding: 40px; background: #ffffff; }
                  .alert-box { background: #fee; border: 2px solid #e74c3c; padding: 25px; border-radius: 8px; margin: 25px 0; }
                  .action-steps { background: #f8f9fa; padding: 20px; border-radius: 6px; margin: 20px 0; }
                  .step-item { margin-bottom: 10px; display: flex; align-items: flex-start; }
                  .step-number { background: #e74c3c; color: white; width: 24px; height: 24px; border-radius: 50%; display: flex; align-items: center; justify-content: center; margin-right: 12px; font-size: 12px; font-weight: 600; }
                  .support-link { color: #e74c3c; text-decoration: none; font-weight: 600; }
                  .footer { background: #0a0a0a; padding: 25px 40px; text-align: center; color: #999; }
                  .footer-text { font-size: 12px; line-height: 1.5; }
              </style>
          </head>
          <body>
              <div class="container">
                  <div class="header">
                      <div class="logo-container">
                          <img src="https://www.dropbox.com/scl/fi/1dq16nex1borvvknpcwox/circular_dark_background.png?rlkey=sq2ujl2oxxk9vyvg1j7oz0cdb&raw=1" alt="BitHash Logo" class="logo-img">
                          <div class="logo-text">BitHash Capital</div>
                      </div>
                  </div>
                  <div class="content">
                      <h2>Hello ${data.name},</h2>
                      
                      <div class="alert-box">
                          <h3 style="color: #e74c3c; margin-bottom: 15px;">Important Account Notification</h3>
                          <p>Your BitHash Capital account has been temporarily suspended due to ${data.reason}.</p>
                      </div>
                      
                      <div class="action-steps">
                          <p><strong>Required Actions:</strong></p>
                          <div class="step-item">
                              <div class="step-number">1</div>
                              <span>Contact our support team to resolve this issue</span>
                          </div>
                          <div class="step-item">
                              <div class="step-number">2</div>
                              <span>Provide any requested documentation or information</span>
                          </div>
                          <div class="step-item">
                              <div class="step-number">3</div>
                              <span>Follow instructions provided by our support team</span>
                          </div>
                      </div>
                      
                      <p>Please contact our support team immediately at <a href="mailto:support@bithashcapital.live" class="support-link">support@bithashcapital.live</a> to resolve this matter.</p>
                      
                      <p>Best regards,<br><strong>BitHash Capital Security Team</strong></p>
                  </div>
                  <div class="footer">
                      <p class="footer-text">© 2024 BitHash Capital. All rights reserved.<br>
                      This is an important security notification.</p>
                  </div>
              </div>
          </body>
          </html>
        `
      }
    };

    const templateData = emailTemplates[template];
    if (!templateData) {
      throw new Error(`Template ${template} not found`);
    }

    const mailOptions = {
      from: `"BitHash Capital" <info@bithashcapital.live>`,
      to: email,
      subject: templateData.subject,
      html: templateData.html
    };

    await transporter.sendMail(mailOptions);
    console.log(`Professional email sent successfully to ${email}`);
  } catch (err) {
    console.error('Error sending professional email:', err);
    throw new Error('Failed to send email');
  }
};











// Routes



// Enhanced Signup Endpoint with OTP - FIXED email handling
app.post('/api/auth/signup', [
  body('firstName').trim().notEmpty().withMessage('First name is required').escape(),
  body('lastName').trim().notEmpty().withMessage('Last name is required').escape(),
  body('email').isEmail().withMessage('Please provide a valid email'),
  body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
      .matches(/[A-Z]/).withMessage('Password must contain at least one uppercase letter')
      .matches(/[a-z]/).withMessage('Password must contain at least one lowercase letter')
      .matches(/[0-9]/).withMessage('Password must contain at least one number')
      .matches(/[^A-Za-z0-9]/).withMessage('Password must contain at least one special character'),
  body('city').trim().notEmpty().withMessage('City is required').escape(),
  body('referralCode').optional().trim().escape()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { firstName, lastName, email, password, city, referralCode } = req.body;

    // Use exact email for all operations
    const originalEmail = email;

    // Check if email already exists - exact match only
    const existingUser = await User.findOne({ email: originalEmail });
    if (existingUser) {
      return res.status(400).json({
        status: 'fail',
        message: 'Email already in use'
      });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    const newReferralCode = generateReferralCode();

    let referredByUser = null;
    let referralSource = 'organic';

    // Handle referral code from URL parameter
    if (referralCode) {
      console.log('Processing referral code:', referralCode);
      
      let actualReferralCode = referralCode;
      if (referralCode.includes('-')) {
        const parts = referralCode.split('-');
        if (parts.length > 1) {
          actualReferralCode = parts[parts.length - 1];
        }
      }
      
      referredByUser = await User.findOne({ referralCode: actualReferralCode });
      
      if (referredByUser) {
        referralSource = 'referral_link';
        console.log(`Referral found: ${referredByUser.firstName} ${referredByUser.lastName} (${referredByUser.email})`);
      }
    }

    // Create user with exact email - no normalization
    const newUser = await User.create({
      firstName,
      lastName,
      email: originalEmail, // Store exact email as provided
      password: hashedPassword,
      city,
      referralCode: newReferralCode,
      referredBy: referredByUser ? referredByUser._id : undefined,
      isVerified: false // User needs to verify via OTP first
    });

    // Generate OTP with exact email
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes

    await OTP.create({
      email: originalEmail, // Exact email
      otp,
      type: 'signup',
      expiresAt,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent']
    });

    // Send OTP email to exact email address
    await sendProfessionalEmail({
      email: originalEmail, // Exact email
      template: 'otp',
      data: {
        name: firstName,
        otp: otp,
        action: 'account verification'
      }
    });

    // Send welcome email to exact email address
    await sendProfessionalEmail({
      email: originalEmail, // Exact email
      template: 'welcome',
      data: {
        firstName,
        referral: referredByUser ? `Referred by ${referredByUser.firstName}` : null
      }
    });

    // Generate temporary token for OTP verification
    const tempToken = generateJWT(newUser._id);

    res.status(201).json({
      status: 'success',
      message: 'Account created successfully. Please verify your email with the OTP sent to your inbox.',
      tempToken,
      data: {
        user: {
          id: newUser._id,
          firstName: newUser.firstName,
          lastName: newUser.lastName,
          email: newUser.email, // Return exact email from database
          needsVerification: true
        }
      }
    });

    // Log activity
    await logActivity('signup_initiated', 'user', newUser._id, newUser._id, 'User', req);

  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred during signup'
    });
  }
});





// Validate referral code endpoint
app.get('/api/referrals/validate/:code', async (req, res) => {
    try {
        const { code } = req.params;
        
        if (!code) {
            return res.status(400).json({
                status: 'fail',
                message: 'Referral code is required'
            });
        }

        let actualReferralCode = code;
        
        // Handle both formats: "firstName-code" and just "code"
        if (code.includes('-')) {
            const parts = code.split('-');
            if (parts.length > 1) {
                actualReferralCode = parts[parts.length - 1];
            }
        }

        const referringUser = await User.findOne({ 
            referralCode: actualReferralCode,
            status: 'active'
        }).select('firstName lastName email referralCode');

        if (!referringUser) {
            return res.status(404).json({
                status: 'fail',
                message: 'Invalid referral code'
            });
        }

        res.status(200).json({
            status: 'success',
            data: {
                valid: true,
                referringUser: {
                    firstName: referringUser.firstName,
                    lastName: referringUser.lastName,
                    referralCode: referringUser.referralCode
                },
                message: `You're being referred by ${referringUser.firstName} ${referringUser.lastName}`
            }
        });

    } catch (err) {
        console.error('Referral validation error:', err);
        res.status(500).json({
            status: 'error',
            message: 'Failed to validate referral code'
        });
    }
});









// Enhanced Login Endpoint with OTP - FIXED email handling
app.post('/api/auth/login', [
  body('email').isEmail().withMessage('Please provide a valid email'),
  body('password').notEmpty().withMessage('Password is required'),
  body('rememberMe').optional().isBoolean().withMessage('Remember me must be a boolean')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { email, password, rememberMe } = req.body;

    // Use exact email for lookup - no normalization
    const user = await User.findOne({ email }).select('+password +twoFactorAuth.secret');
    if (!user || !(await bcrypt.compare(password, user.password))) {
      // Log failed attempt
      await logUserActivity(req, 'login_attempt', 'failed', {
        error: 'Invalid credentials',
        email: email // Log exact email used
      });
      
      return res.status(401).json({
        status: 'fail',
        message: 'Incorrect email or password'
      });
    }

    if (user.status !== 'active') {
      await logUserActivity(req, 'login_attempt', 'failed', {
        error: 'Account suspended',
        userId: user._id,
        status: user.status
      });
      
      return res.status(401).json({
        status: 'fail',
        message: 'Your account has been suspended. Please contact support.'
      });
    }

    // Generate OTP for login
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes

    // Store OTP with exact email
    await OTP.create({
      email: email, // Exact email from request
      otp,
      type: 'login',
      expiresAt,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent']
    });

    // Send OTP email to exact email address
    await sendProfessionalEmail({
      email: email, // Exact email from request
      template: 'otp',
      data: {
        name: user.firstName,
        otp: otp,
        action: 'login'
      }
    });

    // Generate temporary token for OTP verification
    const tempToken = generateJWT(user._id);

    res.status(200).json({
      status: 'success',
      message: 'OTP sent to your email. Please verify to complete login.',
      tempToken,
      needsOtp: true,
      data: {
        user: {
          id: user._id,
          firstName: user.firstName,
          lastName: user.lastName,
          email: user.email // Return exact email from database
        }
      }
    });

    await logUserActivity(req, 'login_otp_sent', 'pending', {
      email: email, // Log exact email used
      userId: user._id
    }, user);

  } catch (err) {
    console.error('Login error:', err);
    
    await logUserActivity(req, 'login_error', 'failed', {
      error: err.message,
      email: req.body.email // Log exact email used
    });

    res.status(500).json({
      status: 'error',
      message: 'An error occurred during login'
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



app.post('/api/auth/google', async (req, res) => {
  try {
    console.log('Google auth request received');
    
    const { credential } = req.body;
    
    if (!credential) {
      console.error('No credential provided');
      return res.status(400).json({
        status: 'fail',
        message: 'Google credential is required'
      });
    }

    console.log('Verifying Google token...');

    // Verify the Google token
    let payload;
    try {
      const ticket = await googleClient.verifyIdToken({
        idToken: credential,
        audience: process.env.GOOGLE_CLIENT_ID || '634814462335-9o4t8q95c4orcsd9sijjl52374g6vm85.apps.googleusercontent.com'
      });
      payload = ticket.getPayload();
      console.log('Google token verified successfully');
    } catch (verifyError) {
      console.error('Google token verification failed:', verifyError);
      return res.status(400).json({
        status: 'fail',
        message: 'Invalid Google token. Please try again.'
      });
    }

    if (!payload) {
      console.error('No payload from Google token');
      return res.status(400).json({
        status: 'fail',
        message: 'Invalid token payload'
      });
    }

    const { email, given_name, family_name, sub } = payload;

    if (!email) {
      console.error('No email in Google payload');
      return res.status(400).json({
        status: 'fail',
        message: 'No email found in Google account'
      });
    }

    console.log('Google auth successful for:', email);

    // Use the EXACT email from Google - no normalization
    const originalEmail = email;

    let user;
    let isNewUser = false;

    try {
      user = await User.findOne({ email: originalEmail });
      console.log('User lookup result:', user ? 'Found' : 'Not found');
    } catch (dbError) {
      console.error('Database lookup error:', dbError);
      return res.status(500).json({
        status: 'error',
        message: 'Database error during user lookup'
      });
    }

    if (!user) {
      // Create new user with Google auth using exact email
      try {
        const referralCode = generateReferralCode();
        user = await User.create({
          firstName: given_name || 'Google',
          lastName: family_name || 'User',
          email: originalEmail,
          googleId: sub,
          isVerified: true,
          referralCode,
          status: 'active'
        });
        isNewUser = true;
        console.log('New user created via Google:', originalEmail);

        // Send welcome email
        try {
          await sendProfessionalEmail({
            email: originalEmail,
            template: 'welcome',
            data: {
              firstName: given_name || 'Google User'
            }
          });
        } catch (emailError) {
          console.error('Welcome email failed:', emailError);
          // Don't fail the request if email fails
        }
      } catch (createError) {
        console.error('User creation error:', createError);
        return res.status(500).json({
          status: 'error',
          message: 'Failed to create user account'
        });
      }
    } else if (!user.googleId) {
      // Existing user, add Google auth
      try {
        user.googleId = sub;
        user.isVerified = true;
        await user.save();
        console.log('Existing user linked with Google:', originalEmail);
      } catch (updateError) {
        console.error('User update error:', updateError);
        return res.status(500).json({
          status: 'error',
          message: 'Failed to link Google account'
        });
      }
    }

    // Check if user is active
    if (user.status !== 'active') {
      return res.status(401).json({
        status: 'fail',
        message: 'Your account has been suspended. Please contact support.'
      });
    }

    // Generate OTP for Google sign-in
    try {
      const otp = Math.floor(100000 + Math.random() * 900000).toString();
      const expiresAt = new Date(Date.now() + 5 * 60 * 1000);

      await OTP.create({
        email: originalEmail,
        otp,
        type: 'login',
        expiresAt,
        ipAddress: req.ip,
        userAgent: req.headers['user-agent']
      });

      // Send OTP email
      await sendProfessionalEmail({
        email: originalEmail,
        template: 'otp',
        data: {
          name: user.firstName,
          otp: otp,
          action: 'Google sign-in verification'
        }
      });
    } catch (otpError) {
      console.error('OTP creation error:', otpError);
      // Continue even if OTP fails for now
    }

    // Generate temporary token
    const tempToken = generateJWT(user._id);

    // Update last login
    try {
      user.lastLogin = new Date();
      const deviceInfo = await getUserDeviceInfo(req);
      user.loginHistory.push(deviceInfo);
      await user.save();
    } catch (updateError) {
      console.error('User update error:', updateError);
      // Continue even if update fails
    }

    // SUCCESS RESPONSE
    res.status(200).json({
      status: 'success',
      message: 'OTP sent to your email. Please verify to complete Google sign-in.',
      tempToken,
      needsOtp: true,
      isNewUser: isNewUser,
      data: {
        user: {
          id: user._id,
          firstName: user.firstName,
          lastName: user.lastName,
          email: user.email
        }
      }
    });

    // Log activity (don't let this break the response)
    try {
      await logActivity('google_signin_otp_sent', 'user', user._id, user._id, 'User', req, {
        isNewUser,
        provider: 'google',
        email: originalEmail
      });
    } catch (logError) {
      console.error('Activity logging error:', logError);
    }

  } catch (err) {
    console.error('Google auth UNEXPECTED error:', err);
    console.error('Error stack:', err.stack);
    
    res.status(500).json({
      status: 'error',
      message: 'An unexpected error occurred during Google authentication'
    });
  }
});



app.post('/api/auth/forgot-password', [
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
    const user = await User.findOne({ email });

    if (!user) {
      // Return success even if user doesn't exist to prevent email enumeration
      return res.status(200).json({
        status: 'success',
        message: 'If your email is registered, you will receive a password reset link'
      });
    }

    const { resetToken, hashedToken, tokenExpires } = createPasswordResetToken();
    user.passwordResetToken = hashedToken;
    user.passwordResetExpires = tokenExpires;
    await user.save();

    const resetURL = `https://bithhash.vercel.app/reset-password?token=${resetToken}`;
    const message = `Forgot your password? Click the link below to reset it: \n\n${resetURL}\n\nThis link is valid for 60 minutes. If you didn't request this, please ignore this email.`;

    await sendEmail({
      email: user.email,
      subject: 'Your password reset token (valid for 60 minutes)',
      message,
      html: `<p>Forgot your password? Click the link below to reset it:</p><p><a href="${resetURL}">Reset Password</a></p><p>This link is valid for 60 minutes. If you didn't request this, please ignore this email.</p>`
    });

    res.status(200).json({
      status: 'success',
      message: 'Password reset link sent to email'
    });

    await logActivity('forgot-password', 'user', user._id, user._id, 'User', req);
  } catch (err) {
    console.error('Forgot password error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while sending the password reset email'
    });
  }
});

app.post('/api/auth/reset-password', [
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

    const user = await User.findOne({
      passwordResetToken: hashedToken,
      passwordResetExpires: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).json({
        status: 'fail',
        message: 'Token is invalid or has expired'
      });
    }

    user.password = await bcrypt.hash(password, 12);
    user.passwordChangedAt = Date.now();
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save();

    const newToken = generateJWT(user._id);

    // Set cookie
    res.cookie('jwt', newToken, {
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

    await logActivity('reset-password', 'user', user._id, user._id, 'User', req);
  } catch (err) {
    console.error('Reset password error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while resetting the password'
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



// Investment routes - ENHANCED VERSION WITH EMAIL NOTIFICATIONS
app.post('/api/investments', protect, [
  body('planId').notEmpty().withMessage('Plan ID is required').isMongoId().withMessage('Invalid Plan ID'),
  body('amount').isFloat({ min: 1 }).withMessage('Amount must be a positive number'),
  body('balanceType').isIn(['main', 'matured']).withMessage('Balance type must be either "main" or "matured"')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { planId, amount, balanceType } = req.body;
    const userId = req.user._id;

    // Verify plan exists and is active
    const plan = await Plan.findById(planId);
    if (!plan || !plan.isActive) {
      return res.status(400).json({
        status: 'fail',
        message: 'Invalid or inactive investment plan'
      });
    }

    // Verify amount is within plan limits
    if (amount < plan.minAmount || amount > plan.maxAmount) {
      return res.status(400).json({
        status: 'fail',
        message: `Amount must be between $${plan.minAmount} and $${plan.maxAmount} for this plan`
      });
    }

    // Verify user has sufficient balance in the selected balance type
    const user = await User.findById(userId);
    const selectedBalance = user.balances[balanceType];
    
    if (selectedBalance < amount) {
      return res.status(400).json({
        status: 'fail',
        message: `Insufficient ${balanceType} balance`
      });
    }

    // Calculate investment amount after 3% fee
    const investmentFee = amount * 0.03;
    const investmentAmountAfterFee = amount - investmentFee;

    // Calculate expected return based on the amount after fee
    const expectedReturn = investmentAmountAfterFee + (investmentAmountAfterFee * plan.percentage / 100);
    const endDate = new Date(Date.now() + plan.duration * 60 * 60 * 1000);

    // Create investment
    const investment = await Investment.create({
      user: userId,
      plan: planId,
      amount: investmentAmountAfterFee, // Store the amount after fee
      originalAmount: amount, // Store original amount before fee
      originalCurrency: 'USD',
      currency: 'USD',
      expectedReturn,
      returnPercentage: plan.percentage,
      endDate,
      payoutSchedule: 'end_term',
      status: 'active',
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
      deviceInfo: getDeviceType(req),
      termsAccepted: true,
      investmentFee: investmentFee, // Store the fee for record keeping
      balanceType: balanceType // Store which balance was used
    });

    // Deduct from user's selected balance (only the original amount)
    user.balances[balanceType] -= amount;
    user.balances.active += investmentAmountAfterFee; // Add the amount after fee to active balance
    await user.save();

    // Create transaction record for the investment with fee
    const transaction = await Transaction.create({
      user: userId,
      type: 'investment',
      amount: -amount,
      currency: 'USD',
      status: 'completed',
      method: 'internal',
      reference: `INV-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
      details: {
        investmentId: investment._id,
        planName: plan.name,
        balanceType: balanceType,
        investmentFee: investmentFee,
        amountAfterFee: investmentAmountAfterFee
      },
      fee: investmentFee,
      netAmount: -investmentAmountAfterFee
    });

    // RECORD PLATFORM REVENUE
    await PlatformRevenue.create({
      source: 'investment_fee',
      amount: investmentFee,
      currency: 'USD',
      transactionId: transaction._id,
      investmentId: investment._id,
      userId: userId,
      description: `3% investment fee for ${plan.name} investment`,
      metadata: {
        planName: plan.name,
        originalAmount: amount,
        amountAfterFee: investmentAmountAfterFee,
        feePercentage: 3
      }
    });

    // ✅ FIXED: ALWAYS CHECK FOR DOWNLINE COMMISSIONS (Not just referredBy)
    await calculateReferralCommissions(investment);

    // ✅ FIXED: Handle direct referral bonus separately (if user was referred by someone)
    if (user.referredBy) {
      const referralBonus = (amount * plan.referralBonus) / 100;
      
      // Update referring user's balance for direct referral bonus
      await User.findByIdAndUpdate(user.referredBy, {
        $inc: {
          'balances.main': referralBonus,
          'referralStats.totalEarnings': referralBonus,
          'referralStats.availableBalance': referralBonus
        },
        $push: {
          referralHistory: {
            referredUser: userId,
            amount: referralBonus,
            percentage: plan.referralBonus,
            level: 1,
            status: 'available',
            date: new Date()
          }
        }
      });

      // Create referral commission record for direct referral
      await CommissionHistory.create({
        upline: user.referredBy,
        downline: userId,
        investment: investment._id,
        investmentAmount: amount,
        commissionPercentage: plan.referralBonus,
        commissionAmount: referralBonus,
        roundNumber: 0, // 0 indicates direct referral bonus, not downline commission
        status: 'paid',
        paidAt: new Date()
      });

      // Create transaction for direct referral bonus
      await Transaction.create({
        user: user.referredBy,
        type: 'referral',
        amount: referralBonus,
        currency: 'USD',
        status: 'completed',
        method: 'internal',
        reference: `REF-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
        details: {
          referralFrom: userId,
          investmentId: investment._id,
          type: 'direct_referral',
          bonusPercentage: plan.referralBonus
        },
        fee: 0,
        netAmount: referralBonus
      });

      // Mark investment with referral info
      investment.referredBy = user.referredBy;
      investment.referralBonusAmount = referralBonus;
      investment.referralBonusDetails = {
        percentage: plan.referralBonus,
        payoutDate: new Date()
      };
      await investment.save();

      console.log(`🎁 Direct referral bonus of $${referralBonus} paid to ${user.referredBy}`);
    }

    // ✅ ENHANCED: Send investment creation email
    try {
      await sendProfessionalEmail({
        email: user.email,
        template: 'investment_created',
        data: {
          name: user.firstName,
          planName: plan.name,
          amount: amount,
          expectedReturn: expectedReturn,
          duration: plan.duration,
          startDate: investment.startDate,
          endDate: investment.endDate
        }
      });
      console.log(`📧 Investment creation email sent to ${user.email}`);
    } catch (emailError) {
      console.error('Failed to send investment creation email:', emailError);
      // Don't fail the investment if email fails
    }

    // Log activity
    await logActivity('create_investment', 'investment', investment._id, userId, 'User', req);

    res.status(201).json({
      status: 'success',
      data: {
        investment: {
          id: investment._id,
          plan: plan.name,
          amount: investment.amount, // This shows amount after fee to user
          originalAmount: investment.originalAmount, // Original amount for reference
          investmentFee: investmentFee,
          expectedReturn: investment.expectedReturn,
          endDate: investment.endDate,
          status: investment.status,
          balanceType: balanceType
        }
      }
    });
  } catch (err) {
    console.error('Investment creation error:', err);
    
    // Even on error, return success to frontend as requested
    res.status(200).json({
      status: 'success',
      message: 'Investment created successfully'
    });
  }
});

app.post('/api/investments/:id/complete', protect, async (req, res) => {
  try {
    const investmentId = req.params.id;
    const userId = req.user._id;

    // Find the investment with more comprehensive query
    const investment = await Investment.findOne({ 
      _id: investmentId, 
      user: userId,
      status: 'active' 
    }).populate('plan');
    
    if (!investment) {
      return res.status(404).json({
        status: 'fail',
        message: 'Active investment not found'
      });
    }

    // Enhanced completion check - ensure investment has actually matured
    const now = new Date();
    if (now < investment.endDate) {
      return res.status(400).json({
        status: 'fail',
        message: 'Investment has not matured yet'
      });
    }

    // Find the user with proper session handling
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'User not found'
      });
    }

    // Calculate total return (principal + profit) - based on amount after fee
    const totalReturn = investment.expectedReturn;

    // Enhanced balance transfer with validation
    if (user.balances.active < investment.amount) {
      return res.status(400).json({
        status: 'fail',
        message: 'Insufficient active balance to complete investment'
      });
    }

    // Use transaction to ensure atomic operation
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      // Transfer from active to matured balance
      user.balances.active -= investment.amount;
      user.balances.matured += totalReturn;
      
      // Update investment status with completion details
      investment.status = 'completed';
      investment.completionDate = now;
      investment.actualReturn = totalReturn - investment.amount;
      investment.isProcessed = true; // Add flag to ensure it's processed

      // Save changes with session
      await user.save({ session });
      await investment.save({ session });

      // Create transaction record for the return
      await Transaction.create([{
        user: userId,
        type: 'interest',
        amount: totalReturn - investment.amount,
        currency: 'USD',
        status: 'completed',
        method: 'internal',
        reference: `RET-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
        details: {
          investmentId: investment._id,
          planName: investment.plan.name,
          principal: investment.amount,
          interest: totalReturn - investment.amount,
          originalInvestment: investment.originalAmount,
          investmentFee: investment.investmentFee
        },
        fee: 0,
        netAmount: totalReturn - investment.amount
      }], { session });

      // Commit transaction
      await session.commitTransaction();
      
      // ✅ ENHANCED: Send investment completion email
      try {
        await sendProfessionalEmail({
          email: user.email,
          template: 'investment_completed',
          data: {
            name: user.firstName,
            planName: investment.plan.name,
            amount: investment.originalAmount,
            totalReturn: totalReturn,
            profit: totalReturn - investment.amount,
            completionDate: investment.completionDate,
            newMaturedBalance: user.balances.matured
          }
        });
        console.log(`📧 Investment completion email sent to ${user.email}`);
      } catch (emailError) {
        console.error('Failed to send investment completion email:', emailError);
        // Don't fail the investment completion if email fails
      }

      res.status(200).json({
        status: 'success',
        data: {
          investment: {
            id: investment._id,
            status: investment.status,
            completionDate: investment.completionDate,
            amountReturned: totalReturn,
            profit: totalReturn - investment.amount,
            originalInvestment: investment.originalAmount,
            investmentFee: investment.investmentFee
          },
          balances: {
            active: user.balances.active,
            matured: user.balances.matured
          }
        }
      });

      await logActivity('complete_investment', 'investment', investment._id, userId, 'User', req);

    } catch (transactionError) {
      // Rollback transaction on error
      await session.abortTransaction();
      throw transactionError;
    } finally {
      session.endSession();
    }

  } catch (err) {
    console.error('Complete investment error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while completing the investment'
    });
  }
});















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



// Enhanced activity logger with device and location info
const logUserActivity = async (req, action, status = 'success', metadata = {}, relatedEntity = null) => {
  try {
    // Skip logging if no user is associated (like during signup)
    if (!req.user && !(action === 'signup' || action === 'login' || action === 'password_reset_request')) {
      return;
    }

    // Get device and location info
    const deviceInfo = await getUserDeviceInfo(req);
    
    // Prepare log data
    const logData = {
      user: req.user?._id || null,
      username: req.user?.email || (action === 'signup' ? req.body.email : 'unknown'),
      email: req.user?.email || (action === 'signup' ? req.body.email : null),
      action,
      ipAddress: deviceInfo.ip,
      userAgent: deviceInfo.device,
      deviceInfo: {
        type: getDeviceType(req),
        os: getOSFromUserAgent(req.headers['user-agent']),
        browser: getBrowserFromUserAgent(req.headers['user-agent'])
      },
      location: {
        country: deviceInfo.location?.split(', ')[2] || 'Unknown',
        region: deviceInfo.location?.split(', ')[1] || 'Unknown',
        city: deviceInfo.location?.split(', ')[0] || 'Unknown',
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone
      },
      status,
      metadata,
      ...(relatedEntity && {
        relatedEntity: relatedEntity._id || relatedEntity,
        relatedEntityModel: relatedEntity.constructor.modelName
      })
    };

    // Create the log
    await UserLog.create(logData);

    // Also add to system logs for admin viewing
    await SystemLog.create({
      action,
      entity: 'User',
      entityId: req.user?._id || null,
      performedBy: req.user?._id || null,
      performedByModel: req.user ? 'User' : 'System',
      ip: deviceInfo.ip,
      device: deviceInfo.device,
      location: deviceInfo.location,
      changes: metadata
    });

  } catch (err) {
    console.error('Error logging user activity:', err);
    // Fail silently to not disrupt user experience
  }
};

// Helper functions for device detection
const getDeviceType = (req) => {
  const userAgent = req.headers['user-agent'];
  if (/mobile/i.test(userAgent)) return 'mobile';
  if (/tablet/i.test(userAgent)) return 'tablet';
  if (/iPad|Android|Touch/i.test(userAgent)) return 'tablet';
  return 'desktop';
};

const getOSFromUserAgent = (userAgent) => {
  if (!userAgent) return 'Unknown';
  if (/windows/i.test(userAgent)) return 'Windows';
  if (/macintosh|mac os x/i.test(userAgent)) return 'MacOS';
  if (/linux/i.test(userAgent)) return 'Linux';
  if (/android/i.test(userAgent)) return 'Android';
  if (/iphone|ipad|ipod/i.test(userAgent)) return 'iOS';
  return 'Unknown';
};

const getBrowserFromUserAgent = (userAgent) => {
  if (!userAgent) return 'Unknown';
  if (/edg/i.test(userAgent)) return 'Edge';
  if (/chrome/i.test(userAgent)) return 'Chrome';
  if (/safari/i.test(userAgent)) return 'Safari';
  if (/firefox/i.test(userAgent)) return 'Firefox';
  if (/opera|opr/i.test(userAgent)) return 'Opera';
  return 'Unknown';
};

// Middleware to track user activity on protected routes
const trackUserActivity = (action, options = {}) => {
  return async (req, res, next) => {
    try {
      // Call next first to let the route handler process the request
      await next();
      
      // Only log if the request was successful (2xx status)
      if (res.statusCode >= 200 && res.statusCode < 300) {
        let metadata = {};
        let relatedEntity = null;
        
        // Custom metadata extraction based on action
        switch (action) {
          case 'profile_update':
            metadata = {
              fields: Object.keys(req.body).filter(key => 
                !key.toLowerCase().includes('password')
              )
            };
            break;
            
          case 'deposit':
          case 'withdrawal':
          case 'transfer':
            relatedEntity = res.locals.transaction || req.body;
            metadata = {
              amount: req.body.amount,
              currency: req.body.currency || 'USD',
              method: req.body.method
            };
            break;
            
          case 'investment':
            relatedEntity = res.locals.investment || req.body;
            metadata = {
              plan: req.body.planId,
              amount: req.body.amount
            };
            break;
            
          case 'kyc_submission':
            metadata = {
              type: req.body.type,
              status: 'pending'
            };
            break;
        }
        
        // Merge with any additional metadata from options
        if (options.metadata) {
          metadata = { ...metadata, ...options.metadata };
        }
        
        await logUserActivity(req, action, 'success', metadata, relatedEntity);
      }
    } catch (err) {
      console.error('Activity tracking middleware error:', err);
      // Don't interrupt the request flow if tracking fails
    }
  };
};

// Middleware to track failed login attempts
const trackFailedLogin = async (req, res, next) => {
  try {
    await next();
    
    // If login failed (unauthorized)
    if (res.statusCode === 401) {
      await logUserActivity(req, 'failed_login', 'failed', {
        email: req.body.email,
        reason: res.locals.failReason || 'Invalid credentials'
      });
    }
  } catch (err) {
    console.error('Failed login tracking error:', err);
  }
};



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

// Admin Add User Endpoint
app.post('/api/admin/users', adminProtect, [
  body('firstName').trim().notEmpty().withMessage('First name is required'),
  body('lastName').trim().notEmpty().withMessage('Last name is required'),
  body('email').isEmail().withMessage('Please provide a valid email'),
  body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        status: 'fail',
        errors: errors.array()
      });
    }
    
    const { firstName, lastName, email, password, city, country } = req.body;
    
    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({
        status: 'fail',
        message: 'User with this email already exists'
      });
    }
    
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);
    
    // Generate referral code
    const referralCode = generateReferralCode();
    
    // Create user
    const user = await User.create({
      firstName,
      lastName,
      email,
      password: hashedPassword,
      city,
      country,
      referralCode,
      isVerified: true
    });
    
    res.status(201).json({
      status: 'success',
      data: {
        user: {
          id: user._id,
          firstName: user.firstName,
          lastName: user.lastName,
          email: user.email
        }
      }
    });
    
    await logActivity('create-user', 'user', user._id, req.admin._id, 'Admin', req);
  } catch (err) {
    console.error('Admin add user error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to create user'
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


// Admin Get Deposit Details Endpoint
app.get('/api/admin/deposits/:id', adminProtect, async (req, res) => {
  try {
    const deposit = await Transaction.findById(req.params.id)
      .populate('user', 'firstName lastName email')
      .lean();
    
    if (!deposit || deposit.type !== 'deposit') {
      return res.status(404).json({
        status: 'fail',
        message: 'Deposit not found'
      });
    }
    
    res.status(200).json({
      status: 'success',
      data: { deposit }
    });
  } catch (err) {
    console.error('Admin get deposit error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch deposit details'
    });
  }
});

// Admin Approve Deposit Endpoint
app.post('/api/admin/deposits/:id/approve', adminProtect, [
  body('notes').optional().trim()
], async (req, res) => {
  try {
    const { notes } = req.body;
    
    // Find deposit
    const deposit = await Transaction.findById(req.params.id)
      .populate('user');
    
    if (!deposit || deposit.type !== 'deposit') {
      return res.status(404).json({
        status: 'fail',
        message: 'Deposit not found'
      });
    }
    
    if (deposit.status !== 'pending') {
      return res.status(400).json({
        status: 'fail',
        message: 'Deposit is not pending approval'
      });
    }
    
    // Find user
    const user = await User.findById(deposit.user._id);
    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'User not found'
      });
    }
    
    // Update user balance
    user.balances.main += deposit.amount;
    await user.save();
    
    // Update deposit status
    deposit.status = 'completed';
    deposit.processedBy = req.admin._id;
    deposit.processedAt = new Date();
    deposit.adminNotes = notes;
    await deposit.save();
    
    res.status(200).json({
      status: 'success',
      message: 'Deposit approved successfully'
    });


await sendAutomatedEmail(user, 'deposit_received', {
  amount: deposit.amount,
  method: deposit.method,
  reference: deposit.reference,
  newBalance: user.balances.main
});
    
    await logActivity('approve-deposit', 'transaction', deposit._id, req.admin._id, 'Admin', req, {
      amount: deposit.amount,
      userId: user._id
    });
  } catch (err) {
    console.error('Admin approve deposit error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to approve deposit'
    });
  }
});

// Admin Reject Deposit Endpoint
app.post('/api/admin/deposits/:id/reject', adminProtect, [
  body('rejectionReason').trim().notEmpty().withMessage('Rejection reason is required')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        status: 'fail',
        errors: errors.array()
      });
    }
    
    const { rejectionReason } = req.body;
    
    // Find deposit
    const deposit = await Transaction.findById(req.params.id);
    
    if (!deposit || deposit.type !== 'deposit') {
      return res.status(404).json({
        status: 'fail',
        message: 'Deposit not found'
      });
    }
    
    if (deposit.status !== 'pending') {
      return res.status(400).json({
        status: 'fail',
        message: 'Deposit is not pending approval'
      });
    }
    
    // Update deposit status
    deposit.status = 'failed';
    deposit.adminNotes = rejectionReason;
    await deposit.save();
    
    res.status(200).json({
      status: 'success',
      message: 'Deposit rejected successfully'
    });
    
    await logActivity('reject-deposit', 'transaction', deposit._id, req.admin._id, 'Admin', req, {
      amount: deposit.amount,
      reason: rejectionReason
    });
  } catch (err) {
    console.error('Admin reject deposit error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to reject deposit'
    });
  }
});

// Admin Get Withdrawal Details Endpoint
app.get('/api/admin/withdrawals/:id', adminProtect, async (req, res) => {
  try {
    const withdrawal = await Transaction.findById(req.params.id)
      .populate('user', 'firstName lastName email')
      .lean();
    
    if (!withdrawal || withdrawal.type !== 'withdrawal') {
      return res.status(404).json({
        status: 'fail',
        message: 'Withdrawal not found'
      });
    }
    
    res.status(200).json({
      status: 'success',
      data: { withdrawal }
    });
  } catch (err) {
    console.error('Admin get withdrawal error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch withdrawal details'
    });
  }
});

// Admin Approve Withdrawal Endpoint
app.post('/api/admin/withdrawals/:id/approve', adminProtect, [
  body('notes').optional().trim()
], async (req, res) => {
  try {
    const { notes } = req.body;
    
    // Find withdrawal
    const withdrawal = await Transaction.findById(req.params.id);
    
    if (!withdrawal || withdrawal.type !== 'withdrawal') {
      return res.status(404).json({
        status: 'fail',
        message: 'Withdrawal not found'
      });
    }
    
    if (withdrawal.status !== 'pending') {
      return res.status(400).json({
        status: 'fail',
        message: 'Withdrawal is not pending approval'
      });
    }
    
    // Update withdrawal status
    withdrawal.status = 'completed';
    withdrawal.processedBy = req.admin._id;
    withdrawal.processedAt = new Date();
    withdrawal.adminNotes = notes;
    await withdrawal.save();
    
    res.status(200).json({
      status: 'success',
      message: 'Withdrawal approved successfully'
    });
    
    await logActivity('approve-withdrawal', 'transaction', withdrawal._id, req.admin._id, 'Admin', req, {
      amount: withdrawal.amount,
      userId: withdrawal.user
    });
  } catch (err) {
    console.error('Admin approve withdrawal error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to approve withdrawal'
    });
  }
});






// CORRECTED Admin Reject Withdrawal Endpoint
app.post('/api/admin/withdrawals/:id/reject', adminProtect, [
  body('reason').trim().notEmpty().withMessage('Rejection reason is required')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        status: 'fail',
        errors: errors.array()
      });
    }
    
    const { reason } = req.body;
    
    // Find withdrawal
    const withdrawal = await Transaction.findById(req.params.id)
      .populate('user');
    
    if (!withdrawal || withdrawal.type !== 'withdrawal') {
      return res.status(404).json({
        status: 'fail',
        message: 'Withdrawal not found'
      });
    }
    
    if (withdrawal.status !== 'pending') {
      return res.status(400).json({
        status: 'fail',
        message: 'Withdrawal is not pending approval'
      });
    }
    
    // Find user
    const user = await User.findById(withdrawal.user._id);
    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'User not found'
      });
    }
    
    // Return funds to user balance
    user.balances.matured += withdrawal.amount;
    await user.save();
    
    // Update withdrawal status
    withdrawal.status = 'failed';
    withdrawal.adminNotes = reason; // Changed from rejectionReason to reason
    await withdrawal.save();
    
    res.status(200).json({
      status: 'success',
      message: 'Withdrawal rejected successfully'
    });
    
    await logActivity('reject-withdrawal', 'transaction', withdrawal._id, req.admin._id, 'Admin', req, {
      amount: withdrawal.amount,
      reason: reason,
      userId: user._id
    });
  } catch (err) {
    console.error('Admin reject withdrawal error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to reject withdrawal'
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









// Admin Activity Endpoint - FIXED VERSION
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

    // Transform activities with PROPER user data mapping
    const activities = allActivities.map(activity => {
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
        status: status,
        type: isUserLog ? 'user_activity' : 'system_activity',
        metadata: activity.metadata || activity.changes || {}
      };
    });

    // Get total count for pagination
    const totalCount = await UserLog.countDocuments() + await SystemLog.countDocuments();

    console.log('Sending activities:', activities.length);

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


















// Downline Management Endpoints

// Get all downline relationships with pagination
app.get('/api/admin/downline', adminProtect, restrictTo('super', 'support'), async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const relationships = await DownlineRelationship.find({})
      .populate('upline', 'firstName lastName email')
      .populate('downline', 'firstName lastName email')
      .populate('assignedBy', 'name email')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .lean();

    const total = await DownlineRelationship.countDocuments();

    res.status(200).json({
      status: 'success',
      data: {
        relationships,
        pagination: {
          currentPage: page,
          totalPages: Math.ceil(total / limit),
          totalItems: total,
          itemsPerPage: limit
        }
      }
    });
  } catch (err) {
    console.error('Get downline relationships error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch downline relationships'
    });
  }
});

// Assign downline to upline
app.post('/api/admin/downline/assign', adminProtect, restrictTo('super', 'support'), [
  body('downlineUserId').isMongoId().withMessage('Valid downline user ID is required'),
  body('uplineUserId').isMongoId().withMessage('Valid upline user ID is required')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { downlineUserId, uplineUserId } = req.body;

    // Check if users exist
    const [downlineUser, uplineUser] = await Promise.all([
      User.findById(downlineUserId),
      User.findById(uplineUserId)
    ]);

    if (!downlineUser || !uplineUser) {
      return res.status(404).json({
        status: 'fail',
        message: 'One or both users not found'
      });
    }

    // Check if downline already has an upline
    const existingRelationship = await DownlineRelationship.findOne({ 
      downline: downlineUserId 
    });

    if (existingRelationship) {
      return res.status(400).json({
        status: 'fail',
        message: 'This user already has an upline assigned'
      });
    }

    // Prevent circular relationships (user cannot be their own upline)
    if (downlineUserId.toString() === uplineUserId.toString()) {
      return res.status(400).json({
        status: 'fail',
        message: 'User cannot be their own upline'
      });
    }

    // Get current commission settings
    const commissionSettings = await CommissionSettings.findOne({ isActive: true }) || 
      await CommissionSettings.create({
        commissionPercentage: 5,
        commissionRounds: 3,
        updatedBy: req.admin._id
      });

    // Create downline relationship
    const relationship = await DownlineRelationship.create({
      upline: uplineUserId,
      downline: downlineUserId,
      commissionPercentage: commissionSettings.commissionPercentage,
      commissionRounds: commissionSettings.commissionRounds,
      remainingRounds: commissionSettings.commissionRounds,
      assignedBy: req.admin._id
    });

    // Populate and return the relationship
    const populatedRelationship = await DownlineRelationship.findById(relationship._id)
      .populate('upline', 'firstName lastName email')
      .populate('downline', 'firstName lastName email')
      .populate('assignedBy', 'name email');

    res.status(201).json({
      status: 'success',
      data: {
        relationship: populatedRelationship
      }
    });

    await logActivity('assign_downline', 'DownlineRelationship', relationship._id, req.admin._id, 'Admin', req, {
      upline: uplineUserId,
      downline: downlineUserId,
      commissionPercentage: commissionSettings.commissionPercentage,
      commissionRounds: commissionSettings.commissionRounds
    });

  } catch (err) {
    console.error('Assign downline error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to assign downline relationship'
    });
  }
});

// Remove downline relationship
app.delete('/api/admin/downline/:relationshipId', adminProtect, restrictTo('super', 'support'), async (req, res) => {
  try {
    const relationshipId = req.params.relationshipId;

    const relationship = await DownlineRelationship.findByIdAndDelete(relationshipId);

    if (!relationship) {
      return res.status(404).json({
        status: 'fail',
        message: 'Downline relationship not found'
      });
    }

    res.status(200).json({
      status: 'success',
      message: 'Downline relationship removed successfully'
    });

    await logActivity('remove_downline', 'DownlineRelationship', relationshipId, req.admin._id, 'Admin', req, {
      upline: relationship.upline,
      downline: relationship.downline
    });

  } catch (err) {
    console.error('Remove downline error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to remove downline relationship'
    });
  }
});

// Get commission settings
app.get('/api/admin/commission-settings', adminProtect, restrictTo('super', 'support'), async (req, res) => {
  try {
    let settings = await CommissionSettings.findOne({ isActive: true });

    if (!settings) {
      // Create default settings if none exist
      settings = await CommissionSettings.create({
        commissionPercentage: 5,
        commissionRounds: 3,
        updatedBy: req.admin._id
      });
    }

    res.status(200).json({
      status: 'success',
      data: {
        settings
      }
    });
  } catch (err) {
    console.error('Get commission settings error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch commission settings'
    });
  }
});

// Update commission settings
app.post('/api/admin/commission-settings', adminProtect, restrictTo('super'), [
  body('commissionPercentage').isFloat({ min: 0, max: 50 }).withMessage('Commission percentage must be between 0 and 50'),
  body('commissionRounds').isInt({ min: 1, max: 10 }).withMessage('Commission rounds must be between 1 and 10')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { commissionPercentage, commissionRounds } = req.body;

    // Deactivate all current settings
    await CommissionSettings.updateMany(
      { isActive: true },
      { isActive: false }
    );

    // Create new active settings
    const settings = await CommissionSettings.create({
      commissionPercentage,
      commissionRounds,
      updatedBy: req.admin._id
    });

    // Update all active relationships with new settings
    await DownlineRelationship.updateMany(
      { status: 'active' },
      { 
        commissionPercentage,
        commissionRounds,
        remainingRounds: commissionRounds
      }
    );

    res.status(200).json({
      status: 'success',
      data: {
        settings
      }
    });

    await logActivity('update_commission_settings', 'CommissionSettings', settings._id, req.admin._id, 'Admin', req, {
      commissionPercentage,
      commissionRounds
    });

  } catch (err) {
    console.error('Update commission settings error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to update commission settings'
    });
  }
});

// Get commission history
app.get('/api/admin/commission-history', adminProtect, restrictTo('super', 'support'), async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const commissions = await CommissionHistory.find({})
      .populate('upline', 'firstName lastName email')
      .populate('downline', 'firstName lastName email')
      .populate('investment', 'amount plan')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .lean();

    const total = await CommissionHistory.countDocuments();

    res.status(200).json({
      status: 'success',
      data: {
        commissions,
        pagination: {
          currentPage: page,
          totalPages: Math.ceil(total / limit),
          totalItems: total,
          itemsPerPage: limit
        }
      }
    });
  } catch (err) {
    console.error('Get commission history error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch commission history'
    });
  }
});

// Get user's downline tree (for user dashboard)
app.get('/api/users/downline', protect, async (req, res) => {
  try {
    const userId = req.user._id;

    // Get direct downlines
    const directDownlines = await DownlineRelationship.find({ upline: userId })
      .populate('downline', 'firstName lastName email createdAt')
      .select('downline commissionPercentage remainingRounds totalCommissionEarned assignedAt')
      .lean();

    // Calculate total downline stats
    const downlineStats = {
      totalDirectDownlines: directDownlines.length,
      totalCommissionEarned: directDownlines.reduce((sum, rel) => sum + (rel.totalCommissionEarned || 0), 0),
      activeDownlines: directDownlines.filter(rel => rel.remainingRounds > 0).length
    };

    res.status(200).json({
      status: 'success',
      data: {
        downlines: directDownlines,
        stats: downlineStats
      }
    });

  } catch (err) {
    console.error('Get user downline error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch downline information'
    });
  }
});







app.get('/api/referrals', protect, async (req, res) => {
    try {
        const userId = req.user._id;

        // Get user's referral code and details
        const user = await User.findById(userId).select('referralCode referralStats firstName lastName email');
        if (!user) {
            return res.status(404).json({
                status: 'fail',
                message: 'User not found'
            });
        }

        // Generate referral link using user's first name and unique code
        const referralLink = `https://www.bithashcapital.live/signup.html?ref=${user.referralCode}`;
        const referralLinkWithName = `https://www.bithashcapital.live/signup.html?ref=${encodeURIComponent(user.firstName)}-${user.referralCode}`;

        // Get all downline relationships where this user is the upline
        const downlineRelationships = await DownlineRelationship.find({ 
            upline: userId 
        })
        .populate('downline', 'firstName lastName email createdAt')
        .sort({ createdAt: -1 })
        .lean();

        // Calculate referral statistics
        const totalReferrals = downlineRelationships.length;
        const activeReferrals = downlineRelationships.filter(rel => rel.status === 'active').length;
        
        // Calculate total earnings from commission history
        const commissionEarnings = await CommissionHistory.aggregate([
            { 
                $match: { 
                    upline: userId,
                    status: 'paid'
                } 
            },
            {
                $group: {
                    _id: null,
                    totalEarnings: { $sum: '$commissionAmount' }
                }
            }
        ]);

        const totalEarnings = commissionEarnings.length > 0 ? commissionEarnings[0].totalEarnings : 0;

        // Calculate pending earnings (commissions that are earned but not yet paid)
        const pendingEarningsResult = await CommissionHistory.aggregate([
            { 
                $match: { 
                    upline: userId,
                    status: 'pending'
                } 
            },
            {
                $group: {
                    _id: null,
                    totalPending: { $sum: '$commissionAmount' }
                }
            }
        ]);

        const pendingEarnings = pendingEarningsResult.length > 0 ? pendingEarningsResult[0].totalPending : 0;

        // Format referral data for the referrals table
        const referrals = downlineRelationships.map(relationship => {
            const downlineUser = relationship.downline;
            const roundsCompleted = relationship.commissionRounds - relationship.remainingRounds;
            
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

        // Calculate earnings breakdown by round for each referral
        const earningsBreakdown = await CommissionHistory.aggregate([
            { 
                $match: { 
                    upline: userId,
                    status: { $in: ['paid', 'pending'] }
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
                                { $and: ['$downlineInfo.firstName', '$downlineInfo.lastName'] },
                                { $concat: ['$downlineInfo.firstName', ' ', '$downlineInfo.lastName'] },
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

        // Update user's referral stats in the database
        await User.findByIdAndUpdate(userId, {
            $set: {
                'referralStats.totalReferrals': totalReferrals,
                'referralStats.totalEarnings': totalEarnings,
                'referralStats.availableBalance': totalEarnings - (user.referralStats?.withdrawn || 0),
                'referralStats.pendingEarnings': pendingEarnings,
                'downlineStats.totalDownlines': totalReferrals,
                'downlineStats.activeDownlines': activeReferrals,
                'downlineStats.totalCommissionEarned': totalEarnings
            }
        });

        // Return the complete referral data in the EXACT format expected by frontend
        const responseData = {
            status: 'success',
            data: {
                // Enhanced referral data with links
                code: user.referralCode || 'XXXXXX',
                referralLink: referralLink,
                referralLinkWithName: referralLinkWithName,
                shareableLinks: {
                    direct: referralLinkWithName,
                    withMessage: `Join me on BitHash Capital! Use my referral link: ${referralLinkWithName}`,
                    social: {
                        facebook: `https://www.facebook.com/sharer/sharer.php?u=${encodeURIComponent(referralLinkWithName)}`,
                        twitter: `https://twitter.com/intent/tweet?text=${encodeURIComponent(`Join me on BitHash Capital! Use my referral link: ${referralLinkWithName}`)}`,
                        whatsapp: `https://wa.me/?text=${encodeURIComponent(`Join me on BitHash Capital! Use my referral link: ${referralLinkWithName}`)}`,
                        telegram: `https://t.me/share/url?url=${encodeURIComponent(referralLinkWithName)}&text=${encodeURIComponent('Join me on BitHash Capital!')}`
                    }
                },
                totalReferrals: totalReferrals,
                totalEarnings: totalEarnings,
                pendingEarnings: pendingEarnings,
                activeReferrals: activeReferrals,
                
                // Detailed data for the tabs
                referrals: referrals, // For "My Referrals" tab
                earnings: earningsBreakdown, // For "Earnings Breakdown" tab
                
                // Stats object (if needed elsewhere)
                stats: {
                    directReferrals: totalReferrals,
                    totalCommission: totalEarnings,
                    availableBalance: totalEarnings - (user.referralStats?.withdrawn || 0),
                    withdrawn: user.referralStats?.withdrawn || 0,
                    pending: pendingEarnings
                }
            }
        };

        res.status(200).json(responseData);

        // Log the activity
        await logActivity('view_referrals', 'referral', userId, userId, 'User', req);

    } catch (error) {
        console.error('Error loading referral data:', error);
        res.status(500).json({
            status: 'error',
            message: 'Failed to load referral data'
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
















// =============================================
// ADMIN KYC MANAGEMENT ENDPOINTS
// =============================================

// Get all KYC submissions with filtering and pagination
app.get('/api/admin/kyc/submissions', adminProtect, restrictTo('super', 'support'), async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const status = req.query.status || 'all';
    const skip = (page - 1) * limit;

    console.log('Fetching KYC submissions with params:', { page, limit, status });

    // Build query based on status filter
    let query = {};
    
    if (status !== 'all') {
      if (status === 'not-started') {
        query.overallStatus = 'not-started';
      } else if (status === 'pending') {
        query.overallStatus = 'pending';
      } else if (status === 'verified') {
        query.overallStatus = 'verified';
      } else if (status === 'rejected') {
        query.overallStatus = 'rejected';
      } else if (status === 'in-progress') {
        query.overallStatus = 'in-progress';
      }
    }

    // Get KYC submissions with user data
    const submissions = await KYC.find(query)
      .populate('user', 'firstName lastName email phone')
      .populate('identity.verifiedBy', 'name email')
      .populate('address.verifiedBy', 'name email')
      .populate('facial.verifiedBy', 'name email')
      .sort({ submittedAt: -1, createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .lean();

    // Get total count for pagination
    const totalCount = await KYC.countDocuments(query);
    const totalPages = Math.ceil(totalCount / limit);

    // Format response to match frontend expectations
    const formattedSubmissions = submissions.map(submission => ({
      _id: submission._id,
      user: submission.user || {},
      identity: submission.identity || { status: 'not-submitted' },
      address: submission.address || { status: 'not-submitted' },
      facial: submission.facial || { status: 'not-submitted' },
      overallStatus: submission.overallStatus || 'not-started',
      submittedAt: submission.submittedAt,
      createdAt: submission.createdAt,
      reviewedAt: submission.reviewedAt,
      adminNotes: submission.adminNotes
    }));

    console.log(`Found ${formattedSubmissions.length} KYC submissions`);

    res.status(200).json({
      status: 'success',
      data: {
        submissions: formattedSubmissions,
        pagination: {
          currentPage: page,
          totalPages: totalPages,
          totalItems: totalCount,
          itemsPerPage: limit,
          hasNextPage: page < totalPages,
          hasPrevPage: page > 1
        }
      }
    });

  } catch (err) {
    console.error('Get KYC submissions error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch KYC submissions'
    });
  }
});

// Get specific KYC submission details
app.get('/api/admin/kyc/submissions/:submissionId', adminProtect, restrictTo('super', 'support'), async (req, res) => {
  try {
    const { submissionId } = req.params;

    const submission = await KYC.findById(submissionId)
      .populate('user', 'firstName lastName email phone country city address')
      .populate('identity.verifiedBy', 'name email')
      .populate('address.verifiedBy', 'name email')
      .populate('facial.verifiedBy', 'name email')
      .lean();

    if (!submission) {
      return res.status(404).json({
        status: 'fail',
        message: 'KYC submission not found'
      });
    }

    res.status(200).json({
      status: 'success',
      data: {
        submission
      }
    });

  } catch (err) {
    console.error('Get KYC submission details error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch KYC submission details'
    });
  }
});

// Approve KYC submission
app.post('/api/admin/kyc/submissions/:submissionId/approve', adminProtect, restrictTo('super', 'support'), [
  body('notes').optional().trim()
], async (req, res) => {
  try {
    const { submissionId } = req.params;
    const { notes } = req.body;

    const kycSubmission = await KYC.findById(submissionId)
      .populate('user');

    if (!kycSubmission) {
      return res.status(404).json({
        status: 'fail',
        message: 'KYC submission not found'
      });
    }

    // Update KYC status
    kycSubmission.identity.status = 'verified';
    kycSubmission.identity.verifiedAt = new Date();
    kycSubmission.identity.verifiedBy = req.admin._id;

    kycSubmission.address.status = 'verified';
    kycSubmission.address.verifiedAt = new Date();
    kycSubmission.address.verifiedBy = req.admin._id;

    kycSubmission.facial.status = 'verified';
    kycSubmission.facial.verifiedAt = new Date();
    kycSubmission.facial.verifiedBy = req.admin._id;

    kycSubmission.overallStatus = 'verified';
    kycSubmission.reviewedAt = new Date();
    kycSubmission.adminNotes = notes;

    await kycSubmission.save();

    // Update user's KYC status
    await User.findByIdAndUpdate(kycSubmission.user._id, {
      'kycStatus.identity': 'verified',
      'kycStatus.address': 'verified',
      'kycStatus.facial': 'verified'
    });

    res.status(200).json({
      status: 'success',
      message: 'KYC application approved successfully',
      data: {
        submission: kycSubmission
      }
    });

    await logActivity('approve_kyc', 'kyc', kycSubmission._id, req.admin._id, 'Admin', req, {
      userId: kycSubmission.user._id,
      notes
    });

  } catch (err) {
    console.error('Approve KYC error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to approve KYC application'
    });
  }
});

// Reject KYC submission
app.post('/api/admin/kyc/submissions/:submissionId/reject', adminProtect, restrictTo('super', 'support'), [
  body('reason').trim().notEmpty().withMessage('Rejection reason is required'),
  body('section').optional().isIn(['all', 'identity', 'address', 'facial']).withMessage('Invalid section')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { submissionId } = req.params;
    const { reason, section = 'all' } = req.body;

    const kycSubmission = await KYC.findById(submissionId)
      .populate('user');

    if (!kycSubmission) {
      return res.status(404).json({
        status: 'fail',
        message: 'KYC submission not found'
      });
    }

    // Update status based on rejected section
    if (section === 'all' || section === 'identity') {
      kycSubmission.identity.status = 'rejected';
      kycSubmission.identity.rejectionReason = reason;
      kycSubmission.identity.verifiedAt = new Date();
      kycSubmission.identity.verifiedBy = req.admin._id;
    }

    if (section === 'all' || section === 'address') {
      kycSubmission.address.status = 'rejected';
      kycSubmission.address.rejectionReason = reason;
      kycSubmission.address.verifiedAt = new Date();
      kycSubmission.address.verifiedBy = req.admin._id;
    }

    if (section === 'all' || section === 'facial') {
      kycSubmission.facial.status = 'rejected';
      kycSubmission.facial.rejectionReason = reason;
      kycSubmission.facial.verifiedAt = new Date();
      kycSubmission.facial.verifiedBy = req.admin._id;
    }

    // Update overall status
    if (section === 'all') {
      kycSubmission.overallStatus = 'rejected';
    } else {
      // If only specific section rejected, mark as in-progress for resubmission
      kycSubmission.overallStatus = 'in-progress';
    }

    kycSubmission.reviewedAt = new Date();
    kycSubmission.adminNotes = reason;

    await kycSubmission.save();

    // Update user's KYC status
    const userUpdate = {};
    if (section === 'all' || section === 'identity') {
      userUpdate['kycStatus.identity'] = 'rejected';
    }
    if (section === 'all' || section === 'address') {
      userUpdate['kycStatus.address'] = 'rejected';
    }
    if (section === 'all' || section === 'facial') {
      userUpdate['kycStatus.facial'] = 'rejected';
    }

    await User.findByIdAndUpdate(kycSubmission.user._id, userUpdate);

    res.status(200).json({
      status: 'success',
      message: 'KYC application rejected successfully',
      data: {
        submission: kycSubmission
      }
    });

    await logActivity('reject_kyc', 'kyc', kycSubmission._id, req.admin._id, 'Admin', req, {
      userId: kycSubmission.user._id,
      reason,
      section
    });

  } catch (err) {
    console.error('Reject KYC error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to reject KYC application'
    });
  }
});

// Serve KYC files for admin (with authentication) - ENHANCED FOR MEDIA PREVIEW WITH TOKEN SUPPORT
app.get('/api/admin/kyc/files/:type/:filename', adminProtect, restrictTo('super', 'support'), async (req, res) => {
  try {
    const { type, filename } = req.params;
    
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

    // Set CORS headers to allow cross-origin requests from the same domain
    res.setHeader('Access-Control-Allow-Origin', req.headers.origin || '*');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    
    // Set headers for proper media display in browser
    res.setHeader('Content-Type', contentType);
    res.setHeader('Content-Disposition', 'inline; filename="' + filename + '"');
    res.setHeader('Cache-Control', 'private, max-age=3600'); // Cache for 1 hour
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
    console.error('Serve KYC file error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to serve file'
    });
  }
});

// NEW ENDPOINT: Generate secure preview URLs with tokens
app.get('/api/admin/kyc/files/secure/:type/:filename', adminProtect, restrictTo('super', 'support'), async (req, res) => {
  try {
    const { type, filename } = req.params;
    
    // Generate a short-lived token for secure access
    const token = jwt.sign(
      { 
        file: `${type}/${filename}`,
        adminId: req.admin._id,
        timestamp: Date.now()
      },
      process.env.JWT_SECRET,
      { expiresIn: '1h' } // Token valid for 1 hour
    );

    // Return the secure URL
    res.status(200).json({
      status: 'success',
      data: {
        secureUrl: `/api/admin/kyc/files/preview/${token}/${type}/${filename}`,
        token: token
      }
    });

  } catch (err) {
    console.error('Generate secure URL error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to generate secure URL'
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









// Stats endpoint with Redis caching and real-time updates
app.get('/api/stats', async (req, res) => {
    try {
        // Check if we have cached stats
        const cachedStats = await redis.get('stats-data');
        
        if (cachedStats) {
            return res.status(200).json(JSON.parse(cachedStats));
        }

        // Get current UTC time for daily tracking
        const now = new Date();
        const todayUTC = now.toISOString().split('T')[0]; // YYYY-MM-DD

        // Initialize stats with YOUR SPECIFIED FIGURES
        let stats = {
            totalInvestors: 4254256, // 4,254,256 million investors
            totalInvested: 105000000.00,
            totalWithdrawals: 155000000.00,
            totalLoans: 85000000.00,
            totalCloudMiners: 4251235, // 4,251,235 cloud miners
            lastUpdated: now.toISOString(),
            changeRates: {
                investors: 0,
                invested: 0,
                withdrawals: 0,
                loans: 0
            }
        };

        // Set persistent investor count with YOUR FIGURE
        await redis.set('persistent-investor-count', '4254256');
        // Set persistent cloud miner count with YOUR FIGURE
        await redis.set('persistent-cloud-miner-count', '4251235');

        // Initialize fresh daily tracking data with YOUR LIMITS
        let dailyData = {
            date: todayUTC,
            dailyInvestment: 0, // Will grow up to 10 million daily
            dailyInvestmentVolume: 0,
            dailyWithdrawal: 0, // Will grow up to 17 million daily
            dailyLoan: 0, // Will grow up to 10 million daily
            dailyCloudMiners: 0, // Will grow up to 9999 daily
            hourlyInvestors: 0 // Track investors added this hour (max 599)
        };

        // Calculate change rates (random between -11.3% to 31%)
        stats.changeRates = {
            investors: getRandomInRange(-11.3, 31, 1),
            invested: getRandomInRange(-11.3, 31, 1),
            withdrawals: getRandomInRange(-11.3, 31, 1),
            loans: getRandomInRange(-11.3, 31, 1)
        };

        // Cache the stats for 30 seconds
        await redis.set('stats-data', JSON.stringify(stats), 'EX', 30);
        await redis.set('daily-stats', JSON.stringify(dailyData));

        res.status(200).json(stats);
    } catch (err) {
        console.error('Stats error:', err);
        res.status(500).json({
            status: 'error',
            message: 'Failed to fetch stats'
        });
    }
});

// Helper function to generate random numbers in range
function getRandomInRange(min, max, decimals = 2) {
    const rand = Math.random() * (max - min) + min;
    return parseFloat(rand.toFixed(decimals));
}

// Clear previous Redis data to start fresh
async function initializeFreshStats() {
    try {
        // Delete all history from redis
        const keys = await redis.keys('*');
        if (keys.length > 0) {
            await redis.del(keys);
        }
        
        // Set initial investor count
        await redis.set('persistent-investor-count', '4254256');
        // Set initial cloud miner count
        await redis.set('persistent-cloud-miner-count', '4251235');
        
        // Clear any existing stats
        await redis.del('stats-data');
        await redis.del('daily-stats');
        await redis.del('previous-stats');
        
        console.log('Fresh stats initialized with:');
        console.log('- Investors: 4,254,256');
        console.log('- Cloud Miners: 4,251,235');
        console.log('- 24h Investment limit: 10 million');
        console.log('- 24h Withdrawal limit: 17 million');
        console.log('- 24h Loan limit: 10 million');
        console.log('- 24h Cloud Miner join limit: 9999');
    } catch (err) {
        console.error('Failed to initialize fresh stats:', err);
    }
}

// Initialize fresh stats on startup
initializeFreshStats();

// Real-time stats updater with daily limits
setInterval(async () => {
    try {
        // Get current UTC date for daily tracking
        const now = new Date();
        const todayUTC = now.toISOString().split('T')[0];
        const currentHour = now.getUTCHours(); // Track hour for hourly investor limit
        const seconds = now.getSeconds();

        // Get or initialize daily tracking data with YOUR LIMITS
        let dailyData = await redis.get('daily-stats');
        if (!dailyData) {
            dailyData = {
                date: todayUTC,
                dailyInvestment: 0, // 10 million daily limit
                dailyInvestmentVolume: 0,
                dailyWithdrawal: 0, // 17 million daily limit
                dailyLoan: 0, // 10 million daily limit
                dailyCloudMiners: 0, // 9999 daily limit
                hourlyInvestors: 0, // Track investors this hour
                lastHour: currentHour // Track which hour we're in
            };
        } else {
            dailyData = JSON.parse(dailyData);
            // Reset if it's a new day
            if (dailyData.date !== todayUTC) {
                dailyData = {
                    date: todayUTC,
                    dailyInvestment: 0,
                    dailyInvestmentVolume: 0,
                    dailyWithdrawal: 0,
                    dailyLoan: 0,
                    dailyCloudMiners: 0,
                    hourlyInvestors: 0,
                    lastHour: currentHour
                };
            }
            // Reset hourly counter if hour changed
            if (dailyData.lastHour !== currentHour) {
                dailyData.hourlyInvestors = 0;
                dailyData.lastHour = currentHour;
            }
        }

        // Get current stats from cache or initialize with YOUR FIGURES
        let stats = {
            totalInvestors: 4254256,
            totalInvested: 105000000.00,
            totalWithdrawals: 155000000.00,
            totalLoans: 85000000.00,
            totalCloudMiners: 4251235,
            lastUpdated: now.toISOString(),
            changeRates: {
                investors: 0,
                invested: 0,
                withdrawals: 0,
                loans: 0
            }
        };

        // Get current investor count (start with YOUR FIGURE)
        let investorCount = await redis.get('persistent-investor-count');
        if (!investorCount) {
            investorCount = 4254256; // YOUR SPECIFIED FIGURE
            await redis.set('persistent-investor-count', investorCount.toString());
        } else {
            investorCount = parseInt(investorCount);
        }

        // Get current cloud miner count (start with YOUR FIGURE)
        let cloudMinerCount = await redis.get('persistent-cloud-miner-count');
        if (!cloudMinerCount) {
            cloudMinerCount = 4251235; // YOUR SPECIFIED FIGURE
            await redis.set('persistent-cloud-miner-count', cloudMinerCount.toString());
        } else {
            cloudMinerCount = parseInt(cloudMinerCount);
        }

        // Get cached stats if they exist
        const cachedStats = await redis.get('stats-data');
        if (cachedStats) {
            const parsedStats = JSON.parse(cachedStats);
            // Use cached values for totals (they should have grown from your base figures)
            stats.totalInvestors = parsedStats.totalInvestors || investorCount;
            stats.totalInvested = parsedStats.totalInvested || 105000000.00;
            stats.totalWithdrawals = parsedStats.totalWithdrawals || 155000000.00;
            stats.totalLoans = parsedStats.totalLoans || 85000000.00;
            stats.totalCloudMiners = parsedStats.totalCloudMiners || cloudMinerCount;
            stats.changeRates = parsedStats.changeRates || stats.changeRates;
        } else {
            // If no cache, use base values from your specifications
            stats.totalInvestors = investorCount;
            stats.totalCloudMiners = cloudMinerCount;
        }

        // Update investors - grow with up to 599 per hour, added randomly over time
        // Random number of people at random number of seconds (example: 3 sec 1 person, 15 sec 4 people, etc.)
        const lastInvestorUpdate = await redis.get('last-investor-update') || 0;
        const currentTime = Date.now();
        
        // Generate random seconds between 1 and 60 for the next update
        const randomSecondsDelay = Math.floor(Math.random() * 60) + 1; // 1 to 60 seconds
        const minUpdateInterval = randomSecondsDelay * 1000; // Convert to milliseconds
        
        // Check if enough random time has passed since last update
        const timeSinceLastUpdate = currentTime - lastInvestorUpdate;
        
        if (timeSinceLastUpdate >= minUpdateInterval) {
            const maxHourlyInvestors = 599; // Maximum 599 per hour
            if (dailyData.hourlyInvestors < maxHourlyInvestors) {
                const remainingHourly = maxHourlyInvestors - dailyData.hourlyInvestors;
                
                // Generate random number of investors (1 to 15 people per update)
                // But ensure we don't exceed remaining hourly limit
                let increment = Math.floor(Math.random() * 15) + 1; // 1 to 15 people
                const actualIncrement = Math.min(increment, remainingHourly);
                
                if (actualIncrement > 0) {
                    investorCount += actualIncrement;
                    dailyData.hourlyInvestors += actualIncrement;
                    await redis.set('persistent-investor-count', investorCount.toString());
                    await redis.set('last-investor-update', currentTime.toString());
                    stats.totalInvestors = investorCount;
                    
                    console.log(`Investor update: +${actualIncrement} after ${randomSecondsDelay} seconds (Hourly total: ${dailyData.hourlyInvestors}/599)`);
                }
            }
        }

        // Update cloud miners - grow with 1-9 users in random time between 3 sec -5 min
        const lastCloudMinerUpdate = await redis.get('last-cloud-miner-update') || 0;
        const minCloudMinerInterval = 3000; // 3 seconds in milliseconds
        const maxCloudMinerInterval = 300000; // 5 minutes in milliseconds
        
        // Check if enough random time has passed since last update
        const timeSinceLastCloudMinerUpdate = currentTime - lastCloudMinerUpdate;
        const randomCloudMinerInterval = getRandomInRange(minCloudMinerInterval, maxCloudMinerInterval, 0);
        
        if (timeSinceLastCloudMinerUpdate >= randomCloudMinerInterval) {
            const dailyCloudMinerLimit = 9999; // YOUR SPECIFIED: 9999 daily limit
            if (dailyData.dailyCloudMiners < dailyCloudMinerLimit) {
                const remainingDaily = dailyCloudMinerLimit - dailyData.dailyCloudMiners;
                // Random increment 1-9 users (not more than 9 per update)
                const increment = Math.floor(Math.random() * 9) + 1;
                const actualIncrement = Math.min(increment, remainingDaily);
                
                if (actualIncrement > 0) {
                    cloudMinerCount += actualIncrement;
                    dailyData.dailyCloudMiners += actualIncrement;
                    await redis.set('persistent-cloud-miner-count', cloudMinerCount.toString());
                    await redis.set('last-cloud-miner-update', currentTime.toString());
                    stats.totalCloudMiners = cloudMinerCount;
                }
            }
        }

        // Update invested with daily limit of 10 million
        if (seconds % getRandomInRange(5, 20, 0) === 0) {
            const dailyInvestmentLimit = 10000000; // YOUR SPECIFIED: 10 million daily limit
            if (dailyData.dailyInvestment < dailyInvestmentLimit) {
                const remainingDaily = dailyInvestmentLimit - dailyData.dailyInvestment;
                const increment = getRandomInRange(1200.33, 111368.21, 2);
                const actualIncrement = Math.min(increment, remainingDaily);
                
                if (actualIncrement > 0) {
                    stats.totalInvested += actualIncrement;
                    dailyData.dailyInvestment += actualIncrement;
                }
            }
        }

        // Update withdrawals with daily limit of 17 million
        if (seconds % getRandomInRange(10, 25, 0) === 0) {
            const dailyWithdrawalLimit = 17000000; // YOUR SPECIFIED: 17 million daily limit
            if (dailyData.dailyWithdrawal < dailyWithdrawalLimit) {
                const remainingDaily = dailyWithdrawalLimit - dailyData.dailyWithdrawal;
                const increment = getRandomInRange(4997.33, 321238.11, 2);
                const actualIncrement = Math.min(increment, remainingDaily);
                
                if (actualIncrement > 0) {
                    stats.totalWithdrawals += actualIncrement;
                    dailyData.dailyWithdrawal += actualIncrement;
                }
            }
        }

        // Update loans with daily limit of 10 million
        if (seconds % getRandomInRange(8, 18, 0) === 0) {
            const dailyLoanLimit = 10000000; // YOUR SPECIFIED: 10 million daily limit
            if (dailyData.dailyLoan < dailyLoanLimit) {
                const remainingDaily = dailyLoanLimit - dailyData.dailyLoan;
                const increment = getRandomInRange(1000, 100000, 2);
                const actualIncrement = Math.min(increment, remainingDaily);
                
                if (actualIncrement > 0) {
                    stats.totalLoans += actualIncrement;
                    dailyData.dailyLoan += actualIncrement;
                }
            }
        }

        // Recalculate change rates periodically
        if (seconds % 30 === 0) {
            stats.changeRates = {
                investors: getRandomInRange(-11.3, 31, 1),
                invested: getRandomInRange(-11.3, 31, 1),
                withdrawals: getRandomInRange(-11.3, 31, 1),
                loans: getRandomInRange(-11.3, 31, 1)
            };
        }

        stats.lastUpdated = now.toISOString();

        // Update cache and daily tracking
        await redis.set('stats-data', JSON.stringify(stats), 'EX', 30);
        await redis.set('daily-stats', JSON.stringify(dailyData));

    } catch (err) {
        console.error('Stats updater error:', err);
    }
}, 1000); // Run every second to check for updates









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











/**
 * GET /api/withdrawals/asset - Get available assets for withdrawal
 */
app.get('/api/withdrawals/asset', protect, async (req, res) => {
    try {
        const userId = req.user._id;

        // Get user's asset balances
        const userAssetBalance = await UserAssetBalance.findOne({ user: userId });
        
        if (!userAssetBalance) {
            return res.status(200).json({
                status: 'success',
                data: {
                    assets: []
                }
            });
        }

        // Filter assets with balance > 0
        const balances = userAssetBalance.balances || {};
        const assets = [];

        for (const [symbol, amount] of Object.entries(balances)) {
            if (amount > 0) {
                // Get current price for USD value
                let usdValue = 0;
                let currentPrice = 0;
                try {
                    const assetPrice = await AssetPrice.findOne({ symbol: symbol });
                    if (assetPrice) {
                        currentPrice = assetPrice.currentPrice;
                        usdValue = amount * currentPrice;
                    }
                } catch (err) {
                    console.warn(`Could not fetch price for ${symbol}`);
                }

                assets.push({
                    symbol: symbol,
                    amount: amount,
                    usdValue: usdValue,
                    currentPrice: currentPrice
                });
            }
        }

        // Sort by USD value descending
        assets.sort((a, b) => b.usdValue - a.usdValue);

        return res.status(200).json({
            status: 'success',
            data: {
                assets: assets
            }
        });

    } catch (err) {
        console.error('Error fetching assets:', err);
        return res.status(500).json({
            status: 'error',
            message: 'Failed to fetch assets'
        });
    }
});

/**
 * POST /api/withdrawals/asset - Process asset withdrawal
 */
app.post('/api/withdrawals/asset', protect, async (req, res) => {
    try {
        const userId = req.user._id;
        const {
            amount,
            asset,
            walletAddress,
            gasFee,
            exchangeRate,
            balanceSource,
            mainAmountUsed,
            maturedAmountUsed
        } = req.body;

        // Validation
        if (!amount || amount < 100) {
            return res.status(400).json({
                status: 'error',
                message: 'Minimum withdrawal amount is $100'
            });
        }

        if (!asset) {
            return res.status(400).json({
                status: 'error',
                message: 'Asset is required'
            });
        }

        if (!walletAddress || walletAddress.length < 26) {
            return res.status(400).json({
                status: 'error',
                message: 'Valid wallet address is required'
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
        const reference = `WDR-${asset.toUpperCase()}-${Date.now()}-${Math.floor(Math.random() * 1000)}`;

        // Calculate asset amount
        const assetAmount = amount / exchangeRate;

        // Create transaction record
        const transaction = await Transaction.create({
            user: userId,
            type: 'withdrawal',
            amount: amount,
            asset: asset,
            assetAmount: assetAmount,
            currency: 'USD',
            status: 'pending',
            method: asset,
            reference: reference,
            details: {
                walletAddress: walletAddress,
                exchangeRate: exchangeRate,
                gasFee: gasFee,
                balanceSource: balanceSource,
                mainAmountUsed: mainAmountUsed || 0,
                maturedAmountUsed: maturedAmountUsed || 0,
                assetAmount: assetAmount
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
                asset: asset,
                reference: reference,
                walletAddress: walletAddress,
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
                    asset: asset,
                    status: 'pending',
                    createdAt: transaction.createdAt
                }
            },
            message: 'Withdrawal request submitted successfully'
        });

    } catch (err) {
        console.error('Asset withdrawal error:', err);
        return res.status(500).json({
            status: 'error',
            message: err.message || 'Failed to process withdrawal request'
        });
    }
});

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

/**
 * POST /api/withdrawals/confirm-gas-payment - Confirm gas fee payment
 */
app.post('/api/withdrawals/confirm-gas-payment', protect, async (req, res) => {
    try {
        const userId = req.user._id;
        const {
            asset,
            amount,
            address,
            withdrawalData
        } = req.body;

        // Create a deposit record for the gas fee
        const gasFeeDeposit = await DepositAsset.create({
            user: userId,
            asset: asset,
            amount: amount,
            usdValue: amount * (withdrawalData?.exchangeRate || 1),
            status: 'pending',
            metadata: {
                type: 'gas_fee',
                withdrawalReference: withdrawalData?.reference,
                destinationAddress: address,
                submittedAt: new Date()
            }
        });

        return res.status(200).json({
            status: 'success',
            data: {
                depositId: gasFeeDeposit._id,
                message: 'Gas fee payment recorded, awaiting confirmation'
            }
        });

    } catch (err) {
        console.error('Error confirming gas payment:', err);
        return res.status(500).json({
            status: 'error',
            message: err.message || 'Failed to confirm gas payment'
        });
    }
});








// =============================================
// TRADING ORDERS ENDPOINT - Get all user orders
// =============================================
app.get('/api/trading/orders', protect, async (req, res) => {
  try {
    const userId = req.user._id;
    
    // Find all orders for this user
    const orders = await UserOrder.find({ user: userId })
      .sort({ createdAt: -1 })
      .limit(100); // Limit to last 100 orders for performance

    // Format orders exactly as frontend expects
    const formattedOrders = orders.map(order => ({
      id: order._id,
      symbol: order.symbol + order.quoteAsset || 'USDT', // e.g., "ETHUSDT"
      baseAsset: order.symbol,
      quoteAsset: order.quoteAsset || 'USDT',
      side: order.type, // 'buy' or 'sell'
      type: order.orderType || 'limit', // 'limit' or 'market'
      price: order.price,
      amount: order.amount,
      filled: order.filled || 0,
      remaining: order.remaining || order.amount,
      total: order.total || (order.price * order.amount),
      status: order.status, // 'open', 'partial', 'filled', 'cancelled'
      createdAt: order.createdAt,
      updatedAt: order.updatedAt
    }));

    return res.status(200).json({
      status: 'success',
      results: formattedOrders.length,
      data: formattedOrders
    });

  } catch (err) {
    console.error('Error fetching trading orders:', err);
    return res.status(500).json({
      status: 'error',
      message: 'Failed to fetch orders'
    });
  }
});

// =============================================
// USER TRADES ENDPOINT - Get user's trade history
// =============================================
app.get('/api/trading/trades', protect, async (req, res) => {
  try {
    const userId = req.user._id;
    
    // Combine completed orders and trade history
    const [completedOrders, recentTrades] = await Promise.all([
      // Get all completed orders (filled/cancelled)
      UserOrder.find({ 
        user: userId,
        status: { $in: ['filled', 'completed'] }
      }).sort({ updatedAt: -1 }).limit(50),
      
      // Get user's recent trades from trade history
      RecentTrade.find({ userId })
        .sort({ timestamp: -1 })
        .limit(50)
        .populate('orderId')
    ]);

    // Format completed orders as trades
    const orderTrades = completedOrders.map(order => ({
      id: order._id,
      symbol: order.symbol + (order.quoteAsset || 'USDT'),
      baseAsset: order.symbol,
      quoteAsset: order.quoteAsset || 'USDT',
      side: order.type,
      price: order.price,
      amount: order.filled || order.amount,
      total: order.filled ? order.filled * order.price : order.total,
      time: order.updatedAt || order.createdAt,
      isBuyerMaker: order.type === 'buy'
    }));

    // Format recent trades
    const tradeHistory = recentTrades.map(trade => ({
      id: trade._id,
      symbol: trade.symbol + 'USDT',
      baseAsset: trade.symbol,
      quoteAsset: 'USDT',
      side: trade.type,
      price: trade.price,
      amount: trade.amount,
      total: trade.total,
      time: trade.timestamp,
      isBuyerMaker: trade.type === 'buy'
    }));

    // Combine and sort by time (newest first)
    const allTrades = [...orderTrades, ...tradeHistory]
      .sort((a, b) => new Date(b.time) - new Date(a.time))
      .slice(0, 100);

    return res.status(200).json({
      status: 'success',
      results: allTrades.length,
      data: allTrades
    });

  } catch (err) {
    console.error('Error fetching user trades:', err);
    return res.status(500).json({
      status: 'error',
      message: 'Failed to fetch trade history'
    });
  }
});








// =============================================
// SELL ORDER ENDPOINT - Create a sell order
// =============================================
app.post('/api/trading/orders/sell', protect, async (req, res) => {
  try {
    const userId = req.user._id;
    const { symbol, baseAsset, quoteAsset, side, type, price, amount, total, useMaturedBalance } = req.body;

    // Validation
    if (!symbol || !baseAsset || !amount || !total || !price) {
      return res.status(400).json({
        status: 'error',
        message: 'Missing required fields'
      });
    }

    // Check minimum trade amount ($10)
    if (total < 10) {
      return res.status(400).json({
        status: 'error',
        message: `Minimum trade amount is $10. Your total is $${total.toFixed(2)}`
      });
    }

    // Get user and their asset balance
    const user = await User.findById(userId).select('balances');
    if (!user) {
      return res.status(404).json({
        status: 'error',
        message: 'User not found'
      });
    }

    // Get user's asset balance
    const assetKey = baseAsset.toLowerCase();
    const userAssetBalance = await mongoose.model('UserAssetBalance').findOne({ user: userId });
    
    if (!userAssetBalance) {
      return res.status(400).json({
        status: 'error',
        message: `You don't have any ${baseAsset} balance`
      });
    }

    const assetBalance = userAssetBalance.balances?.[assetKey] || 0;
    
    // Check sufficient asset balance
    if (amount > assetBalance) {
      return res.status(400).json({
        status: 'error',
        message: `Insufficient ${baseAsset} balance. You have ${assetBalance.toFixed(6)} but need ${amount.toFixed(6)}`
      });
    }

    // Calculate average buy price for profit/loss (if needed)
    const buyHistory = userAssetBalance.history?.filter(h => h.asset === assetKey && h.type === 'buy') || [];
    const avgBuyPrice = buyHistory.length > 0 
      ? buyHistory.reduce((sum, h) => sum + h.price, 0) / buyHistory.length 
      : price;
    
    const profitLoss = (price - avgBuyPrice) * amount;
    const profitLossPercentage = avgBuyPrice > 0 ? ((price - avgBuyPrice) / avgBuyPrice) * 100 : 0;

    // Generate unique reference
    const reference = `SELL-${Date.now()}-${Math.floor(Math.random() * 10000)}`;

    // Create transaction record
    const transaction = new Transaction({
      user: userId,
      type: 'sell',
      amount: total,
      currency: 'USD',
      status: 'completed',
      method: quoteAsset || 'USDT',
      reference: reference,
      details: {
        asset: baseAsset,
        assetAmount: amount,
        price: price,
        symbol: symbol,
        profitLoss: profitLoss,
        profitLossPercentage: profitLossPercentage
      },
      asset: assetKey,
      assetAmount: amount,
      sellDetails: {
        asset: assetKey,
        amountUSD: total,
        assetAmount: amount,
        sellingPrice: price,
        buyingPrice: avgBuyPrice,
        profitLoss: profitLoss,
        profitLossPercentage: profitLossPercentage
      },
      fee: 0,
      netAmount: total
    });
    
    await transaction.save();

    // Credit USD to user's main/matured balance
    let mainCredit = 0;
    let maturedCredit = 0;

    if (useMaturedBalance) {
      maturedCredit = total;
    } else {
      mainCredit = total;
    }

    await User.findByIdAndUpdate(userId, {
      $inc: {
        'balances.main': mainCredit,
        'balances.matured': maturedCredit
      }
    });

    // Update user's asset balance (deduct the sold amount)
    userAssetBalance.balances[assetKey] = (userAssetBalance.balances[assetKey] || 0) - amount;
    
    // Add to history
    userAssetBalance.history.push({
      asset: assetKey,
      type: 'sell',
      amount: -amount,
      balance: userAssetBalance.balances[assetKey],
      usdValue: total,
      price: price,
      profitLoss: profitLoss,
      profitLossPercentage: profitLossPercentage,
      transactionId: transaction._id,
      timestamp: new Date()
    });
    
    userAssetBalance.lastUpdated = new Date();
    await userAssetBalance.save();

    // Create sell record using your existing Sell model
    const sell = new Sell({
      user: userId,
      asset: assetKey,
      amountUSD: total,
      assetAmount: amount,
      price: price,
      total: total,
      fromWallets: {
        main: mainCredit,
        matured: maturedCredit
      },
      profitLoss: profitLoss,
      profitLossPercentage: profitLossPercentage,
      avgBuyPrice: avgBuyPrice,
      status: 'completed',
      transactionId: transaction._id
    });
    
    await sell.save();

    // Log activity
    await logActivity('sell_completed', 'Sell', sell._id, userId, 'User', req, {
      amount: total,
      asset: baseAsset,
      assetAmount: amount,
      price: price,
      profitLoss: profitLoss,
      profitLossPercentage: profitLossPercentage,
      toBalances: {
        main: mainCredit,
        matured: maturedCredit
      }
    });

    return res.status(201).json({
      status: 'success',
      message: 'Sell order completed successfully',
      data: {
        orderId: sell._id,
        transactionId: transaction._id,
        symbol: `${baseAsset}/${quoteAsset}`,
        side: 'sell',
        price: price,
        amount: amount,
        total: total,
        profitLoss: profitLoss,
        profitLossPercentage: profitLossPercentage,
        status: 'completed',
        createdAt: new Date()
      }
    });

  } catch (err) {
    console.error('Error creating sell order:', err);
    return res.status(500).json({
      status: 'error',
      message: err.message || 'Failed to create sell order'
    });
  }
});





// =============================================
// BUY ORDER ENDPOINT - Create a buy order (FIXED)
// =============================================
app.post('/api/trading/orders/buy', protect, async (req, res) => {
  try {
    const userId = req.user._id;
    const { symbol, baseAsset, quoteAsset, side, type, price, amount, total, useMaturedBalance } = req.body;

    // Validation
    if (!symbol || !baseAsset || !amount || !total || !price) {
      return res.status(400).json({
        status: 'error',
        message: 'Missing required fields'
      });
    }

    // Check minimum trade amount ($10)
    if (total < 10) {
      return res.status(400).json({
        status: 'error',
        message: `Minimum trade amount is $10. Your total is $${total.toFixed(2)}`
      });
    }

    // Get user with current balances
    const user = await User.findById(userId).select('balances');
    if (!user) {
      return res.status(404).json({
        status: 'error',
        message: 'User not found'
      });
    }

    // Calculate available balance (main + matured)
    const mainBalance = user.balances.main || 0;
    const maturedBalance = user.balances.matured || 0;
    const totalAvailable = mainBalance + maturedBalance;

    // Check sufficient funds
    if (total > totalAvailable) {
      return res.status(400).json({
        status: 'error',
        message: `Insufficient balance. You have $${totalAvailable.toFixed(2)} available but need $${total.toFixed(2)}`
      });
    }

    // Determine which balance to deduct from (matured first if allowed)
    let mainDeduction = 0;
    let maturedDeduction = 0;

    if (useMaturedBalance && maturedBalance >= total) {
      maturedDeduction = total;
    } else if (useMaturedBalance && maturedBalance > 0) {
      maturedDeduction = maturedBalance;
      mainDeduction = total - maturedBalance;
    } else {
      mainDeduction = total;
    }

    // Deduct from user balances FIRST
    await User.findByIdAndUpdate(userId, {
      $inc: {
        'balances.main': -mainDeduction,
        'balances.matured': -maturedDeduction
      }
    });

    // Generate unique reference
    const reference = `BUY-${Date.now()}-${Math.floor(Math.random() * 10000)}`;

    // Create buy record using your existing Buy model
    const buy = new Buy({
      user: userId,
      asset: baseAsset.toLowerCase(),
      amountUSD: total,
      assetAmount: amount,
      price: price,
      total: total,
      fromWallets: {
        main: mainDeduction,
        matured: maturedDeduction
      },
      status: 'completed',
      transactionId: null // Will update after transaction is created
    });
    
    await buy.save();

    // Create transaction record with CORRECT method enum
    const transaction = new Transaction({
      user: userId,
      type: 'buy',
      amount: total,
      currency: 'USD',
      status: 'completed',
      method: 'internal', // FIXED: Using 'internal' instead of 'USDT' which matches your enum
      reference: reference,
      details: {
        asset: baseAsset,
        assetAmount: amount,
        price: price,
        symbol: symbol,
        buyId: buy._id
      },
      asset: baseAsset.toLowerCase(),
      assetAmount: amount,
      fee: 0,
      netAmount: total
    });
    
    await transaction.save();

    // Update buy record with transaction ID
    buy.transactionId = transaction._id;
    await buy.save();

    // Update or create user asset balance
    let userAssetBalance = await mongoose.model('UserAssetBalance').findOne({ user: userId });
    
    if (!userAssetBalance) {
      userAssetBalance = new (mongoose.model('UserAssetBalance'))({
        user: userId,
        balances: {}
      });
    }
    
    // Initialize balances if not exists
    if (!userAssetBalance.balances) {
      userAssetBalance.balances = {};
    }
    
    const assetKey = baseAsset.toLowerCase();
    userAssetBalance.balances[assetKey] = (userAssetBalance.balances[assetKey] || 0) + amount;
    
    // Add to history
    if (!userAssetBalance.history) {
      userAssetBalance.history = [];
    }
    
    userAssetBalance.history.push({
      asset: assetKey,
      type: 'buy',
      amount: amount,
      balance: userAssetBalance.balances[assetKey],
      usdValue: total,
      price: price,
      transactionId: transaction._id,
      timestamp: new Date()
    });
    
    userAssetBalance.lastUpdated = new Date();
    await userAssetBalance.save();

    // Log activity
    await logActivity('buy_completed', 'Buy', buy._id, userId, 'User', req, {
      amount: total,
      asset: baseAsset,
      assetAmount: amount,
      price: price,
      fromBalances: {
        main: mainDeduction,
        matured: maturedDeduction
      }
    });

    return res.status(201).json({
      status: 'success',
      message: 'Buy order completed successfully',
      data: {
        orderId: buy._id,
        transactionId: transaction._id,
        symbol: `${baseAsset}/${quoteAsset}`,
        side: 'buy',
        price: price,
        amount: amount,
        total: total,
        status: 'completed',
        createdAt: new Date()
      }
    });

  } catch (err) {
    console.error('Error creating buy order:', err);
    return res.status(500).json({
      status: 'error',
      message: err.message || 'Failed to create buy order'
    });
  }
});







// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Global error handler:', err);
  res.status(500).json({
    status: 'error',
    message: 'Something went wrong on the server'
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    status: 'fail',
    message: `Can't find ${req.originalUrl} on this server`
  });
});

// Create HTTP server and Socket.IO
const PORT = process.env.PORT || 3000;
const httpServer = createServer(app);
const io = new Server(httpServer, {
  cors: {
    origin: ['https://bithhash.vercel.app', 'https://website-backendd-1.onrender.com'],
    methods: ['GET', 'POST']
  }
});

// Socket.IO connection handler
io.on('connection', (socket) => {
  console.log('New client connected:', socket.id);

  // Verify admin token for admin connections
  socket.on('authenticate', async (token) => {
    try {
      const decoded = verifyJWT(token);
      if (!decoded.isAdmin) {
        socket.disconnect();
        return;
      }

      const admin = await Admin.findById(decoded.id);
      if (!admin) {
        socket.disconnect();
        return;
      }

      socket.adminId = admin._id;
      console.log(`Admin ${admin.email} connected`);
    } catch (err) {
      socket.disconnect();
    }
  });

  socket.on('disconnect', () => {
    console.log('Client disconnected:', socket.id);
  });
});


// Function to automatically complete matured investments
const processMaturedInvestments = async () => {
  try {
    const now = new Date();
    const maturedInvestments = await Investment.find({
      status: 'active',
      endDate: { $lte: now }
    }).populate('user plan');

    for (const investment of maturedInvestments) {
      try {
        const user = await User.findById(investment.user._id);
        if (!user) continue;

        // Calculate total return
        const totalReturn = investment.amount + (investment.amount * investment.plan.percentage / 100);

        // Transfer balances
        user.balances.active -= investment.amount;
        user.balances.matured += totalReturn;

        // Update investment
        investment.status = 'completed';
        investment.completionDate = now;
        investment.actualReturn = totalReturn - investment.amount;

        await user.save();
        await investment.save();

        // Create transaction record
        await Transaction.create({
          user: investment.user._id,
          type: 'interest',
          amount: totalReturn - investment.amount,
          currency: 'USD',
          status: 'completed',
          method: 'internal',
          reference: `AUTO-RET-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
          details: {
            investmentId: investment._id,
            planName: investment.plan.name,
            principal: investment.amount,
            interest: totalReturn - investment.amount
          },
          fee: 0,
          netAmount: totalReturn - investment.amount
        });

        console.log(`Automatically completed investment ${investment._id} for user ${user.email}`);
      } catch (err) {
        console.error(`Error processing investment ${investment._id}:`, err);
      }
    }
  } catch (err) {
    console.error('Error processing matured investments:', err);
  }
};

// Run every hour to check for matured investments
setInterval(processMaturedInvestments, 60 * 60 * 1000);

// Also run once on server start
processMaturedInvestments();

// Start server
httpServer.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
