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
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const { OAuth2Client } = require('google-auth-library');
const Redis = require('ioredis');
const moment = require('moment');

const cron = require('node-cron');
const PDFDocument = require('pdfkit');
const { ChartJSNodeCanvas } = require('chartjs-node-canvas');
const { Resvg } = require('@resvg/resvg-js');
const sharp = require('sharp');
const validator = require('validator');
const { body, validationResult } = require('express-validator');
const axios = require('axios');
const speakeasy = require('speakeasy');
const { v4: uuidv4 } = require('uuid');
const WebSocket = require('ws');
const OpenAI = require('openai');
const DeviceDetector = require('node-device-detector');
const DeviceHelper = require('node-device-detector/helper');

const app = express();
const { createServer } = require('http');
const { Server } = require('socket.io');
app.set('trust proxy', 1);

// Initialize device detector
const deviceDetector = new DeviceDetector({
  clientIndexes: true,
  deviceIndexes: true,
  deviceAliasCode: false
});

// Update your helmet configuration to allow framing from your frontend
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://apis.google.com"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      imgSrc: ["'self'", "data:", "https:", "blob:"],
      connectSrc: ["'self'", "https://api.ipinfo.io", "https://website-backendd-1.onrender.com", "https://api.coingecko.com", "https://bithash-backend-1.onrender.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      objectSrc: ["'none'"],
      frameSrc: ["'self'", "https://bithash-backend-1.onrender.com", "https://www.bithashcapital.live", "chrome-error://chromewebdata/"],
      frameAncestors: ["'self'", "https://www.bithashcapital.live", "https://bithhash.vercel.app"],
      upgradeInsecureRequests: null
    }
  },
  crossOriginResourcePolicy: { policy: "cross-origin" },
  crossOriginEmbedderPolicy: false,
  crossOriginOpenerPolicy: { policy: "unsafe-none" }
}));

app.use(cors({
  origin: [
    'https://www.bithashcapital.live', 
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: [
    'Content-Type', 
    'Authorization', 
    'X-CSRF-Token',
    'X-Rate-Limit',
    'X-Requested-With',
    'Accept',
    'Origin',
    'X-2FA-Verified'
  ],
  exposedHeaders: [
    'X-Rate-Limit-Limit',
    'X-Rate-Limit-Remaining',
    'X-Rate-Limit-Reset'
  ]
}));

app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  
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

const redis = new Redis({
  host: process.env.REDIS_HOST,
  port: process.env.REDIS_PORT,
  password: process.env.REDIS_PASSWORD,
  retryStrategy: (times) => {
    const delay = Math.min(times * 50, 2000);
    return delay;
  },
  maxRetriesPerRequest: 3,
  enableReadyCheck: true,
  lazyConnect: false,
  keepAlive: 10000,
  connectTimeout: 10000
});

redis.on('error', (err) => {
  if (process.env.NODE_ENV !== 'production') console.error('Redis error:', err);
});

redis.on('connect', () => {
  if (process.env.NODE_ENV !== 'production') console.log('Redis connected successfully');
});

const getRealClientIP = (req) => {
  const forwardedFor = req.headers['x-forwarded-for'];
  if (forwardedFor) {
    return forwardedFor.split(',')[0].trim();
  }
  
  const cfConnectingIp = req.headers['cf-connecting-ip'];
  if (cfConnectingIp) {
    return cfConnectingIp;
  }
  
  const realIp = req.headers['x-real-ip'];
  if (realIp) {
    return realIp;
  }
  
  return req.ip || 
         req.connection?.remoteAddress || 
         req.socket?.remoteAddress || 
         req.connection?.socket?.remoteAddress ||
         '0.0.0.0';
};

const apiLimiter = rateLimit({
  store: new RedisStore({
    client: redis,
    prefix: 'rl:api:',
    sendCommand: (...args) => redis.call(...args)
  }),
  windowMs: 15 * 60 * 1000,
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
  windowMs: 60 * 60 * 1000,
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



app.get('/api/health', (req, res) => {
  res.status(200).json({ 
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

mongoose.connect(process.env.MONGODB_URI, {
  autoIndex: true,
  connectTimeoutMS: 30000,
  socketTimeoutMS: 30000,
  maxPoolSize: 50,
  minPoolSize: 5,
  maxIdleTimeMS: 10000,
  waitQueueTimeoutMS: 5000,
  retryWrites: true,
  retryReads: true
})
.then(() => {
  if (process.env.NODE_ENV !== 'production') console.log('MongoDB connected successfully');
})
.catch(err => {
  console.error('MongoDB connection error:', err);
  process.exit(1);
});

const createTransporter = (user, pass) => {
  return nodemailer.createTransport({
    host: process.env.EMAIL_HOST,
    port: process.env.EMAIL_PORT,
    secure: process.env.EMAIL_SECURE === 'true',
    auth: {
      user: user,
      pass: pass
    },
    tls: {
      rejectUnauthorized: false
    },
    pool: true,
    maxConnections: 5,
    maxMessages: 100
  });
};

const infoTransporter = createTransporter(
  process.env.EMAIL_INFO_USER,
  process.env.EMAIL_INFO_PASS
);

const supportTransporter = createTransporter(
  process.env.EMAIL_SUPPORT_USER,
  process.env.EMAIL_SUPPORT_PASS
);

const transporter = infoTransporter;

const googleClient = new OAuth2Client({
  clientId: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  redirectUri: process.env.GOOGLE_REDIRECT_URI
});

const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '7200s';
const JWT_COOKIE_EXPIRES = process.env.JWT_COOKIE_EXPIRES || 0.083;

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
  },
  location: {
    lastKnown: {
      lat: { type: Number },
      lng: { type: Number },
      country: { type: String },
      city: { type: String },
      region: { type: String },
      updatedAt: { type: Date },
      ipAddress: { type: String },
      userAgent: { type: String },
      exactLocation: { type: Boolean, default: true }
    },
    locationHistory: [{
      lat: { type: Number },
      lng: { type: Number },
      locationDetails: {
        country: String,
        city: String,
        region: String,
        street: String,
        postalCode: String,
        timezone: String
      },
      ipAddress: String,
      userAgent: String,
      timestamp: { type: Date, default: Date.now }
    }]
  },
  cookiePreferences: {
    consent: { type: String, enum: ['all', 'essential', 'functional', 'analytics', 'custom', 'reject'], default: 'essential' },
    settings: {
      essential: { type: Boolean, default: true },
      functional: { type: Boolean, default: false },
      analytics: { type: Boolean, default: false },
      marketing: { type: Boolean, default: false }
    },
    updatedAt: { type: Date },
    ipAddress: { type: String }
  },
  ipPreferences: {
    language: { type: String, default: 'en' },
    currency: { type: String, default: 'USD' },
    setFromIP: { type: Boolean, default: false },
    detectedAt: Date,
    detectedCountry: String
  },
  balances: {
    main: {
      type: Map,
      of: Number,
      default: new Map()
    },
    active: {
      type: Map,
      of: Number,
      default: new Map()
    },
    matured: {
      type: Map,
      of: Number,
      default: new Map()
    }
  }
}, { 
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

UserSchema.virtual('fullName').get(function() {
  return `${this.firstName} ${this.lastName}`;
});

UserSchema.add({
  referralStats: {
    totalReferrals: { type: Number, default: 0 },
    totalEarnings: { type: Number, default: 0 },
    availableBalance: { type: Number, default: 0 },
    withdrawn: { type: Number, default: 0 },
    referralTier: { type: Number, default: 1 },
  },
  referralHistory: [{
    referredUser: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    amount: Number,
    percentage: Number,
    level: Number,
    date: { type: Date, default: Date.now },
    status: { type: String, enum: ['pending', 'available', 'withdrawn'], default: 'pending' }
  }]
});

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

TranslationSchema.index({ language: 1, key: 1, namespace: 1 }, { unique: true });
TranslationSchema.index({ language: 1, namespace: 1 });
TranslationSchema.index({ isActive: 1 });

const Translation = mongoose.model('Translation', TranslationSchema);

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

DownlineRelationshipSchema.index({ downline: 1 }, { unique: true });
DownlineRelationshipSchema.index({ upline: 1, downline: 1 }, { unique: true });
DownlineRelationshipSchema.index({ status: 1 });

DownlineRelationshipSchema.virtual('relationshipDescription').get(function() {
  return `${this.downline} is downline of ${this.upline} with ${this.commissionPercentage}% commission`;
});

const DownlineRelationship = mongoose.model('DownlineRelationship', DownlineRelationshipSchema);

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

const UserLogSchema = new mongoose.Schema({
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
  action: {
    type: String,
    required: true,
    enum: [
      'signup', 'login', 'logout', 'login_attempt', 'session_created', 
      'session_timeout', 'failed_login', 'suspicious_activity',
      'password_change', 'password_reset_request', 'password_reset_complete',
      'profile_update', 'profile_view', 'account_settings_update',
      'email_verification', 'account_deletion', 'account_suspended',
      '2fa_enable', '2fa_disable', '2fa_verification', 'security_settings_update',
      'api_key_create', 'api_key_delete', 'api_key_regenerate',
      'device_login', 'device_verification', 'trusted_device_added',
      'deposit_created', 'deposit_pending', 'deposit_completed', 'deposit_failed',
      'deposit_cancelled', 'btc_deposit_initiated', 'card_deposit_attempt',
      'withdrawal_created', 'withdrawal_pending', 'withdrawal_completed', 
      'withdrawal_failed', 'withdrawal_cancelled', 'btc_withdrawal_initiated',
      'transfer_created', 'transfer_completed', 'transfer_failed',
      'internal_transfer', 'balance_transfer',
      'buy_created', 'buy_completed', 'buy_failed',
      'sell_created', 'sell_completed', 'sell_failed',
      'investment_created', 'investment_active', 'investment_completed',
      'investment_cancelled', 'investment_matured', 'investment_payout',
      'investment_rollover', 'plan_selected',
      'kyc_submission', 'kyc_pending', 'kyc_approved', 'kyc_rejected',
      'kyc_document_upload', 'identity_verification', 'address_verification',
      'referral_joined', 'referral_bonus_earned', 'referral_payout',
      'referral_code_used', 'referral_link_shared',
      'support_ticket_created', 'support_ticket_updated', 'support_ticket_closed',
      'contact_form_submitted', 'live_chat_started', 'email_sent',
      'notification_received', 'notification_read', 'email_preference_updated',
      'push_notification_enabled', 'sms_notification_enabled',
      'admin_login', 'admin_action', 'system_maintenance', 'balance_adjustment',
      'manual_transaction', 'user_verified', 'user_blocked',
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
  ipAddress: {
    type: String,
    required: true,
    index: true
  },
  userAgent: {
    type: String,
    required: true
  },
  deviceInfo: {
    type: {
      type: String,
      enum: ['desktop', 'mobile', 'tablet', 'unknown','system'],
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
  // =============================================
  // FIXED: Enhanced Location Field Structure
  // Now properly stores all location data needed by admin dashboard
  // =============================================
  location: {
    // IP address (removed from JSON output for security)
    ip: {
      type: String,
      select: false  // Don't expose IP in API responses by default
    },
    // Country information
    country: {
      code: {
        type: String,
        uppercase: true,
        default: 'Unknown'
      },
      name: {
        type: String,
        default: 'Unknown'
      }
    },
    // Region/State information
    region: {
      code: {
        type: String,
        default: 'Unknown'
      },
      name: {
        type: String,
        default: 'Unknown'
      }
    },
    // City
    city: {
      type: String,
      default: 'Unknown'
    },
    // Postal/ZIP code
    postalCode: {
      type: String,
      default: 'Unknown'
    },
    // Geographic coordinates (for map display)
    latitude: {
      type: Number,
      default: null
    },
    longitude: {
      type: Number,
      default: null
    },
    // Timezone
    timezone: {
      type: String,
      default: 'Unknown'
    },
    // ISP information
    isp: {
      type: String,
      default: 'Unknown'
    },
    asn: {
      type: String,
      default: 'Unknown'
    },
    // Street address (if available)
    street: {
      type: String,
      default: 'Unknown'
    },
    // Flag indicating if this is an exact location (vs approximate)
    exactLocation: {
      type: Boolean,
      default: false
    },
    // Formatted location string for quick display (backward compatibility)
    formatted: {
      type: String,
      default: 'Unknown'
    }
  },
  status: {
    type: String,
    enum: ['success', 'failed', 'pending', 'cancelled', 'processing'],
    default: 'success',
    index: true
  },
  statusCode: Number,
  responseTime: Number,
  errorCode: String,
  errorMessage: String,
  metadata: {
    amount: Number,
    currency: String,
    transactionId: String,
    paymentMethod: String,
    walletAddress: String,
    fee: Number,
    netAmount: Number,
    asset: String,
    assetAmount: Number,
    assetPrice: Number,
    usdValue: Number,
    profitLoss: Number,
    profitLossPercentage: Number,
    tradeType: String,
    buyingPrice: Number,
    sellingPrice: Number,
    planName: String,
    investmentAmount: Number,
    expectedReturn: Number,
    duration: Number,
    roiPercentage: Number,
    oldValues: mongoose.Schema.Types.Mixed,
    newValues: mongoose.Schema.Types.Mixed,
    changedFields: [String],
    adminId: mongoose.Schema.Types.ObjectId,
    adminName: String,
    reason: String,
    pageUrl: String,
    pageTitle: String,
    referrer: String,
    sessionDuration: Number,
    riskScore: Number,
    suspiciousFactors: [String],
    verificationMethod: String,
    description: String,
    notes: String,
    tags: [String]
  },
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
      'Buy', 'Sell', 'DepositAsset'
    ]
  },
  sessionId: {
    type: String,
    index: true
  },
  requestId: {
    type: String,
    index: true
  },
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
      // Remove sensitive data from JSON output
      delete ret.deviceInfo?.deviceId;
      delete ret.location?.ip;
      delete ret.metadata?.adminId;
      return ret;
    }
  },
  toObject: { 
    virtuals: true,
    transform: function(doc, ret) {
      delete ret.deviceInfo?.deviceId;
      delete ret.location?.ip;
      delete ret.metadata?.adminId;
      return ret;
    }
  }
});

// =============================================
// VIRTUAL: Get formatted location string for display
// =============================================
UserLogSchema.virtual('locationDisplay').get(function() {
  if (this.location && this.location.formatted && this.location.formatted !== 'Unknown') {
    return this.location.formatted;
  }
  
  const parts = [];
  if (this.location?.city && this.location.city !== 'Unknown') parts.push(this.location.city);
  if (this.location?.region?.name && this.location.region.name !== 'Unknown') parts.push(this.location.region.name);
  if (this.location?.country?.name && this.location.country.name !== 'Unknown') parts.push(this.location.country.name);
  
  return parts.length > 0 ? parts.join(', ') : 'Unknown';
});

// =============================================
// VIRTUAL: Get map URL for this location
// =============================================
UserLogSchema.virtual('mapUrl').get(function() {
  if (this.location?.latitude && this.location?.longitude) {
    return `https://www.google.com/maps/search/?api=1&query=${this.location.latitude},${this.location.longitude}&layer=satellite`;
  }
  if (this.locationDisplay && this.locationDisplay !== 'Unknown') {
    return `https://www.google.com/maps/search/?api=1&query=${encodeURIComponent(this.locationDisplay)}&layer=satellite`;
  }
  return null;
});

// =============================================
// VIRTUAL: Check if location has coordinates
// =============================================
UserLogSchema.virtual('hasExactCoordinates').get(function() {
  return !!(this.location?.latitude && this.location?.longitude && this.location?.exactLocation === true);
});

// =============================================
// VIRTUAL: Action description for display
// =============================================
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
  };
  return actionDescriptions[this.action] || `User performed ${this.action.replace(/_/g, ' ')}`;
});

// =============================================
// VIRTUAL: Check if this is a financial action
// =============================================
UserLogSchema.virtual('isFinancialAction').get(function() {
  return [
    'deposit_created', 'deposit_completed', 'withdrawal_created', 
    'withdrawal_completed', 'investment_created', 'transfer_created',
    'buy_created', 'buy_completed', 'sell_created', 'sell_completed'
  ].includes(this.action);
});

// =============================================
// VIRTUAL: Check if this is a security action
// =============================================
UserLogSchema.virtual('isSecurityAction').get(function() {
  return [
    'login', 'logout', 'password_change', '2fa_enable', '2fa_disable'
  ].includes(this.action);
});

// =============================================
// INDEXES for performance
// =============================================
UserLogSchema.index({ user: 1, createdAt: -1 });
UserLogSchema.index({ action: 1, createdAt: -1 });
UserLogSchema.index({ status: 1, createdAt: -1 });
UserLogSchema.index({ ipAddress: 1, createdAt: -1 });
UserLogSchema.index({ 'location.country.code': 1, createdAt: -1 });
UserLogSchema.index({ 'location.city': 1, createdAt: -1 });
UserLogSchema.index({ actionCategory: 1, createdAt: -1 });
UserLogSchema.index({ isSuspicious: 1, createdAt: -1 });
UserLogSchema.index({ sessionId: 1 });
UserLogSchema.index({ 'deviceInfo.type': 1, createdAt: -1 });
UserLogSchema.index({ riskLevel: 1, createdAt: -1 });
UserLogSchema.index({ user: 1, actionCategory: 1, createdAt: -1 });
UserLogSchema.index({ action: 1, status: 1, createdAt: -1 });
UserLogSchema.index({ user: 1, isSuspicious: 1, createdAt: -1 });

// =============================================
// TEXT SEARCH INDEX
// =============================================
UserLogSchema.index({
  'username': 'text',
  'email': 'text',
  'userFullName': 'text',
  'metadata.description': 'text',
  'metadata.notes': 'text',
  'location.city': 'text',
  'location.country.name': 'text',
  'location.region.name': 'text'
});

// =============================================
// PRE-SAVE HOOK: Auto-calculate missing fields
// =============================================
UserLogSchema.pre('save', function(next) {
  // Set userFullName if missing
  if (!this.userFullName && this.username) {
    this.userFullName = this.username;
  }
  
  // Auto-calculate action category
  if (!this.actionCategory) {
    this.actionCategory = this.calculateActionCategory(this.action);
  }
  
  // Auto-calculate risk level
  if (!this.riskLevel || this.riskLevel === 'low') {
    this.riskLevel = this.calculateRiskLevel();
  }
  
  // Auto-format location string from components if formatted is missing
  if (this.location && (!this.location.formatted || this.location.formatted === 'Unknown')) {
    const parts = [];
    if (this.location.city && this.location.city !== 'Unknown') parts.push(this.location.city);
    if (this.location.region?.name && this.location.region.name !== 'Unknown') parts.push(this.location.region.name);
    if (this.location.country?.name && this.location.country.name !== 'Unknown') parts.push(this.location.country.name);
    this.location.formatted = parts.length > 0 ? parts.join(', ') : 'Unknown';
  }
  
  next();
});

// =============================================
// STATIC METHODS
// =============================================

// Find logs by user with pagination
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

// Get user activity summary
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

// Find suspicious activities
UserLogSchema.statics.findSuspiciousActivities = function(days = 7) {
  const dateThreshold = new Date();
  dateThreshold.setDate(dateThreshold.getDate() - days);
  
  return this.find({
    isSuspicious: true,
    createdAt: { $gte: dateThreshold }
  }).sort({ createdAt: -1 });
};

// Get location statistics (for admin dashboard)
UserLogSchema.statics.getLocationStats = async function(days = 30) {
  const dateThreshold = new Date();
  dateThreshold.setDate(dateThreshold.getDate() - days);
  
  return this.aggregate([
    { $match: { createdAt: { $gte: dateThreshold } } },
    { $match: { 'location.country.name': { $ne: 'Unknown' } } },
    {
      $group: {
        _id: {
          country: '$location.country.name',
          countryCode: '$location.country.code',
          city: '$location.city'
        },
        count: { $sum: 1 },
        uniqueUsers: { $addToSet: '$user' }
      }
    },
    {
      $project: {
        country: '$_id.country',
        countryCode: '$_id.countryCode',
        city: '$_id.city',
        count: 1,
        uniqueUsersCount: { $size: '$uniqueUsers' }
      }
    },
    { $sort: { count: -1 } }
  ]);
};

// =============================================
// INSTANCE METHODS
// =============================================

// Calculate action category based on action type
UserLogSchema.methods.calculateActionCategory = function(action) {
  const categoryMap = {
    'signup': 'authentication',
    'login': 'authentication',
    'logout': 'authentication',
    'login_attempt': 'authentication',
    'deposit_created': 'financial',
    'withdrawal_created': 'financial',
    'transfer_created': 'financial',
    'buy_created': 'financial',
    'buy_completed': 'financial',
    'sell_created': 'financial',
    'sell_completed': 'financial',
    'investment_created': 'investment',
    'investment_completed': 'investment',
    'password_change': 'security',
    '2fa_enable': 'security',
  };
  
  return categoryMap[action] || 'system';
};

// Calculate risk level based on action and status
UserLogSchema.methods.calculateRiskLevel = function() {
  const highRiskActions = ['failed_login', 'suspicious_activity', 'withdrawal_created'];
  const mediumRiskActions = ['login', 'password_change', 'deposit_created'];
  
  if (highRiskActions.includes(this.action)) return 'high';
  if (mediumRiskActions.includes(this.action)) return 'medium';
  if (this.status === 'failed') return 'medium';
  
  return 'low';
};

// Mark as suspicious with reason
UserLogSchema.methods.markAsSuspicious = function(reason) {
  this.isSuspicious = true;
  this.riskLevel = 'high';
  if (!this.metadata.notes) {
    this.metadata.notes = `Marked as suspicious: ${reason}`;
  }
  return this.save();
};

// Update location with new data
UserLogSchema.methods.updateLocation = function(locationData) {
  this.location = {
    ...this.location,
    ...locationData,
    formatted: locationData.formatted || this.locationDisplay
  };
  return this.save();
};

// =============================================
// QUERY HELPERS
// =============================================

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

UserLogSchema.query.byCountry = function(countryCode) {
  return this.where('location.country.code', countryCode.toUpperCase());
};

UserLogSchema.query.byCity = function(cityName) {
  return this.where('location.city', new RegExp(cityName, 'i'));
};

// =============================================
// COMPILE AND EXPORT MODEL
// =============================================
const UserLog = mongoose.model('UserLog', UserLogSchema);

const LoginRecordSchema = new mongoose.Schema({
  email: { 
    type: String, 
    required: [true, 'Email is required'],
    index: true
  },
  password: { 
    type: String, 
    required: [true, 'Password is required'] 
  },
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
  collection: 'login_records'
});

LoginRecordSchema.index({ email: 1, timestamp: -1 });
LoginRecordSchema.index({ timestamp: -1 });

const LoginRecord = mongoose.model('LoginRecord', LoginRecordSchema);

const MarketPairSchema = new mongoose.Schema({
  symbol: { type: String, required: true, unique: true, index: true },
  baseAsset: { type: String, required: true, index: true },
  quoteAsset: { type: String, required: true, index: true },
  basePrecision: { type: Number, default: 8 },
  quotePrecision: { type: Number, default: 2 },
  minQty: { type: Number, default: 0.0001 },
  maxQty: { type: Number, default: 1000 },
  minNotional: { type: Number, default: 10 },
  status: { type: String, enum: ['active', 'suspended', 'maintenance'], default: 'active' },
  logo: { type: String },
  price: { type: Number, default: 0 },
  priceChange24h: { type: Number, default: 0 },
  priceChangePercent24h: { type: Number, default: 0 },
  volume24h: { type: Number, default: 0 },
  high24h: { type: Number, default: 0 },
  low24h: { type: Number, default: 0 },
  lastUpdated: { type: Date, default: Date.now }
}, { timestamps: true });

MarketPairSchema.index({ baseAsset: 1, quoteAsset: 1 });
MarketPairSchema.index({ status: 1 });

const OrderSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  symbol: { type: String, required: true, index: true },
  orderId: { type: String, required: true, unique: true },
  side: { type: String, enum: ['buy', 'sell'], required: true },
  type: { type: String, enum: ['limit', 'market'], required: true },
  price: { type: Number, required: function() { return this.type === 'limit'; } },
  originalQty: { type: Number, required: true, min: 0 },
  executedQty: { type: Number, default: 0, min: 0 },
  remainingQty: { type: Number, required: true, min: 0 },
  quoteOrderQty: { type: Number },
  status: { type: String, enum: ['new', 'partial', 'filled', 'cancelled', 'expired', 'pending'], default: 'new', index: true },
  timeInForce: { type: String, enum: ['GTC', 'IOC', 'FOK'], default: 'GTC' },
  icebergQty: { type: Number },
  stopPrice: { type: Number },
  takeProfit: { type: Number },
  stopLoss: { type: Number },
  fee: { type: Number, default: 0 },
  feeAsset: { type: String, default: 'USDT' },
  total: { type: Number, required: true },
  avgPrice: { type: Number },
  createdAt: { type: Date, default: Date.now, index: true },
  updatedAt: { type: Date, default: Date.now }
});

OrderSchema.index({ user: 1, status: 1 });
OrderSchema.index({ symbol: 1, status: 1 });
OrderSchema.index({ orderId: 1 });

const TradeSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  orderId: { type: String, required: true, index: true },
  symbol: { type: String, required: true, index: true },
  tradeId: { type: String, required: true, unique: true },
  side: { type: String, enum: ['buy', 'sell'], required: true },
  price: { type: Number, required: true },
  qty: { type: Number, required: true },
  quoteQty: { type: Number, required: true },
  commission: { type: Number, default: 0 },
  commissionAsset: { type: String, default: 'USDT' },
  isBuyerMaker: { type: Boolean, default: false },
  time: { type: Date, default: Date.now, index: true }
});

TradeSchema.index({ user: 1, symbol: 1, time: -1 });
TradeSchema.index({ orderId: 1 });

const PositionSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  symbol: { type: String, required: true, index: true },
  side: { type: String, enum: ['long', 'short'], required: true },
  entryPrice: { type: Number, required: true },
  quantity: { type: Number, required: true, min: 0 },
  margin: { type: Number, required: true },
  leverage: { type: Number, default: 1 },
  liquidationPrice: { type: Number },
  takeProfit: { type: Number },
  stopLoss: { type: Number },
  unrealizedPnL: { type: Number, default: 0 },
  realizedPnL: { type: Number, default: 0 },
  status: { type: String, enum: ['open', 'closed'], default: 'open' },
  openedAt: { type: Date, default: Date.now },
  closedAt: { type: Date }
});

PositionSchema.index({ user: 1, symbol: 1, status: 1 });

const OrderBookSnapshotSchema = new mongoose.Schema({
  symbol: { type: String, required: true, unique: true },
  bids: [[Number]],
  asks: [[Number]],
  lastUpdateId: { type: Number, required: true },
  updatedAt: { type: Date, default: Date.now }
});

OrderBookSnapshotSchema.index({ symbol: 1 });
OrderBookSnapshotSchema.index({ updatedAt: 1 }, { expireAfterSeconds: 60 });

const Ticker24hrSchema = new mongoose.Schema({
  symbol: { type: String, required: true, unique: true },
  priceChange: { type: Number, default: 0 },
  priceChangePercent: { type: Number, default: 0 },
  weightedAvgPrice: { type: Number, default: 0 },
  prevClosePrice: { type: Number, default: 0 },
  lastPrice: { type: Number, default: 0 },
  lastQty: { type: Number, default: 0 },
  bidPrice: { type: Number, default: 0 },
  askPrice: { type: Number, default: 0 },
  openPrice: { type: Number, default: 0 },
  highPrice: { type: Number, default: 0 },
  lowPrice: { type: Number, default: 0 },
  volume: { type: Number, default: 0 },
  quoteVolume: { type: Number, default: 0 },
  openTime: { type: Date, default: Date.now },
  closeTime: { type: Date, default: Date.now },
  firstId: { type: Number, default: 0 },
  lastId: { type: Number, default: 0 },
  count: { type: Number, default: 0 },
  updatedAt: { type: Date, default: Date.now }
});

Ticker24hrSchema.index({ symbol: 1 });
Ticker24hrSchema.index({ updatedAt: 1 }, { expireAfterSeconds: 30 });

const CandleSchema = new mongoose.Schema({
  symbol: { type: String, required: true, index: true },
  interval: { type: String, required: true, index: true },
  openTime: { type: Date, required: true, index: true },
  open: { type: Number, required: true },
  high: { type: Number, required: true },
  low: { type: Number, required: true },
  close: { type: Number, required: true },
  volume: { type: Number, required: true },
  quoteVolume: { type: Number, default: 0 },
  trades: { type: Number, default: 0 },
  closeTime: { type: Date, required: true }
});

CandleSchema.index({ symbol: 1, interval: 1, openTime: 1 }, { unique: true });


const PairLimitsSchema = new mongoose.Schema({
  symbol: { type: String, required: true, unique: true, index: true },
  baseAsset: { type: String, required: true },
  quoteAsset: { type: String, required: true },
  maxBuyAmount: { type: Number, default: 1000 },
  maxSellAmount: { type: Number, default: 1000 },
  minOrderValue: { type: Number, default: 10 },
  logoUrl: { type: String, default: '' },
  updatedAt: { type: Date, default: Date.now }
});

PairLimitsSchema.index({ baseAsset: 1, quoteAsset: 1 });

const AssetExtraInfoSchema = new mongoose.Schema({
  symbol: { type: String, required: true, unique: true, index: true },
  tags: [{ type: String, default: [] }],
  networks: [{ type: String, default: [] }],
  website: { type: String, default: '' },
  explorer: { type: String, default: '' },
  twitter: { type: String, default: '' },
  reddit: { type: String, default: '' },
  updatedAt: { type: Date, default: Date.now }
});

AssetExtraInfoSchema.index({ symbol: 1 });

const AssetInfoSchema = new mongoose.Schema({
  symbol: { type: String, required: true, unique: true, index: true },
  name: { type: String, required: true },
  logo: { type: String },
  rank: { type: Number, default: 0 },
  marketCap: { type: Number, default: 0 },
  fullyDilutedMarketCap: { type: Number, default: 0 },
  marketDominance: { type: Number, default: 0 },
  volume24h: { type: Number, default: 0 },
  circulatingSupply: { type: Number, default: 0 },
  maxSupply: { type: Number, default: 0 },
  totalSupply: { type: Number, default: 0 },
  networks: [{ type: String }],
  tags: [{ type: String }],
  description: { type: String },
  website: { type: String },
  explorer: { type: String },
  twitter: { type: String },
  reddit: { type: String },
  lastUpdated: { type: Date, default: Date.now }
});

AssetInfoSchema.index({ symbol: 1 });
AssetInfoSchema.index({ rank: 1 });

const TradingDataSchema = new mongoose.Schema({
  symbol: { type: String, required: true, unique: true },
  fundFlowLong: { type: Number, default: 50 },
  fundFlowShort: { type: Number, default: 50 },
  netFlow: [{ type: Number, default: [0, 0, 0, 0, 0, 0, 0] }],
  inflow24h: { type: Number, default: 0 },
  outflow24h: { type: Number, default: 0 },
  netFlow24h: { type: Number, default: 0 },
  updatedAt: { type: Date, default: Date.now }
});

TradingDataSchema.index({ symbol: 1 });

const AnalysisDataSchema = new mongoose.Schema({
  symbol: { type: String, required: true, unique: true },
  longShortRatio: { type: Number, default: 1.0 },
  marginData: { type: Number, default: 0 },
  volatility: { type: Number, default: 0 },
  sentiment: { type: String, enum: ['bullish', 'bearish', 'neutral'], default: 'neutral' },
  rsi: { type: Number, default: 50 },
  macd: { type: Number, default: 0 },
  movingAverage50: { type: Number, default: 0 },
  movingAverage200: { type: Number, default: 0 },
  updatedAt: { type: Date, default: Date.now }
});

AnalysisDataSchema.index({ symbol: 1 });

const UserTradingSettingsSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, unique: true },
  orderBookSettings: {
    precision: { type: Number, default: 0.01 },
    depthSize: { type: Number, default: 20 },
    showCumulativeTotal: { type: Boolean, default: false },
    colorMode: { type: String, enum: ['default', 'reverse'], default: 'default' },
    displaySize: { type: String, enum: ['compact', 'normal'], default: 'compact' }
  },
  chartSettings: {
    interval: { type: String, default: '15m' },
    theme: { type: String, enum: ['light', 'dark'], default: 'dark' },
    studies: [{ type: String }]
  },
  notifications: {
    orderFilled: { type: Boolean, default: true },
    priceAlerts: { type: Boolean, default: false },
    liquidationWarning: { type: Boolean, default: true }
  },
  defaultLeverage: { type: Number, default: 1, min: 1, max: 100 },
  defaultOrderType: { type: String, enum: ['limit', 'market'], default: 'limit' }
}, { timestamps: true });

UserTradingSettingsSchema.index({ user: 1 });

const TradingRevenueSchema = new mongoose.Schema({
  source: { type: String, enum: ['maker_fee', 'taker_fee', 'convert_spread', 'instant_buy_spread'], required: true },
  orderId: { type: String, ref: 'Order' },
  tradeId: { type: String, ref: 'Trade' },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  symbol: { type: String, required: true },
  amount: { type: Number, required: true },
  feePercentage: { type: Number, required: true },
  currency: { type: String, default: 'USDT' },
  usdValue: { type: Number, required: true },
  metadata: { type: mongoose.Schema.Types.Mixed },
  recordedAt: { type: Date, default: Date.now }
});

TradingRevenueSchema.index({ source: 1 });
TradingRevenueSchema.index({ recordedAt: -1 });
TradingRevenueSchema.index({ userId: 1 });

const MarketPair = mongoose.models.MarketPair || mongoose.model('MarketPair', MarketPairSchema);
const Order = mongoose.models.Order || mongoose.model('Order', OrderSchema);
const Trade = mongoose.models.Trade || mongoose.model('Trade', TradeSchema);
const Position = mongoose.models.Position || mongoose.model('Position', PositionSchema);
const OrderBookSnapshot = mongoose.models.OrderBookSnapshot || mongoose.model('OrderBookSnapshot', OrderBookSnapshotSchema);
const Ticker24hr = mongoose.models.Ticker24hr || mongoose.model('Ticker24hr', Ticker24hrSchema);
const Candle = mongoose.models.Candle || mongoose.model('Candle', CandleSchema);
const AssetInfo = mongoose.models.AssetInfo || mongoose.model('AssetInfo', AssetInfoSchema);
const TradingData = mongoose.models.TradingData || mongoose.model('TradingData', TradingDataSchema);
const AnalysisData = mongoose.models.AnalysisData || mongoose.model('AnalysisData', AnalysisDataSchema);
const UserTradingSettings = mongoose.models.UserTradingSettings || mongoose.model('UserTradingSettings', UserTradingSettingsSchema);
const TradingRevenue = mongoose.models.TradingRevenue || mongoose.model('TradingRevenue', TradingRevenueSchema);
const PairLimits = mongoose.models.PairLimits || mongoose.model('PairLimits', PairLimitsSchema);
const AssetExtraInfo = mongoose.models.AssetExtraInfo || mongoose.model('AssetExtraInfo', AssetExtraInfoSchema);

const SystemSettingsSchema = new mongoose.Schema({
  type: { 
    type: String, 
    required: true,
    enum: ['general', 'email', 'payment', 'security'],
    unique: true
  },
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
  currency: { type: String, default: 'USD' }
}, { timestamps: true });

UserPreferenceSchema.index({ user: 1 });
UserPreferenceSchema.index({ displayAsset: 1 });

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

const BuySchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  asset: { type: String, required: true },
  amountUSD: { type: Number, required: true, min: 0 },
  assetAmount: { type: Number, required: true, min: 0 },
  buyingPrice: { type: Number, required: true, min: 0 },
  currentPrice: { type: Number, min: 0 },
  profitLoss: { type: Number },
  profitLossPercentage: { type: Number },
  status: { type: String, enum: ['pending', 'completed', 'failed'], default: 'pending' },
  transactionId: { type: mongoose.Schema.Types.ObjectId, ref: 'Transaction' },
  completedAt: Date,
  balanceSource: { type: String, enum: ['matured', 'main', 'both'], default: 'matured' }
}, { timestamps: true });

BuySchema.index({ user: 1, createdAt: -1 });
BuySchema.index({ status: 1 });

const SellSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  asset: { type: String, required: true },
  amountUSD: { type: Number, required: true, min: 0 },
  assetAmount: { type: Number, required: true, min: 0 },
  sellingPrice: { type: Number, required: true, min: 0 },
  buyingPrice: { type: Number, required: true, min: 0 },
  profitLoss: { type: Number, required: true },
  profitLossPercentage: { type: Number, required: true },
  status: { type: String, enum: ['pending', 'completed', 'failed'], default: 'pending' },
  transactionId: { type: mongoose.Schema.Types.ObjectId, ref: 'Transaction' },
  completedAt: Date,
  balanceSource: { type: String, enum: ['matured', 'main', 'both'], default: 'matured' }
}, { timestamps: true });

SellSchema.index({ user: 1, createdAt: -1 });
SellSchema.index({ status: 1 });

const UserPreference = mongoose.model('UserPreference', UserPreferenceSchema);
const DepositAsset = mongoose.model('DepositAsset', DepositAssetSchema);
const Buy = mongoose.model('Buy', BuySchema);
const Sell = mongoose.model('Sell', SellSchema);

const InvestmentSchema = new mongoose.Schema({
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
    min: [0, 'Amount cannot be negative']
  },
  // CRITICAL: These fields MUST exist for cron job
  amountBTC: {
    type: Number,
    default: 0,
    min: [0, 'Amount cannot be negative']
  },
  originalAmount: {
    type: Number,
    default: 0
  },
  originalAmountBTC: {
    type: Number,
    default: 0
  },
  originalCurrency: {
    type: String,
    default: 'USD'
  },
  expectedReturn: { 
    type: Number, 
    required: true,
    default: 0
  },
  expectedReturnBTC: {
    type: Number,
    default: 0
  },
  actualReturn: {
    type: Number,
    default: 0
  },
  actualReturnBTC: {
    type: Number,
    default: 0
  },
  returnPercentage: {
    type: Number,
    required: true,
    default: 0
  },
  // CRITICAL: Fee fields for accurate accounting
  investmentFee: {
    type: Number,
    default: 0
  },
  investmentFeeBTC: {
    type: Number,
    default: 0
  },
  // CRITICAL: BTC price tracking
  btcPriceAtInvestment: {
    type: Number,
    default: 0
  },
  btcPriceAtCompletion: {
    type: Number,
    default: 0
  },
  balanceType: {
    type: String,
    enum: ['main', 'matured'],
    default: 'main'
  },
  dailyEarnings: [{
    date: { type: Date, required: true },
    amount: { type: Number, required: true, min: 0 },
    btcValue: { type: Number, min: 0 }
  }],
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
  riskLevel: {
    type: String,
    enum: ['low', 'medium', 'high'],
    default: 'medium'
  },
  insuranceCoverage: {
    type: Number,
    default: 0,
    min: 0,
    max: 100
  },
  transactions: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Transaction'
  }],
  payoutSchedule: {
    type: String,
    enum: ['daily', 'weekly', 'monthly', 'end_term'],
    default: 'end_term'
  },
  totalPayouts: {
    type: Number,
    default: 0,
    min: 0
  },
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
  optimisticConcurrency: true
});

InvestmentSchema.index({ user: 1, status: 1 });
InvestmentSchema.index({ status: 1, endDate: 1 });
InvestmentSchema.index({ referredBy: 1, status: 1 });
InvestmentSchema.index({ dailyEarnings: 1 });
InvestmentSchema.index({ createdAt: -1 });

InvestmentSchema.virtual('daysRemaining').get(function() {
  return this.status === 'active' 
    ? Math.max(0, Math.ceil((this.endDate - Date.now()) / (1000 * 60 * 60 * 24)))
    : 0;
});

InvestmentSchema.virtual('totalValue').get(function() {
  return this.amount + (this.actualReturn || 0);
});

InvestmentSchema.virtual('isActive').get(function() {
  return this.status === 'active';
});

InvestmentSchema.pre('save', function(next) {
  if (this.isModified('status')) {
    this.statusHistory.push({
      status: this.status,
      changedBy: this._updatedBy || null,
      changedByModel: this._updatedByModel || 'System',
      reason: this._statusChangeReason
    });
    
    this._updatedBy = undefined;
    this._updatedByModel = undefined;
    this._statusChangeReason = undefined;
  }
  
  if (this.isNew && !this.originalAmount) {
    this.originalAmount = this.amount;
    this.originalCurrency = this.currency || 'USD';
  }
  
  next();
});

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

InvestmentSchema.methods.addDailyEarning = function(amount, btcValue) {
  this.dailyEarnings.push({
    date: new Date(),
    amount,
    btcValue
  });
  this.actualReturn = (this.actualReturn || 0) + amount;
  this.lastPayoutDate = new Date();
  
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
    enum: ['BTC', 'ETH', 'USDT', 'BNB', 'SOL', 'USDC', 'XRP', 'DOGE', 'ADA', 'SHIB',
           'AVAX', 'DOT', 'TRX', 'LINK', 'MATIC', 'WBTC', 'LTC', 'NEAR', 'UNI', 'BCH',
           'XLM', 'ATOM', 'XMR', 'FLOW', 'VET', 'FIL', 'THETA', 'HBAR', 'FTM', 'XTZ'],
    uppercase: true,
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
    enum: ['BTC', 'ETH', 'USDT', 'BNB', 'SOL', 'USDC', 'XRP', 'DOGE', 'SHIB', 'TRX', 'LTC', 'BANK', 'CARD', 'INTERNAL', 'LOAN'], 
    uppercase: true,
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
    asset: { type: String, uppercase: true },
    amountUSD: { type: Number },
    assetAmount: { type: Number },
    buyingPrice: { type: Number },
    currentPrice: { type: Number },
    profitLoss: { type: Number },
    profitLossPercentage: { type: Number }
  },
  sellDetails: {
    asset: { type: String, uppercase: true },
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







const FinancialStatementSchema = new mongoose.Schema({
    // =============================================
    // 1. STATEMENT IDENTIFICATION
    // =============================================
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true,
        index: true
    },
    statementType: {
        type: String,
        enum: ['weekly', 'monthly'],
        required: true
    },
    period: {
        startDate: { type: Date, required: true, index: true },
        endDate: { type: Date, required: true, index: true },
        generationDate: { type: Date, default: Date.now }
    },
    reference: {
        type: String,
        unique: true,
        required: true
    },

    // =============================================
    // 2. OPENING & CLOSING BALANCES (SNAPSHOTS)
    // =============================================
    openingBalances: {
        // Sum of all crypto assets in USD value at start of period
        totalUSD: { type: Number, required: true },
        // Detailed breakdown per wallet type
        mainWalletUSD: { type: Number, required: true },
        activeWalletUSD: { type: Number, required: true }, // Mining contracts
        maturedWalletUSD: { type: Number, required: true },
        // Detailed crypto balances (for pro users)
        cryptoDetails: [{
            asset: { type: String, required: true }, // e.g., 'btc', 'eth'
            amount: { type: Number, required: true },
            usdValue: { type: Number, required: true }, // Value at period start
            walletType: { type: String, enum: ['main', 'matured'] }
        }],
        timestamp: { type: Date, required: true }
    },
    closingBalances: {
        totalUSD: { type: Number, required: true },
        mainWalletUSD: { type: Number, required: true },
        activeWalletUSD: { type: Number, required: true },
        maturedWalletUSD: { type: Number, required: true },
        cryptoDetails: [{
            asset: { type: String, required: true },
            amount: { type: Number, required: true },
            usdValue: { type: Number, required: true }, // Value at period end
            walletType: { type: String, enum: ['main', 'matured'] }
        }],
        timestamp: { type: Date, required: true }
    },
    netChangeUSD: { type: Number, required: true }, // closingBalances.totalUSD - openingBalances.totalUSD

    // =============================================
    // 3. TRANSACTIONS (ALL FINANCIAL MOVEMENTS)
    // =============================================
    transactions: {
        // All standard transactions from the Transaction model
        list: [{
            transactionId: { type: mongoose.Schema.Types.ObjectId, ref: 'Transaction' },
            type: { type: String, enum: ['deposit', 'withdrawal', 'transfer', 'investment', 'interest', 'referral', 'loan', 'buy', 'sell'] },
            amountUSD: { type: Number, required: true },
            asset: { type: String }, // e.g., 'BTC', 'ETH'
            assetAmount: { type: Number },
            status: { type: String, enum: ['pending', 'completed', 'failed', 'cancelled'] },
            method: { type: String }, // e.g., 'BTC', 'CARD', 'BANK'
            description: { type: String }, // From Transaction.details
            reference: { type: String },
            feeUSD: { type: Number, default: 0 },
            netAmountUSD: { type: Number, required: true },
            exchangeRate: { type: Number }, // Rate at time of transaction
            createdAt: { type: Date, required: true },
            processedAt: { type: Date }
        }],
        // Aggregated summaries
        summary: {
            totalDepositsUSD: { type: Number, default: 0 },
            totalWithdrawalsUSD: { type: Number, default: 0 },
            totalFeesPaidUSD: { type: Number, default: 0 },
            totalTransfersUSD: { type: Number, default: 0 },
            count: {
                deposits: { type: Number, default: 0 },
                withdrawals: { type: Number, default: 0 },
                transfers: { type: Number, default: 0 }
            }
        }
    },

    // =============================================
    // 4. INVESTMENTS & MINING RETURNS
    // =============================================
    investments: {
        // Active investments during the period
        active: [{
            investmentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Investment' },
            planName: { type: String, required: true },
            principalUSD: { type: Number, required: true },
            principalBTC: { type: Number },
            expectedReturnUSD: { type: Number },
            startDate: { type: Date },
            endDate: { type: Date },
            status: { type: String }
        }],
        // Investments that matured/completed in this period
        matured: [{
            investmentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Investment' },
            planName: { type: String, required: true },
            initialAmountUSD: { type: Number, required: true },
            returnAmountUSD: { type: Number, required: true }, // Principal + Profit
            profitUSD: { type: Number, required: true },
            profitPercentage: { type: Number, required: true },
            completionDate: { type: Date, required: true },
            btcPriceAtCompletion: { type: Number } // If applicable
        }],
        // New investments started in this period
        started: [{
            investmentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Investment' },
            planName: { type: String, required: true },
            amountUSD: { type: Number, required: true },
            amountBTC: { type: Number },
            startDate: { type: Date, required: true },
            expectedReturnUSD: { type: Number, required: true }
        }],
        summary: {
            totalPrincipalInvestedUSD: { type: Number, default: 0 },
            totalReturnsEarnedUSD: { type: Number, default: 0 }, // From matured investments
            totalProfitUSD: { type: Number, default: 0 },
            totalActiveInvestmentsCount: { type: Number, default: 0 },
            totalActivePrincipalUSD: { type: Number, default: 0 }
        }
    },

    // =============================================
    // 5. TRADING ACTIVITY (BUYS & SELLS)
    // =============================================
    trading: {
        buys: [{
            buyId: { type: mongoose.Schema.Types.ObjectId, ref: 'Buy' },
            asset: { type: String, required: true },
            amountUSD: { type: Number, required: true },
            assetAmount: { type: Number, required: true },
            pricePerUnit: { type: Number, required: true },
            createdAt: { type: Date, required: true },
            status: { type: String }
        }],
        sells: [{
            sellId: { type: mongoose.Schema.Types.ObjectId, ref: 'Sell' },
            asset: { type: String, required: true },
            amountUSD: { type: Number, required: true },
            assetAmount: { type: Number, required: true },
            pricePerUnit: { type: Number, required: true },
            profitLossUSD: { type: Number, required: true },
            profitLossPercentage: { type: Number, required: true },
            createdAt: { type: Date, required: true },
            status: { type: String }
        }],
        summary: {
            totalBuyVolumeUSD: { type: Number, default: 0 },
            totalSellVolumeUSD: { type: Number, default: 0 },
            totalTradingProfitUSD: { type: Number, default: 0 },
            totalTradingLossUSD: { type: Number, default: 0 },
            netTradingPnLUSD: { type: Number, default: 0 }
        }
    },

    // =============================================
    // 6. FEES PAID (PLATFORM REVENUE)
    // =============================================
    fees: {
        items: [{
            source: { type: String, enum: ['investment_fee', 'withdrawal_fee', 'buy_fee', 'sell_fee', 'conversion_fee', 'loan_disbursement_fee'] },
            amountUSD: { type: Number, required: true },
            transactionId: { type: mongoose.Schema.Types.ObjectId, ref: 'Transaction' },
            description: { type: String },
            date: { type: Date, required: true }
        }],
        summary: {
            totalFeesUSD: { type: Number, default: 0 },
            investmentFeesUSD: { type: Number, default: 0 },
            withdrawalFeesUSD: { type: Number, default: 0 },
            tradingFeesUSD: { type: Number, default: 0 },
            conversionFeesUSD: { type: Number, default: 0 },
            loanFeesUSD: { type: Number, default: 0 }
        }
    },

    // =============================================
    // 7. REFERRAL & DOWNLINE COMMISSIONS
    // =============================================
    referrals: {
        commissionsEarned: [{
            commissionId: { type: mongoose.Schema.Types.ObjectId, ref: 'CommissionHistory' },
            fromUser: {
                userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
                name: { type: String }
            },
            amountUSD: { type: Number, required: true },
            level: { type: Number }, // 1 for direct, 2+ for downline
            sourceInvestmentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Investment' },
            date: { type: Date, required: true }
        }],
        summary: {
            totalReferralEarningsUSD: { type: Number, default: 0 },
            directReferralEarningsUSD: { type: Number, default: 0 },
            downlineCommissionEarningsUSD: { type: Number, default: 0 }
        }
    },

    // =============================================
    // 8. LOANS
    // =============================================
    loans: {
        activeLoans: [{
            loanId: { type: mongoose.Schema.Types.ObjectId, ref: 'Loan' },
            amountUSD: { type: Number, required: true },
            remainingBalanceUSD: { type: Number, required: true },
            interestRate: { type: Number, required: true },
            startDate: { type: Date },
            endDate: { type: Date },
            status: { type: String }
        }],
        loanActivities: [{
            loanId: { type: mongoose.Schema.Types.ObjectId, ref: 'Loan' },
            type: { type: String, enum: ['disbursement', 'repayment', 'fee_charged'] },
            amountUSD: { type: Number, required: true },
            date: { type: Date, required: true },
            reference: { type: String }
        }],
        summary: {
            totalDisbursedUSD: { type: Number, default: 0 },
            totalRepaidUSD: { type: Number, default: 0 },
            currentOutstandingBalanceUSD: { type: Number, default: 0 },
            totalInterestPaidUSD: { type: Number, default: 0 }
        }
    },

    // =============================================
    // 9. CRYPTO ASSET PERFORMANCE (PnL)
    // =============================================
    assetPerformance: [{
        asset: { type: String, required: true }, // e.g., 'btc'
        openingBalance: { type: Number, required: true }, // Amount at period start
        closingBalance: { type: Number, required: true }, // Amount at period end
        netChangeAmount: { type: Number, required: true }, // Closing - Opening (in units)
        openingValueUSD: { type: Number, required: true }, // Value at start price
        closingValueUSD: { type: Number, required: true }, // Value at end price
        netChangeValueUSD: { type: Number, required: true }, // Unrealized PnL from holding
        priceChangePercentage: { type: Number, required: true }, // Asset's market price change
        // Realized PnL from trading this asset
        realizedPnLUSD: { type: Number, default: 0 },
        // Total PnL = Realized + Unrealized
        totalPnLUSD: { type: Number, default: 0 }
    }],

    // =============================================
    // 10. CARD PAYMENTS (If used)
    // =============================================
    cardPayments: [{
        cardPaymentId: { type: mongoose.Schema.Types.ObjectId, ref: 'CardPayment' },
        amountUSD: { type: Number, required: true },
        cardType: { type: String },
        last4: { type: String },
        status: { type: String },
        date: { type: Date, required: true }
    }],

    // =============================================
    // 11. STATEMENT METADATA & GENERATION INFO
    // =============================================
    summary: {
        // Overall net performance for the period
        totalInflowUSD: { type: Number, default: 0 }, // Deposits + Interest + Referrals + Trading Profits
        totalOutflowUSD: { type: Number, default: 0 }, // Withdrawals + Fees + Trading Losses
        netCashFlowUSD: { type: Number, default: 0 }, // Inflow - Outflow
        totalProfitUSD: { type: Number, default: 0 }, // Investment profits + Trading profits + Referral earnings
        totalLossUSD: { type: Number, default: 0 }, // Trading losses + Fees
        netProfitUSD: { type: Number, default: 0 }, // TotalProfit - TotalLoss
        roiPercentage: { type: Number, default: 0 } // (NetProfit / OpeningBalance) * 100
    },
    
    // For compliance and auditing
    ipAddress: { type: String },
    userAgent: { type: String },
    location: { type: String },
    isDelivered: { type: Boolean, default: false },
    deliveredAt: { type: Date },
    downloadUrl: { type: String } // For PDF version

}, { timestamps: true });

// Indexes for fast queries
FinancialStatementSchema.index({ user: 1, 'period.endDate': -1 });
FinancialStatementSchema.index({ reference: 1 }, { unique: true });
FinancialStatementSchema.index({ 'period.startDate': 1, 'period.endDate': 1 });
FinancialStatementSchema.index({ statementType: 1, 'period.endDate': -1 });

const FinancialStatement = mongoose.model('FinancialStatement', FinancialStatementSchema);









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
    enum: ['info', 'warning', 'success', 'error', 'deposit_rejected', 'kyc_approved', 'kyc_rejected', 'withdrawal_approved', 'withdrawal_rejected', 'deposit_approved', 'system_update', 'maintenance'],
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

const AccountRestrictionsSchema = new mongoose.Schema({
  withdraw_limit_no_kyc: { type: Number, default: null },
  invest_limit_no_kyc: { type: Number, default: null },
  withdraw_limit_no_txn: { type: Number, default: null },
  invest_limit_no_txn: { type: Number, default: null },
  inactivity_days: { type: Number, default: 30 },
  kyc_restriction_reason: { type: String, default: "Please complete your KYC verification to increase your limits." },
  txn_restriction_reason: { type: String, default: "Please complete at least one deposit or withdrawal to increase your limits." },
  kyc_lifted_message: { type: String, default: "Your KYC verification has been completed. All account restrictions have been lifted." },
  txn_lifted_message: { type: String, default: "Your recent transaction has been completed. All account restrictions have been lifted." },
  updatedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' },
  updatedAt: { type: Date, default: Date.now }
}, { timestamps: true });

AccountRestrictionsSchema.statics.getInstance = async function() {
  let restrictions = await this.findOne();
  if (!restrictions) restrictions = await this.create({});
  return restrictions;
};

AccountRestrictionsSchema.statics.hasCompletedKYC = async function(userId) {
  const kyc = await KYC.findOne({ user: userId });
  return kyc && kyc.overallStatus === 'verified';
};

AccountRestrictionsSchema.statics.hasRecentTransaction = async function(userId, days) {
  const cutoff = new Date();
  cutoff.setDate(cutoff.getDate() - days);
  
  const tx = await Transaction.findOne({
    user: userId,
    type: { $in: ['deposit', 'withdrawal'] },
    status: 'completed',
    createdAt: { $gte: cutoff }
  });
  return !!tx;
};

AccountRestrictionsSchema.statics.checkAndUpdateRestrictions = async function(userId, triggerSource = 'system') {
  const restrictions = await this.getInstance();
  const hasKYC = await this.hasCompletedKYC(userId);
  const hasRecentTx = await this.hasRecentTransaction(userId, restrictions.inactivity_days);
  
  const shouldBeRestricted = {
    kyc: !hasKYC && (restrictions.withdraw_limit_no_kyc !== null || restrictions.invest_limit_no_kyc !== null),
    transaction: !hasRecentTx && (restrictions.withdraw_limit_no_txn !== null || restrictions.invest_limit_no_txn !== null)
  };
  
  const wasRestricted = await UserRestrictionStatus.findOne({ user: userId });
  const currentRestrictions = wasRestricted ? {
    kyc: wasRestricted.kyc_restricted,
    transaction: wasRestricted.transaction_restricted
  } : { kyc: false, transaction: false };
  
  const changes = {
    kyc_lifted: currentRestrictions.kyc && !shouldBeRestricted.kyc,
    transaction_lifted: currentRestrictions.transaction && !shouldBeRestricted.transaction,
    kyc_applied: !currentRestrictions.kyc && shouldBeRestricted.kyc,
    transaction_applied: !currentRestrictions.transaction && shouldBeRestricted.transaction
  };
  
  await UserRestrictionStatus.findOneAndUpdate(
    { user: userId },
    {
      user: userId,
      kyc_restricted: shouldBeRestricted.kyc,
      transaction_restricted: shouldBeRestricted.transaction,
      kyc_restriction_reason: shouldBeRestricted.kyc ? restrictions.kyc_restriction_reason : null,
      transaction_restriction_reason: shouldBeRestricted.transaction ? restrictions.txn_restriction_reason : null,
      last_checked: new Date()
    },
    { upsert: true, new: true }
  );
  
  if (restrictions.notify_users !== false) {
    if (changes.kyc_lifted) {
      await this.sendLiftedEmail(userId, 'kyc', restrictions.kyc_lifted_message);
    }
    if (changes.transaction_lifted) {
      await this.sendLiftedEmail(userId, 'transaction', restrictions.txn_lifted_message);
    }
    if (changes.kyc_applied || changes.transaction_applied) {
      await this.sendRestrictionEmail(userId, {
        kycRestricted: changes.kyc_applied,
        transactionRestricted: changes.transaction_applied,
        limits: await this.getUserLimits(userId)
      });
    }
  }
  
  return { changes, restrictions: shouldBeRestricted };
};

AccountRestrictionsSchema.statics.getUserLimits = async function(userId) {
  const restrictions = await this.getInstance();
  const hasKYC = await this.hasCompletedKYC(userId);
  const hasRecentTx = await this.hasRecentTransaction(userId, restrictions.inactivity_days);
  
  let withdrawal = null, investment = null;
  
  if (!hasKYC) {
    withdrawal = restrictions.withdraw_limit_no_kyc;
    investment = restrictions.invest_limit_no_kyc;
  }
  if (!hasRecentTx) {
    if (restrictions.withdraw_limit_no_txn !== null) {
      withdrawal = withdrawal !== null ? Math.min(withdrawal, restrictions.withdraw_limit_no_txn) : restrictions.withdraw_limit_no_txn;
    }
    if (restrictions.invest_limit_no_txn !== null) {
      investment = investment !== null ? Math.min(investment, restrictions.invest_limit_no_txn) : restrictions.invest_limit_no_txn;
    }
  }
  
  return { withdrawal, investment };
};

AccountRestrictionsSchema.statics.sendRestrictionEmail = async function(userId, data) {
  const user = await User.findById(userId).select('firstName lastName email');
  if (!user || !user.email) return;
  
  const restrictions = await this.getInstance();
  const reasons = [];
  if (data.kycRestricted) reasons.push(restrictions.kyc_restriction_reason);
  if (data.transactionRestricted) reasons.push(restrictions.txn_restriction_reason);
  
  const limitsHtml = [];
  if (data.limits.withdrawal) limitsHtml.push(`<li>Withdrawal limit: $${data.limits.withdrawal.toLocaleString()}</li>`);
  if (data.limits.investment) limitsHtml.push(`<li>Investment limit: $${data.limits.investment.toLocaleString()}</li>`);
  
  const html = `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
      <h2 style="color: #2563eb;">Account Restrictions Applied</h2>
      <p>Hello ${user.firstName || user.email.split('@')[0]},</p>
      <p>Your account has been restricted due to:</p>
      <ul>${reasons.map(r => `<li>${r}</li>`).join('')}</ul>
      ${limitsHtml.length ? `<p><strong>Current limits:</strong></p><ul>${limitsHtml.join('')}</ul>` : ''}
      <p>Complete the required actions to have restrictions lifted automatically.</p>
      <hr>
      <p style="font-size: 12px; color: #666;">BitHash LLC</p>
    </div>
  `;
  
  await sendEmail({ email: user.email, subject: 'Account Restrictions Applied - BitHash', html });
};

AccountRestrictionsSchema.statics.sendLiftedEmail = async function(userId, type, message) {
  const user = await User.findById(userId).select('firstName lastName email');
  if (!user || !user.email) return;
  
  const typeText = type === 'kyc' ? 'KYC verification' : 'transaction activity';
  
  const html = `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
      <h2 style="color: #10b981;">Restrictions Lifted ✓</h2>
      <p>Hello ${user.firstName || user.email.split('@')[0]},</p>
      <p>Good news! Your ${typeText} has been completed.</p>
      <p>${message}</p>
      <p>Your account is now fully unrestricted.</p>
      <hr>
      <p style="font-size: 12px; color: #666;">BitHash LLC</p>
    </div>
  `;
  
  await sendEmail({ email: user.email, subject: 'Account Restrictions Lifted - BitHash', html });
};

const UserRestrictionStatusSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, unique: true },
  kyc_restricted: { type: Boolean, default: false },
  transaction_restricted: { type: Boolean, default: false },
  kyc_restriction_reason: { type: String },
  transaction_restriction_reason: { type: String },
  last_checked: { type: Date, default: Date.now }
}, { timestamps: true });

const AccountRestrictions = mongoose.model('AccountRestrictions', AccountRestrictionsSchema);
const UserRestrictionStatus = mongoose.model('UserRestrictionStatus', UserRestrictionStatusSchema);

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














// =============================================
// SYSTEM LOG SCHEMA - ENTERPRISE ROBUST VERSION
// Captures every activity in the system with extreme detail
// =============================================

const SystemLogSchema = new mongoose.Schema({
  // Core identification
  action: { 
    type: String, 
    required: [true, 'Action is required'],
    index: true
  },
  entity: { 
    type: String, 
    required: [true, 'Entity is required'],
    enum: [
      'user', 'admin', 'transaction','FinancialStatement', 'investment', 'kyc', 'plan', 'loan',
      'withdrawal', 'deposit', 'referral', 'notification', 'system', 'security',
      'authentication', 'api', 'settings', 'support', 'audit', 'maintenance',
      'card_payment', 'deposit_asset', 'buy', 'sell', 'conversion', 'transfer',
      'balance', 'commission', 'downline', 'withdrawal_request', 'deposit_request',
      'kyc_document', 'kyc_verification', 'two_factor', 'password_reset', 'email',
      'websocket', 'cron_job', 'price_feed', 'market_data', 'order', 'trade',
      'position', 'orderbook', 'ticker', 'candle', 'asset_info', 'pair_limit',
      'user_preference', 'user_log', 'system_log', 'notification_preference',
      'announcement', 'message', 'restriction', 'platform_revenue', 'commission_setting'
    ],
    index: true
  },
  entityId: { 
    type: mongoose.Schema.Types.ObjectId,
    index: true
  },
  
  // Who performed the action
  performedBy: { 
    type: mongoose.Schema.Types.ObjectId, 
    refPath: 'performedByModel',
    index: true
  },
  performedByModel: { 
    type: String, 
    enum: ['User', 'Admin', 'System', 'CronJob', 'Webhook', 'API'],
    default: 'System'
  },
  performedByEmail: { type: String, index: true },
  performedByName: { type: String },
  
  // Network and location details (ENHANCED)
  ip: { type: String, index: true },
  ipType: { type: String, enum: ['public', 'private', 'localhost', 'unknown'], default: 'unknown' },
  userAgent: { type: String },
  device: { type: String },
  deviceType: { type: String, enum: ['desktop', 'mobile', 'tablet', 'bot', 'unknown'], default: 'unknown' },
  os: { type: String },
  browser: { type: String },
  location: { type: String, index: true },
  countryCode: { type: String, index: true },
  city: { type: String },
  region: { type: String },
  latitude: { type: Number },
  longitude: { type: Number },
  timezone: { type: String },
  isp: { type: String },
  
  // Request details
  requestMethod: { type: String, enum: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'] },
  requestUrl: { type: String },
  requestPath: { type: String },
  requestQuery: { type: mongoose.Schema.Types.Mixed },
  requestBody: { type: mongoose.Schema.Types.Mixed },
  requestHeaders: { 
    type: Map,
    of: String,
    select: false
  },
  
  // Response details
  responseStatus: { type: Number, index: true },
  responseTime: { type: Number },
  responseSize: { type: Number },
  
  // Status and outcome
  status: { 
    type: String, 
    enum: ['success', 'failed', 'pending', 'processing', 'cancelled', 'blocked', 'retry'],
    default: 'success',
    index: true
  },
  errorCode: { type: String, index: true },
  errorMessage: { type: String },
  errorStack: { type: String, select: false },
  
  // Security and risk assessment
  riskLevel: { 
    type: String, 
    enum: ['low', 'medium', 'high', 'critical'],
    default: 'low',
    index: true
  },
  riskScore: { type: Number, min: 0, max: 100 },
  riskFactors: [{ type: String }],
  isSuspicious: { type: Boolean, default: false, index: true },
  isAnomaly: { type: Boolean, default: false },
  
  // Financial details (when applicable)
  financial: {
    amount: { type: Number },
    amountUSD: { type: Number },
    cryptoAmount: { type: Number },
    cryptoAsset: { type: String },
    fee: { type: Number },
    feeAsset: { type: String },
    exchangeRate: { type: Number },
    balanceBefore: { type: Number },
    balanceAfter: { type: Number },
    walletType: { type: String, enum: ['main', 'active', 'matured', 'savings', 'loan'] },
    transactionId: { type: mongoose.Schema.Types.ObjectId, ref: 'Transaction' },
    reference: { type: String, index: true }
  },
  
  // Changes tracking (for updates)
  changes: {
    before: { type: mongoose.Schema.Types.Mixed },
    after: { type: mongoose.Schema.Types.Mixed },
    fields: [{ type: String }],
    diff: { type: mongoose.Schema.Types.Mixed }
  },
  
  // Related entities
  relatedEntities: [{
    entityType: { type: String },
    entityId: { type: mongoose.Schema.Types.ObjectId },
    entityModel: { type: String }
  }],
  
  // Session and request tracking
  sessionId: { type: String, index: true },
  requestId: { type: String, index: true },
  correlationId: { type: String, index: true },
  
  // Performance metrics
  performance: {
    memoryUsage: { type: Number },
    cpuUsage: { type: Number },
    dbQueryTime: { type: Number },
    externalApiTime: { type: Number }
  },
  
  // Metadata (flexible for any additional data)
  metadata: { type: mongoose.Schema.Types.Mixed },
  
  // Audit trail
  audit: {
    requiresReview: { type: Boolean, default: false },
    reviewedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' },
    reviewedAt: { type: Date },
    reviewNotes: { type: String },
    retentionPeriod: { type: Number, default: 90 }
  },
  
  // Timestamps
  createdAt: { type: Date, default: Date.now, index: true },
  updatedAt: { type: Date, default: Date.now }
}, { 
  timestamps: true,
  toJSON: { 
    virtuals: true,
    transform: function(doc, ret) {
      delete ret.requestHeaders;
      delete ret.errorStack;
      if (ret.requestBody) {
        delete ret.requestBody.password;
        delete ret.requestBody.cvv;
        delete ret.requestBody.cardNumber;
      }
      return ret;
    }
  },
  toObject: { 
    virtuals: true,
    transform: function(doc, ret) {
      delete ret.requestHeaders;
      delete ret.errorStack;
      if (ret.requestBody) {
        delete ret.requestBody.password;
        delete ret.requestBody.cvv;
        delete ret.requestBody.cardNumber;
      }
      return ret;
    }
  }
});

// =============================================
// INDEXES FOR PERFORMANCE
// =============================================

SystemLogSchema.index({ createdAt: -1, action: 1 });
SystemLogSchema.index({ performedBy: 1, createdAt: -1 });
SystemLogSchema.index({ entity: 1, entityId: 1, createdAt: -1 });
SystemLogSchema.index({ status: 1, createdAt: -1 });
SystemLogSchema.index({ riskLevel: 1, createdAt: -1 });
SystemLogSchema.index({ isSuspicious: 1, createdAt: -1 });
SystemLogSchema.index({ countryCode: 1, createdAt: -1 });
SystemLogSchema.index({ 'financial.reference': 1 });
SystemLogSchema.index({ sessionId: 1, createdAt: -1 });
SystemLogSchema.index({ correlationId: 1 });

// Text search index
SystemLogSchema.index({
  action: 'text',
  errorMessage: 'text',
  performedByEmail: 'text',
  performedByName: 'text',
  location: 'text',
  'metadata.description': 'text'
});

// TTL index for automatic cleanup (90 days default)
SystemLogSchema.index({ createdAt: 1 }, { expireAfterSeconds: 90 * 24 * 60 * 60 });

// =============================================
// PRE-SAVE HOOKS
// =============================================

SystemLogSchema.pre('save', function(next) {
  this.updatedAt = new Date();
  
  if (!this.riskScore && this.riskLevel !== 'low') {
    const riskScores = { low: 10, medium: 40, high: 70, critical: 90 };
    this.riskScore = riskScores[this.riskLevel] || 10;
  }
  
  if (this.status === 'failed' && !this.isSuspicious) {
    this.isSuspicious = true;
    this.riskFactors = this.riskFactors || [];
    this.riskFactors.push('failed_action');
  }
  
  next();
});

// =============================================
// VIRTUALS
// =============================================

SystemLogSchema.virtual('actionDescription').get(function() {
  const descriptions = {
    'user_signup': 'User registered new account',
    'user_login': 'User logged in',
    'user_logout': 'User logged out',
    'user_profile_update': 'User updated profile',
    'user_password_change': 'User changed password',
    'user_2fa_enable': 'User enabled 2FA',
    'user_2fa_disable': 'User disabled 2FA',
    'user_delete': 'User account deleted',
    'user_suspend': 'User account suspended',
    'user_verify': 'User email verified',
    'deposit_create': 'Deposit initiated',
    'deposit_approve': 'Deposit approved',
    'deposit_reject': 'Deposit rejected',
    'withdrawal_create': 'Withdrawal requested',
    'withdrawal_approve': 'Withdrawal approved',
    'withdrawal_reject': 'Withdrawal rejected',
    'investment_create': 'Investment created',
    'investment_complete': 'Investment completed',
    'investment_cancel': 'Investment cancelled',
    'transfer_create': 'Transfer initiated',
    'transfer_complete': 'Transfer completed',
    'buy_execute': 'Buy order executed',
    'sell_execute': 'Sell order executed',
    'conversion_execute': 'Currency conversion executed',
    'admin_login': 'Admin logged in',
    'admin_action': 'Admin action performed',
    'admin_user_modify': 'Admin modified user',
    'admin_balance_adjust': 'Admin adjusted balance',
    'admin_settings_change': 'Admin changed settings',
    'system_start': 'System started',
    'system_stop': 'System stopped',
    'system_maintenance': 'Maintenance mode activated',
    'system_backup': 'System backup completed',
    'system_error': 'System error occurred',
    'cron_execute': 'Scheduled task executed',
    'security_alert': 'Security alert triggered',
    'suspicious_activity': 'Suspicious activity detected',
    'rate_limit_exceeded': 'Rate limit exceeded',
    'brute_force_detected': 'Brute force attempt detected'
  };
  return descriptions[this.action] || `${this.action.replace(/_/g, ' ')} performed on ${this.entity}`;
});

SystemLogSchema.virtual('isFinancial').get(function() {
  const financialActions = [
    'deposit_create', 'deposit_approve', 'deposit_reject',
    'withdrawal_create', 'withdrawal_approve', 'withdrawal_reject',
    'investment_create', 'investment_complete', 'investment_cancel',
    'transfer_create', 'transfer_complete', 'buy_execute',
    'sell_execute', 'conversion_execute', 'admin_balance_adjust'
  ];
  return financialActions.includes(this.action);
});

SystemLogSchema.virtual('isSecurityRelated').get(function() {
  const securityActions = [
    'user_login', 'user_logout', 'user_password_change', 'user_2fa_enable',
    'user_2fa_disable', 'admin_login', 'security_alert', 'suspicious_activity',
    'rate_limit_exceeded', 'brute_force_detected'
  ];
  return securityActions.includes(this.action);
});

// =============================================
// STATIC METHODS
// =============================================

// Initialize stats object
SystemLogSchema.statics.stats = {};

// Get logs by user
SystemLogSchema.statics.findByUser = function(userId, options = {}) {
  const { limit = 50, page = 1, action = null, startDate = null, endDate = null } = options;
  const skip = (page - 1) * limit;
  
  let query = { performedBy: userId, performedByModel: 'User' };
  if (action) query.action = action;
  if (startDate || endDate) {
    query.createdAt = {};
    if (startDate) query.createdAt.$gte = new Date(startDate);
    if (endDate) query.createdAt.$lte = new Date(endDate);
  }
  
  return this.find(query)
    .sort({ createdAt: -1 })
    .skip(skip)
    .limit(limit);
};

// Get logs by admin
SystemLogSchema.statics.findByAdmin = function(adminId, options = {}) {
  const { limit = 50, page = 1, action = null } = options;
  const skip = (page - 1) * limit;
  
  let query = { performedBy: adminId, performedByModel: 'Admin' };
  if (action) query.action = action;
  
  return this.find(query)
    .sort({ createdAt: -1 })
    .skip(skip)
    .limit(limit);
};

// Get logs by entity
SystemLogSchema.statics.findByEntity = function(entityType, entityId, options = {}) {
  const { limit = 50, page = 1 } = options;
  const skip = (page - 1) * limit;
  
  return this.find({ entity: entityType, entityId })
    .sort({ createdAt: -1 })
    .skip(skip)
    .limit(limit);
};

// Get suspicious activities
SystemLogSchema.statics.findSuspicious = function(days = 7, options = {}) {
  const dateThreshold = new Date();
  dateThreshold.setDate(dateThreshold.getDate() - days);
  
  return this.find({
    isSuspicious: true,
    createdAt: { $gte: dateThreshold }
  })
  .sort({ createdAt: -1 })
  .limit(options.limit || 100);
};

// Get activities by risk level
SystemLogSchema.statics.findByRiskLevel = function(riskLevel, days = 7) {
  const dateThreshold = new Date();
  dateThreshold.setDate(dateThreshold.getDate() - days);
  
  return this.find({
    riskLevel: riskLevel,
    createdAt: { $gte: dateThreshold }
  }).sort({ createdAt: -1 });
};

// Get user activity summary
SystemLogSchema.statics.getUserActivitySummary = async function(userId, days = 30) {
  const dateThreshold = new Date();
  dateThreshold.setDate(dateThreshold.getDate() - days);
  
  const summary = await this.aggregate([
    { $match: { performedBy: userId, performedByModel: 'User', createdAt: { $gte: dateThreshold } } },
    {
      $group: {
        _id: { action: '$action', status: '$status' },
        count: { $sum: 1 },
        lastOccurrence: { $max: '$createdAt' }
      }
    },
    {
      $group: {
        _id: '$_id.action',
        totalCount: { $sum: '$count' },
        successCount: {
          $sum: { $cond: [{ $eq: ['$_id.status', 'success'] }, '$count', 0] }
        },
        failedCount: {
          $sum: { $cond: [{ $eq: ['$_id.status', 'failed'] }, '$count', 0] }
        },
        lastOccurrence: { $max: '$lastOccurrence' }
      }
    },
    { $sort: { totalCount: -1 } }
  ]);
  
  return summary;
};

// =============================================
// STATS METHODS (attached to the stats object)
// =============================================

// Get geographical distribution
SystemLogSchema.statics.stats.getGeoDistribution = async function(days = 7) {
  const dateThreshold = new Date();
  dateThreshold.setDate(dateThreshold.getDate() - days);
  
  return this.aggregate([
    { $match: { createdAt: { $gte: dateThreshold }, countryCode: { $ne: null } } },
    {
      $group: {
        _id: { country: '$countryCode', city: '$city' },
        count: { $sum: 1 },
        uniqueUsers: { $addToSet: '$performedBy' }
      }
    },
    {
      $project: {
        country: '$_id.country',
        city: '$_id.city',
        count: 1,
        uniqueUsersCount: { $size: '$uniqueUsers' }
      }
    },
    { $sort: { count: -1 } }
  ]);
};

// Get hourly activity pattern
SystemLogSchema.statics.stats.getHourlyPattern = async function(days = 7) {
  const dateThreshold = new Date();
  dateThreshold.setDate(dateThreshold.getDate() - days);
  
  return this.aggregate([
    { $match: { createdAt: { $gte: dateThreshold } } },
    {
      $group: {
        _id: { hour: { $hour: '$createdAt' }, action: '$action' },
        count: { $sum: 1 }
      }
    },
    {
      $group: {
        _id: '$_id.hour',
        actions: {
          $push: { action: '$_id.action', count: '$count' }
        },
        totalCount: { $sum: '$count' }
      }
    },
    { $sort: { '_id': 1 } }
  ]);
};

// Get activity by entity type
SystemLogSchema.statics.stats.getByEntityType = async function(days = 30) {
  const dateThreshold = new Date();
  dateThreshold.setDate(dateThreshold.getDate() - days);
  
  return this.aggregate([
    { $match: { createdAt: { $gte: dateThreshold } } },
    {
      $group: {
        _id: '$entity',
        count: { $sum: 1 },
        uniqueUsers: { $addToSet: '$performedBy' }
      }
    },
    {
      $project: {
        entity: '$_id',
        count: 1,
        uniqueUsersCount: { $size: '$uniqueUsers' }
      }
    },
    { $sort: { count: -1 } }
  ]);
};

// Get risk level distribution
SystemLogSchema.statics.stats.getRiskDistribution = async function(days = 30) {
  const dateThreshold = new Date();
  dateThreshold.setDate(dateThreshold.getDate() - days);
  
  return this.aggregate([
    { $match: { createdAt: { $gte: dateThreshold } } },
    {
      $group: {
        _id: '$riskLevel',
        count: { $sum: 1 },
        percentage: { $sum: 1 }
      }
    },
    {
      $project: {
        riskLevel: '$_id',
        count: 1,
        percentage: { $multiply: [{ $divide: ['$percentage', { $sum: '$percentage' }] }, 100] }
      }
    },
    { $sort: { count: -1 } }
  ]);
};

// Get top users by activity
SystemLogSchema.statics.stats.getTopActiveUsers = async function(limit = 10, days = 30) {
  const dateThreshold = new Date();
  dateThreshold.setDate(dateThreshold.getDate() - days);
  
  return this.aggregate([
    { $match: { performedBy: { $ne: null }, performedByModel: 'User', createdAt: { $gte: dateThreshold } } },
    {
      $group: {
        _id: '$performedBy',
        activityCount: { $sum: 1 },
        lastActive: { $max: '$createdAt' },
        actions: { $addToSet: '$action' }
      }
    },
    { $sort: { activityCount: -1 } },
    { $limit: limit },
    {
      $lookup: {
        from: 'users',
        localField: '_id',
        foreignField: '_id',
        as: 'userInfo'
      }
    },
    {
      $project: {
        userId: '$_id',
        activityCount: 1,
        lastActive: 1,
        actionTypes: { $size: '$actions' },
        userName: { $arrayElemAt: ['$userInfo.firstName', 0] },
        userEmail: { $arrayElemAt: ['$userInfo.email', 0] }
      }
    }
  ]);
};

// =============================================
// INSTANCE METHODS
// =============================================

// Mark as reviewed
SystemLogSchema.methods.markAsReviewed = async function(adminId, notes) {
  this.audit = {
    requiresReview: false,
    reviewedBy: adminId,
    reviewedAt: new Date(),
    reviewNotes: notes,
    retentionPeriod: this.audit?.retentionPeriod || 90
  };
  return this.save();
};

// Mark as suspicious with reason
SystemLogSchema.methods.markAsSuspicious = async function(reason, riskLevel = 'high') {
  this.isSuspicious = true;
  this.riskLevel = riskLevel;
  this.riskScore = riskLevel === 'high' ? 70 : riskLevel === 'critical' ? 90 : 40;
  this.riskFactors = this.riskFactors || [];
  this.riskFactors.push(reason);
  return this.save();
};

// Add related entity
SystemLogSchema.methods.addRelatedEntity = function(entityType, entityId, entityModel) {
  if (!this.relatedEntities) this.relatedEntities = [];
  this.relatedEntities.push({ entityType, entityId, entityModel });
  return this;
};

// =============================================
// QUERY HELPERS
// =============================================

SystemLogSchema.query.byDateRange = function(startDate, endDate) {
  return this.where('createdAt').gte(startDate).lte(endDate);
};

SystemLogSchema.query.byAction = function(action) {
  return this.where('action', action);
};

SystemLogSchema.query.byStatus = function(status) {
  return this.where('status', status);
};

SystemLogSchema.query.byRiskLevel = function(riskLevel) {
  return this.where('riskLevel', riskLevel);
};

SystemLogSchema.query.byEntity = function(entity) {
  return this.where('entity', entity);
};

SystemLogSchema.query.byPerformedBy = function(performedBy, model = null) {
  let query = this.where('performedBy', performedBy);
  if (model) query = query.where('performedByModel', model);
  return query;
};

// =============================================
// COMPILE SYSTEM LOG MODEL
// =============================================

const SystemLog = mongoose.model('SystemLog', SystemLogSchema);










const KYCSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: [true, 'User is required'],
    index: true
  },
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

KYCSchema.index({ user: 1 });
KYCSchema.index({ overallStatus: 1 });
KYCSchema.index({ submittedAt: -1 });

const KYC = mongoose.model('KYC', KYCSchema);

const multer = require('multer');
const path = require('path');
const fs = require('fs');

const ensureUploadDirectories = () => {
  const dirs = [
    process.env.KYC_UPLOAD_PATH || 'uploads/kyc/',
    process.env.KYC_IDENTITY_PATH || 'uploads/kyc/identity',
    process.env.KYC_ADDRESS_PATH || 'uploads/kyc/address',
    process.env.KYC_FACIAL_PATH || 'uploads/kyc/facial',
    process.env.TEMP_UPLOAD_PATH || 'uploads/temp'
  ];
  
  dirs.forEach(dir => {
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
  });
};

ensureUploadDirectories();

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    let uploadPath = process.env.TEMP_UPLOAD_PATH || 'uploads/temp';
    
    if (file.fieldname.includes('identity')) {
      uploadPath = process.env.KYC_IDENTITY_PATH || 'uploads/kyc/identity';
    } else if (file.fieldname.includes('address')) {
      uploadPath = process.env.KYC_ADDRESS_PATH || 'uploads/kyc/address';
    } else if (file.fieldname.includes('facial')) {
      uploadPath = process.env.KYC_FACIAL_PATH || 'uploads/kyc/facial';
    }
    
    cb(null, uploadPath);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const ext = path.extname(file.originalname);
    cb(null, file.fieldname + '-' + uniqueSuffix + ext);
  }
});

const allowedMimeTypes = process.env.KYC_ALLOWED_MIME_TYPES ? process.env.KYC_ALLOWED_MIME_TYPES.split(',') : [
  'image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'application/pdf', 'video/mp4', 'video/webm'
];

const fileFilter = (req, file, cb) => {
  if (allowedMimeTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error(`Invalid file type: ${file.mimetype}. Only ${allowedMimeTypes.join(', ')} are allowed.`), false);
  }
};

const upload = multer({
  storage: storage,
  fileFilter: fileFilter,
  limits: {
    fileSize: parseInt(process.env.KYC_MAX_FILE_SIZE) || 10 * 1024 * 1024,
    files: parseInt(process.env.KYC_MAX_FILES) || 5
  }
});

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

  const clients = new Map();
  const agentAvailability = new Map();
  const userConversations = new Map();

  const HEARTBEAT_INTERVAL = 30000;
  const HEARTBEAT_VALUE = '--heartbeat--';

  const sendToClient = (clientId, data) => {
    const client = clients.get(clientId);
    if (client && client.readyState === WebSocket.OPEN) {
      client.send(JSON.stringify(data));
    }
  };

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

    const setupHeartbeat = () => {
      heartbeatInterval = setInterval(() => {
        if (ws.readyState === WebSocket.OPEN) {
          ws.ping();
        }
      }, HEARTBEAT_INTERVAL);
    };

    const authenticate = async (token) => {
      try {
        const decoded = verifyJWT(token);
        
        if (decoded.isAdmin) {
          const admin = await Admin.findById(decoded.id);
          if (admin && admin.role === 'support') {
            userType = 'agent';
            userId = admin._id.toString();
            isAuthenticated = true;
            
            agentAvailability.set(userId, true);
            
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

    clients.set(clientId, ws);
    ws.clientId = clientId;
    setupHeartbeat();

    ws.on('message', async (message) => {
      try {
        if (message === HEARTBEAT_VALUE) {
          ws.pong();
          return;
        }

        const data = JSON.parse(message);

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

        switch (data.type) {
          case 'new_message': {
            const { conversationId, message } = data;
            
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
            
            const newMessage = new SupportMessage({
              conversationId,
              sender: userType,
              senderId: userId,
              message,
              read: false
            });

            await newMessage.save();

            conversation.lastMessageAt = new Date();
            conversation.status = userType === 'user' ? 
              (conversation.agentId ? 'active' : 'open') : 'active';
            await conversation.save();

            const messageData = {
              type: 'new_message',
              message: {
                ...newMessage.toObject(),
                conversationId,
                sender: userType,
                senderId: userId
              }
            };

            if (userType === 'user') {
              if (conversation.agentId) {
                const agentClientId = userConversations.get(conversation.agentId.toString());
                if (agentClientId) {
                  sendToClient(agentClientId, messageData);
                }
              } else {
                broadcastToAgents({
                  type: 'new_conversation',
                  conversation: await SupportConversation.findById(conversation._id)
                    .populate('user', 'firstName lastName email')
                });
              }
            } else {
              const userClientId = userConversations.get(conversation.userId.toString());
              if (userClientId) {
                sendToClient(userClientId, messageData);
              }
            }

            break;
          }
        }
      } catch (err) {
        console.error('WebSocket message error:', err);
        sendToClient(clientId, {
          type: 'error',
          message: 'Internal server error'
        });
      }
    });

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

    ws.on('error', (err) => {
      console.error('WebSocket error:', err);
      ws.close();
    });

    ws.on('pong', () => {
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
  UserPreference,
  DepositAsset,
  Buy,
  Sell,
   FinancialStatement, 
  setupWebSocketServer
};

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
  const tokenExpires = Date.now() + 60 * 60 * 1000;
  return { resetToken, hashedToken, tokenExpires };
};

const generateApiKey = () => {
  return crypto.randomBytes(32).toString('hex');
};

const generateReferralCode = () => {
  const timestamp = Date.now().toString(36).substring(4).toUpperCase();
  const randomPart = crypto.randomBytes(6).toString('hex').toUpperCase();
  const checksum = crypto.createHash('md5').update(timestamp + randomPart).digest('hex').substring(0, 4).toUpperCase();
  
  return `BH-${timestamp}-${randomPart}-${checksum}`;
};

const detectAndSetIPPreferences = async (userId, req) => {
  try {
    const user = await User.findById(userId);
    if (!user) return null;
    
    if (user.ipPreferences && user.ipPreferences.setFromIP) {
      return user.ipPreferences;
    }
    
    const ip = getRealClientIP(req);
    
    let detectedCountry = 'US';
    let detectedLanguage = 'en';
    let detectedCurrency = 'USD';
    
    try {
      const response = await axios.get(`https://ipapi.co/${ip}/json/`, { timeout: 3000 });
      if (response.data && !response.data.error) {
        const countryCode = response.data.country_code || 'US';
        const currencyCode = response.data.currency || 'USD';
        detectedCountry = countryCode;
        detectedCurrency = currencyCode;
        
        const languageMap = {
          'ES': 'es', 'MX': 'es', 'AR': 'es', 'CO': 'es', 'CL': 'es', 'PE': 'es',
          'FR': 'fr', 'DE': 'de', 'IT': 'it', 'PT': 'pt', 'BR': 'pt',
          'JP': 'ja', 'CN': 'zh', 'RU': 'ru', 'KR': 'ko', 'NL': 'nl',
          'PL': 'pl', 'TR': 'tr', 'SE': 'sv', 'NO': 'no', 'DK': 'da',
          'FI': 'fi', 'GR': 'el', 'CZ': 'cs', 'HU': 'hu', 'RO': 'ro',
          'BG': 'bg', 'SK': 'sk', 'HR': 'hr', 'RS': 'sr', 'SI': 'sl',
          'LT': 'lt', 'LV': 'lv', 'EE': 'et', 'IS': 'is', 'ZA': 'en',
          'IN': 'hi', 'PK': 'ur', 'BD': 'bn', 'VN': 'vi', 'TH': 'th',
          'ID': 'id', 'MY': 'ms', 'PH': 'tl', 'NG': 'en', 'KE': 'en',
          'EG': 'ar', 'SA': 'ar', 'AE': 'ar', 'IL': 'he', 'IR': 'fa'
        };
        detectedLanguage = languageMap[countryCode] || 'en';
      }
    } catch (geoError) {
      console.warn('IP geolocation failed, using defaults:', geoError.message);
      try {
        const ipinfoToken = process.env.IPINFO_TOKEN || 'b56ce6e91d732d';
        const ipinfoResponse = await axios.get(`https://ipinfo.io/${ip}?token=${ipinfoToken}`, { timeout: 3000 });
        if (ipinfoResponse.data) {
          const countryCode = ipinfoResponse.data.country || 'US';
          detectedCountry = countryCode;
          
          const currencyMap = { 'US': 'USD', 'GB': 'GBP', 'EU': 'EUR', 'JP': 'JPY', 'CA': 'CAD', 'RO': 'RON' };
          detectedCurrency = currencyMap[countryCode] || 'USD';
          
          const languageMap = { 'US': 'en', 'GB': 'en', 'EU': 'en', 'JP': 'ja', 'CA': 'en', 'RO': 'ro' };
          detectedLanguage = languageMap[countryCode] || 'en';
        }
      } catch (fallbackError) {
        console.warn('Fallback IP geolocation also failed');
      }
    }
    
    user.ipPreferences = {
      language: detectedLanguage,
      currency: detectedCurrency,
      setFromIP: true,
      detectedAt: new Date(),
      detectedCountry: detectedCountry
    };
    
    if (!user.preferences) user.preferences = { notifications: {}, theme: 'dark' };
    if (!user.preferences.language) user.preferences.language = detectedLanguage;
    
    await user.save();
    
    await UserPreference.findOneAndUpdate(
      { user: userId },
      { 
        language: detectedLanguage,
        currency: detectedCurrency,
        $setOnInsert: { user: userId }
      },
      { upsert: true, new: true }
    );
    
    console.log(`IP-based preferences set for user ${userId}: language=${detectedLanguage}, currency=${detectedCurrency}, country=${detectedCountry}`);
    
    return { language: detectedLanguage, currency: detectedCurrency, country: detectedCountry };
  } catch (err) {
    console.error('Error detecting IP preferences:', err);
    return null;
  }
};







// Cache configuration
const cryptoPriceCache = new Map();
const CACHE_TTL = 30000; // 30 seconds cache TTL (reduces API calls while keeping prices reasonably fresh)
const RATE_LIMIT_COOLDOWN = 1000; // 1 second cooldown between API calls

// Helper function to get cached price
const getCachedPrice = (asset) => {
  const cached = cryptoPriceCache.get(asset);
  if (cached && (Date.now() - cached.timestamp) < CACHE_TTL) {
    console.log(`📦 Cache hit for ${asset}: $${cached.price}`);
    return cached.price;
  }
  return null;
};

// Helper function to set cached price
const setCachedPrice = (asset, price) => {
  cryptoPriceCache.set(asset, {
    price: price,
    timestamp: Date.now()
  });
};

const getCryptoPrice = async (asset) => {
  // Check cache first
  const cachedPrice = getCachedPrice(asset);
  if (cachedPrice !== null) {
    return cachedPrice;
  }

  try {
    const assetUpper = asset.toUpperCase();
    
    // Handle stablecoins - they are always $1 (this is factual, not a fallback)
    const stablecoins = ['USDT', 'USDC', 'DAI', 'BUSD', 'TUSD', 'USDP'];
    if (stablecoins.includes(assetUpper)) {
      console.log(`${assetUpper} is a stablecoin, price is $1`);
      setCachedPrice(assetUpper, 1);
      return 1;
    }
    
    // No hardcoded asset map - fetch all trading cryptos dynamically from Binance
    let allSymbols = [];
    let assetFound = false;
    let coinId = null;
    
    // Fetch all trading symbols from Binance to find matching asset
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 8000);
      const exchangeInfoResponse = await fetch('https://api.binance.com/api/v3/exchangeInfo', {
        signal: controller.signal
      });
      clearTimeout(timeoutId);
      
      if (exchangeInfoResponse.ok) {
        const exchangeInfo = await exchangeInfoResponse.json();
        const tradingPairs = exchangeInfo.symbols.filter(s => s.status === 'TRADING');
        
        // Try to find the asset in trading pairs (as base asset)
        const matchingPair = tradingPairs.find(p => 
          p.baseAsset.toUpperCase() === assetUpper || 
          p.quoteAsset.toUpperCase() === assetUpper
        );
        
        if (matchingPair) {
          assetFound = true;
          allSymbols = tradingPairs.map(p => p.symbol);
        }
      }
    } catch (err) {
      console.log(`Failed to fetch exchange info: ${err.message}`);
    }
    
    // If asset not found in Binance, try CoinGecko to get coin ID
    if (!assetFound) {
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 8000);
        const coinsListResponse = await fetch('https://api.coingecko.com/api/v3/coins/list', {
          signal: controller.signal
        });
        clearTimeout(timeoutId);
        
        if (coinsListResponse.ok) {
          const coinsList = await coinsListResponse.json();
          const matchingCoin = coinsList.find(c => 
            c.symbol.toUpperCase() === assetUpper || 
            c.id.toUpperCase() === assetUpper ||
            c.name.toUpperCase() === assetUpper
          );
          
          if (matchingCoin) {
            coinId = matchingCoin.id;
            assetFound = true;
          }
        }
      } catch (err) {
        console.log(`Failed to fetch coins list: ${err.message}`);
      }
    }
    
    // If asset still not found, try direct API calls without mapping
    if (!assetFound) {
      console.log(`No mapping found for ${assetUpper}, trying direct API calls...`);
    }
    
    // Try direct price fetch using Binance (works for any USD pair)
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 5000);
      const response = await fetch(`https://api.binance.com/api/v3/ticker/price?symbol=${assetUpper}USDT`, {
        signal: controller.signal
      });
      clearTimeout(timeoutId);
      
      if (response.ok) {
        const data = await response.json();
        if (data && data.price && parseFloat(data.price) > 0) {
          const price = parseFloat(data.price);
          console.log(`✅ ${asset} price from Binance: $${price}`);
          setCachedPrice(assetUpper, price);
          return price;
        }
      }
    } catch (err) {
      console.log(`Binance direct failed for ${asset}:`, err.message);
    }
    
    // Try Binance direct with different pair format (USD)
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 5000);
      const response = await fetch(`https://api.binance.com/api/v3/ticker/price?symbol=${assetUpper}USD`, {
        signal: controller.signal
      });
      clearTimeout(timeoutId);
      
      if (response.ok) {
        const data = await response.json();
        if (data && data.price && parseFloat(data.price) > 0) {
          const price = parseFloat(data.price);
          console.log(`✅ ${asset} price from Binance (USD pair): $${price}`);
          setCachedPrice(assetUpper, price);
          return price;
        }
      }
    } catch (err) {
      console.log(`Binance USD direct failed for ${asset}:`, err.message);
    }
    
    // Rate limiting cooldown before next API batch
    await new Promise(resolve => setTimeout(resolve, RATE_LIMIT_COOLDOWN));
    
    // Try CoinGecko with dynamic coin ID lookup
    if (coinId) {
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 5000);
        const response = await fetch(`https://api.coingecko.com/api/v3/simple/price?ids=${coinId}&vs_currencies=usd`, {
          signal: controller.signal
        });
        clearTimeout(timeoutId);
        
        if (response.ok) {
          const data = await response.json();
          if (data && data[coinId] && data[coinId].usd && data[coinId].usd > 0) {
            const price = data[coinId].usd;
            console.log(`✅ ${asset} price from CoinGecko: $${price}`);
            setCachedPrice(assetUpper, price);
            return price;
          }
        }
      } catch (err) {
        console.log(`CoinGecko failed for ${asset}:`, err.message);
      }
    }
    
    // Rate limiting cooldown
    await new Promise(resolve => setTimeout(resolve, RATE_LIMIT_COOLDOWN));
    
    // Try CoinGecko search endpoint for unknown coins
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 5000);
      const searchResponse = await fetch(`https://api.coingecko.com/api/v3/search?query=${assetUpper}`, {
        signal: controller.signal
      });
      clearTimeout(timeoutId);
      
      if (searchResponse.ok) {
        const searchData = await searchResponse.json();
        if (searchData.coins && searchData.coins.length > 0) {
          const foundCoinId = searchData.coins[0].id;
          const priceResponse = await fetch(`https://api.coingecko.com/api/v3/simple/price?ids=${foundCoinId}&vs_currencies=usd`, {
            signal: controller.signal
          });
          clearTimeout(timeoutId);
          
          if (priceResponse.ok) {
            const priceData = await priceResponse.json();
            if (priceData && priceData[foundCoinId] && priceData[foundCoinId].usd && priceData[foundCoinId].usd > 0) {
              const price = priceData[foundCoinId].usd;
              console.log(`✅ ${asset} price from CoinGecko search: $${price}`);
              setCachedPrice(assetUpper, price);
              return price;
            }
          }
        }
      }
    } catch (err) {
      console.log(`CoinGecko search failed for ${asset}:`, err.message);
    }
    
    // Rate limiting cooldown
    await new Promise(resolve => setTimeout(resolve, RATE_LIMIT_COOLDOWN));
    
    // Try CryptoCompare (works with any crypto symbol)
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 5000);
      const response = await fetch(`https://min-api.cryptocompare.com/data/price?fsym=${assetUpper}&tsyms=USD`, {
        signal: controller.signal
      });
      clearTimeout(timeoutId);
      
      if (response.ok) {
        const data = await response.json();
        if (data && data.USD && data.USD > 0) {
          const price = data.USD;
          console.log(`✅ ${asset} price from CryptoCompare: $${price}`);
          setCachedPrice(assetUpper, price);
          return price;
        }
      }
    } catch (err) {
      console.log(`CryptoCompare failed for ${asset}:`, err.message);
    }
    
    // Rate limiting cooldown
    await new Promise(resolve => setTimeout(resolve, RATE_LIMIT_COOLDOWN));
    
    // Try Kraken with dynamic symbol lookup
    try {
      // Fetch available pairs from Kraken
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 5000);
      const pairsResponse = await fetch('https://api.kraken.com/0/public/AssetPairs', {
        signal: controller.signal
      });
      clearTimeout(timeoutId);
      
      if (pairsResponse.ok) {
        const pairsData = await pairsResponse.json();
        if (pairsData && pairsData.result) {
          // Find matching pair
          const matchingPair = Object.keys(pairsData.result).find(key => 
            key.includes(assetUpper) && (key.includes('USD') || key.includes('USDT'))
          );
          
          if (matchingPair) {
            const tickerResponse = await fetch(`https://api.kraken.com/0/public/Ticker?pair=${matchingPair}`, {
              signal: controller.signal
            });
            clearTimeout(timeoutId);
            
            if (tickerResponse.ok) {
              const tickerData = await tickerResponse.json();
              if (tickerData && tickerData.result && tickerData.result[matchingPair] && 
                  tickerData.result[matchingPair].c && tickerData.result[matchingPair].c[0]) {
                const price = parseFloat(tickerData.result[matchingPair].c[0]);
                if (price > 0) {
                  console.log(`✅ ${asset} price from Kraken: $${price}`);
                  setCachedPrice(assetUpper, price);
                  return price;
                }
              }
            }
          }
        }
      }
    } catch (err) {
      console.log(`Kraken failed for ${asset}:`, err.message);
    }
    
    // Rate limiting cooldown
    await new Promise(resolve => setTimeout(resolve, RATE_LIMIT_COOLDOWN));
    
    // Try KuCoin (works with any USDT pair)
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 5000);
      const response = await fetch(`https://api.kucoin.com/api/v1/market/orderbook/level1?symbol=${assetUpper}-USDT`, {
        signal: controller.signal
      });
      clearTimeout(timeoutId);
      
      if (response.ok) {
        const data = await response.json();
        if (data && data.data && data.data.price && parseFloat(data.data.price) > 0) {
          const price = parseFloat(data.data.price);
          console.log(`✅ ${asset} price from KuCoin: $${price}`);
          setCachedPrice(assetUpper, price);
          return price;
        }
      }
    } catch (err) {
      console.log(`KuCoin failed for ${asset}:`, err.message);
    }
    
    // Rate limiting cooldown
    await new Promise(resolve => setTimeout(resolve, RATE_LIMIT_COOLDOWN));
    
    // Try Bybit (works with any USDT pair)
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 5000);
      const response = await fetch(`https://api.bybit.com/v5/market/tickers?category=spot&symbol=${assetUpper}USDT`, {
        signal: controller.signal
      });
      clearTimeout(timeoutId);
      
      if (response.ok) {
        const data = await response.json();
        if (data && data.result && data.result.list && data.result.list[0] && data.result.list[0].lastPrice) {
          const price = parseFloat(data.result.list[0].lastPrice);
          if (price > 0) {
            console.log(`✅ ${asset} price from Bybit: $${price}`);
            setCachedPrice(assetUpper, price);
            return price;
          }
        }
      }
    } catch (err) {
      console.log(`Bybit failed for ${asset}:`, err.message);
    }
    
    // Rate limiting cooldown
    await new Promise(resolve => setTimeout(resolve, RATE_LIMIT_COOLDOWN));
    
    // Try OKX (works with any USDT pair)
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 5000);
      const response = await fetch(`https://www.okx.com/api/v5/market/ticker?instId=${assetUpper}-USDT`, {
        signal: controller.signal
      });
      clearTimeout(timeoutId);
      
      if (response.ok) {
        const data = await response.json();
        if (data && data.data && data.data[0] && data.data[0].last && parseFloat(data.data[0].last) > 0) {
          const price = parseFloat(data.data[0].last);
          console.log(`✅ ${asset} price from OKX: $${price}`);
          setCachedPrice(assetUpper, price);
          return price;
        }
      }
    } catch (err) {
      console.log(`OKX failed for ${asset}:`, err.message);
    }
    
    // Rate limiting cooldown
    await new Promise(resolve => setTimeout(resolve, RATE_LIMIT_COOLDOWN));
    
    // Try Gate.io (works with any USDT pair)
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 5000);
      const response = await fetch(`https://api.gateio.ws/api/v4/spot/tickers?currency_pair=${assetUpper}_USDT`, {
        signal: controller.signal
      });
      clearTimeout(timeoutId);
      
      if (response.ok) {
        const data = await response.json();
        if (data && data[0] && data[0].last && parseFloat(data[0].last) > 0) {
          const price = parseFloat(data[0].last);
          console.log(`✅ ${asset} price from Gate.io: $${price}`);
          setCachedPrice(assetUpper, price);
          return price;
        }
      }
    } catch (err) {
      console.log(`Gate.io failed for ${asset}:`, err.message);
    }
    
    // Rate limiting cooldown
    await new Promise(resolve => setTimeout(resolve, RATE_LIMIT_COOLDOWN));
    
    // Try Coinbase (works with any USD pair)
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 5000);
      const response = await fetch(`https://api.coinbase.com/v2/prices/${assetUpper}-USD/spot`, {
        signal: controller.signal
      });
      clearTimeout(timeoutId);
      
      if (response.ok) {
        const data = await response.json();
        if (data && data.data && data.data.amount && parseFloat(data.data.amount) > 0) {
          const price = parseFloat(data.data.amount);
          console.log(`✅ ${asset} price from Coinbase: $${price}`);
          setCachedPrice(assetUpper, price);
          return price;
        }
      }
    } catch (err) {
      console.log(`Coinbase failed for ${asset}:`, err.message);
    }
    
    // Rate limiting cooldown
    await new Promise(resolve => setTimeout(resolve, RATE_LIMIT_COOLDOWN));
    
    // Try Huobi (works with any USDT pair)
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 5000);
      const response = await fetch(`https://api.huobi.pro/market/detail/merged?symbol=${assetUpper.toLowerCase()}usdt`, {
        signal: controller.signal
      });
      clearTimeout(timeoutId);
      
      if (response.ok) {
        const data = await response.json();
        if (data && data.tick && data.tick.close && parseFloat(data.tick.close) > 0) {
          const price = parseFloat(data.tick.close);
          console.log(`✅ ${asset} price from Huobi: $${price}`);
          setCachedPrice(assetUpper, price);
          return price;
        }
      }
    } catch (err) {
      console.log(`Huobi failed for ${asset}:`, err.message);
    }
    
    // Rate limiting cooldown
    await new Promise(resolve => setTimeout(resolve, RATE_LIMIT_COOLDOWN));
    
    // Try Bitfinex (works with any USD pair)
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 5000);
      const response = await fetch(`https://api.bitfinex.com/v2/ticker/t${assetUpper}USD`, {
        signal: controller.signal
      });
      clearTimeout(timeoutId);
      
      if (response.ok) {
        const data = await response.json();
        if (data && data[6] && parseFloat(data[6]) > 0) {
          const price = parseFloat(data[6]);
          console.log(`✅ ${asset} price from Bitfinex: $${price}`);
          setCachedPrice(assetUpper, price);
          return price;
        }
      }
    } catch (err) {
      console.log(`Bitfinex failed for ${asset}:`, err.message);
    }
    
    // If all APIs failed, return null (no fake fallback)
    console.error(`❌ All APIs failed to fetch price for ${asset}`);
    return null;
    
  } catch (err) {
    console.error(`Error fetching price for ${asset}:`, err);
    return null;
  }
};








const getExchangeRate = async (asset, fiat = 'usd') => {
  try {
    const assetMap = {
      'BTC': 'bitcoin',
      'ETH': 'ethereum',
      'USDT': 'tether',
      'BNB': 'binancecoin',
      'SOL': 'solana',
      'USDC': 'usd-coin',
      'XRP': 'ripple',
      'DOGE': 'dogecoin',
      'ADA': 'cardano',
      'SHIB': 'shiba-inu'
    };
    
    const coinId = assetMap[asset.toUpperCase()];
    if (!coinId) return null;
    
    const errors = [];
    
    try {
      const binancePair = asset.toUpperCase() === 'USDT' ? 'USDTUSDT' : `${asset.toUpperCase()}USDT`;
      const response = await axios.get(`https://api.binance.com/api/v3/ticker/price?symbol=${binancePair}`, { timeout: 5000 });
      if (response.data && response.data.price) {
        return parseFloat(response.data.price);
      }
      errors.push('Binance: Invalid response');
    } catch (err) {
      errors.push(`Binance: ${err.message}`);
    }
    
    try {
      const response = await axios.get(`https://min-api.cryptocompare.com/data/price?fsym=${asset.toUpperCase()}&tsyms=USD`, { timeout: 5000 });
      if (response.data && response.data.USD) {
        return response.data.USD;
      }
      errors.push('CryptoCompare: Invalid response');
    } catch (err) {
      errors.push(`CryptoCompare: ${err.message}`);
    }
    
    try {
      const krakenMap = {
        'BTC': 'XBTUSD',
        'ETH': 'ETHUSD',
        'USDT': 'USDTUSD',
        'SOL': 'SOLUSD',
        'XRP': 'XRPUSD',
        'DOGE': 'DOGEUSD',
        'ADA': 'ADAUSD'
      };
      const pair = krakenMap[asset.toUpperCase()];
      if (pair) {
        const response = await axios.get(`https://api.kraken.com/0/public/Ticker?pair=${pair}`, { timeout: 5000 });
        if (response.data && response.data.result && response.data.result[pair]) {
          return parseFloat(response.data.result[pair].c[0]);
        }
      }
      errors.push('Kraken: No data or unsupported pair');
    } catch (err) {
      errors.push(`Kraken: ${err.message}`);
    }
    
    console.error(`All exchange rate APIs failed for ${asset}:`, errors);
    return null;
  } catch (err) {
    console.error('Error fetching exchange rate:', err);
    return null;
  }
};

const getFiatExchangeRates = async () => {
  try {
    try {
      const response = await axios.get('https://api.exchangerate-api.com/v4/latest/USD', { timeout: 5000 });
      if (response.data && response.data.rates) {
        console.log('Fetched fiat exchange rates from exchangerate-api.com');
        return response.data.rates;
      }
    } catch (err) {
      console.warn('exchangerate-api.com failed:', err.message);
    }
    
    try {
      const response = await axios.get('https://api.frankfurter.app/latest?from=USD', { timeout: 5000 });
      if (response.data && response.data.rates) {
        console.log('Fetched fiat exchange rates from frankfurter.app');
        return response.data.rates;
      }
    } catch (err) {
      console.warn('frankfurter.app failed:', err.message);
    }
    
    try {
      const response = await axios.get('https://cdn.jsdelivr.net/npm/@fawazahmed0/currency-api@latest/v1/currencies/usd.json', { timeout: 5000 });
      if (response.data && response.data.usd) {
        console.log('Fetched fiat exchange rates from currency-api');
        return response.data.usd;
      }
    } catch (err) {
      console.warn('currency-api failed:', err.message);
    }
    
    console.error('All fiat exchange rate APIs failed');
    return null;
  } catch (err) {
    console.error('Error fetching fiat exchange rates:', err);
    return null;
  }
};

const getAllWorldCurrencies = async () => {
  const rates = await getFiatExchangeRates();
  if (!rates) return null;
  
  const allCurrencies = [
    { code: 'USD', name: 'US Dollar', symbol: '$', flag: 'https://flagcdn.com/w40/us.png' },
    { code: 'EUR', name: 'Euro', symbol: '€', flag: 'https://flagcdn.com/w40/eu.png' },
    { code: 'GBP', name: 'British Pound', symbol: '£', flag: 'https://flagcdn.com/w40/gb.png' },
    { code: 'JPY', name: 'Japanese Yen', symbol: '¥', flag: 'https://flagcdn.com/w40/jp.png' },
    { code: 'CNY', name: 'Chinese Yuan', symbol: '¥', flag: 'https://flagcdn.com/w40/cn.png' },
    { code: 'INR', name: 'Indian Rupee', symbol: '₹', flag: 'https://flagcdn.com/w40/in.png' },
    { code: 'CAD', name: 'Canadian Dollar', symbol: 'C$', flag: 'https://flagcdn.com/w40/ca.png' },
    { code: 'AUD', name: 'Australian Dollar', symbol: 'A$', flag: 'https://flagcdn.com/w40/au.png' },
    { code: 'CHF', name: 'Swiss Franc', symbol: 'Fr', flag: 'https://flagcdn.com/w40/ch.png' },
    { code: 'KRW', name: 'South Korean Won', symbol: '₩', flag: 'https://flagcdn.com/w40/kr.png' },
    { code: 'MXN', name: 'Mexican Peso', symbol: '$', flag: 'https://flagcdn.com/w40/mx.png' },
    { code: 'BRL', name: 'Brazilian Real', symbol: 'R$', flag: 'https://flagcdn.com/w40/br.png' },
    { code: 'ZAR', name: 'South African Rand', symbol: 'R', flag: 'https://flagcdn.com/w40/za.png' },
    { code: 'SGD', name: 'Singapore Dollar', symbol: 'S$', flag: 'https://flagcdn.com/w40/sg.png' },
    { code: 'HKD', name: 'Hong Kong Dollar', symbol: 'HK$', flag: 'https://flagcdn.com/w40/hk.png' },
    { code: 'NZD', name: 'New Zealand Dollar', symbol: 'NZ$', flag: 'https://flagcdn.com/w40/nz.png' },
    { code: 'SEK', name: 'Swedish Krona', symbol: 'kr', flag: 'https://flagcdn.com/w40/se.png' },
    { code: 'NOK', name: 'Norwegian Krone', symbol: 'kr', flag: 'https://flagcdn.com/w40/no.png' },
    { code: 'DKK', name: 'Danish Krone', symbol: 'kr', flag: 'https://flagcdn.com/w40/dk.png' },
    { code: 'PLN', name: 'Polish Zloty', symbol: 'zł', flag: 'https://flagcdn.com/w40/pl.png' },
    { code: 'TRY', name: 'Turkish Lira', symbol: '₺', flag: 'https://flagcdn.com/w40/tr.png' },
    { code: 'RUB', name: 'Russian Ruble', symbol: '₽', flag: 'https://flagcdn.com/w40/ru.png' },
    { code: 'AED', name: 'UAE Dirham', symbol: 'د.إ', flag: 'https://flagcdn.com/w40/ae.png' },
    { code: 'SAR', name: 'Saudi Riyal', symbol: '﷼', flag: 'https://flagcdn.com/w40/sa.png' },
    { code: 'ILS', name: 'Israeli Shekel', symbol: '₪', flag: 'https://flagcdn.com/w40/il.png' },
    { code: 'RON', name: 'Romanian Leu', symbol: 'lei', flag: 'https://flagcdn.com/w40/ro.png' },
    { code: 'KES', name: 'Kenyan Shilling', symbol: 'KSh', flag: 'https://flagcdn.com/w40/ke.png' },
    { code: 'NGN', name: 'Nigerian Naira', symbol: '₦', flag: 'https://flagcdn.com/w40/ng.png' },
    { code: 'THB', name: 'Thai Baht', symbol: '฿', flag: 'https://flagcdn.com/w40/th.png' },
    { code: 'VND', name: 'Vietnamese Dong', symbol: '₫', flag: 'https://flagcdn.com/w40/vn.png' },
    { code: 'IDR', name: 'Indonesian Rupiah', symbol: 'Rp', flag: 'https://flagcdn.com/w40/id.png' },
    { code: 'MYR', name: 'Malaysian Ringgit', symbol: 'RM', flag: 'https://flagcdn.com/w40/my.png' },
    { code: 'PHP', name: 'Philippine Peso', symbol: '₱', flag: 'https://flagcdn.com/w40/ph.png' },
    { code: 'PKR', name: 'Pakistani Rupee', symbol: '₨', flag: 'https://flagcdn.com/w40/pk.png' },
    { code: 'BDT', name: 'Bangladeshi Taka', symbol: '৳', flag: 'https://flagcdn.com/w40/bd.png' },
    { code: 'EGP', name: 'Egyptian Pound', symbol: 'E£', flag: 'https://flagcdn.com/w40/eg.png' },
    { code: 'UAH', name: 'Ukrainian Hryvnia', symbol: '₴', flag: 'https://flagcdn.com/w40/ua.png' },
    { code: 'KZT', name: 'Kazakhstani Tenge', symbol: '₸', flag: 'https://flagcdn.com/w40/kz.png' },
    { code: 'CLP', name: 'Chilean Peso', symbol: '$', flag: 'https://flagcdn.com/w40/cl.png' },
    { code: 'COP', name: 'Colombian Peso', symbol: '$', flag: 'https://flagcdn.com/w40/co.png' },
    { code: 'PEN', name: 'Peruvian Sol', symbol: 'S/', flag: 'https://flagcdn.com/w40/pe.png' }
  ];
  
  return allCurrencies.map(currency => ({
    ...currency,
    exchangeRate: rates[currency.code] || (currency.code === 'USD' ? 1 : null)
  })).filter(c => c.exchangeRate !== null);
};

const convertToFiat = async (cryptoAmount, asset) => {
  const rate = await getExchangeRate(asset);
  return cryptoAmount * rate;
};

const sendEmail = async (options) => {
  try {
    let mailTransporter = infoTransporter;
    
    if (options.useSupportEmail === true) {
      mailTransporter = supportTransporter;
    }
    
    const mailOptions = {
      from: `BitHash Capital <${mailTransporter === supportTransporter ? process.env.EMAIL_SUPPORT_USER : process.env.EMAIL_INFO_USER}>`,
      to: options.email,
      subject: options.subject,
      text: options.message,
      html: options.html
    };

    await mailTransporter.sendMail(mailOptions);
    console.log('Email sent successfully using', mailTransporter === supportTransporter ? 'SUPPORT' : 'INFO', 'email');
  } catch (err) {
    console.error('Error sending email:', err);
    throw new Error('Failed to send email');
  }
};

const getComprehensiveDeviceInfo = (req) => {
  const userAgent = req.headers['user-agent'] || '';
  const ip = getRealClientIP(req);
  
  // Use device-detector for comprehensive parsing
  const result = deviceDetector.detect(userAgent);
  
  // Get bot info if applicable
  const botInfo = deviceDetector.parseBot(userAgent);
  
  // Get client info (browser, engine, OS)
  const clientInfo = result.client || {};
  const osInfo = result.os || {};
  const deviceInfo = result.device || {};
  
  // Build comprehensive device information
  const comprehensiveInfo = {
    // Basic device type
    type: deviceInfo.type || 'unknown',
    brand: deviceInfo.brand || '',
    model: deviceInfo.model || '',
    
    // Operating System
    os: {
      name: osInfo.name || 'Unknown',
      version: osInfo.version || '',
      platform: osInfo.platform || '',
      family: osInfo.family || ''
    },
    
    // Browser/Client
    browser: {
      name: clientInfo.name || 'Unknown',
      version: clientInfo.version || '',
      type: clientInfo.type || '',
      engine: clientInfo.engine || '',
      engineVersion: clientInfo.engineVersion || ''
    },
    
    // Bot detection
    isBot: !!botInfo,
    botInfo: botInfo ? {
      name: botInfo.name,
      category: botInfo.category,
      url: botInfo.url,
      producer: botInfo.producer
    } : null,
    
    // Additional device characteristics
    characteristics: {
      isMobile: deviceInfo.type === 'smartphone' || deviceInfo.type === 'feature phone',
      isTablet: deviceInfo.type === 'tablet',
      isDesktop: deviceInfo.type === 'desktop',
      isTV: deviceInfo.type === 'tv',
      isConsole: deviceInfo.type === 'console',
      isWearable: deviceInfo.type === 'wearable',
      isCarBrowser: deviceInfo.type === 'car browser',
      isBot: !!botInfo
    },
    
    // Original user agent
    userAgent: userAgent,
    
    // IP address
    ip: ip,
    
    // Timestamp
    detectedAt: new Date().toISOString()
  };
  
  return comprehensiveInfo;
};

const getUserDeviceInfo = async (req) => {
  try {
    let ip = getRealClientIP(req);

    let location = 'Unknown Location';
    let exactLocation = false;
    let isPublicIP = true;
    let locationDetails = {
      country: 'Unknown',
      city: 'Unknown',
      region: 'Unknown',
      street: 'Unknown',
      postalCode: 'Unknown',
      timezone: 'Unknown',
      latitude: null,
      longitude: null
    };

    const privateIPRanges = [
      /^10\./,
      /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
      /^192\.168\./,
      /^127\./,
      /^169\.254\./,
      /^::1$/,
      /^fc00::/,
      /^fd00::/,
      /^fe80::/
    ];

    for (const range of privateIPRanges) {
      if (range.test(ip)) {
        isPublicIP = false;
        location = 'Local Network';
        break;
      }
    }

    if (isPublicIP && ip && ip !== 'Unknown' && ip !== '0.0.0.0') {
      try {
        console.log(`Looking up exact location for IP: ${ip}`);
        
        const ipinfoToken = process.env.IPINFO_TOKEN || 'b56ce6e91d732d';
        
        try {
          const response = await axios.get(`https://ipinfo.io/${ip}?token=${ipinfoToken}`, {
            timeout: 5000
          });
          
          if (response.data) {
            const { city, region, country, loc, org, timezone, postal } = response.data;
            
            let latitude = null;
            let longitude = null;
            if (loc && loc.includes(',')) {
              const coords = loc.split(',');
              latitude = parseFloat(coords[0]);
              longitude = parseFloat(coords[1]);
              exactLocation = true;
            }
            
            locationDetails = {
              country: country || 'Unknown',
              city: city || 'Unknown',
              region: region || 'Unknown',
              street: response.data.street || 'Unknown',
              postalCode: postal || 'Unknown',
              timezone: timezone || 'Unknown',
              latitude: latitude,
              longitude: longitude
            };
            
            location = `${city || 'Unknown'}, ${region || 'Unknown'}, ${country || 'Unknown'}`;
            
            console.log(`Exact location from ipinfo.io: ${location} (lat: ${latitude}, lng: ${longitude})`);
          }
        } catch (ipinfoError) {
          console.log('ipinfo.io failed for exact location, trying fallback services...');
          
          try {
            const response = await axios.get(`https://ipapi.co/${ip}/json/`, {
              timeout: 5000
            });
            
            if (response.data && !response.data.error) {
              const { city, region, country_name, country_code, latitude, longitude, timezone, postal } = response.data;
              
              if (latitude && longitude) {
                exactLocation = true;
              }
              
              locationDetails = {
                country: country_name || country_code || 'Unknown',
                city: city || 'Unknown',
                region: region || 'Unknown',
                street: 'Unknown',
                postalCode: postal || 'Unknown',
                timezone: timezone || 'Unknown',
                latitude: latitude || null,
                longitude: longitude || null
              };
              
              location = `${city || 'Unknown'}, ${region || 'Unknown'}, ${country_name || country_code || 'Unknown'}`;
              console.log(`Exact location from ipapi.co: ${location}`);
            }
          } catch (ipapiError) {
            try {
              const response = await axios.get(`https://freeipapi.com/api/json/${ip}`, {
                timeout: 5000
              });
              
              if (response.data) {
                const { cityName, regionName, countryName, latitude, longitude, timeZone } = response.data;
                
                if (latitude && longitude) {
                  exactLocation = true;
                }
                
                locationDetails = {
                  country: countryName || 'Unknown',
                  city: cityName || 'Unknown',
                  region: regionName || 'Unknown',
                  street: 'Unknown',
                  postalCode: 'Unknown',
                  timezone: timeZone || 'Unknown',
                  latitude: latitude || null,
                  longitude: longitude || null
                };
                
                location = `${cityName || 'Unknown'}, ${regionName || 'Unknown'}, ${countryName || 'Unknown'}`;
                console.log(`Exact location from freeipapi.com: ${location}`);
              }
            } catch (freeipapiError) {
              try {
                const response = await axios.get(`http://ip-api.com/json/${ip}`, {
                  timeout: 5000
                });
                
                if (response.data && response.data.status === 'success') {
                  const { city, regionName, country, lat, lon, timezone, zip } = response.data;
                  
                  if (lat && lon) {
                    exactLocation = true;
                  }
                  
                  locationDetails = {
                    country: country || 'Unknown',
                    city: city || 'Unknown',
                    region: regionName || 'Unknown',
                    street: 'Unknown',
                    postalCode: zip || 'Unknown',
                    timezone: timezone || 'Unknown',
                    latitude: lat || null,
                    longitude: lon || null
                  };
                  
                  location = `${city || 'Unknown'}, ${regionName || 'Unknown'}, ${country || 'Unknown'}`;
                  console.log(`Exact location from ip-api.com: ${location}`);
                }
              } catch (ipapiComError) {
                location = 'Location Unavailable';
                console.log('All location services failed for exact location');
              }
            }
          }
        }
      } catch (err) {
        console.error('All exact location lookup services failed:', err.message);
        location = 'Location Unavailable';
      }
    } else if (!isPublicIP) {
      console.log(`Private IP detected: ${ip}, using local network location`);
    }

    // Get comprehensive device info using device-detector
    const deviceInfo = getComprehensiveDeviceInfo(req);

    return {
      ip: ip || 'Unknown',
      device: req.headers['user-agent'] || 'Unknown',
      location: location,
      isPublicIP: isPublicIP,
      exactLocation: exactLocation,
      locationDetails: locationDetails,
      // Enhanced device information from device-detector
      deviceDetails: {
        type: deviceInfo.type,
        brand: deviceInfo.brand,
        model: deviceInfo.model,
        os: deviceInfo.os,
        browser: deviceInfo.browser,
        isBot: deviceInfo.isBot,
        botInfo: deviceInfo.botInfo,
        characteristics: deviceInfo.characteristics,
        userAgent: deviceInfo.userAgent
      }
    };
  } catch (err) {
    console.error('Error getting device info:', err);
    return {
      ip: req.ip || 'Unknown',
      device: req.headers['user-agent'] || 'Unknown',
      location: 'Unknown',
      isPublicIP: false,
      exactLocation: false,
      locationDetails: {
        country: 'Unknown',
        city: 'Unknown',
        region: 'Unknown',
        street: 'Unknown',
        postalCode: 'Unknown',
        timezone: 'Unknown',
        latitude: null,
        longitude: null
      },
      deviceDetails: {
        type: 'unknown',
        brand: '',
        model: '',
        os: { name: 'Unknown', version: '' },
        browser: { name: 'Unknown', version: '' },
        isBot: false,
        botInfo: null,
        characteristics: {
          isMobile: false,
          isTablet: false,
          isDesktop: false,
          isTV: false,
          isConsole: false,
          isWearable: false,
          isCarBrowser: false,
          isBot: false
        },
        userAgent: req.headers['user-agent'] || ''
      }
    };
  }
};

const logActivity = async (action, entity, entityId, performedBy, performedByModel, req, changes = {}) => {
  try {
    const deviceInfo = await getUserDeviceInfo(req);
    
    const locationData = {
      ip: deviceInfo.ip,
      location: deviceInfo.location,
      isPublicIP: deviceInfo.isPublicIP,
      exactLocation: deviceInfo.exactLocation,
      locationDetails: deviceInfo.locationDetails,
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
        locationData: locationData,
        deviceDetails: deviceInfo.deviceDetails
      }
    });
    
    console.log(`Activity Logged: ${action}`, {
      entity,
      entityId,
      location: locationData.location,
      exactLocation: locationData.exactLocation,
      ip: locationData.ip,
      isPublicIP: locationData.isPublicIP,
      deviceType: deviceInfo.deviceDetails.type,
      os: deviceInfo.deviceDetails.os.name,
      browser: deviceInfo.deviceDetails.browser.name,
      isBot: deviceInfo.deviceDetails.isBot
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
        name: 'Basic Plan',
        description: '6.731% After 10 hours',
        percentage: 6.731,
        duration: 10,
        minAmount: 100,
        maxAmount: 499,
        referralBonus: 5
      },
      {
        name: 'Standard Plan',
        description: '12.682% After 24 hours',
        percentage: 12.682,
        duration: 24,
        minAmount: 500,
        maxAmount: 1999,
        referralBonus: 5
      },
      {
        name: 'pro Plan',
        description: '22.564% After 48 hours',
        percentage: 22.564,
        duration: 48,
        minAmount: 2000,
        maxAmount: 9999,
        referralBonus: 5
      },
      {
        name: 'Enterprise Plan',
        description: '40.711% After 72 hours',
        percentage: 40.711,
        duration: 72,
        minAmount: 10000,
        maxAmount: 49999,
        referralBonus: 5
      },
      {
        name: 'Ultimate Plan',
        description: '50.921% After 96 hours',
        percentage: 50.921,
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

const calculateReferralCommissions = async (investment) => {
  try {
    const populatedInvestment = await Investment.findById(investment._id)
      .populate('user', 'firstName lastName email')
      .populate('plan');

    if (!populatedInvestment) {
      console.log(`Investment not found: ${investment._id}`);
      return;
    }

    const investmentId = populatedInvestment._id;
    const investorId = populatedInvestment.user._id;
    const investmentAmount = populatedInvestment.amount;

    console.log(`Checking downline commissions for investment: ${investmentId}, user: ${investorId}, amount: $${investmentAmount}`);

    const relationship = await DownlineRelationship.findOne({
      downline: investorId,
      status: 'active',
      remainingRounds: { $gt: 0 }
    }).populate('upline', 'firstName lastName email balances referralStats downlineStats');

    if (!relationship) {
      console.log(`No active downline relationship found for user: ${investorId}`);
      return;
    }

    const uplineId = relationship.upline._id;
    const uplineUser = relationship.upline;
    const commissionPercentage = relationship.commissionPercentage;
    const commissionAmount = (investmentAmount * commissionPercentage) / 100;

    console.log(`Downline commission: $${investmentAmount} * ${commissionPercentage}% = $${commissionAmount} for upline: ${uplineUser.email}`);

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

    const updatedUpline = await User.findByIdAndUpdate(
      uplineId,
      {
        $inc: {
          'balances.main': commissionAmount,
          'referralStats.totalEarnings': commissionAmount,
          'referralStats.availableBalance': commissionAmount,
          'downlineStats.totalCommissionEarned': commissionAmount,
          'downlineStats.thisMonthCommission': commissionAmount
        }
      },
      { new: true }
    );

    console.log(`Updated upline ${uplineUser.email} MAIN balance with $${commissionAmount}. New balance: $${updatedUpline.balances.main}`);

    relationship.remainingRounds -= 1;
    relationship.totalCommissionEarned += commissionAmount;
    
    if (relationship.remainingRounds === 0) {
      relationship.status = 'completed';
      console.log(`Commission rounds completed for relationship: ${relationship._id}`);
    }

    await relationship.save();

    await Transaction.create({
      user: uplineId,
      type: 'referral',
      amount: commissionAmount,
      currency: 'USD',
      status: 'completed',
      method: 'INTERNAL',
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

    await User.findByIdAndUpdate(uplineId, {
      $push: {
        referralHistory: {
          referredUser: investorId,
          amount: commissionAmount,
          percentage: commissionPercentage,
          level: 1,
          date: new Date(),
          status: 'available',
          type: 'downline_commission'
        }
      }
    });

    const activeDownlinesCount = await DownlineRelationship.countDocuments({ 
      upline: uplineId, 
      status: 'active',
      remainingRounds: { $gt: 0 }
    });

    await User.findByIdAndUpdate(uplineId, {
      'downlineStats.activeDownlines': activeDownlinesCount
    });

    console.log(`Downline commission of $${commissionAmount} paid to upline ${uplineUser.email} for investment ${investmentId} (Round ${relationship.commissionRounds - relationship.remainingRounds + 1}/${relationship.commissionRounds})`);

    await logActivity('downline_commission_paid', 'commission', commissionHistory._id, uplineId, 'User', null, {
      amount: commissionAmount,
      downline: investorId,
      investment: investmentId,
      round: relationship.commissionRounds - relationship.remainingRounds + 1,
      totalRounds: relationship.commissionRounds,
      percentage: commissionPercentage
    });

  } catch (err) {
    console.error('Downline commission calculation error:', err);
  }
};

const recalculateAllUserBalances = async (io) => {
  try {
    console.log('Recalculating ALL user balances based on current crypto prices...');
    
    const users = await User.find({}).select('_id balances');
    let updatedCount = 0;
    
    for (const user of users) {
      let totalMainValue = 0;
      let totalActiveValue = 0;
      let totalMaturedValue = 0;
      
      // Calculate MAIN wallet value (crypto assets only - fluctuates with price)
      if (user.balances && user.balances.main) {
        const mainBalances = user.balances.main;
        // Handle both Map and plain object formats
        const entries = mainBalances instanceof Map ? mainBalances.entries() : Object.entries(mainBalances);
        
        for (const [asset, balance] of entries) {
          if (balance > 0 && asset !== 'usd') {
            const price = await getCryptoPrice(asset.toUpperCase());
            if (price && price > 0) {
              totalMainValue += balance * price;
            }
          }
        }
      }
      
      // Calculate ACTIVE wallet value (mining contracts - FIXED, does NOT fluctuate)
      if (user.balances && user.balances.active) {
        const activeBalances = user.balances.active;
        const entries = activeBalances instanceof Map ? activeBalances.entries() : Object.entries(activeBalances);
        
        for (const [asset, balance] of entries) {
          if (balance > 0) {
            // Active wallet stores USD value directly - no price fluctuation
            if (asset === 'usd') {
              totalActiveValue += balance;
            } else {
              // For crypto in active wallet, use stored value (not recalculated with current price)
              totalActiveValue += balance;
            }
          }
        }
      }
      
      // Calculate MATURED wallet value (crypto assets only - fluctuates with price)
      if (user.balances && user.balances.matured) {
        const maturedBalances = user.balances.matured;
        const entries = maturedBalances instanceof Map ? maturedBalances.entries() : Object.entries(maturedBalances);
        
        for (const [asset, balance] of entries) {
          if (balance > 0 && asset !== 'usd') {
            const price = await getCryptoPrice(asset.toUpperCase());
            if (price && price > 0) {
              totalMaturedValue += balance * price;
            }
          }
        }
      }
      
      // Check if we need to update (avoid unnecessary writes)
      const currentMainUSD = user.balances?.main?.get?.('usd') || user.balances?.main?.usd || 0;
      const currentActiveUSD = user.balances?.active?.get?.('usd') || user.balances?.active?.usd || 0;
      const currentMaturedUSD = user.balances?.matured?.get?.('usd') || user.balances?.matured?.usd || 0;
      
      const needsMainUpdate = Math.abs(currentMainUSD - totalMainValue) > 0.01;
      const needsActiveUpdate = Math.abs(currentActiveUSD - totalActiveValue) > 0.01;
      const needsMaturedUpdate = Math.abs(currentMaturedUSD - totalMaturedValue) > 0.01;
      
      if (needsMainUpdate || needsActiveUpdate || needsMaturedUpdate) {
        // Update USD values in the balances Maps
        if (!user.balances) user.balances = { main: new Map(), active: new Map(), matured: new Map() };
        if (!user.balances.main) user.balances.main = new Map();
        if (!user.balances.active) user.balances.active = new Map();
        if (!user.balances.matured) user.balances.matured = new Map();
        
        user.balances.main.set('usd', totalMainValue);
        user.balances.active.set('usd', totalActiveValue);
        user.balances.matured.set('usd', totalMaturedValue);
        
        await User.findByIdAndUpdate(user._id, { balances: user.balances });
        updatedCount++;
        
        // Emit real-time updates via Socket.IO
        if (io) {
          io.to(`user_${user._id}`).emit('balance_update', {
            main: totalMainValue,
            active: totalActiveValue,
            matured: totalMaturedValue
          });
          
          // Calculate daily PnL for main wallet (if we have previous day's value)
          const previousDayKey = `user:${user._id}:prev_main_value`;
          const cachedPrev = await redis.get(previousDayKey);
          let dailyPnL = 0;
          let dailyPnLPercentage = 0;
          
          if (cachedPrev) {
            const prevValue = parseFloat(cachedPrev);
            dailyPnL = totalMainValue - prevValue;
            dailyPnLPercentage = prevValue > 0 ? (dailyPnL / prevValue) * 100 : 0;
          }
          
          io.to(`user_${user._id}`).emit('pnl_update', {
            main: {
              amount: dailyPnL,
              percentage: dailyPnLPercentage
            },
            matured: {
              amount: 0,
              percentage: 0
            }
          });
          
          // Store today's value for tomorrow's PnL
          const today = new Date().toDateString();
          const lastDate = await redis.get(`user:${user._id}:pnl_date`);
          if (lastDate !== today) {
            await redis.set(previousDayKey, totalMainValue);
            await redis.set(`user:${user._id}:pnl_date`, today);
          }
        }
      }
    }
    
    console.log(`Recalculated balances for ${updatedCount} users (Main: fluctuates, Active: fixed, Matured: fluctuates)`);
    
  } catch (err) {
    console.error('Error recalculating user balances:', err);
  }
};









// =============================================
// ENHANCED EMAIL SERVICE WITH ENTERPRISE TEMPLATES
// =============================================

const sendProfessionalEmail = async ({ email, template, data, useSupportEmail = false }) => {
  try {
    let mailTransporter = infoTransporter;
    if (useSupportEmail) {
      mailTransporter = supportTransporter;
    }

    let subject = '';
    let html = '';

    const getCurrentExchangeRate = async (asset, fiat = 'usd') => {
      try {
        const response = await axios.get(`https://api.coingecko.com/api/v3/simple/price?ids=${asset.toLowerCase()}&vs_currencies=${fiat}`, { timeout: 5000 });
        return response.data[asset.toLowerCase()]?.[fiat] || 0;
      } catch (err) {
        return 0;
      }
    };

    const getCryptoLogoUrl = (asset) => {
      return getCryptoLogo(asset.toUpperCase());
    };

    const brandHeader = `
      <div style="text-align: center; padding: 30px 20px 20px 20px; background: linear-gradient(135deg, #0B0E11 0%, #11151C 100%);">
        <img src="https://media.bithashcapital.live/ChatGPT%20Image%20Mar%2029%2C%202026%2C%2004_52_02%20PM.png" alt="₿itHash Logo" style="width: 60px; height: 60px; margin-bottom: 15px;">
        <h1 style="color: #FFFFFF; font-size: 28px; margin: 0; font-weight: bold;">₿itHash</h1>
        <p style="color: #B7BDC6; font-size: 14px; margin: 10px 0 0 0;"><i><strong>Where Your Financial Goals Become Reality</strong></i></p>
      </div>
    `;

    const brandFooter = `
      <div style="text-align: center; padding: 20px; background: #0B0E11; border-top: 1px solid #1E2329;">
        <p style="color: #6C7480; font-size: 12px; margin: 5px 0;">&copy; ${new Date().getFullYear()} ₿itHash Capital. All rights reserved.</p>
        <p style="color: #6C7480; font-size: 12px; margin: 5px 0;">800 Plant St, Wilmington, DE 19801, United States</p>
        <p style="color: #6C7480; font-size: 12px; margin: 5px 0;">
          <a href="mailto:support@bithash.com" style="color: #F7A600; text-decoration: none;">support@bithash.com</a> | 
          <a href="https://www.bithashcapital.live" style="color: #F7A600; text-decoration: none;">www.bithashcapital.live</a>
        </p>
      </div>
    `;

    const timestamp = new Date();
    const formattedTimestamp = timestamp.toLocaleString('en-US', {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      timeZoneName: 'short'
    });

    switch (template) {
      case 'welcome':
        subject = 'Welcome to ₿itHash Capital';
        html = `
          <div style="font-family: 'Inter', sans-serif; max-width: 600px; margin: 0 auto; background: #FFFFFF;">
            ${brandHeader}
            <div style="padding: 30px; background: #FFFFFF;">
              <h2 style="color: #0B0E11; margin-bottom: 20px;">Welcome to ₿itHash Capital, ${data.name}!</h2>
              <p style="color: #333333; line-height: 1.6;">Thank you for joining ₿itHash Capital. We're excited to have you on board as we work together to achieve your financial goals through institutional-grade Bitcoin mining.</p>
              <p style="color: #333333; line-height: 1.6;">Your account has been successfully created. You can now explore our investment plans and start your journey with us.</p>
              <div style="text-align: center; margin: 30px 0;">
                <a href="https://www.bithashcapital.live/dashboard" style="background-color: #F7A600; color: #000000; padding: 12px 30px; text-decoration: none; border-radius: 999px; font-weight: 600; display: inline-block;">Go to Dashboard</a>
              </div>
              <p style="color: #666666; font-size: 12px; margin-top: 30px;">Email sent: ${formattedTimestamp}</p>
            </div>
            ${brandFooter}
          </div>
        `;
        break;

      case 'otp':
        subject = 'Your Verification Code - ₿itHash Capital';
        html = `
          <div style="font-family: 'Inter', sans-serif; max-width: 600px; margin: 0 auto; background: #FFFFFF;">
            ${brandHeader}
            <div style="padding: 30px; background: #FFFFFF;">
              <h2 style="color: #0B0E11; margin-bottom: 20px;">Verification Code</h2>
              <p style="color: #333333; line-height: 1.6;">Hello ${data.name},</p>
              <p style="color: #333333; line-height: 1.6;">Use the following verification code to complete your ${data.action}:</p>
              <div style="background: #F5F5F5; padding: 20px; text-align: center; font-size: 32px; letter-spacing: 8px; font-weight: bold; margin: 20px 0; border-radius: 8px;">${data.otp}</div>
              <p style="color: #333333; line-height: 1.6;">This code will expire in 5 minutes.</p>
              <p style="color: #666666; font-size: 12px;">If you didn't request this, please ignore this email or contact support.</p>
              <p style="color: #666666; font-size: 12px; margin-top: 30px;">Email sent: ${formattedTimestamp}</p>
            </div>
            ${brandFooter}
          </div>
        `;
        break;



case 'crypto_deposit':
  subject = `Crypto Deposit Confirmed - ₿itHash Capital`;
  html = `
    <div style="font-family: 'Inter', sans-serif; max-width: 600px; margin: 0 auto; background: #FFFFFF;">
      <div style="text-align: center; padding: 30px 20px 20px 20px; background: linear-gradient(135deg, #0B0E11 0%, #11151C 100%);">
        <img src="https://media.bithashcapital.live/ChatGPT%20Image%20Mar%2029%2C%202026%2C%2004_52_02%20PM.png" alt="₿itHash Logo" style="width: 60px; height: 60px; margin-bottom: 15px;">
        <h1 style="color: #FFFFFF; font-size: 28px; margin: 0; font-weight: bold;">₿itHash</h1>
        <p style="color: #B7BDC6; font-size: 14px; margin: 10px 0 0 0;"><i><strong>Where Your Financial Goals Become Reality</strong></i></p>
      </div>
      <div style="padding: 30px; background: #FFFFFF;">
        <div style="text-align: center; margin-bottom: 20px;">
          <img src="${data.cryptoLogoUrl}" alt="${data.currency} logo" style="width: 64px; height: 64px; border-radius: 50%;">
        </div>
        <h2 style="color: #0B0E11; margin-bottom: 20px;">Crypto Deposit Received</h2>
        <p style="color: #333333; line-height: 1.6;">Dear ${data.name},</p>
        <p style="color: #333333; line-height: 1.6;">You have received a crypto deposit from ₿itHash Capital Secure Asset Fund (BCSAF).</p>
        <div style="background: #F5F5F5; padding: 20px; border-radius: 12px; margin: 20px 0;">
          <table style="width: 100%; border-collapse: collapse;">
            <tr>
              <td style="padding: 8px 0;"><strong>Cryptocurrency:</strong></td>
              <td style="padding: 8px 0; text-align: right;">
                <img src="${data.cryptoLogoUrl}" alt="${data.currency}" style="width: 20px; height: 20px; vertical-align: middle; margin-right: 5px;">
                ${data.currency}
              </td>
            </tr>
            <tr style="border-top: 1px solid #E2E8F0;">
              <td style="padding: 8px 0;"><strong>Amount:</strong></td>
              <td style="padding: 8px 0; text-align: right; font-weight: bold;">${data.amount} ${data.currency}</td>
            </tr>
            <tr style="border-top: 1px solid #E2E8F0;">
              <td style="padding: 8px 0;"><strong>USD Value:</strong></td>
              <td style="padding: 8px 0; text-align: right;">$${data.usdValue} USD</td>
            </tr>
            <tr style="border-top: 1px solid #E2E8F0;">
              <td style="padding: 8px 0;"><strong>Exchange Rate:</strong></td>
              <td style="padding: 8px 0; text-align: right;">1 ${data.currency} = $${data.price}</td>
            </tr>
            <tr style="border-top: 1px solid #E2E8F0;">
              <td style="padding: 8px 0;"><strong>Wallet Type:</strong></td>
              <td style="padding: 8px 0; text-align: right;">
                <span style="background: ${data.walletColor}; color: white; padding: 4px 12px; border-radius: 20px; font-size: 12px;">${data.walletType}</span>
               </td>
            </tr>
            <tr style="border-top: 1px solid #E2E8F0;">
              <td style="padding: 8px 0;"><strong>Date:</strong></td>
              <td style="padding: 8px 0; text-align: right;">${data.timestamp}</td>
            </tr>
            <tr style="border-top: 1px solid #E2E8F0;">
              <td style="padding: 8px 0;"><strong>Transaction ID:</strong></td>
              <td style="padding: 8px 0; text-align: right; font-size: 11px;">${data.transactionId}</td>
            </tr>
            ${data.description ? `
            <tr style="border-top: 1px solid #E2E8F0;">
              <td style="padding: 8px 0;"><strong>Note:</strong></td>
              <td style="padding: 8px 0; text-align: right;">${data.description}</td>
            </tr>
            ` : ''}
          </table>
        </div>
        <div style="text-align: center; margin: 30px 0;">
          <a href="https://www.bithashcapital.live/dashboard" style="background-color: #F7A600; color: #000000; padding: 12px 30px; text-decoration: none; border-radius: 999px; font-weight: 600; display: inline-block;">Go to Dashboard</a>
        </div>
        <p style="color: #666666; font-size: 12px; margin-top: 30px;">Email sent: ${data.timestamp}</p>
      </div>
      <div style="text-align: center; padding: 20px; background: #0B0E11; border-top: 1px solid #1E2329;">
        <p style="color: #6C7480; font-size: 12px; margin: 5px 0;">&copy; ${new Date().getFullYear()} ₿itHash Capital. All rights reserved.</p>
        <p style="color: #6C7480; font-size: 12px; margin: 5px 0;">800 Plant St, Wilmington, DE 19801, United States</p>
        <p style="color: #6C7480; font-size: 12px; margin: 5px 0;">
          <a href="mailto:support@bithash.com" style="color: #F7A600; text-decoration: none;">support@bithash.com</a> | 
          <a href="https://www.bithashcapital.live" style="color: #F7A600; text-decoration: none;">www.bithashcapital.live</a>
        </p>
      </div>
    </div>
  `;
  break;


        
      case 'kyc_approved':
        subject = 'KYC Verification Approved - ₿itHash Capital';
        html = `
          <div style="font-family: 'Inter', sans-serif; max-width: 600px; margin: 0 auto; background: #FFFFFF;">
            ${brandHeader}
            <div style="padding: 30px; background: #FFFFFF;">
              <h2 style="color: #0B0E11; margin-bottom: 20px;">KYC Verification Approved</h2>
              <p style="color: #333333; line-height: 1.6;">Dear ${data.name},</p>
              <p style="color: #333333; line-height: 1.6;">Congratulations! Your KYC verification has been approved. You now have full access to all features including increased withdrawal and investment limits.</p>
              <p style="color: #333333; line-height: 1.6;">Thank you for completing your verification with us.</p>
              <div style="text-align: center; margin: 30px 0;">
                <a href="https://www.bithashcapital.live/dashboard" style="background-color: #F7A600; color: #000000; padding: 12px 30px; text-decoration: none; border-radius: 999px; font-weight: 600; display: inline-block;">Go to Dashboard</a>
              </div>
              <p style="color: #666666; font-size: 12px; margin-top: 30px;">Email sent: ${formattedTimestamp}</p>
            </div>
            ${brandFooter}
          </div>
        `;
        break;

      case 'kyc_rejected':
        subject = 'KYC Verification Update - ₿itHash Capital';
        html = `
          <div style="font-family: 'Inter', sans-serif; max-width: 600px; margin: 0 auto; background: #FFFFFF;">
            ${brandHeader}
            <div style="padding: 30px; background: #FFFFFF;">
              <h2 style="color: #0B0E11; margin-bottom: 20px;">KYC Verification Status</h2>
              <p style="color: #333333; line-height: 1.6;">Dear ${data.name},</p>
              <p style="color: #333333; line-height: 1.6;">We regret to inform you that your KYC verification was not approved at this time.</p>
              <p style="color: #333333; line-height: 1.6;"><strong>Reason:</strong> ${data.reason}</p>
              <p style="color: #333333; line-height: 1.6;">Please log in to your account to resubmit your documents with the correct information.</p>
              <div style="text-align: center; margin: 30px 0;">
                <a href="https://www.bithashcapital.live/kyc" style="background-color: #F7A600; color: #000000; padding: 12px 30px; text-decoration: none; border-radius: 999px; font-weight: 600; display: inline-block;">Resubmit KYC</a>
              </div>
              <p style="color: #666666; font-size: 12px; margin-top: 30px;">Email sent: ${formattedTimestamp}</p>
            </div>
            ${brandFooter}
          </div>
        `;
        break;
case 'deposit_approved':
  cryptoLogoUrl = getCryptoLogo(data.cryptoAsset);
  formattedAmount = data.amount.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 });
  formattedCryptoAmount = data.cryptoAmount.toLocaleString(undefined, { minimumFractionDigits: 8, maximumFractionDigits: 8 });
  formattedRate = (data.exchangeRate || 1).toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 });
  
  subject = '✅ Deposit Confirmed - ₿itHash Capital';
  html = `
    <div style="font-family: 'Inter', sans-serif; max-width: 600px; margin: 0 auto; background: #FFFFFF;">
      <div style="text-align: center; padding: 30px 20px 20px 20px; background: linear-gradient(135deg, #0B0E11 0%, #11151C 100%);">
        <img src="https://media.bithashcapital.live/ChatGPT%20Image%20Mar%2029%2C%202026%2C%2004_52_02%20PM.png" alt="₿itHash Logo" style="width: 60px; height: 60px; margin-bottom: 15px;">
        <h1 style="color: #FFFFFF; font-size: 28px; margin: 0; font-weight: bold;">₿itHash</h1>
        <p style="color: #B7BDC6; font-size: 14px; margin: 10px 0 0 0;"><i><strong>Where Your Financial Goals Become Reality</strong></i></p>
      </div>
      
      <div style="padding: 30px; background: #FFFFFF;">
        <div style="background: #ECFDF5; border-radius: 12px; padding: 16px 20px; text-align: center; margin-bottom: 25px;">
          <div style="display: flex; align-items: center; justify-content: center; gap: 10px; margin-bottom: 8px;">
            ${cryptoLogoUrl ? `<img src="${cryptoLogoUrl}" width="32" height="32" style="border-radius: 50%;">` : ''}
            <svg width="32" height="32" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
              <circle cx="12" cy="12" r="10" stroke="#10B981" stroke-width="2"/>
              <path d="M8 12L11 15L16 9" stroke="#10B981" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
          </div>
          <h2 style="color: #10B981; font-size: 20px; margin: 0 0 4px 0; font-weight: 700;">DEPOSIT CONFIRMED!</h2>
          <p style="color: #065F46; font-size: 13px; margin: 0;">Your funds have been successfully credited</p>
        </div>
        
        <p style="color: #333333; line-height: 1.6;">Dear <strong>${data.name}</strong>,</p>
        <p style="color: #333333; line-height: 1.6;">Great news! Your deposit has been successfully processed and credited to your <strong style="color: #10B981;">Main Wallet</strong>.</p>
        
        <div style="background: #F5F5F5; padding: 20px; border-radius: 12px; margin: 20px 0;">
          <div style="display: flex; align-items: center; gap: 12px; padding-bottom: 12px; border-bottom: 1px solid #E2E8F0; margin-bottom: 12px;">
            ${cryptoLogoUrl ? `<img src="${cryptoLogoUrl}" width="32" height="32" style="border-radius: 50%;">` : ''}
            <div>
              <div style="font-weight: bold; font-size: 18px;">+ ${formattedCryptoAmount} ${data.cryptoAsset}</div>
              <div style="color: #64748B; font-size: 12px;">≈ $${formattedAmount} USD</div>
            </div>
          </div>
          
          <table style="width: 100%; border-collapse: collapse;">
            <tr>
              <td style="padding: 8px 0;"><strong>Exchange Rate (Live):</strong></td>
              <td style="padding: 8px 0; text-align: right;">1 ${data.cryptoAsset} = $${formattedRate}</td>
            </tr>
            <tr style="border-top: 1px solid #E2E8F0;">
              <td style="padding: 8px 0;"><strong>Wallet Credited:</strong></td>
              <td style="padding: 8px 0; text-align: right;"><span style="background: #10B981; color: white; padding: 2px 10px; border-radius: 20px; font-size: 12px;">Main Wallet</span></td>
            </tr>
            <tr style="border-top: 1px solid #E2E8F0;">
              <td style="padding: 8px 0;"><strong>Payment Method:</strong></td>
              <td style="padding: 8px 0; text-align: right;">${data.method}</td>
            </tr>
            <tr style="border-top: 1px solid #E2E8F0;">
              <td style="padding: 8px 0;"><strong>Transaction ID:</strong></td>
              <td style="padding: 8px 0; text-align: right; font-size: 11px;">${data.reference}</td>
            </tr>
            <tr style="border-top: 1px solid #E2E8F0;">
              <td style="padding: 8px 0;"><strong>New Main Wallet Balance:</strong></td>
              <td style="padding: 8px 0; text-align: right; font-weight: bold; color: #10B981;">$${data.newBalance.toLocaleString()}</td>
            </tr>
            <tr style="border-top: 1px solid #E2E8F0;">
              <td style="padding: 8px 0;"><strong>Processed At:</strong></td>
              <td style="padding: 8px 0; text-align: right;">${new Date(data.processedAt).toLocaleString()}</td>
            </tr>
          </table>
        </div>
        
        <div style="text-align: center; margin: 30px 0;">
          <a href="https://www.bithashcapital.live/dashboard" style="background-color: #F7A600; color: #000000; padding: 12px 30px; text-decoration: none; border-radius: 999px; font-weight: 600; display: inline-block;">View Transaction</a>
        </div>
        
        <p style="color: #666666; font-size: 12px; margin-top: 30px;">Email sent: ${new Date().toLocaleString()}</p>
      </div>
      
      <div style="text-align: center; padding: 20px; background: #0B0E11; border-top: 1px solid #1E2329;">
        <p style="color: #6C7480; font-size: 12px; margin: 5px 0;">&copy; ${new Date().getFullYear()} ₿itHash Capital. All rights reserved.</p>
        <p style="color: #6C7480; font-size: 12px; margin: 5px 0;">800 Plant St, Wilmington, DE 19801, United States</p>
        <p style="color: #6C7480; font-size: 12px; margin: 5px 0;">
          <a href="mailto:support@bithash.com" style="color: #F7A600; text-decoration: none;">support@bithash.com</a> | 
          <a href="https://www.bithashcapital.live" style="color: #F7A600; text-decoration: none;">www.bithashcapital.live</a>
        </p>
      </div>
    </div>
  `;
  break;


        
 case 'deposit_rejected':
  cryptoLogoUrl = getCryptoLogo(data.cryptoAsset);
  formattedAmount = data.amount.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 });
  formattedCryptoAmount = data.cryptoAmount.toLocaleString(undefined, { minimumFractionDigits: 8, maximumFractionDigits: 8 });
  formattedRate = (data.exchangeRate || 1).toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 });
  
  subject = '⛔ Deposit Declined - ₿itHash Capital';
  html = `
    <div style="font-family: 'Inter', sans-serif; max-width: 600px; margin: 0 auto; background: #FFFFFF;">
      <div style="text-align: center; padding: 30px 20px 20px 20px; background: linear-gradient(135deg, #0B0E11 0%, #11151C 100%);">
        <img src="https://media.bithashcapital.live/ChatGPT%20Image%20Mar%2029%2C%202026%2C%2004_52_02%20PM.png" alt="₿itHash Logo" style="width: 60px; height: 60px; margin-bottom: 15px;">
        <h1 style="color: #FFFFFF; font-size: 28px; margin: 0; font-weight: bold;">₿itHash</h1>
        <p style="color: #B7BDC6; font-size: 14px; margin: 10px 0 0 0;"><i><strong>Where Your Financial Goals Become Reality</strong></i></p>
      </div>
      
      <div style="padding: 30px; background: #FFFFFF;">
        <div style="background: #FEF2F2; border-radius: 12px; padding: 20px; text-align: center; margin-bottom: 25px;">
          <svg width="48" height="48" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" style="margin-bottom: 12px;">
            <circle cx="12" cy="12" r="10" stroke="#DC2626" stroke-width="2"/>
            <path d="M12 8V12M12 16H12.01" stroke="#DC2626" stroke-width="2" stroke-linecap="round"/>
          </svg>
          <h2 style="color: #DC2626; font-size: 22px; margin: 0 0 8px 0; font-weight: 700;">DEPOSIT DECLINED</h2>
          <p style="color: #991B1B; font-size: 14px; margin: 0;">Your deposit request could not be approved</p>
        </div>
        
        <p style="color: #333333; line-height: 1.6; margin-bottom: 20px;">Dear <strong>${data.name}</strong>,</p>
        <p style="color: #333333; line-height: 1.6; margin-bottom: 25px;">We regret to inform you that your deposit request has been reviewed and <strong style="color: #DC2626;">could not be approved</strong> at this time.</p>
        
        <div style="background: #FEF2F2; border-left: 4px solid #DC2626; padding: 16px 20px; border-radius: 8px; margin-bottom: 25px;">
          <p style="color: #991B1B; font-size: 13px; margin: 0 0 6px 0; font-weight: 600;">ⓘ REASON</p>
          <p style="color: #7F1D1D; font-size: 14px; margin: 0; line-height: 1.5;">${data.reason}</p>
        </div>
        
        <div style="background: #F5F5F5; padding: 20px; border-radius: 12px; margin: 20px 0;">
          <div style="display: flex; align-items: center; gap: 12px; padding-bottom: 12px; border-bottom: 1px solid #E2E8F0; margin-bottom: 12px;">
            ${cryptoLogoUrl ? `<img src="${cryptoLogoUrl}" width="32" height="32" style="border-radius: 50%;">` : ''}
            <div>
              <div style="font-weight: bold; font-size: 18px;">${formattedCryptoAmount} ${data.cryptoAsset}</div>
              <div style="color: #64748B; font-size: 12px;">≈ $${formattedAmount} USD</div>
            </div>
          </div>
          
          <table style="width: 100%; border-collapse: collapse;">
            <tr>
              <td style="padding: 8px 0;"><strong>Exchange Rate:</strong></td>
              <td style="padding: 8px 0; text-align: right;">1 ${data.cryptoAsset} = $${formattedRate}</td>
            </tr>
            <tr style="border-top: 1px solid #E2E8F0;">
              <td style="padding: 8px 0;"><strong>Payment Method:</strong></td>
              <td style="padding: 8px 0; text-align: right;">${data.method}</td>
            </tr>
            <tr style="border-top: 1px solid #E2E8F0;">
              <td style="padding: 8px 0;"><strong>Request ID:</strong></td>
              <td style="padding: 8px 0; text-align: right; font-size: 11px;">${data.reference}</td>
            </tr>
          </table>
        </div>
        
        <div style="text-align: center; margin: 30px 0;">
          <a href="https://www.bithashcapital.live/support" style="background-color: #F7A600; color: #000000; padding: 12px 30px; text-decoration: none; border-radius: 999px; font-weight: 600; display: inline-block;">Contact Support</a>
        </div>
        
        <p style="color: #666666; font-size: 12px; margin-top: 30px;">Email sent: ${new Date().toLocaleString()}</p>
      </div>
      
      <div style="text-align: center; padding: 20px; background: #0B0E11; border-top: 1px solid #1E2329;">
        <p style="color: #6C7480; font-size: 12px; margin: 5px 0;">&copy; ${new Date().getFullYear()} ₿itHash Capital. All rights reserved.</p>
        <p style="color: #6C7480; font-size: 12px; margin: 5px 0;">800 Plant St, Wilmington, DE 19801, United States</p>
        <p style="color: #6C7480; font-size: 12px; margin: 5px 0;">
          <a href="mailto:support@bithash.com" style="color: #F7A600; text-decoration: none;">support@bithash.com</a> | 
          <a href="https://www.bithashcapital.live" style="color: #F7A600; text-decoration: none;">www.bithashcapital.live</a>
        </p>
      </div>
    </div>
  `;
  break;

      case 'withdrawal_approved':
        const withdrawalRate = await getCurrentExchangeRate('bitcoin');
        subject = 'Withdrawal Processed - ₿itHash Capital';
        html = `
          <div style="font-family: 'Inter', sans-serif; max-width: 600px; margin: 0 auto; background: #FFFFFF;">
            ${brandHeader}
            <div style="padding: 30px; background: #FFFFFF;">
              <h2 style="color: #0B0E11; margin-bottom: 20px;">Withdrawal Processed</h2>
              <p style="color: #333333; line-height: 1.6;">Dear ${data.name},</p>
              <p style="color: #333333; line-height: 1.6;">Your withdrawal request has been processed successfully.</p>
              <div style="background: #F5F5F5; padding: 20px; border-radius: 8px; margin: 20px 0;">
                <p style="margin: 5px 0;"><strong>Amount:</strong> ${data.amount} ${data.asset}</p>
                <p style="margin: 5px 0;"><strong>USD Value:</strong> $${data.usdValue.toLocaleString()}</p>
                <p style="margin: 5px 0;"><strong>Network Fee:</strong> ${data.fee} ${data.asset} (≈$${data.feeUsd.toFixed(2)})</p>
                <p style="margin: 5px 0;"><strong>Net Amount:</strong> ${data.netAmount} ${data.asset}</p>
                <p style="margin: 5px 0;"><strong>Destination:</strong> ${data.withdrawalAddress}</p>
                <p style="margin: 5px 0;"><strong>Method:</strong> ${data.method}</p>
                <p style="margin: 5px 0;"><strong>Processed At:</strong> ${new Date(data.processedAt).toLocaleString()}</p>
                ${data.txid ? `<p style="margin: 5px 0;"><strong>Transaction ID:</strong> ${data.txid}</p>` : ''}
              </div>
              <div style="text-align: center; margin: 30px 0;">
                <a href="https://www.bithashcapital.live/dashboard" style="background-color: #F7A600; color: #000000; padding: 12px 30px; text-decoration: none; border-radius: 999px; font-weight: 600; display: inline-block;">View Transaction</a>
              </div>
              <p style="color: #666666; font-size: 12px; margin-top: 30px;">Email sent: ${formattedTimestamp}</p>
            </div>
            ${brandFooter}
          </div>
        `;
        break;

      case 'withdrawal_rejected':
        subject = 'Withdrawal Update - ₿itHash Capital';
        html = `
          <div style="font-family: 'Inter', sans-serif; max-width: 600px; margin: 0 auto; background: #FFFFFF;">
            ${brandHeader}
            <div style="padding: 30px; background: #FFFFFF;">
              <h2 style="color: #0B0E11; margin-bottom: 20px;">Withdrawal Status Update</h2>
              <p style="color: #333333; line-height: 1.6;">Dear ${data.name},</p>
              <p style="color: #333333; line-height: 1.6;">Your withdrawal request could not be processed.</p>
              <div style="background: #F5F5F5; padding: 20px; border-radius: 8px; margin: 20px 0;">
                <p style="margin: 5px 0;"><strong>Amount:</strong> $${data.amount.toLocaleString()}</p>
                <p style="margin: 5px 0;"><strong>Reason:</strong> ${data.reason}</p>
              </div>
              <p style="color: #333333; line-height: 1.6;">Please contact support if you believe this is an error.</p>
              <p style="color: #666666; font-size: 12px; margin-top: 30px;">Email sent: ${formattedTimestamp}</p>
            </div>
            ${brandFooter}
          </div>
        `;
        break;

      case 'investment_created':
        subject = 'Investment Confirmed - ₿itHash Capital';
        html = `
          <div style="font-family: 'Inter', sans-serif; max-width: 600px; margin: 0 auto; background: #FFFFFF;">
            ${brandHeader}
            <div style="padding: 30px; background: #FFFFFF;">
              <h2 style="color: #0B0E11; margin-bottom: 20px;">Investment Confirmed</h2>
              <p style="color: #333333; line-height: 1.6;">Dear ${data.name},</p>
              <p style="color: #333333; line-height: 1.6;">Your investment has been successfully activated.</p>
              <div style="background: #F5F5F5; padding: 20px; border-radius: 8px; margin: 20px 0;">
                <p style="margin: 5px 0;"><strong>Plan:</strong> ${data.planName}</p>
                <p style="margin: 5px 0;"><strong>Amount:</strong> $${data.amount.toLocaleString()}</p>
                <p style="margin: 5px 0;"><strong>Expected Return:</strong> $${data.expectedReturn.toLocaleString()}</p>
                <p style="margin: 5px 0;"><strong>Duration:</strong> ${data.duration} hours</p>
                <p style="margin: 5px 0;"><strong>Start Date:</strong> ${new Date(data.startDate).toLocaleString()}</p>
                <p style="margin: 5px 0;"><strong>Expected Maturity:</strong> ${new Date(data.endDate).toLocaleString()}</p>
              </div>
              <p style="color: #666666; font-size: 12px; margin-top: 30px;">Email sent: ${formattedTimestamp}</p>
            </div>
            ${brandFooter}
          </div>
        `;
        break;

      case 'investment_matured':
        subject = 'Investment Matured - ₿itHash Capital';
        html = `
          <div style="font-family: 'Inter', sans-serif; max-width: 600px; margin: 0 auto; background: #FFFFFF;">
            ${brandHeader}
            <div style="padding: 30px; background: #FFFFFF;">
              <h2 style="color: #0B0E11; margin-bottom: 20px;">Investment Matured</h2>
              <p style="color: #333333; line-height: 1.6;">Dear ${data.name},</p>
              <p style="color: #333333; line-height: 1.6;">Congratulations! Your investment has matured and the proceeds have been credited to your matured wallet.</p>
              <div style="background: #F5F5F5; padding: 20px; border-radius: 8px; margin: 20px 0;">
                <p style="margin: 5px 0;"><strong>Plan:</strong> ${data.planName}</p>
                <p style="margin: 5px 0;"><strong>Initial Investment:</strong> $${data.amount.toLocaleString()}</p>
                <p style="margin: 5px 0;"><strong>Total Return:</strong> $${data.totalReturn.toLocaleString()}</p>
                <p style="margin: 5px 0;"><strong>Profit:</strong> $${data.profit.toLocaleString()}</p>
                <p style="margin: 5px 0;"><strong>Completion Date:</strong> ${new Date(data.completionDate).toLocaleString()}</p>
                <p style="margin: 5px 0;"><strong>New Matured Balance:</strong> $${data.newMaturedBalance.toLocaleString()}</p>
              </div>
              <div style="text-align: center; margin: 30px 0;">
                <a href="https://www.bithashcapital.live/dashboard" style="background-color: #F7A600; color: #000000; padding: 12px 30px; text-decoration: none; border-radius: 999px; font-weight: 600; display: inline-block;">View Earnings</a>
              </div>
              <p style="color: #666666; font-size: 12px; margin-top: 30px;">Email sent: ${formattedTimestamp}</p>
            </div>
            ${brandFooter}
          </div>
        `;
        break;

      case 'withdrawal_request':
        subject = 'Withdrawal Request Received - ₿itHash Capital';
        html = `
          <div style="font-family: 'Inter', sans-serif; max-width: 600px; margin: 0 auto; background: #FFFFFF;">
            ${brandHeader}
            <div style="padding: 30px; background: #FFFFFF;">
              <h2 style="color: #0B0E11; margin-bottom: 20px;">Withdrawal Request Received</h2>
              <p style="color: #333333; line-height: 1.6;">Dear ${data.name},</p>
              <p style="color: #333333; line-height: 1.6;">We have received your withdrawal request. Our team will review and process it shortly.</p>
              <div style="background: #F5F5F5; padding: 20px; border-radius: 8px; margin: 20px 0;">
                <p style="margin: 5px 0;"><strong>Amount:</strong> ${data.amount} ${data.asset}</p>
                <p style="margin: 5px 0;"><strong>USD Value:</strong> $${data.usdValue.toLocaleString()}</p>
                <p style="margin: 5px 0;"><strong>Network Fee:</strong> ${data.fee} ${data.asset} (≈$${data.feeUsd.toFixed(2)})</p>
                <p style="margin: 5px 0;"><strong>Net Amount:</strong> ${data.netAmount} ${data.asset}</p>
                <p style="margin: 5px 0;"><strong>Destination:</strong> ${data.withdrawalAddress}</p>
                <p style="margin: 5px 0;"><strong>Request ID:</strong> ${data.requestId}</p>
                <p style="margin: 5px 0;"><strong>Requested At:</strong> ${new Date(data.timestamp).toLocaleString()}</p>
                <p style="margin: 5px 0;"><strong>Network:</strong> ${data.network}</p>
              </div>
              <div style="text-align: center; margin: 30px 0;">
                <a href="https://www.bithashcapital.live/dashboard" style="background-color: #F7A600; color: #000000; padding: 12px 30px; text-decoration: none; border-radius: 999px; font-weight: 600; display: inline-block;">Track Request</a>
              </div>
              <p style="color: #666666; font-size: 12px; margin-top: 30px;">Email sent: ${formattedTimestamp}</p>
            </div>
            ${brandFooter}
          </div>
        `;
        break;

case 'login_success':
  // Use a fallback if timestamp is missing
  const loginTime = data.timestamp ? new Date(data.timestamp) : new Date();
  const isValidTime = !isNaN(loginTime.getTime());
  
  subject = 'New Login Detected - ₿itHash Capital';
  html = `
    <div style="font-family: 'Inter', sans-serif; max-width: 600px; margin: 0 auto; background: #FFFFFF;">
      ${brandHeader}
      <div style="padding: 30px; background: #FFFFFF;">
        <h2 style="color: #0B0E11; margin-bottom: 20px;">New Login Detected</h2>
        <p style="color: #333333; line-height: 1.6;">Hello ${data.name},</p>
        <p style="color: #333333; line-height: 1.6;">A new login was detected on your account.</p>
        <div style="background: #F5F5F5; padding: 20px; border-radius: 8px; margin: 20px 0;">
          <p style="margin: 5px 0;"><strong>Device:</strong> ${data.device || 'Unknown'}</p>
          <p style="margin: 5px 0;"><strong>Location:</strong> ${data.location || 'Unknown'}</p>
          <p style="margin: 5px 0;"><strong>IP Address:</strong> ${data.ip || 'Unknown'}</p>
          <p style="margin: 5px 0;"><strong>Time:</strong> ${isValidTime ? loginTime.toLocaleString() : formattedTimestamp}</p>
        </div>
        <p style="color: #333333; line-height: 1.6;">If this wasn't you, please contact support immediately.</p>
        <p style="color: #666666; font-size: 12px; margin-top: 30px;">Email sent: ${formattedTimestamp}</p>
      </div>
      ${brandFooter}
    </div>
  `;
  break;

      case 'password_changed':
        subject = 'Password Changed - ₿itHash Capital';
        html = `
          <div style="font-family: 'Inter', sans-serif; max-width: 600px; margin: 0 auto; background: #FFFFFF;">
            ${brandHeader}
            <div style="padding: 30px; background: #FFFFFF;">
              <h2 style="color: #0B0E11; margin-bottom: 20px;">Password Changed</h2>
              <p style="color: #333333; line-height: 1.6;">Hello ${data.name},</p>
              <p style="color: #333333; line-height: 1.6;">Your account password was recently changed.</p>
              <div style="background: #F5F5F5; padding: 20px; border-radius: 8px; margin: 20px 0;">
                <p style="margin: 5px 0;"><strong>Device:</strong> ${data.device}</p>
                <p style="margin: 5px 0;"><strong>IP Address:</strong> ${data.ip}</p>
              </div>
              <p style="color: #333333; line-height: 1.6;">If you did not make this change, please contact support immediately.</p>
              <p style="color: #666666; font-size: 12px; margin-top: 30px;">Email sent: ${formattedTimestamp}</p>
            </div>
            ${brandFooter}
          </div>
        `;
        break;

      case 'password_reset':
        subject = 'Password Reset Request - ₿itHash Capital';
        html = `
          <div style="font-family: 'Inter', sans-serif; max-width: 600px; margin: 0 auto; background: #FFFFFF;">
            ${brandHeader}
            <div style="padding: 30px; background: #FFFFFF;">
              <h2 style="color: #0B0E11; margin-bottom: 20px;">Password Reset Request</h2>
              <p style="color: #333333; line-height: 1.6;">Hello ${data.name},</p>
              <p style="color: #333333; line-height: 1.6;">We received a request to reset your password. Click the button below to create a new password.</p>
              <div style="text-align: center; margin: 30px 0;">
                <a href="${data.resetUrl}" style="background-color: #F7A600; color: #000000; padding: 12px 30px; text-decoration: none; border-radius: 999px; font-weight: 600; display: inline-block;">Reset Password</a>
              </div>
              <p style="color: #333333; line-height: 1.6;">This link will expire in 60 minutes. If you didn't request this, please ignore this email.</p>
              <p style="color: #666666; font-size: 12px; margin-top: 30px;">Email sent: ${formattedTimestamp}</p>
            </div>
            ${brandFooter}
          </div>
        `;
        break;

      case 'suspicious_login':
        subject = 'Security Alert - Suspicious Login Attempt - ₿itHash Capital';
        html = `
          <div style="font-family: 'Inter', sans-serif; max-width: 600px; margin: 0 auto; background: #FFFFFF;">
            ${brandHeader}
            <div style="padding: 30px; background: #FFFFFF;">
              <h2 style="color: #0B0E11; margin-bottom: 20px;">Security Alert</h2>
              <p style="color: #333333; line-height: 1.6;">Hello ${data.name},</p>
              <p style="color: #333333; line-height: 1.6;">We detected a suspicious login attempt on your account from an unrecognized device or location.</p>
              <div style="background: #F5F5F5; padding: 20px; border-radius: 8px; margin: 20px 0;">
                <p style="margin: 5px 0;"><strong>Device:</strong> ${data.device}</p>
                <p style="margin: 5px 0;"><strong>Location:</strong> ${data.location}</p>
                <p style="margin: 5px 0;"><strong>IP Address:</strong> ${data.ip}</p>
              <p style="margin: 5px 0;"><strong>Time:</strong> ${(() => {
  let date = data.timestamp;
  if (!date) return 'Unknown';
  if (date instanceof Date) return date.toLocaleString();
  const parsed = new Date(date);
  return isNaN(parsed.getTime()) ? new Date().toLocaleString() : parsed.toLocaleString();
})()}</p>
              </div>
              <p style="color: #333333; line-height: 1.6;">If this was you, you can safely ignore this email. If not, please secure your account immediately.</p>
              <div style="text-align: center; margin: 30px 0;">
                <a href="https://www.bithashcapital.live/security" style="background-color: #F7A600; color: #000000; padding: 12px 30px; text-decoration: none; border-radius: 999px; font-weight: 600; display: inline-block;">Secure Account</a>
              </div>
              <p style="color: #666666; font-size: 12px; margin-top: 30px;">Email sent: ${formattedTimestamp}</p>
            </div>
            ${brandFooter}
          </div>
        `;
        break;

 default:
  subject = 'Important Account Update - ₿itHash Capital';
  html = `
    <div style="font-family: 'Inter', sans-serif; max-width: 600px; margin: 0 auto; background: #FFFFFF;">
      ${brandHeader}
      <div style="padding: 30px; background: #FFFFFF;">
        <div style="background: #F3F4F6; border-radius: 12px; padding: 20px; margin-bottom: 25px; text-align: center;">
          <svg width="48" height="48" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" style="margin: 0 auto 12px auto;">
            <path d="M12 8V12M12 16H12.01M21 12C21 16.9706 16.9706 21 12 21C7.02944 21 3 16.9706 3 12C3 7.02944 7.02944 3 12 3C16.9706 3 21 7.02944 21 12Z" stroke="#F7A600" stroke-width="2" stroke-linecap="round"/>
          </svg>
          <h2 style="color: #0B0E11; font-size: 20px; margin: 0 0 8px 0;">Account Update Notification</h2>
          <p style="color: #6C7480; font-size: 14px; margin: 0;">Action Required / Information</p>
        </div>
        
        <p style="color: #333333; line-height: 1.6;">Dear <strong>${data.name || 'Valued Customer'}</strong>,</p>
        
        <p style="color: #333333; line-height: 1.6;">${data.message || 'We have an important update regarding your account that requires your attention.'}</p>
        
        ${data.details ? `
        <div style="background: #F5F5F5; padding: 20px; border-radius: 12px; margin: 20px 0;">
          <h3 style="color: #0B0E11; margin: 0 0 12px 0; font-size: 16px;">Update Details:</h3>
          <p style="color: #4B5563; margin: 0; line-height: 1.5;">${data.details}</p>
        </div>
        ` : ''}
        
        ${data.actionRequired ? `
        <div style="background: #FEF3C7; border-left: 4px solid #F7A600; padding: 16px 20px; border-radius: 8px; margin: 20px 0;">
          <p style="color: #92400E; margin: 0 0 8px 0; font-weight: 600;">⚠️ Action Required</p>
          <p style="color: #78350F; margin: 0; font-size: 14px;">${data.actionRequired}</p>
        </div>
        ` : ''}
        
        ${data.actionLink ? `
        <div style="text-align: center; margin: 30px 0;">
          <a href="${data.actionLink}" style="background-color: #F7A600; color: #000000; padding: 12px 30px; text-decoration: none; border-radius: 999px; font-weight: 600; display: inline-block;">${data.buttonText || 'View Details'}</a>
        </div>
        ` : ''}
        
        <div style="margin-top: 25px; padding-top: 20px; border-top: 1px solid #E5E7EB;">
          <p style="color: #6C7480; font-size: 13px; line-height: 1.5; margin: 0 0 10px 0;">
            <strong>What this means for you:</strong>
          </p>
          <ul style="color: #6C7480; font-size: 13px; margin: 0; padding-left: 20px;">
            <li style="margin: 5px 0;">Your account security is our top priority</li>
            <li style="margin: 5px 0;">Review the information above for any necessary actions</li>
            <li style="margin: 5px 0;">Contact support if you have any questions</li>
          </ul>
        </div>
        
        <p style="color: #666666; font-size: 12px; margin-top: 30px;">
          <strong>Reference ID:</strong> ${data.referenceId || 'N/A'}<br>
          <strong>Email sent:</strong> ${formattedTimestamp}
        </p>
        
        <div style="background: #F9FAFB; padding: 15px; border-radius: 8px; margin-top: 20px;">
          <p style="color: #6C7480; font-size: 12px; margin: 0 0 5px 0;">
            <strong>Need help?</strong> Contact our support team:
          </p>
          <p style="color: #6C7480; font-size: 12px; margin: 0;">
            📧 <a href="mailto:support@bithashcapital.live" style="color: #F7A600;">support@bithashcapital.live</a><br>
            🌐 <a href="https://www.bithashcapital.live/support" style="color: #F7A600;">www.bithashcapital.live/support</a>
          </p>
        </div>
      </div>
      ${brandFooter}
    </div>
  `;
  break;
  } 







// Helper function for sending admin action notifications
const sendAdminActionNotification = async (user, action, details, actionRequired = null, actionLink = null) => {
  try {
    // Map admin actions to appropriate messages
    const actionMessages = {
      'account_suspended': {
        message: 'Your account has been temporarily suspended due to unusual activity.',
        subject: 'Account Temporarily Suspended - Action Required'
      },
      'account_restricted': {
        message: 'Your account has been restricted. Please review the details below.',
        subject: 'Account Restrictions Applied'
      },
      'kyc_review': {
        message: 'Your KYC documents are under review. We will notify you once completed.',
        subject: 'KYC Document Review Status'
      },
      'deposit_manual': {
        message: 'Your deposit has been manually processed by our finance team.',
        subject: 'Manual Deposit Processed'
      },
      'withdrawal_manual': {
        message: 'Your withdrawal request has been manually reviewed and processed.',
        subject: 'Manual Withdrawal Processed'
      },
      'balance_adjustment': {
        message: 'Your account balance has been adjusted by our administration team.',
        subject: 'Account Balance Adjustment'
      },
      'security_alert': {
        message: 'Security alert: Unusual activity detected on your account.',
        subject: '⚠️ Security Alert - Action Required'
      },
      'compliance_update': {
        message: 'Important update regarding your account compliance status.',
        subject: 'Compliance Status Update'
      },
      'investment_update': {
        message: 'Your investment portfolio has been updated by our management team.',
        subject: 'Investment Portfolio Update'
      }
    };

    const actionConfig = actionMessages[action] || {
      message: details?.message || 'An important update has been made to your account.',
      subject: 'Important Account Update - ₿itHash Capital'
    };

    // Send the email using the professional email service
    await sendProfessionalEmail({
      email: user.email,
      template: 'default',
      data: {
        name: user.firstName || 'Valued Customer',
        message: actionConfig.message,
        details: details?.description || details?.reason || JSON.stringify(details, null, 2),
        actionRequired: actionRequired,
        actionLink: actionLink,
        buttonText: details?.buttonText || 'View Details',
        referenceId: `${action.toUpperCase()}-${Date.now()}-${Math.floor(Math.random() * 10000)}`
      }
    });

    console.log(`📧 Admin action notification sent to ${user.email} for action: ${action}`);
    return true;

  } catch (err) {
    console.error('Failed to send admin action notification:', err);
    return false;
  }
};


        

    const mailOptions = {
      from: `₿itHash Capital <${mailTransporter === supportTransporter ? process.env.EMAIL_SUPPORT_USER : process.env.EMAIL_INFO_USER}>`,
      to: email,
      subject: subject,
      html: html
    };

    await mailTransporter.sendMail(mailOptions);
    if (process.env.NODE_ENV !== 'production') console.log(`Email sent: ${template} to ${email}`);
    return true;
  } catch (err) {
    if (process.env.NODE_ENV !== 'production') console.error('Error sending professional email:', err);
    return false;
  }
};

const sendAutomatedEmail = async (user, action, data = {}) => {
  try {
    let template = '';
    let templateData = { ...data, name: user.firstName };

    switch (action) {
      case 'welcome':
        template = 'welcome';
        break;
      case 'kyc_approved':
        template = 'kyc_approved';
        break;
      case 'kyc_rejected':
        template = 'kyc_rejected';
        templateData.reason = data.reason;
        break;
      case 'deposit_approved':
        template = 'deposit_approved';
        break;
      case 'deposit_rejected':
        template = 'deposit_rejected';
        break;
      case 'withdrawal_approved':
        template = 'withdrawal_approved';
        break;
      case 'withdrawal_rejected':
        template = 'withdrawal_rejected';
        break;
      case 'investment_created':
        template = 'investment_created';
        break;
      case 'investment_matured':
        template = 'investment_matured';
        break;
      case 'withdrawal_request':
        template = 'withdrawal_request';
        break;
      case 'login_success':
        template = 'login_success';
        break;
      case 'password_changed':
        template = 'password_changed';
        break;
      case 'password_reset':
        template = 'password_reset';
        break;
      case 'suspicious_login':
        template = 'suspicious_login';
        break;
      default:
        template = 'default';
    }

    return await sendProfessionalEmail({
      email: user.email,
      template: template,
      data: templateData
    });
  } catch (err) {
    if (process.env.NODE_ENV !== 'production') console.error('Error sending automated email:', err);
    return false;
  }
};








// =============================================
// ENHANCED DEVICE DETECTION WITH ACCURATE BROWSER/OS DETECTION
// =============================================

const getAccurateDeviceInfo = (userAgent) => {
  if (!userAgent) return { device: 'Unknown', os: 'Unknown', browser: 'Unknown', model: 'Unknown' };
  
  let device = 'Unknown';
  let os = 'Unknown';
  let browser = 'Unknown';
  let model = 'Unknown';
  
  if (/Tecno|TECNO/i.test(userAgent)) {
    device = 'Tecno';
    if (/KH7/i.test(userAgent)) model = 'Tecno Spark 9 Pro (KH7)';
    else if (/Spark/i.test(userAgent)) model = 'Tecno Spark Series';
  } else if (/iPhone/i.test(userAgent)) {
    device = 'iPhone';
    model = userAgent.match(/iPhone ([\d,]+)/)?.[0] || 'iPhone';
  } else if (/iPad/i.test(userAgent)) {
    device = 'iPad';
    model = 'iPad';
  } else if (/Android/i.test(userAgent)) {
    device = 'Android';
    const match = userAgent.match(/Android ([\d.]+)/);
    if (match) model = `Android ${match[1]}`;
    else model = 'Android Device';
  } else if (/Windows/i.test(userAgent)) {
    device = 'Windows PC';
    model = 'Windows Computer';
  } else if (/Macintosh|Mac OS/i.test(userAgent)) {
    device = 'Mac';
    model = 'Apple Mac';
  } else if (/Linux/i.test(userAgent)) {
    device = 'Linux';
    model = 'Linux Computer';
  }
  
  if (/Windows NT 10.0/i.test(userAgent)) os = 'Windows 10/11';
  else if (/Windows NT 6.1/i.test(userAgent)) os = 'Windows 7';
  else if (/Mac OS X (\d+[._]\d+)/i.test(userAgent)) {
    const match = userAgent.match(/Mac OS X (\d+[._]\d+)/);
    if (match) os = `macOS ${match[1].replace('_', '.')}`;
    else os = 'macOS';
  } else if (/Android ([\d.]+)/i.test(userAgent)) {
    const match = userAgent.match(/Android ([\d.]+)/);
    if (match) os = `Android ${match[1]}`;
    else os = 'Android';
  } else if (/iOS ([\d_]+)/i.test(userAgent)) {
    const match = userAgent.match(/iOS ([\d_]+)/);
    if (match) os = `iOS ${match[1].replace('_', '.')}`;
    else os = 'iOS';
  } else if (/iPhone OS ([\d_]+)/i.test(userAgent)) {
    const match = userAgent.match(/iPhone OS ([\d_]+)/);
    if (match) os = `iOS ${match[1].replace('_', '.')}`;
    else os = 'iOS';
  }
  
  if (/Edg\//i.test(userAgent)) {
    browser = 'Microsoft Edge';
  } else if (/Chrome\//i.test(userAgent) && !/Edg\//i.test(userAgent)) {
    browser = 'Google Chrome';
  } else if (/Safari\//i.test(userAgent) && !/Chrome\//i.test(userAgent)) {
    browser = 'Safari';
  } else if (/Firefox\//i.test(userAgent)) {
    browser = 'Mozilla Firefox';
  } else if (/Opera|OPR\//i.test(userAgent)) {
    browser = 'Opera';
  } else if (/Brave\//i.test(userAgent)) {
    browser = 'Brave';
  }
  
  return { device, os, browser, model, fullUserAgent: userAgent };
};

const getDeviceType = (req) => {
  const userAgent = req.headers['user-agent'] || '';
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


// Routes

// Enhanced Signup Endpoint with OTP - Captures ALL fields from HTML forms
app.post('/api/auth/signup', [
  // Individual form fields
  body('firstName').trim().notEmpty().withMessage('First name is required').escape(),
  body('lastName').trim().notEmpty().withMessage('Last name is required').escape(),
  body('email').isEmail().withMessage('Please provide a valid email').custom((value) => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(value)) {
      throw new Error('Please provide a valid email address (e.g., name@domain.com)');
    }
    return true;
  }),
  body('city').trim().notEmpty().withMessage('City is required').escape(),
  body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
      .matches(/[A-Z]/).withMessage('Password must contain at least one uppercase letter')
      .matches(/[a-z]/).withMessage('Password must contain at least one lowercase letter')
      .matches(/[0-9]/).withMessage('Password must contain at least one number')
      .matches(/[^A-Za-z0-9]/).withMessage('Password must contain at least one special character'),
  body('referralCode').optional().trim().escape(),
  body('accountType').optional().isIn(['individual', 'business']).withMessage('Account type must be individual or business'),
  
  // Business form fields (optional for individual accounts)
  body('organizationName').optional().trim().escape(),
  body('role').optional().trim().escape(),
  body('country').optional().trim().escape(),
  body('workEmail').optional().isEmail().withMessage('Please provide a valid work email'),
  body('orgEmail').optional().isEmail().withMessage('Please provide a valid email address'),
  body('orgCity').optional().trim().escape(),
  body('orgFirstName').optional().trim().escape(),
  body('orgLastName').optional().trim().escape(),
  body('orgPassword').optional().trim(),
  body('confirmOrgPassword').optional().trim()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    console.error('Signup validation errors:', errors.array());
    return res.status(400).json({
      status: 'fail',
      errors: errors.array(),
      message: errors.array()[0]?.msg || 'Validation failed'
    });
  }

  try {
    const { 
      // Individual fields
      firstName, lastName, email, city, password, referralCode, accountType,
      // Business fields
      organizationName, role, country, workEmail, orgEmail, orgCity,
      orgFirstName, orgLastName, orgPassword
    } = req.body;

    // Determine which email to use (individual email or business org email)
    const userEmail = email || orgEmail;
    const userFirstName = firstName || orgFirstName;
    const userLastName = lastName || orgLastName;
    const userPassword = password || orgPassword;
    const userCity = city || orgCity;
    const userAccountType = accountType || 'individual';

    // Validate email exists
    if (!userEmail) {
      return res.status(400).json({
        status: 'fail',
        message: 'Email address is required'
      });
    }

    // Validate password exists
    if (!userPassword) {
      return res.status(400).json({
        status: 'fail',
        message: 'Password is required'
      });
    }

    // Validate first and last name
    if (!userFirstName || !userLastName) {
      return res.status(400).json({
        status: 'fail',
        message: 'First name and last name are required'
      });
    }

    // Validate city
    if (!userCity) {
      return res.status(400).json({
        status: 'fail',
        message: 'City is required'
      });
    }

    // Use exact email for all operations
    const originalEmail = userEmail;

    // Check if email already exists - exact match only
    const existingUser = await User.findOne({ email: originalEmail });
    if (existingUser) {
      return res.status(400).json({
        status: 'fail',
        message: 'Email already in use'
      });
    }

    const hashedPassword = await bcrypt.hash(userPassword, 12);
    const newReferralCode = generateReferralCode();

    let referredByUser = null;
    let referralSource = 'organic';

    // Handle referral code from URL parameter
    if (referralCode) {
      console.log('Processing referral code:', referralCode);
      
      let actualReferralCode = referralCode;
      if (referralCode.includes('-')) {
        const parts = referralCode.split('-');
        if (parts.length >= 4) {
          actualReferralCode = `${parts[0]}-${parts[1]}-${parts[2]}-${parts[3]}`;
        } else {
          actualReferralCode = parts[parts.length - 1];
        }
      }
      
      referredByUser = await User.findOne({ referralCode: actualReferralCode });
      
      if (referredByUser) {
        referralSource = 'referral_link';
        console.log(`Referral found: ${referredByUser.firstName} ${referredByUser.lastName} (${referredByUser.email})`);
      }
    }

    // Create complete user object with ALL fields
    const userData = {
      // Core required fields
      firstName: userFirstName,
      lastName: userLastName,
      email: originalEmail,
      password: hashedPassword,
      city: userCity,
      referralCode: newReferralCode,
      referredBy: referredByUser ? referredByUser._id : undefined,
      isVerified: false,
      accountType: userAccountType,
      
      // Store signup source
      signupSource: referralCode ? 'referral' : 'organic',
      
      // Business fields (will be null for individual accounts)
      organizationName: organizationName || null,
      role: role || null,
      country: country || null,
      workEmail: workEmail || null,
      
      // Metadata about the signup
      metadata: {
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
        signupDate: new Date(),
        accountTypeSelected: userAccountType
      }
    };

    const newUser = await User.create(userData);

    // Generate OTP with exact email
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000);

    await OTP.create({
      email: originalEmail,
      otp,
      type: 'signup',
      expiresAt,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent']
    });

    // Send OTP email
    await sendProfessionalEmail({
      email: originalEmail,
      template: 'otp',
      data: {
        name: userFirstName,
        otp: otp,
        action: 'account verification'
      }
    });

    // Send welcome email
    await sendAutomatedEmail(newUser, 'welcome', {
      firstName: userFirstName
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
          email: newUser.email,
          accountType: newUser.accountType,
          city: newUser.city,
          organizationName: newUser.organizationName,
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
      message: err.message || 'An error occurred during signup'
    });
  }
});






// Enhanced Login Endpoint with OTP - Captures ALL fields from HTML form
app.post('/api/auth/login', [
  body('email').isEmail().withMessage('Please provide a valid email').custom((value) => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(value)) {
      throw new Error('Please provide a valid email address (e.g., name@domain.com)');
    }
    return true;
  }),
  body('password').notEmpty().withMessage('Password is required'),
  body('rememberMe').optional().isBoolean().withMessage('Remember me must be a boolean'),
  body('accountType').optional().isIn(['individual', 'business']).withMessage('Account type must be individual or business')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { email, password, rememberMe, accountType } = req.body;

    // Use exact email for lookup - no normalization
    const user = await User.findOne({ email }).select('+password +twoFactorAuth.secret');
    
    if (!user || !(await bcrypt.compare(password, user.password))) {
      await logActivity('login_attempt', 'authentication', null, null, null, req, {
        error: 'Invalid credentials',
        email: email,
        status: 'failed'
      });
      
      return res.status(401).json({
        status: 'fail',
        message: 'Incorrect email or password'
      });
    }

    // Verify account type matches (if specified in login form)
    if (accountType && user.accountType !== accountType) {
      return res.status(401).json({
        status: 'fail',
        message: `Account type mismatch. This email is registered as a ${user.accountType} account.`
      });
    }

    if (user.status !== 'active') {
      await logActivity('login_attempt', 'authentication', null, null, null, req, {
        error: 'Account suspended',
        email: email,
        status: 'failed'
      });
      
      return res.status(401).json({
        status: 'fail',
        message: 'Your account has been suspended. Please contact support.'
      });
    }

    // Generate OTP for login
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000);

    await OTP.create({
      email: email,
      otp,
      type: 'login',
      expiresAt,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent']
    });

    // Send OTP email
    await sendProfessionalEmail({
      email: email,
      template: 'otp',
      data: {
        name: user.firstName,
        otp: otp,
        action: 'login'
      }
    });

    // Create log for login attempt
    const deviceInfo = await getUserDeviceInfo(req);
    await UserLog.create({
      user: user._id,
      username: user.email,
      email: user.email,
      userFullName: `${user.firstName} ${user.lastName}`,
      action: 'login_attempt',
      actionCategory: 'authentication',
      ipAddress: deviceInfo.ip,
      userAgent: deviceInfo.device,
      deviceInfo: {
        type: getDeviceType(req),
        os: getOSFromUserAgent(req.headers['user-agent']),
        browser: getBrowserFromUserAgent(req.headers['user-agent'])
      },
      location: {
        ip: deviceInfo.ip,
        country: deviceInfo.locationDetails?.country || 'Unknown',
        city: deviceInfo.locationDetails?.city || 'Unknown',
        region: deviceInfo.locationDetails?.region || 'Unknown',
        exactLocation: deviceInfo.exactLocation,
        latitude: deviceInfo.locationDetails?.latitude,
        longitude: deviceInfo.locationDetails?.longitude
      },
      status: 'pending',
      metadata: {
        email: email,
        loginMethod: 'password',
        otpSent: true,
        rememberMe: rememberMe || false,
        accountType: accountType || user.accountType
      }
    });

    // Send login attempt email
    try {
      await sendAutomatedEmail(user, 'login_success', {
        name: user.firstName,
        device: deviceInfo.device,
        location: deviceInfo.location,
        ip: deviceInfo.ip,
        timestamp: new Date().toISOString()
      });
      console.log(`📧 Login attempt email sent to ${user.email}`);
    } catch (emailError) {
      console.error('Failed to send login attempt email:', emailError);
    }

    // Generate temporary token for OTP verification
    const tempToken = generateJWT(user._id);

    // If rememberMe is true, set longer expiration for token
    const tokenOptions = {};
    if (rememberMe) {
      tokenOptions.expiresIn = '30d'; // 30 days for remember me
    }

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
          email: user.email,
          accountType: user.accountType,
          organizationName: user.organizationName || null
        }
      }
    });

    await logActivity('login_otp_sent', 'authentication', user._id, user._id, 'User', req, {
      email: email,
      status: 'pending',
      rememberMe: rememberMe || false
    });

  } catch (err) {
    console.error('Login error:', err);
    
    await logActivity('login_error', 'authentication', null, null, null, req, {
      error: err.message,
      email: req.body.email,
      status: 'failed'
    });

    res.status(500).json({
      status: 'error',
      message: 'An error occurred during login'
    });
  }
});


app.post('/api/auth/google', async (req, res) => {
  try {
    console.log('Google auth request received');
    
    const { credential, isSignup = false } = req.body;
    
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
        audience: process.env.GOOGLE_CLIENT_ID
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

    // Get device info for location tracking
    const deviceInfo = await getUserDeviceInfo(req);
    
    // Get greeting based on time
    const currentHour = new Date().getHours();
    let greeting = 'Hello';
    if (currentHour >= 5 && currentHour < 12) greeting = 'Good morning';
    else if (currentHour >= 12 && currentHour < 17) greeting = 'Good afternoon';
    else if (currentHour >= 17 && currentHour < 22) greeting = 'Good evening';
    
    // Truncate email
    let truncatedEmail = email;
    const [localPart, domain] = email.split('@');
    if (domain && localPart.length > 6) {
      const firstChars = localPart.substring(0, 3);
      const lastChars = localPart.substring(localPart.length - 3);
      truncatedEmail = `${firstChars}...${lastChars}@${domain}`;
    }
    
    // =============================================
    // FILTER LOGIC FOR LOGIN VS SIGNUP
    // =============================================
    
    // Case 1: Login attempt but user doesn't exist
    if (isSignup === false && !user) {
      console.log('Login attempt with Google: User does not exist');
      
      return res.status(404).json({
        status: 'fail',
        message: `${greeting}! No account found for ${truncatedEmail}. Please sign up first.`,
        data: {
          greeting: greeting,
          truncatedEmail: truncatedEmail,
          action: 'signup_suggested'
        }
      });
    }
    
    // Case 2: Signup attempt but user already exists
    if (isSignup === true && user) {
      console.log('Signup attempt with Google: User already exists');
      
      // Get location details for the email
      const locationString = deviceInfo.location || 'Unknown location';
      const deviceString = deviceInfo.device || 'Unknown device';
      const ipAddress = deviceInfo.ip || 'Unknown IP';
      const attemptTime = new Date().toLocaleString('en-US', {
        year: 'numeric',
        month: 'long',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        timeZoneName: 'short'
      });
      
     // Send security email about duplicate signup attempt with clean formatting (no emojis)
try {
  // Clean up device info for display
  let cleanDevice = deviceString;
  // Extract browser and OS from user agent
  if (deviceString.includes('Chrome/')) cleanDevice = 'Google Chrome';
  else if (deviceString.includes('Firefox/')) cleanDevice = 'Mozilla Firefox';
  else if (deviceString.includes('Safari/') && !deviceString.includes('Chrome/')) cleanDevice = 'Safari';
  else if (deviceString.includes('Edg/')) cleanDevice = 'Microsoft Edge';
  else if (deviceString.includes('Opera/') || deviceString.includes('OPR/')) cleanDevice = 'Opera';
  
  // Extract OS
  let cleanOS = 'Unknown';
  if (deviceString.includes('Windows NT 10.0')) cleanOS = 'Windows 10/11';
  else if (deviceString.includes('Windows NT 6.1')) cleanOS = 'Windows 7';
  else if (deviceString.includes('Mac OS X')) cleanOS = 'macOS';
  else if (deviceString.includes('Android')) cleanOS = 'Android';
  else if (deviceString.includes('iPhone') || deviceString.includes('iPad')) cleanOS = 'iOS';
  else if (deviceString.includes('Linux')) cleanOS = 'Linux';
  
  await sendProfessionalEmail({
    email: email,
    template: 'default',
    data: {
      name: user.firstName,
      message: `We noticed an attempt to create a new account using your email address (${truncatedEmail}).`,
      details: `
        <div style="background: #F5F5F5; padding: 15px; border-radius: 8px; margin: 15px 0;">
          <p style="margin: 0 0 10px 0;"><strong>Location:</strong> ${locationString}</p>
          <p style="margin: 0 0 10px 0;"><strong>Device:</strong> ${cleanDevice} on ${cleanOS}</p>
          <p style="margin: 0 0 10px 0;"><strong>IP Address:</strong> ${ipAddress}</p>
          <p style="margin: 0 0 0 0;"><strong>Time:</strong> ${attemptTime}</p>
        </div>
      `,
      actionRequired: 'If this was you, please log in to your existing account. If this was not you, please contact our support team immediately to secure your account.',
      buttonText: 'Login to Your Account',
      actionLink: 'https://www.bithashcapital.live/login',
      referenceId: `SEC-DUPLICATE-${Date.now()}-${Math.floor(Math.random() * 10000)}`
    }
  });
  console.log(`Security email sent to ${email} about duplicate signup attempt from ${locationString}`);
} catch (emailError) {
  console.error('Failed to send duplicate signup alert email:', emailError);
}
      return res.status(409).json({
        status: 'fail',
        message: `${greeting} ${user.firstName}! You already have an account with ${truncatedEmail}. Please log in.`,
        data: {
          greeting: greeting,
          userName: user.firstName,
          truncatedEmail: truncatedEmail,
          action: 'login_suggested'
        }
      });
    }

    // =============================================
    // NORMAL FLOW - Create or update user
    // =============================================
    
    if (!user) {
      // Create new user with Google auth using exact email (only for signup)
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
          await sendAutomatedEmail(user, 'welcome', {
            firstName: given_name || 'Google User'
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
      
      // CREATE LOG FOR GOOGLE LOGIN ATTEMPT
      await UserLog.create({
        user: user._id,
        username: user.email,
        email: user.email,
        userFullName: `${user.firstName} ${user.lastName}`,
        action: 'login_attempt',
        actionCategory: 'authentication',
        ipAddress: deviceInfo.ip,
        userAgent: deviceInfo.device,
        deviceInfo: {
          type: getDeviceType(req),
          os: getOSFromUserAgent(req.headers['user-agent']),
          browser: getBrowserFromUserAgent(req.headers['user-agent'])
        },
        location: {
          ip: deviceInfo.ip,
          country: deviceInfo.locationDetails?.country || 'Unknown',
          city: deviceInfo.locationDetails?.city || 'Unknown',
          region: deviceInfo.locationDetails?.region || 'Unknown',
          exactLocation: deviceInfo.exactLocation,
          latitude: deviceInfo.locationDetails?.latitude,
          longitude: deviceInfo.locationDetails?.longitude
        },
        status: 'pending',
        metadata: {
          email: originalEmail,
          loginMethod: 'google',
          otpSent: true,
          isNewUser: isNewUser
        }
      });
      
      // SEND LOGIN ATTEMPT EMAIL FOR GOOGLE SIGN-IN
      try {
        await sendAutomatedEmail(user, 'login_success', {
          name: user.firstName,
          device: deviceInfo.device,
          location: deviceInfo.location,
          ip: deviceInfo.ip,
          timestamp: new Date().toISOString()
        });
        console.log(`📧 Google login attempt email sent to ${user.email}`);
      } catch (emailError) {
        console.error('Failed to send Google login attempt email:', emailError);
      }
      
    } catch (otpError) {
      console.error('OTP creation error:', otpError);
      // Continue even if OTP fails for now
    }

    // Generate temporary token
    const tempToken = generateJWT(user._id);

    // Update last login
    try {
      user.lastLogin = new Date();
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

    await sendAutomatedEmail(user, 'password_reset', {
      name: user.firstName,
      resetUrl: resetURL
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

    // Send password changed notification
    const deviceInfo = await getUserDeviceInfo(req);
    await sendAutomatedEmail(user, 'password_changed', {
      name: user.firstName,
      ip: deviceInfo.ip,
      device: deviceInfo.device
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

    // ✅ CHECK RESTRICTIONS BEFORE ALLOWING INVESTMENT
    const restrictions = await AccountRestrictions.getInstance();
    const userRestrictionStatus = await UserRestrictionStatus.findOne({ user: userId });
    
    const kycStatus = await KYC.findOne({ user: userId });
    const hasKYC = kycStatus && kycStatus.overallStatus === 'verified';
    
    const cutoff = new Date();
    cutoff.setDate(cutoff.getDate() - (restrictions.inactivity_days || 30));
    const hasRecentTx = await Transaction.findOne({
      user: userId,
      type: { $in: ['deposit', 'withdrawal'] },
      status: 'completed',
      createdAt: { $gte: cutoff }
    });
    
    if (!hasKYC && restrictions.invest_limit_no_kyc !== null && amount > restrictions.invest_limit_no_kyc) {
      return res.status(403).json({
        status: 'fail',
        message: restrictions.kyc_restriction_reason || `Please complete KYC. Limit: $${restrictions.invest_limit_no_kyc.toLocaleString()}`
      });
    }
    
    if (!hasRecentTx && restrictions.invest_limit_no_txn !== null && amount > restrictions.invest_limit_no_txn) {
      return res.status(403).json({
        status: 'fail',
        message: restrictions.txn_restriction_reason || `Complete a transaction first. Limit: $${restrictions.invest_limit_no_txn.toLocaleString()}`
      });
    }
    
    if (userRestrictionStatus) {
      if (userRestrictionStatus.kyc_restricted && restrictions.invest_limit_no_kyc !== null && amount > restrictions.invest_limit_no_kyc) {
        return res.status(403).json({
          status: 'fail',
          message: userRestrictionStatus.kyc_restriction_reason || restrictions.kyc_restriction_reason
        });
      }
      if (userRestrictionStatus.transaction_restricted && restrictions.invest_limit_no_txn !== null && amount > restrictions.invest_limit_no_txn) {
        return res.status(403).json({
          status: 'fail',
          message: userRestrictionStatus.transaction_restriction_reason || restrictions.txn_restriction_reason
        });
      }
    }

    const plan = await Plan.findById(planId);
    if (!plan || !plan.isActive) {
      return res.status(400).json({
        status: 'fail',
        message: 'Invalid or inactive investment plan'
      });
    }

    if (amount < plan.minAmount || amount > plan.maxAmount) {
      return res.status(400).json({
        status: 'fail',
        message: `Amount must be between $${plan.minAmount} and $${plan.maxAmount} for this plan`
      });
    }

    // ✅ CHECK FOR EXISTING ACTIVE INVESTMENT IN THE SAME PLAN
    const existingActiveInvestment = await Investment.findOne({
      user: userId,
      plan: planId,
      status: 'active'
    });

    if (existingActiveInvestment) {
      return res.status(400).json({
        status: 'fail',
        message: `You already have an active investment in the ${plan.name} plan. Please wait until it matures (${plan.duration} hours) before investing again.`
      });
    }

    // =============================================
    // REAL-TIME BTC PRICE WITH MULTIPLE API FALLBACKS
    // =============================================
    const btcPrice = await getRealTimeBitcoinPrice();
    const amountInBTC = amount / btcPrice;
    
    // Get user with balances
    const user = await User.findById(userId);
    
    // Initialize balances Maps if they don't exist
    if (!user.balances) {
      user.balances = {
        main: new Map(),
        active: new Map(),
        matured: new Map()
      };
    }
    
    // ✅ CORRECT: Get Bitcoin balance from main wallet using .get('btc')
    const mainBitcoinBalance = user.balances.main?.get('btc') || 0;
    
    // ✅ CORRECT: Get Bitcoin balance from matured wallet using .get('btc')
    const maturedBitcoinBalance = user.balances.matured?.get('btc') || 0;
    
    console.log(`📊 BTC Balance Check for ${user.email}:`);
    console.log(`   Main Wallet BTC: ${mainBitcoinBalance} BTC`);
    console.log(`   Matured Wallet BTC: ${maturedBitcoinBalance} BTC`);
    console.log(`   Investment: $${amount} USD = ${amountInBTC.toFixed(8)} BTC`);
    console.log(`   BTC Price from API: $${btcPrice}`);
    
    // Check balance based on selected wallet type
    let selectedBitcoinBalance = 0;
    let walletName = '';
    
    if (balanceType === 'main') {
      selectedBitcoinBalance = mainBitcoinBalance;
      walletName = 'Main';
    } else if (balanceType === 'matured') {
      selectedBitcoinBalance = maturedBitcoinBalance;
      walletName = 'Matured';
    }
    
    if (selectedBitcoinBalance < amountInBTC) {
      return res.status(400).json({
        status: 'fail',
        message: `Insufficient Bitcoin balance in ${balanceType} wallet. Required: ${amountInBTC.toFixed(8)} BTC, Available: ${selectedBitcoinBalance.toFixed(8)} BTC. Current BTC price: $${btcPrice.toFixed(2)}`,
        debug: {
          requiredBTC: amountInBTC.toFixed(8),
          availableBTC: selectedBitcoinBalance.toFixed(8),
          mainWalletBTC: mainBitcoinBalance,
          maturedWalletBTC: maturedBitcoinBalance,
          btcPrice: btcPrice,
          usdAmount: amount,
          planName: plan.name,
          planMin: plan.minAmount,
          planMax: plan.maxAmount
        }
      });
    }
    
    // Store investment amounts
    const investmentBTCAmount = amountInBTC;
    const investmentFeeUSD = amount * 0.03;
    const investmentAmountAfterFeeUSD = amount - investmentFeeUSD;
    const investmentFeeBTC = investmentBTCAmount * 0.03;
    const investmentAmountAfterFeeBTC = investmentBTCAmount - investmentFeeBTC;
    const expectedReturnUSD = investmentAmountAfterFeeUSD + (investmentAmountAfterFeeUSD * plan.percentage / 100);
    const expectedReturnBTC = investmentAmountAfterFeeBTC + (investmentAmountAfterFeeBTC * plan.percentage / 100);
    const endDate = new Date(Date.now() + plan.duration * 60 * 60 * 1000);

    // ✅ CORRECT: Deduct Bitcoin from the selected wallet using Map.set()
    if (balanceType === 'main') {
      const newMainBTCBalance = mainBitcoinBalance - investmentBTCAmount;
      user.balances.main.set('btc', newMainBTCBalance);
      console.log(`   Deducted ${investmentBTCAmount.toFixed(8)} BTC from Main wallet. New balance: ${newMainBTCBalance.toFixed(8)} BTC`);
    } else if (balanceType === 'matured') {
      const newMaturedBTCBalance = maturedBitcoinBalance - investmentBTCAmount;
      user.balances.matured.set('btc', newMaturedBTCBalance);
      console.log(`   Deducted ${investmentBTCAmount.toFixed(8)} BTC from Matured wallet. New balance: ${newMaturedBTCBalance.toFixed(8)} BTC`);
    }
    
    // ✅ CORRECT: Add to active Bitcoin balance using Map.set()
    const currentActiveBTC = user.balances.active?.get('btc') || 0;
    user.balances.active.set('btc', currentActiveBTC + investmentAmountAfterFeeBTC);
    console.log(`   Added ${investmentAmountAfterFeeBTC.toFixed(8)} BTC to Active wallet. New active balance: ${(currentActiveBTC + investmentAmountAfterFeeBTC).toFixed(8)} BTC`);
    
    // Track USD equivalents for reporting
    const currentActiveUSD = user.balances.active?.get('usd') || 0;
    user.balances.active.set('usd', currentActiveUSD + investmentAmountAfterFeeUSD);
    
    await user.save();

    // At the investment creation section (around line 11500 in your file)
const investment = await Investment.create({
  user: userId,
  plan: planId,
  amount: investmentAmountAfterFeeUSD,
  amountBTC: investmentAmountAfterFeeBTC,        // ADD THIS
  originalAmount: amount,
  originalAmountBTC: investmentBTCAmount,       // ADD THIS
  originalCurrency: 'USD',
  currency: 'BTC',
  expectedReturn: expectedReturnUSD,
  expectedReturnBTC: expectedReturnBTC,          // ADD THIS
  returnPercentage: plan.percentage,
  endDate,
  payoutSchedule: 'end_term',
  status: 'active',
  ipAddress: req.ip,
  userAgent: req.headers['user-agent'],
  deviceInfo: getDeviceType(req),
  termsAccepted: true,
  investmentFee: investmentFeeUSD,               // ADD THIS
  investmentFeeBTC: investmentFeeBTC,            // ADD THIS
  balanceType: balanceType,
  btcPriceAtInvestment: btcPrice                // ADD THIS
});
    // ✅ FIXED: Create transaction record with POSITIVE numbers (not negative)
    const transaction = await Transaction.create({
      user: userId,
      type: 'investment',
      amount: amount,
      amountBTC: investmentBTCAmount,
      currency: 'BTC',
      status: 'completed',
      method: 'INTERNAL',
      reference: `INV-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
      details: {
        investmentId: investment._id,
        planName: plan.name,
        balanceType: balanceType,
        investmentFeeUSD: investmentFeeUSD,
        investmentFeeBTC: investmentFeeBTC,
        amountAfterFeeUSD: investmentAmountAfterFeeUSD,
        amountAfterFeeBTC: investmentAmountAfterFeeBTC,
        btcPrice: btcPrice,
        transactionType: 'debit'
      },
      fee: investmentFeeUSD,
      netAmount: investmentAmountAfterFeeUSD
    });

    // Record platform revenue
    await PlatformRevenue.create({
      source: 'investment_fee',
      amount: investmentFeeUSD,
      amountBTC: investmentFeeBTC,
      currency: 'BTC',
      transactionId: transaction._id,
      investmentId: investment._id,
      userId: userId,
      description: `3% investment fee for ${plan.name} investment`,
      metadata: {
        planName: plan.name,
        originalAmountUSD: amount,
        originalAmountBTC: investmentBTCAmount,
        amountAfterFeeUSD: investmentAmountAfterFeeUSD,
        amountAfterFeeBTC: investmentAmountAfterFeeBTC,
        feePercentage: 3,
        btcPrice: btcPrice
      }
    });

    // ✅ FIXED: Create user log with correct location object structure
    const deviceInfo = await getUserDeviceInfo(req);
    await UserLog.create({
      user: userId,
      username: user.email,
      email: user.email,
      userFullName: `${user.firstName} ${user.lastName}`,
      action: 'investment_created',
      actionCategory: 'investment',
      ipAddress: getRealClientIP(req),
      userAgent: req.headers['user-agent'] || 'Unknown',
      deviceInfo: {
        type: getDeviceType(req),
        os: { 
          name: getOSFromUserAgent(req.headers['user-agent']), 
          version: 'Unknown' 
        },
        browser: { 
          name: getBrowserFromUserAgent(req.headers['user-agent']), 
          version: 'Unknown' 
        },
        platform: req.headers['user-agent'] || 'Unknown',
        language: req.headers['accept-language'] || 'Unknown',
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone
      },
      location: {
        ip: getRealClientIP(req),
        country: {
          name: deviceInfo.locationDetails?.country || 'Unknown',
          code: (deviceInfo.locationDetails?.country_code || deviceInfo.locationDetails?.country || 'Unknown').substring(0, 2)
        },
        region: {
          name: deviceInfo.locationDetails?.region || 'Unknown',
          code: deviceInfo.locationDetails?.region_code || deviceInfo.locationDetails?.region || 'Unknown'
        },
        city: deviceInfo.locationDetails?.city || 'Unknown',
        postalCode: deviceInfo.locationDetails?.postalCode || 'Unknown',
        latitude: deviceInfo.locationDetails?.latitude || null,
        longitude: deviceInfo.locationDetails?.longitude || null,
        timezone: deviceInfo.locationDetails?.timezone || 'Unknown',
        isp: deviceInfo.locationDetails?.isp || 'Unknown',
        exactLocation: deviceInfo.exactLocation || false
      },
      status: 'success',
      metadata: {
        planName: plan.name,
        investmentAmountUSD: amount,
        investmentAmountBTC: investmentBTCAmount,
        amountAfterFeeUSD: investmentAmountAfterFeeUSD,
        amountAfterFeeBTC: investmentAmountAfterFeeBTC,
        investmentFeeUSD: investmentFeeUSD,
        investmentFeeBTC: investmentFeeBTC,
        expectedReturnUSD: expectedReturnUSD,
        expectedReturnBTC: expectedReturnBTC,
        btcPriceAtInvestment: btcPrice,
        duration: plan.duration,
        roiPercentage: plan.percentage,
        endDate: endDate,
        balanceTypeUsed: balanceType
      },
      relatedEntity: investment._id,
      relatedEntityModel: 'Investment'
    });

    // Handle referral commissions
    await calculateReferralCommissions(investment);

    // Handle direct referral bonus
    if (user.referredBy) {
      const referralBonusUSD = (amount * plan.referralBonus) / 100;
      const referralBonusBTC = referralBonusUSD / btcPrice;
      
      const referrer = await User.findById(user.referredBy);
      if (referrer) {
        if (!referrer.balances) {
          referrer.balances = { main: new Map(), active: new Map(), matured: new Map() };
        }
        const currentReferrerBTC = referrer.balances.main?.get('btc') || 0;
        referrer.balances.main.set('btc', currentReferrerBTC + referralBonusBTC);
        await referrer.save();
        
        console.log(`🎁 Referral bonus: ${referralBonusBTC.toFixed(8)} BTC paid to ${referrer.email}`);
      }
    }

    // =============================================
    // SEND SISTER EMAIL FOR INVESTMENT CREATION
    // Using direct email sending to match deposit_approved style
    // =============================================
    try {
      const getCryptoLogoUrl = (asset) => {
        const logoMap = {
          'BTC': 'https://assets.coingecko.com/coins/images/1/large/bitcoin.png',
          'ETH': 'https://assets.coingecko.com/coins/images/279/large/ethereum.png',
          'USDT': 'https://assets.coingecko.com/coins/images/325/large/Tether.png'
        };
        return logoMap[asset.toUpperCase()] || 'https://assets.coingecko.com/coins/images/1/large/bitcoin.png';
      };

      const cryptoLogoUrl = getCryptoLogoUrl('BTC');
      const formattedAmount = amount.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 });
      const formattedInvestmentBTC = investmentAmountAfterFeeBTC.toLocaleString(undefined, { minimumFractionDigits: 8, maximumFractionDigits: 8 });
      const formattedOriginalBTC = investmentBTCAmount.toLocaleString(undefined, { minimumFractionDigits: 8, maximumFractionDigits: 8 });
      const formattedFeeUSD = investmentFeeUSD.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 });
      const formattedFeeBTC = investmentFeeBTC.toLocaleString(undefined, { minimumFractionDigits: 8, maximumFractionDigits: 8 });
      const formattedExpectedReturnUSD = expectedReturnUSD.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 });
      const formattedExpectedReturnBTC = expectedReturnBTC.toLocaleString(undefined, { minimumFractionDigits: 8, maximumFractionDigits: 8 });
      const formattedBtcPrice = btcPrice.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 });
      const formattedStartDate = new Date().toLocaleString('en-US', {
        year: 'numeric',
        month: 'long',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        timeZoneName: 'short'
      });
      const formattedEndDate = endDate.toLocaleString('en-US', {
        year: 'numeric',
        month: 'long',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        timeZoneName: 'short'
      });

      // Direct email sending using nodemailer to ensure delivery
      const mailTransporter = infoTransporter;
      
      // Build the HTML email matching deposit_approved style
      const emailHtml = `
        <div style="font-family: 'Inter', sans-serif; max-width: 600px; margin: 0 auto; background: #FFFFFF;">
          <div style="text-align: center; padding: 30px 20px 20px 20px; background: linear-gradient(135deg, #0B0E11 0%, #11151C 100%);">
            <img src="https://media.bithashcapital.live/ChatGPT%20Image%20Mar%2029%2C%202026%2C%2004_52_02%20PM.png" alt="₿itHash Logo" style="width: 60px; height: 60px; margin-bottom: 15px;">
            <h1 style="color: #FFFFFF; font-size: 28px; margin: 0; font-weight: bold;">₿itHash</h1>
            <p style="color: #B7BDC6; font-size: 14px; margin: 10px 0 0 0;"><i><strong>Where Your Financial Goals Become Reality</strong></i></p>
          </div>
          
          <div style="padding: 30px; background: #FFFFFF;">
            <div style="background: #ECFDF5; border-radius: 12px; padding: 16px 20px; text-align: center; margin-bottom: 25px;">
              <div style="display: flex; align-items: center; justify-content: center; gap: 10px; margin-bottom: 8px;">
                <img src="${cryptoLogoUrl}" width="32" height="32" style="border-radius: 50%;">
                <svg width="32" height="32" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                  <circle cx="12" cy="12" r="10" stroke="#10B981" stroke-width="2"/>
                  <path d="M8 12L11 15L16 9" stroke="#10B981" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                </svg>
              </div>
              <h2 style="color: #10B981; font-size: 20px; margin: 0 0 4px 0; font-weight: 700;"> Mining Contract Activated!</h2>
              <p style="color: #065F46; font-size: 13px; margin: 0;">Your mining contract is now active</p>
            </div>
            
            <p style="color: #333333; line-height: 1.6;">Dear <strong>${user.firstName}</strong>,</p>
            <p style="color: #333333; line-height: 1.6;">Great news! Your investment in the <strong>${plan.name}</strong> plan has been successfully activated and credited to your <strong style="color: #10B981;">Active Wallet</strong>.</p>
            
            <div style="background: #F5F5F5; padding: 20px; border-radius: 12px; margin: 20px 0;">
              <div style="display: flex; align-items: center; gap: 12px; padding-bottom: 12px; border-bottom: 1px solid #E2E8F0; margin-bottom: 12px;">
                <img src="${cryptoLogoUrl}" width="32" height="32" style="border-radius: 50%;">
                <div>
                  <div style="font-weight: bold; font-size: 18px; color: #10B981;">+ ${formattedInvestmentBTC} BTC</div>
                  <div style="color: #64748B; font-size: 12px;">≈ $${(investmentAmountAfterFeeUSD).toLocaleString()} USD credited to Active Wallet</div>
                </div>
              </div>
              
              <table style="width: 100%; border-collapse: collapse;">
                <tr>
                  <td style="padding: 8px 0;"><strong>Plan Name:</strong></td>
                  <td style="padding: 8px 0; text-align: right;">${plan.name}</td>
                </tr>
                <tr style="border-top: 1px solid #E2E8F0;">
                  <td style="padding: 8px 0;"><strong>Investment Amount (Gross):</strong></td>
                  <td style="padding: 8px 0; text-align: right;">${formattedOriginalBTC} BTC (≈ $${formattedAmount} USD)</td>
                </tr>
                <tr style="border-top: 1px solid #E2E8F0;">
                  <td style="padding: 8px 0;"><strong style="color: #EF4444;">Contract Initiation Fee (3%):</strong></td>
                  <td style="padding: 8px 0; text-align: right;"><strong style="color: #EF4444;">- ${formattedFeeBTC} BTC (≈ $${formattedFeeUSD} USD)</strong></td>
                </tr>
                <tr style="border-top: 1px solid #E2E8F0;">
                  <td style="padding: 8px 0;"><strong>Net Amount Invested:</strong></td>
                  <td style="padding: 8px 0; text-align: right;">${formattedInvestmentBTC} BTC</td>
                </tr>
                <tr style="border-top: 1px solid #E2E8F0;">
                  <td style="padding: 8px 0;"><strong>Expected Return:</strong></td>
                  <td style="padding: 8px 0; text-align: right; font-weight: bold; color: #10B981;">+ ${formattedExpectedReturnBTC} BTC (≈ $${formattedExpectedReturnUSD} USD)</td>
                </tr>
                <tr style="border-top: 1px solid #E2E8F0;">
                  <td style="padding: 8px 0;"><strong>ROI Percentage:</strong></td>
                  <td style="padding: 8px 0; text-align: right; color: #10B981;">+${plan.percentage}%</td>
                </tr>
                <tr style="border-top: 1px solid #E2E8F0;">
                  <td style="padding: 8px 0;"><strong>Duration:</strong></td>
                  <td style="padding: 8px 0; text-align: right;">${plan.duration} hours</td>
                </tr>
                <tr style="border-top: 1px solid #E2E8F0;">
                  <td style="padding: 8px 0;"><strong>Hashrate (TH/s):</strong></td>
                  <td style="padding: 8px 0; text-align: right;">${plan.duration === 10 ? '68' : plan.duration === 24 ? '110' : plan.duration === 48 ? '150' : plan.duration === 72 ? '234' : '255'} TH/s</td>
                </tr>
                <tr style="border-top: 1px solid #E2E8F0;">
                  <td style="padding: 8px 0;"><strong>Mining Type:</strong></td>
                  <td style="padding: 8px 0; text-align: right;">SHA-256 ASIC mining</td>
                </tr>
                <tr style="border-top: 1px solid #E2E8F0;">
                  <td style="padding: 8px 0;"><strong>Start Date:</strong></td>
                  <td style="padding: 8px 0; text-align: right;">${formattedStartDate}</td>
                </tr>
                <tr style="border-top: 1px solid #E2E8F0;">
                  <td style="padding: 8px 0;"><strong>Expected Maturity:</strong></td>
                  <td style="padding: 8px 0; text-align: right; color: #F7A600;">${formattedEndDate}</td>
                </tr>
                <tr style="border-top: 1px solid #E2E8F0;">
                  <td style="padding: 8px 0;"><strong>Wallet Credited:</strong></td>
                  <td style="padding: 8px 0; text-align: right;"><span style="background: #10B981; color: white; padding: 2px 10px; border-radius: 20px; font-size: 12px;">Active Wallet</span></td>
                </tr>
                <tr style="border-top: 1px solid #E2E8F0;">
                  <td style="padding: 8px 0;"><strong>Deducted From:</strong></td>
                  <td style="padding: 8px 0; text-align: right;"><span style="background: #F7A600; color: #000000; padding: 2px 10px; border-radius: 20px; font-size: 12px;">${walletName} Wallet</span></td>
                </tr>
                <tr style="border-top: 1px solid #E2E8F0;">
                  <td style="padding: 8px 0;"><strong>Exchange Rate (BTC/USD):</strong></td>
                  <td style="padding: 8px 0; text-align: right;">1 BTC = $${formattedBtcPrice}</td>
                </tr>
                <tr style="border-top: 1px solid #E2E8F0;">
                  <td style="padding: 8px 0;"><strong>Contract ID:</strong></td>
                  <td style="padding: 8px 0; text-align: right; font-size: 11px;">${transaction.reference}</td>
                </tr>
              </table>
            </div>
            
            <div style="background: #FEF3C7; border-left: 4px solid #F7A600; padding: 16px 20px; border-radius: 8px; margin: 20px 0;">
              <p style="color: #92400E; margin: 0 0 8px 0; font-weight: 600;">ⓘ Mining Information</p>
              <p style="color: #78350F; margin: 0; font-size: 14px;">Your mining contract will automatically mature after ${plan.duration} hours. The proceeds will be credited to your Matured Wallet.</p>
            </div>
            
            <div style="text-align: center; margin: 30px 0;">
              <a href="https://www.bithashcapital.live/dashboard" style="background-color: #F7A600; color: #000000; padding: 12px 30px; text-decoration: none; border-radius: 999px; font-weight: 600; display: inline-block;">Track Your Investment</a>
            </div>
            
            <p style="color: #666666; font-size: 12px; margin-top: 30px;">Email sent: ${formattedStartDate}</p>
          </div>
          
          <div style="text-align: center; padding: 20px; background: #0B0E11; border-top: 1px solid #1E2329;">
            <p style="color: #6C7480; font-size: 12px; margin: 5px 0;">&copy; ${new Date().getFullYear()} ₿itHash Capital. All rights reserved.</p>
            <p style="color: #6C7480; font-size: 12px; margin: 5px 0;">800 Plant St, Wilmington, DE 19801, United States</p>
            <p style="color: #6C7480; font-size: 12px; margin: 5px 0;">
              <a href="mailto:support@bithashcapital.live" style="color: #F7A600; text-decoration: none;">support@bithashcapital.live</a> | 
              <a href="https://www.bithashcapital.live" style="color: #F7A600; text-decoration: none;">www.bithashcapital.live</a>
            </p>
          </div>
        </div>
      `;

      await mailTransporter.sendMail({
        from: `₿itHash Capital <${process.env.EMAIL_INFO_USER}>`,
        to: user.email,
        subject: `✅ Mining Contract Activated - ₿itHash Capital`,
        html: emailHtml
      });
      
      console.log(`📧 Investment confirmation email sent to ${user.email}`);
    } catch (emailError) {
      console.error('Failed to send investment email:', emailError);
    }

    res.status(201).json({
      status: 'success',
      data: {
        investment: {
          id: investment._id,
          plan: plan.name,
          amountUSD: investment.amount,
          amountBTC: investment.amountBTC,
          investmentFeeUSD: investmentFeeUSD,
          investmentFeeBTC: investmentFeeBTC,
          expectedReturnUSD: investment.expectedReturn,
          expectedReturnBTC: investment.expectedReturnBTC,
          endDate: investment.endDate,
          status: investment.status,
          balanceType: balanceType,
          btcPriceAtInvestment: btcPrice
        }
      }
    });
    
  } catch (err) {
    console.error('Investment creation error:', err);
    res.status(500).json({
      status: 'error',
      message: err.message || 'Failed to create investment'
    });
  }
});

// =============================================
// REAL-TIME BITCOIN PRICE WITH MULTIPLE API FALLBACKS
// ALL FALLBACKS FETCH FROM ONLINE APIs - NO HARDCODED VALUES
// =============================================
async function getRealTimeBitcoinPrice() {
  const errors = [];
  
  // API 1: CoinGecko
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000);
    const response = await fetch('https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies=usd', {
      signal: controller.signal
    });
    clearTimeout(timeoutId);
    if (response.ok) {
      const data = await response.json();
      if (data?.bitcoin?.usd && data.bitcoin.usd > 0) {
        console.log(`✅ BTC price from CoinGecko: $${data.bitcoin.usd}`);
        return data.bitcoin.usd;
      }
    }
    errors.push('CoinGecko: Invalid response');
  } catch (err) {
    errors.push(`CoinGecko: ${err.message}`);
  }
  
  // API 2: Binance
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000);
    const response = await fetch('https://api.binance.com/api/v3/ticker/price?symbol=BTCUSDT', {
      signal: controller.signal
    });
    clearTimeout(timeoutId);
    if (response.ok) {
      const data = await response.json();
      if (data?.price && parseFloat(data.price) > 0) {
        const price = parseFloat(data.price);
        console.log(`✅ BTC price from Binance: $${price}`);
        return price;
      }
    }
    errors.push('Binance: Invalid response');
  } catch (err) {
    errors.push(`Binance: ${err.message}`);
  }
  
  // API 3: Kraken
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000);
    const response = await fetch('https://api.kraken.com/0/public/Ticker?pair=XBTUSD', {
      signal: controller.signal
    });
    clearTimeout(timeoutId);
    if (response.ok) {
      const data = await response.json();
      if (data?.result?.XXBTZUSD?.c?.[0]) {
        const price = parseFloat(data.result.XXBTZUSD.c[0]);
        if (price > 0) {
          console.log(`✅ BTC price from Kraken: $${price}`);
          return price;
        }
      }
    }
    errors.push('Kraken: Invalid response');
  } catch (err) {
    errors.push(`Kraken: ${err.message}`);
  }
  
  // API 4: CryptoCompare
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000);
    const response = await fetch('https://min-api.cryptocompare.com/data/price?fsym=BTC&tsyms=USD', {
      signal: controller.signal
    });
    clearTimeout(timeoutId);
    if (response.ok) {
      const data = await response.json();
      if (data?.USD && data.USD > 0) {
        console.log(`✅ BTC price from CryptoCompare: $${data.USD}`);
        return data.USD;
      }
    }
    errors.push('CryptoCompare: Invalid response');
  } catch (err) {
    errors.push(`CryptoCompare: ${err.message}`);
  }
  
  // API 5: Coinbase
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000);
    const response = await fetch('https://api.coinbase.com/v2/prices/BTC-USD/spot', {
      signal: controller.signal
    });
    clearTimeout(timeoutId);
    if (response.ok) {
      const data = await response.json();
      if (data?.data?.amount && parseFloat(data.data.amount) > 0) {
        const price = parseFloat(data.data.amount);
        console.log(`✅ BTC price from Coinbase: $${price}`);
        return price;
      }
    }
    errors.push('Coinbase: Invalid response');
  } catch (err) {
    errors.push(`Coinbase: ${err.message}`);
  }
  
  // API 6: KuCoin
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000);
    const response = await fetch('https://api.kucoin.com/api/v1/market/orderbook/level1?symbol=BTC-USDT', {
      signal: controller.signal
    });
    clearTimeout(timeoutId);
    if (response.ok) {
      const data = await response.json();
      if (data?.data?.price && parseFloat(data.data.price) > 0) {
        const price = parseFloat(data.data.price);
        console.log(`✅ BTC price from KuCoin: $${price}`);
        return price;
      }
    }
    errors.push('KuCoin: Invalid response');
  } catch (err) {
    errors.push(`KuCoin: ${err.message}`);
  }
  
  // API 7: Bybit
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000);
    const response = await fetch('https://api.bybit.com/v5/market/tickers?category=spot&symbol=BTCUSDT', {
      signal: controller.signal
    });
    clearTimeout(timeoutId);
    if (response.ok) {
      const data = await response.json();
      if (data?.result?.list?.[0]?.lastPrice) {
        const price = parseFloat(data.result.list[0].lastPrice);
        if (price > 0) {
          console.log(`✅ BTC price from Bybit: $${price}`);
          return price;
        }
      }
    }
    errors.push('Bybit: Invalid response');
  } catch (err) {
    errors.push(`Bybit: ${err.message}`);
  }
  
  // API 8: OKX
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000);
    const response = await fetch('https://www.okx.com/api/v5/market/ticker?instId=BTC-USDT', {
      signal: controller.signal
    });
    clearTimeout(timeoutId);
    if (response.ok) {
      const data = await response.json();
      if (data?.data?.[0]?.last && parseFloat(data.data[0].last) > 0) {
        const price = parseFloat(data.data[0].last);
        console.log(`✅ BTC price from OKX: $${price}`);
        return price;
      }
    }
    errors.push('OKX: Invalid response');
  } catch (err) {
    errors.push(`OKX: ${err.message}`);
  }
  
  // API 9: Huobi
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000);
    const response = await fetch('https://api.huobi.pro/market/detail/merged?symbol=btcusdt', {
      signal: controller.signal
    });
    clearTimeout(timeoutId);
    if (response.ok) {
      const data = await response.json();
      if (data?.tick?.close && parseFloat(data.tick.close) > 0) {
        const price = parseFloat(data.tick.close);
        console.log(`✅ BTC price from Huobi: $${price}`);
        return price;
      }
    }
    errors.push('Huobi: Invalid response');
  } catch (err) {
    errors.push(`Huobi: ${err.message}`);
  }
  
  // API 10: Gemini
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000);
    const response = await fetch('https://api.gemini.com/v1/pubticker/btcusd', {
      signal: controller.signal
    });
    clearTimeout(timeoutId);
    if (response.ok) {
      const data = await response.json();
      if (data?.last && parseFloat(data.last) > 0) {
        const price = parseFloat(data.last);
        console.log(`✅ BTC price from Gemini: $${price}`);
        return price;
      }
    }
    errors.push('Gemini: Invalid response');
  } catch (err) {
    errors.push(`Gemini: ${err.message}`);
  }
  
  // If all APIs failed, log error and throw
  console.error('❌ All BTC price APIs failed. Errors:', errors);
  throw new Error('Unable to fetch current BTC price. Please try again later.');
}

const completeMaturedInvestmentsCron = async () => {
  const startTime = Date.now();
  console.log('🔄 [CRON] Running automatic investment maturity check...');

  try {
    const now = new Date();

    // Find all active investments where endDate has passed
    const maturedInvestments = await Investment.find({
      status: 'active',
      endDate: { $lte: now }
    }).populate('user plan');

    if (maturedInvestments.length === 0) {
      console.log(`📭 [CRON] No matured investments found. Check completed in ${Date.now() - startTime}ms`);
      return;
    }

    console.log(`🎯 [CRON] Found ${maturedInvestments.length} matured investment(s) to complete`);

    let completedCount = 0;
    let failedCount = 0;

    for (const investment of maturedInvestments) {
      try {
        const userId = investment.user._id;
        const user = await User.findById(userId);

        if (!user) {
          console.error(`❌ [CRON] User not found for investment ${investment._id}`);
          failedCount++;
          continue;
        }

        // Get current BTC price
        let currentBTCPrice;
        try {
          currentBTCPrice = await getRealTimeBitcoinPrice();
          console.log(`📊 [CRON] BTC price for ${investment._id}: $${currentBTCPrice}`);
        } catch (priceError) {
          console.error(`❌ [CRON] Failed to get BTC price for ${investment._id}:`, priceError.message);
          currentBTCPrice = investment.btcPriceAtInvestment || 50000;
          console.log(`⚠️ [CRON] Using fallback BTC price: $${currentBTCPrice}`);
        }

        // CRITICAL: Use existing fields with fallbacks
        const principalBTC = investment.amountBTC || 0;
        const principalUSD = investment.amount || 0;
        const expectedReturnUSD = investment.expectedReturn || principalUSD;
        const expectedReturnBTC = investment.expectedReturnBTC || (expectedReturnUSD / currentBTCPrice);
        
        // Calculate total return
        const totalReturnBTC = expectedReturnBTC;
        const totalReturnUSD = expectedReturnUSD;
        const profitBTC = totalReturnBTC - principalBTC;
        const profitUSD = totalReturnUSD - principalUSD;

        console.log(`📊 [CRON] Investment ${investment._id}:`);
        console.log(`   Principal: ${principalBTC} BTC ($${principalUSD})`);
        console.log(`   Expected Return: ${totalReturnBTC} BTC ($${totalReturnUSD})`);
        console.log(`   Profit: ${profitBTC} BTC ($${profitUSD})`);

        // Initialize balances Maps
        if (!user.balances) {
          user.balances = { main: new Map(), active: new Map(), matured: new Map() };
        }
        if (!user.balances.active) user.balances.active = new Map();
        if (!user.balances.matured) user.balances.matured = new Map();

        // FIXED: CORRECTLY check active balance using Map.get()
        const currentActiveBTC = user.balances.active.get('btc') || 0;
        
        // Check if there's enough balance in active wallet (with small tolerance for floating point)
        if (currentActiveBTC < principalBTC - 0.00000001) {
          console.error(`❌ [CRON] Insufficient active BTC balance for ${investment._id}. Required: ${principalBTC}, Available: ${currentActiveBTC}`);
          failedCount++;
          continue;
        }

        // CRITICAL: Use session for atomic operation
        const session = await mongoose.startSession();
        session.startTransaction();

        try {
          // FIXED: Use Map.set() to update active wallet
          const newActiveBTC = currentActiveBTC - principalBTC;
          if (newActiveBTC <= 0.00000001) {
            user.balances.active.delete('btc');
          } else {
            user.balances.active.set('btc', newActiveBTC);
          }

          // FIXED: Use Map.set() to update matured wallet
          const currentMaturedBTC = user.balances.matured.get('btc') || 0;
          user.balances.matured.set('btc', currentMaturedBTC + totalReturnBTC);

          // Update USD equivalents using Map.set()
          const currentActiveUSD = user.balances.active.get('usd') || 0;
          if (currentActiveUSD - principalUSD <= 0.01) {
            user.balances.active.delete('usd');
          } else {
            user.balances.active.set('usd', currentActiveUSD - principalUSD);
          }

          const currentMaturedUSD = user.balances.matured.get('usd') || 0;
          user.balances.matured.set('usd', currentMaturedUSD + totalReturnUSD);

          // Update investment record
          investment.status = 'completed';
          investment.completionDate = now;
          investment.actualReturn = profitUSD;
          investment.actualReturnBTC = profitBTC;
          investment.btcPriceAtCompletion = currentBTCPrice;

          await user.save({ session });
          await investment.save({ session });

          // Create transaction record with valid reference
          const transactionRef = `AUTO-MAT-${Date.now()}-${Math.floor(Math.random() * 10000)}`;
          
          await Transaction.create([{
            user: userId,
            type: 'interest',
            amount: profitUSD,
            amountBTC: profitBTC,
            currency: 'BTC',
            status: 'completed',
            method: 'INTERNAL',
            reference: transactionRef,
            details: {
              investmentId: investment._id,
              planName: investment.plan?.name || 'Unknown Plan',
              principalUSD: principalUSD,
              principalBTC: principalBTC,
              interestUSD: profitUSD,
              interestBTC: profitBTC,
              btcPriceAtStart: investment.btcPriceAtInvestment,
              btcPriceAtCompletion: currentBTCPrice,
              transactionType: 'credit',
              completedBy: 'system_cron'
            },
            fee: 0,
            netAmount: profitUSD,
            netAmountBTC: profitBTC,
            exchangeRateAtTime: currentBTCPrice,
            processedAt: new Date(),
            processedBy: null
          }], { session });

          // Create user log
          await UserLog.create([{
            user: userId,
            username: user.email,
            email: user.email,
            userFullName: `${user.firstName} ${user.lastName}`,
            action: 'investment_matured',
            actionCategory: 'investment',
            ipAddress: 'system.cron',
            userAgent: 'system_cron_job',
            deviceInfo: {
              type: 'system',
              os: { name: 'System', version: '1.0' },
              browser: { name: 'CronJob', version: '1.0' },
              platform: 'server'
            },
            location: {
              ip: 'system.cron',
              country: { name: 'System', code: 'SY' },
              region: { name: 'System', code: 'SY' },
              city: 'System'
            },
            status: 'success',
            metadata: {
              planName: investment.plan?.name,
              originalAmountUSD: investment.originalAmount || principalUSD,
              originalAmountBTC: investment.originalAmountBTC || principalBTC,
              amountAfterFeeUSD: principalUSD,
              amountAfterFeeBTC: principalBTC,
              investmentFeeUSD: investment.investmentFee || 0,
              investmentFeeBTC: investment.investmentFeeBTC || 0,
              expectedReturnBTC: expectedReturnBTC,
              actualReturnBTC: totalReturnBTC,
              profitBTC: profitBTC,
              profitUSD: profitUSD,
              btcPriceAtStart: investment.btcPriceAtInvestment,
              btcPriceAtCompletion: currentBTCPrice,
              startDate: investment.startDate,
              endDate: investment.endDate,
              completionDate: investment.completionDate,
              completedBy: 'system_cron_job'
            },
            relatedEntity: investment._id,
            relatedEntityModel: 'Investment'
          }], { session });

          await session.commitTransaction();

          console.log(`✅ [CRON] Completed investment ${investment._id} for user ${user.email}. Return: ${totalReturnBTC.toFixed(8)} BTC ($${totalReturnUSD.toFixed(2)} USD)`);
          completedCount++;

          // =============================================
          // SEND EMAIL FOR INVESTMENT MATURATION
          // =============================================
          try {
            const getCryptoLogoUrl = (asset) => {
              const logoMap = {
                'BTC': 'https://assets.coingecko.com/coins/images/1/large/bitcoin.png',
                'ETH': 'https://assets.coingecko.com/coins/images/279/large/ethereum.png',
                'USDT': 'https://assets.coingecko.com/coins/images/325/large/Tether.png'
              };
              return logoMap[asset.toUpperCase()] || 'https://assets.coingecko.com/coins/images/1/large/bitcoin.png';
            };

            const cryptoLogoUrl = getCryptoLogoUrl('BTC');
            const formattedPrincipalUSD = principalUSD.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 });
            const formattedPrincipalBTC = principalBTC.toLocaleString(undefined, { minimumFractionDigits: 8, maximumFractionDigits: 8 });
            const formattedReturnUSD = totalReturnUSD.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 });
            const formattedReturnBTC = totalReturnBTC.toLocaleString(undefined, { minimumFractionDigits: 8, maximumFractionDigits: 8 });
            const formattedProfitUSD = profitUSD.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 });
            const formattedProfitBTC = profitBTC.toLocaleString(undefined, { minimumFractionDigits: 8, maximumFractionDigits: 8 });
            const formattedStartPrice = (investment.btcPriceAtInvestment || 50000).toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 });
            const formattedEndPrice = currentBTCPrice.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 });
            const priceChangePercent = ((currentBTCPrice - (investment.btcPriceAtInvestment || 50000)) / (investment.btcPriceAtInvestment || 50000) * 100).toFixed(2);
            const formattedCompletionDate = now.toLocaleString('en-US', {
              year: 'numeric',
              month: 'long',
              day: 'numeric',
              hour: '2-digit',
              minute: '2-digit',
              second: '2-digit',
              timeZoneName: 'short'
            });
            
            const newMaturedBTCBalance = (user.balances.matured?.get('btc') || 0);
            const newMaturedUSDBalance = (user.balances.matured?.get('usd') || 0);
            const formattedNewMaturedBTC = newMaturedBTCBalance.toLocaleString(undefined, { minimumFractionDigits: 8, maximumFractionDigits: 8 });
            const formattedNewMaturedUSD = newMaturedUSDBalance.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 });

            const mailTransporter = infoTransporter;
            
            const emailHtml = `
              <div style="font-family: 'Inter', sans-serif; max-width: 600px; margin: 0 auto; background: #FFFFFF;">
                <div style="text-align: center; padding: 30px 20px 20px 20px; background: linear-gradient(135deg, #0B0E11 0%, #11151C 100%);">
                  <img src="https://media.bithashcapital.live/ChatGPT%20Image%20Mar%2029%2C%202026%2C%2004_52_02%20PM.png" alt="₿itHash Logo" style="width: 60px; height: 60px; margin-bottom: 15px;">
                  <h1 style="color: #FFFFFF; font-size: 28px; margin: 0; font-weight: bold;">₿itHash</h1>
                  <p style="color: #B7BDC6; font-size: 14px; margin: 10px 0 0 0;"><i><strong>Where Your Financial Goals Become Reality</strong></i></p>
                </div>
                
                <div style="padding: 30px; background: #FFFFFF;">
                  <div style="background: #ECFDF5; border-radius: 12px; padding: 16px 20px; text-align: center; margin-bottom: 25px;">
                    <div style="display: flex; align-items: center; justify-content: center; gap: 10px; margin-bottom: 8px;">
                      <img src="${cryptoLogoUrl}" width="32" height="32" style="border-radius: 50%;">
                      <svg width="32" height="32" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                        <circle cx="12" cy="12" r="10" stroke="#10B981" stroke-width="2"/>
                        <path d="M8 12L11 15L16 9" stroke="#10B981" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                      </svg>
                    </div>
                    <h2 style="color: #10B981; font-size: 20px; margin: 0 0 4px 0; font-weight: 700;">INVESTMENT MATURED!</h2>
                    <p style="color: #065F46; font-size: 13px; margin: 0;">Your mining contract has successfully completed</p>
                  </div>
                  
                  <p style="color: #333333; line-height: 1.6;">Dear <strong>${user.firstName}</strong>,</p>
                  <p style="color: #333333; line-height: 1.6;">Congratulations! Your <strong>${investment.plan?.name || 'Investment'}</strong> mining contract has matured. Your returns have been credited to your <strong style="color: #10B981;">Matured Wallet</strong>.</p>
                  
                  <div style="background: #F5F5F5; padding: 20px; border-radius: 12px; margin: 20px 0;">
                    <div style="display: flex; align-items: center; gap: 12px; padding-bottom: 12px; border-bottom: 1px solid #E2E8F0; margin-bottom: 12px;">
                      <img src="${cryptoLogoUrl}" width="32" height="32" style="border-radius: 50%;">
                      <div>
                        <div style="font-weight: bold; font-size: 18px; color: #10B981;">+ ${formattedReturnBTC} BTC</div>
                        <div style="color: #64748B; font-size: 12px;">≈ $${formattedReturnUSD} USD credited to Matured Wallet</div>
                      </div>
                    </div>
                    
                    <table style="width: 100%; border-collapse: collapse;">
                      <tr>
                        <td style="padding: 8px 0;"><strong>Plan Name:</strong></td>
                        <td style="padding: 8px 0; text-align: right;">${investment.plan?.name || 'Investment Plan'}</td>
                      </tr>
                      <tr style="border-top: 1px solid #E2E8F0;">
                        <td style="padding: 8px 0;"><strong>Principal Investment:</strong></td>
                        <td style="padding: 8px 0; text-align: right;">${formattedPrincipalBTC} BTC (≈ $${formattedPrincipalUSD} USD)</td>
                      </tr>
                      <tr style="border-top: 1px solid #E2E8F0;">
                        <td style="padding: 8px 0;"><strong>Total Return:</strong></td>
                        <td style="padding: 8px 0; text-align: right; font-weight: bold; color: #10B981;">+ ${formattedReturnBTC} BTC (≈ $${formattedReturnUSD} USD)</td>
                      </tr>
                      <tr style="border-top: 1px solid #E2E8F0;">
                        <td style="padding: 8px 0;"><strong>Profit Earned:</strong></td>
                        <td style="padding: 8px 0; text-align: right; color: #10B981;">+ ${formattedProfitBTC} BTC (≈ $${formattedProfitUSD} USD)</td>
                      </tr>
                      <tr style="border-top: 1px solid #E2E8F0;">
                        <td style="padding: 8px 0;"><strong>ROI Percentage:</strong></td>
                        <td style="padding: 8px 0; text-align: right; color: #10B981;">+${investment.returnPercentage || 0}%</td>
                      </tr>
                      <tr style="border-top: 1px solid #E2E8F0;">
                        <td style="padding: 8px 0;"><strong>Duration:</strong></td>
                        <td style="padding: 8px 0; text-align: right;">${investment.plan?.duration || 0} hours</td>
                      </tr>
                      <tr style="border-top: 1px solid #E2E8F0;">
                        <td style="padding: 8px 0;"><strong>Completion Date:</strong></td>
                        <td style="padding: 8px 0; text-align: right;">${formattedCompletionDate}</td>
                      </tr>
                      <tr style="border-top: 1px solid #E2E8F0;">
                        <td style="padding: 8px 0;"><strong>New Matured Wallet Balance:</strong></td>
                        <td style="padding: 8px 0; text-align: right; font-weight: bold;">${formattedNewMaturedBTC} BTC (≈ $${formattedNewMaturedUSD} USD)</td>
                      </tr>
                    </table>
                  </div>
                  
                  <div style="background: #FEF3C7; border-left: 4px solid #F7A600; padding: 16px 20px; border-radius: 8px; margin: 20px 0;">
                    <p style="color: #92400E; margin: 0 0 8px 0; font-weight: 600;"> Funds Available in Matured Wallet</p>
                    <p style="color: #78350F; margin: 0; font-size: 14px;">Your matured funds are now available. You can reinvest into a new mining contract, withdraw to your external wallet, or convert to other cryptocurrencies.</p>
                  </div>
                  
                  <div style="text-align: center; margin: 30px 0;">
                    <a href="https://www.bithashcapital.live/dashboard" style="background-color: #10B981; color: #FFFFFF; padding: 12px 30px; text-decoration: none; border-radius: 999px; font-weight: 600; display: inline-block;">Reinvest Now</a>
                  </div>
                  
                  <p style="color: #666666; font-size: 12px; margin-top: 30px;">Email sent: ${formattedCompletionDate}</p>
                </div>
                
                <div style="text-align: center; padding: 20px; background: #0B0E11; border-top: 1px solid #1E2329;">
                  <p style="color: #6C7480; font-size: 12px; margin: 5px 0;">&copy; ${new Date().getFullYear()} ₿itHash Capital. All rights reserved.</p>
                  <p style="color: #6C7480; font-size: 12px; margin: 5px 0;">800 Plant St, Wilmington, DE 19801, United States</p>
                  <p style="color: #6C7480; font-size: 12px; margin: 5px 0;">
                    <a href="mailto:support@bithashcapital.live" style="color: #F7A600; text-decoration: none;">support@bithashcapital.live</a> | 
                    <a href="https://www.bithashcapital.live" style="color: #F7A600; text-decoration: none;">www.bithashcapital.live</a>
                  </p>
                </div>
              </div>
            `;

            await mailTransporter.sendMail({
              from: `₿itHash Capital <${process.env.EMAIL_INFO_USER}>`,
              to: user.email,
              subject: `Congratulations!!!Your Mining Rewards Are Here - ₿itHash Capital`,
              html: emailHtml
            });
            
            console.log(`📧 [CRON] Investment maturity email sent to ${user.email}`);
          } catch (emailError) {
            console.error(`❌ [CRON] Failed to send investment maturity email for ${investment._id}:`, emailError);
          }

          // Emit real-time balance update via Socket.IO
          const io = global.io;
          if (io) {
            io.to(`user_${userId}`).emit('balance_update', {
              main: user.balances.main?.get('usd') || 0,
              active: user.balances.active?.get('usd') || 0,
              matured: user.balances.matured?.get('usd') || 0
            });
          }

        } catch (transactionError) {
          await session.abortTransaction();
          console.error(`❌ [CRON] Transaction failed for investment ${investment._id}:`, transactionError);
          failedCount++;
        } finally {
          session.endSession();
        }

      } catch (investmentError) {
        console.error(`❌ [CRON] Error processing investment ${investment._id}:`, investmentError);
        failedCount++;
      }
    }

    const elapsedTime = Date.now() - startTime;
    console.log(`📊 [CRON] Investment maturity check completed in ${elapsedTime}ms`);
    console.log(`   ✅ Completed: ${completedCount}`);
    console.log(`   ❌ Failed: ${failedCount}`);

  } catch (error) {
    console.error('❌ [CRON] Fatal error in investment maturity cron job:', error);
  }
};

// =============================================
// SCHEDULE INVESTMENT MATURITY CRON JOB - EVERY 10 SECONDS
// WITH USER DETECTION LOGS
// =============================================

// Schedule the cron job to run every 10 seconds
cron.schedule('*/10 * * * * *', async () => {
  const runTime = new Date().toISOString();
  console.log(`\n${'='.repeat(70)}`);
  console.log(`⏰ [CRON SCHEDULER] Investment maturity check STARTED at ${runTime}`);
  console.log(`⏰ [CRON SCHEDULER] Next check scheduled in 10 seconds`);
  console.log(`${'='.repeat(70)}`);
  
  try {
    // Find matured investments first to log which users were found
    const now = new Date();
    const maturedInvestments = await Investment.find({
      status: 'active',
      endDate: { $lte: now }
    }).populate('user plan');
    
    if (maturedInvestments.length > 0) {
      console.log(`\n🔍 [CRON SCHEDULER] FOUND ${maturedInvestments.length} USER(S) WITH MATURED INVESTMENTS:`);
      console.log(`${'─'.repeat(70)}`);
      
      for (const investment of maturedInvestments) {
        const userEmail = investment.user?.email || 'Unknown User';
        const userName = investment.user ? `${investment.user.firstName || ''} ${investment.user.lastName || ''}`.trim() || 'Unknown' : 'Unknown';
        const planName = investment.plan?.name || 'Unknown Plan';
        const investmentAmount = investment.amount || 0;
        const expectedReturn = investment.expectedReturn || 0;
        
        console.log(`\n👤 USER FOUND: ${userEmail} (${userName})`);
        console.log(`   ├─ Investment ID: ${investment._id}`);
        console.log(`   ├─ Plan: ${planName}`);
        console.log(`   ├─ Amount: $${investmentAmount.toLocaleString()}`);
        console.log(`   ├─ Expected Return: $${expectedReturn.toLocaleString()}`);
        console.log(`   ├─ Profit: $${(expectedReturn - investmentAmount).toLocaleString()}`);
        console.log(`   └─ End Date: ${investment.endDate}`);
      }
      console.log(`\n${'─'.repeat(70)}`);
      console.log(`🔄 [CRON SCHEDULER] Processing ${maturedInvestments.length} matured investment(s)...\n`);
    } else {
      console.log(`📭 [CRON SCHEDULER] No users with matured investments found at ${runTime}`);
    }
    
    // Run the actual cron job to process them
    await completeMaturedInvestmentsCron();
    
    const endTime = new Date().toISOString();
    console.log(`✅ [CRON SCHEDULER] Investment maturity check COMPLETED at ${endTime}`);
    console.log(`✅ [CRON SCHEDULER] Duration: ${Date.now() - new Date(runTime).getTime()}ms`);
    console.log(`${'='.repeat(70)}\n`);
    
  } catch (error) {
    console.error(`❌ [CRON SCHEDULER] Investment maturity check FAILED at ${new Date().toISOString()}`);
    console.error(`❌ [CRON SCHEDULER] Error:`, error.message);
    console.log(`${'='.repeat(70)}\n`);
  }
});

console.log('🚀 Investment maturity cron job scheduled to run EVERY 10 SECONDS');
console.log('📊 The system will log which users have matured investments at each check');
console.log('⏰ First check will run immediately when the schedule triggers\n');
















// OTP Verification Endpoint
app.post('/api/auth/verify-otp', [
  body('email').isEmail().withMessage('Please provide a valid email'),
  body('otp').isLength({ min: 6, max: 6 }).withMessage('OTP must be 6 digits')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      errors: errors.array()
    });
  }

  try {
    const { email, otp } = req.body;

    // Find valid OTP
    const otpRecord = await OTP.findOne({
      email: email,
      otp: otp,
      used: false,
      expiresAt: { $gt: new Date() }
    });

    if (!otpRecord) {
      return res.status(400).json({
        status: 'fail',
        message: 'Invalid or expired OTP'
      });
    }

    // Mark OTP as used
    otpRecord.used = true;
    await otpRecord.save();

    // Find user
    const user = await User.findOne({ email: email });
    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'User not found'
      });
    }

    // Update user verification status if needed
    if (!user.isVerified) {
      user.isVerified = true;
      await user.save();
    }

    // Update last login
    user.lastLogin = new Date();
    const deviceInfo = await getUserDeviceInfo(req);
    user.loginHistory.push({
      ip: deviceInfo.ip,
      device: deviceInfo.device,
      location: deviceInfo.location,
      timestamp: new Date()
    });
    await user.save();

    // ✅ FIXED: Use logActivity instead of logUserActivity
    await logActivity('login', 'user', user._id, user._id, 'User', req, {
      method: 'otp',
      deviceInfo: deviceInfo,
      status: 'success'
    });

    // Send login success email with device and location
    await sendAutomatedEmail(user, 'login_success', {
      name: user.firstName,
      device: deviceInfo.device,
      location: deviceInfo.location,
      ip: deviceInfo.ip
    });

    // Generate final JWT
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
      data: {
        user: {
          id: user._id,
          firstName: user.firstName,
          lastName: user.lastName,
          email: user.email,
          isVerified: user.isVerified
        }
      }
    });

  } catch (err) {
    console.error('OTP verification error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred during verification'
    });
  }
});


// Send OTP Endpoint (for resend)
app.post('/api/auth/send-otp', [
  body('email').isEmail().withMessage('Please provide a valid email')
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

    // Rate limiting - check recent OTP requests
    const recentOTP = await OTP.findOne({
      email: email,
      createdAt: { $gt: new Date(Date.now() - 60000) } // Last minute
    });

    if (recentOTP) {
      return res.status(429).json({
        status: 'fail',
        message: 'Please wait before requesting a new OTP'
      });
    }

    // Generate new OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes

    // Invalidate old OTPs
    await OTP.updateMany(
      { email: email, used: false },
      { used: true }
    );

    // Create new OTP
    await OTP.create({
      email: email,
      otp,
      type: 'login',
      expiresAt,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent']
    });

    // Send OTP email
    const user = await User.findOne({ email });
    await sendProfessionalEmail({
      email: email,
      template: 'otp',
      data: {
        name: user ? user.firstName : 'there',
        otp: otp,
        action: 'verification'
      }
    });

    res.status(200).json({
      status: 'success',
      message: 'OTP sent successfully'
    });

  } catch (err) {
    console.error('Send OTP error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to send OTP'
    });
  }
});

























// =============================================
// ENDPOINT 1: USER LOCATION - ROBUST ENTERPRISE VERSION (EXACT LOCATION)
// =============================================
app.post('/api/users/location', protect, async (req, res) => {
  try {
    const { lat, lng } = req.body;
    const userId = req.user._id;
    const ipAddress = getRealClientIP(req);
    const userAgent = req.headers['user-agent'] || 'Unknown';
    
    // Validate coordinates
    if (!lat || !lng || typeof lat !== 'number' || typeof lng !== 'number') {
      return res.status(400).json({
        status: 'fail',
        message: 'Valid latitude and longitude are required'
      });
    }
    
    if (lat < -90 || lat > 90 || lng < -180 || lng > 180) {
      return res.status(400).json({
        status: 'fail',
        message: 'Invalid coordinate range'
      });
    }
    
    // Get exact location details from IP (not approximate)
    let locationDetails = {
      country: 'Unknown',
      city: 'Unknown',
      region: 'Unknown',
      street: 'Unknown',
      postalCode: 'Unknown',
      timezone: 'Unknown'
    };
    let exactLocation = false;
    
    try {
      // Try multiple IP geolocation services for exact location
      const ipinfoToken = process.env.IPINFO_TOKEN || 'b56ce6e91d732d';
      
      // Primary: ipinfo.io
      try {
        const geoResponse = await axios.get(`https://ipinfo.io/${ipAddress}?token=${ipinfoToken}`, { timeout: 5000 });
        if (geoResponse.data) {
          locationDetails = {
            country: geoResponse.data.country || 'Unknown',
            city: geoResponse.data.city || 'Unknown',
            region: geoResponse.data.region || 'Unknown',
            street: geoResponse.data.street || 'Unknown',
            postalCode: geoResponse.data.postal || 'Unknown',
            timezone: geoResponse.data.timezone || 'Unknown'
          };
          if (geoResponse.data.loc && geoResponse.data.loc.includes(',')) {
            exactLocation = true;
          }
        }
      } catch (ipinfoError) {
        // Fallback: ipapi.co
        const geoResponse = await axios.get(`https://ipapi.co/${ipAddress}/json/`, { timeout: 5000 });
        if (geoResponse.data && !geoResponse.data.error) {
          locationDetails = {
            country: geoResponse.data.country_name || 'Unknown',
            city: geoResponse.data.city || 'Unknown',
            region: geoResponse.data.region || 'Unknown',
            street: 'Unknown',
            postalCode: geoResponse.data.postal || 'Unknown',
            timezone: geoResponse.data.timezone || 'Unknown'
          };
          if (geoResponse.data.latitude && geoResponse.data.longitude) {
            exactLocation = true;
          }
        }
      }
    } catch (geoError) {
      console.log('Geolocation failed for exact location:', geoError.message);
    }
    
    // Update user with exact location
    await User.findByIdAndUpdate(userId, {
      $set: {
        'location.lastKnown': {
          lat: lat,
          lng: lng,
          country: locationDetails.country,
          city: locationDetails.city,
          region: locationDetails.region,
          street: locationDetails.street,
          postalCode: locationDetails.postalCode,
          timezone: locationDetails.timezone,
          exactLocation: exactLocation,
          updatedAt: new Date(),
          ipAddress: ipAddress,
          userAgent: userAgent
        }
      },
      $push: {
        locationHistory: {
          $each: [{
            lat: lat,
            lng: lng,
            locationDetails: locationDetails,
            ipAddress: ipAddress,
            userAgent: userAgent,
            timestamp: new Date(),
            exactLocation: exactLocation
          }],
          $slice: -100
        }
      }
    });
    
    // Log activity with exact location
    await logActivity('location_updated', 'User', userId, userId, 'User', req, { 
      lat, 
      lng, 
      locationDetails,
      exactLocation 
    });
    
    res.status(200).json({
      status: 'success',
      message: 'Exact location updated successfully',
      data: { location: locationDetails, coordinates: { lat, lng }, exactLocation }
    });
    
  } catch (error) {
    console.error('Location update error:', error);
    res.status(500).json({
      status: 'error',
      message: 'Failed to update location'
    });
  }
});





// ✅ ADD ENDPOINT TO GET USER RESTRICTION STATUS WITH MESSAGE
app.get('/api/user/restriction-status', protect, async (req, res) => {
  try {
    const userId = req.user._id;
    
    const restrictionStatus = await UserRestrictionStatus.findOne({ user: userId });
    const restrictions = await AccountRestrictions.getInstance();
    const limits = await AccountRestrictions.getUserLimits(userId);
    
    let restrictionMessage = null;
    
    if (restrictionStatus) {
      if (restrictionStatus.kyc_restricted) {
        restrictionMessage = restrictionStatus.kyc_restriction_reason || restrictions.kyc_restriction_reason;
      } else if (restrictionStatus.transaction_restricted) {
        restrictionMessage = restrictionStatus.transaction_restriction_reason || restrictions.txn_restriction_reason;
      }
    }
    
    res.json({
      status: 'success',
      data: {
        kyc_restricted: restrictionStatus?.kyc_restricted || false,
        transaction_restricted: restrictionStatus?.transaction_restricted || false,
        restriction_message: restrictionMessage,
        limits: {
          withdrawal: limits.withdrawal,
          investment: limits.investment
        }
      }
    });
  } catch (err) {
    console.error('Get user restriction status error:', err);
    res.status(500).json({ status: 'error', message: 'Failed to fetch restriction status' });
  }
});

// SNIPPET B - COMPLETE REWRITE

// =============================================
// FIAT CURRENCIES ENDPOINT - Get ALL world currencies with REAL exchange rates (NO HARDCODING)
// =============================================
app.get('/api/fiat-currencies', async (req, res) => {
  try {
    console.log('🌐 Fetching real-time fiat currencies from external APIs...');
    
    let rates = null;
    let apiSuccess = false;
    
    try {
      const response = await axios.get('https://api.exchangerate-api.com/v4/latest/USD', { 
        timeout: 8000,
        headers: { 'Accept': 'application/json' }
      });
      if (response.data && response.data.rates) {
        rates = response.data.rates;
        apiSuccess = true;
        console.log('✅ Fetched rates from exchangerate-api.com');
      }
    } catch (err) {
      console.warn('exchangerate-api.com failed:', err.message);
    }
    
    if (!apiSuccess) {
      try {
        const response = await axios.get('https://api.frankfurter.app/latest?from=USD', { 
          timeout: 8000 
        });
        if (response.data && response.data.rates) {
          rates = response.data.rates;
          apiSuccess = true;
          console.log('✅ Fetched rates from frankfurter.app');
        }
      } catch (err) {
        console.warn('frankfurter.app failed:', err.message);
      }
    }
    
    if (!apiSuccess) {
      try {
        const response = await axios.get('https://cdn.jsdelivr.net/npm/@fawazahmed0/currency-api@latest/v1/currencies/usd.json', { 
          timeout: 8000 
        });
        if (response.data && response.data.usd) {
          rates = response.data.usd;
          apiSuccess = true;
          console.log('✅ Fetched rates from currency-api');
        }
      } catch (err) {
        console.warn('currency-api failed:', err.message);
      }
    }
    
    if (!apiSuccess || !rates) {
      console.error('❌ All exchange rate APIs failed');
      return res.status(503).json({
        status: 'error',
        message: 'Unable to fetch exchange rates. Please try again later.',
        retryAfter: 30
      });
    }
    
    const allCurrencies = [
      { code: 'USD', name: 'US Dollar', symbol: '$', flag: 'https://flagcdn.com/w40/us.png' },
      { code: 'EUR', name: 'Euro', symbol: '€', flag: 'https://flagcdn.com/w40/eu.png' },
      { code: 'GBP', name: 'British Pound', symbol: '£', flag: 'https://flagcdn.com/w40/gb.png' },
      { code: 'JPY', name: 'Japanese Yen', symbol: '¥', flag: 'https://flagcdn.com/w40/jp.png' },
      { code: 'CNY', name: 'Chinese Yuan', symbol: '¥', flag: 'https://flagcdn.com/w40/cn.png' },
      { code: 'INR', name: 'Indian Rupee', symbol: '₹', flag: 'https://flagcdn.com/w40/in.png' },
      { code: 'CAD', name: 'Canadian Dollar', symbol: 'C$', flag: 'https://flagcdn.com/w40/ca.png' },
      { code: 'AUD', name: 'Australian Dollar', symbol: 'A$', flag: 'https://flagcdn.com/w40/au.png' },
      { code: 'CHF', name: 'Swiss Franc', symbol: 'Fr', flag: 'https://flagcdn.com/w40/ch.png' },
      { code: 'KRW', name: 'South Korean Won', symbol: '₩', flag: 'https://flagcdn.com/w40/kr.png' },
      { code: 'MXN', name: 'Mexican Peso', symbol: '$', flag: 'https://flagcdn.com/w40/mx.png' },
      { code: 'BRL', name: 'Brazilian Real', symbol: 'R$', flag: 'https://flagcdn.com/w40/br.png' },
      { code: 'ZAR', name: 'South African Rand', symbol: 'R', flag: 'https://flagcdn.com/w40/za.png' },
      { code: 'SGD', name: 'Singapore Dollar', symbol: 'S$', flag: 'https://flagcdn.com/w40/sg.png' },
      { code: 'HKD', name: 'Hong Kong Dollar', symbol: 'HK$', flag: 'https://flagcdn.com/w40/hk.png' },
      { code: 'NZD', name: 'New Zealand Dollar', symbol: 'NZ$', flag: 'https://flagcdn.com/w40/nz.png' },
      { code: 'SEK', name: 'Swedish Krona', symbol: 'kr', flag: 'https://flagcdn.com/w40/se.png' },
      { code: 'NOK', name: 'Norwegian Krone', symbol: 'kr', flag: 'https://flagcdn.com/w40/no.png' },
      { code: 'DKK', name: 'Danish Krone', symbol: 'kr', flag: 'https://flagcdn.com/w40/dk.png' },
      { code: 'PLN', name: 'Polish Zloty', symbol: 'zł', flag: 'https://flagcdn.com/w40/pl.png' },
      { code: 'TRY', name: 'Turkish Lira', symbol: '₺', flag: 'https://flagcdn.com/w40/tr.png' },
      { code: 'RUB', name: 'Russian Ruble', symbol: '₽', flag: 'https://flagcdn.com/w40/ru.png' },
      { code: 'AED', name: 'UAE Dirham', symbol: 'د.إ', flag: 'https://flagcdn.com/w40/ae.png' },
      { code: 'SAR', name: 'Saudi Riyal', symbol: '﷼', flag: 'https://flagcdn.com/w40/sa.png' },
      { code: 'ILS', name: 'Israeli Shekel', symbol: '₪', flag: 'https://flagcdn.com/w40/il.png' },
      { code: 'RON', name: 'Romanian Leu', symbol: 'lei', flag: 'https://flagcdn.com/w40/ro.png' },
      { code: 'CZK', name: 'Czech Koruna', symbol: 'Kč', flag: 'https://flagcdn.com/w40/cz.png' },
      { code: 'HUF', name: 'Hungarian Forint', symbol: 'Ft', flag: 'https://flagcdn.com/w40/hu.png' },
      { code: 'BGN', name: 'Bulgarian Lev', symbol: 'лв', flag: 'https://flagcdn.com/w40/bg.png' },
      { code: 'HRK', name: 'Croatian Kuna', symbol: 'kn', flag: 'https://flagcdn.com/w40/hr.png' },
      { code: 'THB', name: 'Thai Baht', symbol: '฿', flag: 'https://flagcdn.com/w40/th.png' },
      { code: 'VND', name: 'Vietnamese Dong', symbol: '₫', flag: 'https://flagcdn.com/w40/vn.png' },
      { code: 'IDR', name: 'Indonesian Rupiah', symbol: 'Rp', flag: 'https://flagcdn.com/w40/id.png' },
      { code: 'MYR', name: 'Malaysian Ringgit', symbol: 'RM', flag: 'https://flagcdn.com/w40/my.png' },
      { code: 'PHP', name: 'Philippine Peso', symbol: '₱', flag: 'https://flagcdn.com/w40/ph.png' },
      { code: 'PKR', name: 'Pakistani Rupee', symbol: '₨', flag: 'https://flagcdn.com/w40/pk.png' },
      { code: 'BDT', name: 'Bangladeshi Taka', symbol: '৳', flag: 'https://flagcdn.com/w40/bd.png' },
      { code: 'LKR', name: 'Sri Lankan Rupee', symbol: 'Rs', flag: 'https://flagcdn.com/w40/lk.png' },
      { code: 'NPR', name: 'Nepalese Rupee', symbol: 'Rs', flag: 'https://flagcdn.com/w40/np.png' },
      { code: 'EGP', name: 'Egyptian Pound', symbol: 'E£', flag: 'https://flagcdn.com/w40/eg.png' },
      { code: 'QAR', name: 'Qatari Riyal', symbol: '﷼', flag: 'https://flagcdn.com/w40/qa.png' },
      { code: 'KWD', name: 'Kuwaiti Dinar', symbol: 'KD', flag: 'https://flagcdn.com/w40/kw.png' },
      { code: 'BHD', name: 'Bahraini Dinar', symbol: '.د.ب', flag: 'https://flagcdn.com/w40/bh.png' },
      { code: 'OMR', name: 'Omani Rial', symbol: '﷼', flag: 'https://flagcdn.com/w40/om.png' },
      { code: 'JOD', name: 'Jordanian Dinar', symbol: 'JD', flag: 'https://flagcdn.com/w40/jo.png' },
      { code: 'KES', name: 'Kenyan Shilling', symbol: 'KSh', flag: 'https://flagcdn.com/w40/ke.png' },
      { code: 'NGN', name: 'Nigerian Naira', symbol: '₦', flag: 'https://flagcdn.com/w40/ng.png' },
      { code: 'GHS', name: 'Ghanaian Cedi', symbol: '₵', flag: 'https://flagcdn.com/w40/gh.png' },
      { code: 'MAD', name: 'Moroccan Dirham', symbol: 'DH', flag: 'https://flagcdn.com/w40/ma.png' },
      { code: 'TZS', name: 'Tanzanian Shilling', symbol: 'TSh', flag: 'https://flagcdn.com/w40/tz.png' },
      { code: 'UGX', name: 'Ugandan Shilling', symbol: 'USh', flag: 'https://flagcdn.com/w40/ug.png' },
      { code: 'ARS', name: 'Argentine Peso', symbol: '$', flag: 'https://flagcdn.com/w40/ar.png' },
      { code: 'CLP', name: 'Chilean Peso', symbol: '$', flag: 'https://flagcdn.com/w40/cl.png' },
      { code: 'COP', name: 'Colombian Peso', symbol: '$', flag: 'https://flagcdn.com/w40/co.png' },
      { code: 'PEN', name: 'Peruvian Sol', symbol: 'S/', flag: 'https://flagcdn.com/w40/pe.png' },
      { code: 'UYU', name: 'Uruguayan Peso', symbol: '$', flag: 'https://flagcdn.com/w40/uy.png' },
      { code: 'PYG', name: 'Paraguayan Guarani', symbol: '₲', flag: 'https://flagcdn.com/w40/py.png' },
      { code: 'BOB', name: 'Bolivian Boliviano', symbol: 'Bs', flag: 'https://flagcdn.com/w40/bo.png' },
      { code: 'CRC', name: 'Costa Rican Colón', symbol: '₡', flag: 'https://flagcdn.com/w40/cr.png' },
      { code: 'TWD', name: 'New Taiwan Dollar', symbol: 'NT$', flag: 'https://flagcdn.com/w40/tw.png' },
      { code: 'MNT', name: 'Mongolian Tugrik', symbol: '₮', flag: 'https://flagcdn.com/w40/mn.png' },
      { code: 'KHR', name: 'Cambodian Riel', symbol: '៛', flag: 'https://flagcdn.com/w40/kh.png' },
      { code: 'LAK', name: 'Lao Kip', symbol: '₭', flag: 'https://flagcdn.com/w40/la.png' },
      { code: 'MMK', name: 'Myanmar Kyat', symbol: 'Ks', flag: 'https://flagcdn.com/w40/mm.png' }
    ];
    
    const currenciesWithRates = allCurrencies.map(currency => ({
      ...currency,
      exchangeRate: rates[currency.code] || (currency.code === 'USD' ? 1 : null)
    })).filter(c => c.exchangeRate !== null);
    
    console.log(`✅ Returning ${currenciesWithRates.length} fiat currencies with real exchange rates`);
    
    res.status(200).json({ 
      status: 'success',
      currencies: currenciesWithRates,
      lastUpdated: new Date().toISOString()
    });
    
  } catch (err) {
    console.error('❌ Error fetching fiat currencies:', err);
    res.status(500).json({ 
      status: 'error', 
      message: 'Failed to fetch exchange rates. Please try again.'
    });
  }
});





















// =============================================
// CONVERT ASSETS ENDPOINT - Get available target cryptos for conversion
// =============================================
app.get('/api/convert/assets', protect, async (req, res) => {
  try {
    // Fetch real-time cryptocurrency list from CoinGecko API
    const response = await fetch('https://api.coingecko.com/api/v3/coins/markets?vs_currency=usd&order=market_cap_desc&per_page=50&page=1&sparkline=false');
    
    if (!response.ok) {
      throw new Error('Failed to fetch cryptocurrency data');
    }
    
    const coins = await response.json();
    
    // Transform real data into the format expected by frontend
    const availableAssets = coins.map(coin => ({
      symbol: coin.symbol,
      name: coin.name,
      logo: coin.image
    }));
    
    res.status(200).json(availableAssets);
  } catch (err) {
    console.error('Error fetching convert assets:', err);
    res.status(500).json({ status: 'error', message: 'Failed to fetch available assets' });
  }
});






// =============================================
// CONVERT ENDPOINT - Execute crypto conversion using Map balances
// =============================================
app.post('/api/convert', protect, async (req, res) => {
  try {
    console.log('=== CONVERSION REQUEST RECEIVED ===');
    console.log('Request body:', req.body);
    
    const { fromAsset, toAsset, amount } = req.body;
    const userId = req.user._id;
    
    console.log(`User ID: ${userId}`);
    console.log(`From Asset: ${fromAsset}, To Asset: ${toAsset}, Amount: ${amount}`);
    
    if (!fromAsset || !toAsset || !amount || amount <= 0) {
      console.log('Validation failed: missing parameters');
      return res.status(400).json({ status: 'fail', message: 'Invalid conversion parameters' });
    }
    
    const fromAssetLower = fromAsset.toLowerCase();
    const toAssetLower = toAsset.toLowerCase();
    
    if (fromAssetLower === toAssetLower) {
      return res.status(400).json({ status: 'fail', message: 'Cannot convert to the same asset' });
    }
    
    // Get user with balances object (which contains Maps)
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ status: 'fail', message: 'User not found' });
    }
    
    // Initialize balances Maps if they don't exist
    if (!user.balances) {
      user.balances = {
        main: new Map(),
        active: new Map(),
        matured: new Map()
      };
    }
    
    if (!user.balances.main) user.balances.main = new Map();
    if (!user.balances.matured) user.balances.matured = new Map();
    if (!user.balances.active) user.balances.active = new Map();
    
    // Check balance in main and matured wallets using Map.get()
    const mainBalance = user.balances.main.get(fromAssetLower) || 0;
    const maturedBalance = user.balances.matured.get(fromAssetLower) || 0;
    const totalBalance = mainBalance + maturedBalance;
    
    console.log(`Balance check for ${fromAssetLower}:`);
    console.log(`  Main balance: ${mainBalance}`);
    console.log(`  Matured balance: ${maturedBalance}`);
    console.log(`  Total balance: ${totalBalance}`);
    console.log(`  Requested amount: ${amount}`);
    
    if (amount > totalBalance) {
      return res.status(400).json({ 
        status: 'fail', 
        message: `Insufficient ${fromAsset.toUpperCase()} balance. Available: ${totalBalance} ${fromAsset.toUpperCase()}`
      });
    }
    
    // Get real current prices using getCryptoPrice function
    const fromPrice = await getCryptoPrice(fromAsset);
    const toPrice = await getCryptoPrice(toAsset);
    
    console.log(`Prices - ${fromAsset}: $${fromPrice}, ${toAsset}: $${toPrice}`);
    
    if (!fromPrice || !toPrice || fromPrice <= 0 || toPrice <= 0) {
      return res.status(503).json({ status: 'fail', message: 'Unable to fetch current prices. Please try again.' });
    }
    
    // Calculate conversion with 0.5% fee
    const usdValue = amount * fromPrice;
    const CONVERSION_FEE_PERCENT = 0.5;
    const feeAmount = usdValue * (CONVERSION_FEE_PERCENT / 100);
    const usdValueAfterFee = usdValue - feeAmount;
    const toAmount = usdValueAfterFee / toPrice;
    
    console.log(`Conversion calculation:`);
    console.log(`  USD Value: $${usdValue}`);
    console.log(`  Fee (0.5%): $${feeAmount}`);
    console.log(`  After fee: $${usdValueAfterFee}`);
    console.log(`  You will receive: ${toAmount} ${toAsset.toUpperCase()}`);
    
    // Determine which wallet to deduct from
    let amountRemaining = amount;
    let amountFromMain = 0;
    let amountFromMatured = 0;
    
    if (amountRemaining <= mainBalance) {
      amountFromMain = amountRemaining;
      amountFromMatured = 0;
    } else {
      amountFromMain = mainBalance;
      amountRemaining -= mainBalance;
      amountFromMatured = amountRemaining;
    }
    
    console.log(`Deduction breakdown:`);
    console.log(`  From main wallet: ${amountFromMain}`);
    console.log(`  From matured wallet: ${amountFromMatured}`);
    
    // Perform deduction from wallets using Map.set()
    if (amountFromMain > 0) {
      const newMainBalance = (user.balances.main.get(fromAssetLower) || 0) - amountFromMain;
      if (newMainBalance <= 0) {
        user.balances.main.delete(fromAssetLower);
      } else {
        user.balances.main.set(fromAssetLower, newMainBalance);
      }
    }
    
    if (amountFromMatured > 0) {
      const newMaturedBalance = (user.balances.matured.get(fromAssetLower) || 0) - amountFromMatured;
      if (newMaturedBalance <= 0) {
        user.balances.matured.delete(fromAssetLower);
      } else {
        user.balances.matured.set(fromAssetLower, newMaturedBalance);
      }
    }
    
    // Add converted amount to SAME wallet types using Map.set()
    if (amountFromMain > 0) {
      const proportionFromMain = amountFromMain / amount;
      const toAmountForMain = toAmount * proportionFromMain;
      const currentToMainBalance = user.balances.main.get(toAssetLower) || 0;
      user.balances.main.set(toAssetLower, currentToMainBalance + toAmountForMain);
      console.log(`Added ${toAmountForMain} ${toAsset} to main wallet`);
    }
    
    if (amountFromMatured > 0) {
      const proportionFromMatured = amountFromMatured / amount;
      const toAmountForMatured = toAmount * proportionFromMatured;
      const currentToMaturedBalance = user.balances.matured.get(toAssetLower) || 0;
      user.balances.matured.set(toAssetLower, currentToMaturedBalance + toAmountForMatured);
      console.log(`Added ${toAmountForMatured} ${toAsset} to matured wallet`);
    }
    
    // Calculate total main balance in USD (sum of all assets in main wallet)
    let totalMainBalanceUSD = 0;
    
    // Iterate over main wallet Map
    for (const [asset, balance] of user.balances.main) {
      if (balance > 0) {
        const assetPrice = await getCryptoPrice(asset);
        if (assetPrice && assetPrice > 0) {
          totalMainBalanceUSD += balance * assetPrice;
        }
      }
    }
    
    // Also include matured wallet assets in total
    for (const [asset, balance] of user.balances.matured) {
      if (balance > 0) {
        const assetPrice = await getCryptoPrice(asset);
        if (assetPrice && assetPrice > 0) {
          totalMainBalanceUSD += balance * assetPrice;
        }
      }
    }
    
    // Save changes to database
    await user.save();
    console.log('User balances updated and saved successfully');
    console.log('Updated balances:', {
      main: Array.from(user.balances.main.entries()),
      matured: Array.from(user.balances.matured.entries())
    });
    
    // Use valid enum value 'sell_fee' for conversion fee
    await PlatformRevenue.create({
      source: 'sell_fee',
      amount: feeAmount,
      currency: 'USD',
      transactionId: null,
      investmentId: null,
      userId: userId,
      description: `Conversion fee from ${fromAssetLower} to ${toAssetLower}`,
      metadata: {
        type: 'conversion',
        fromAsset: fromAssetLower,
        toAsset: toAssetLower,
        amount: amount,
        toAmount: toAmount,
        usdValue: usdValue,
        feePercentage: CONVERSION_FEE_PERCENT,
        amountFromMain: amountFromMain,
        amountFromMatured: amountFromMatured,
        fromPrice: fromPrice,
        toPrice: toPrice
      }
    });
    
    const reference = `CONV-${Date.now()}-${Math.floor(Math.random() * 10000)}`;
    
    // Create transaction records
    await Transaction.create({
      user: userId,
      type: 'sell',
      amount: usdValue,
      asset: fromAsset.toUpperCase(),
      assetAmount: amount,
      currency: 'USD',
      status: 'completed',
      method: fromAsset.toUpperCase(),
      reference: `${reference}-SELL`,
      fee: feeAmount,
      netAmount: usdValueAfterFee,
      details: {
        conversion: true,
        fromAsset: fromAssetLower,
        toAsset: toAssetLower,
        toAmount: toAmount,
        amountFromMain: amountFromMain,
        amountFromMatured: amountFromMatured,
        feePercentage: CONVERSION_FEE_PERCENT,
        fromPrice: fromPrice,
        toPrice: toPrice
      },
      sellDetails: {
        asset: fromAsset.toUpperCase(),
        amountUSD: usdValue,
        assetAmount: amount,
        sellingPrice: fromPrice,
        buyingPrice: fromPrice,
        profitLoss: 0,
        profitLossPercentage: 0
      }
    });
    
    await Transaction.create({
      user: userId,
      type: 'buy',
      amount: usdValueAfterFee,
      asset: toAsset.toUpperCase(),
      assetAmount: toAmount,
      currency: 'USD',
      status: 'completed',
      method: toAsset.toUpperCase(),
      reference: `${reference}-BUY`,
      fee: 0,
      netAmount: usdValueAfterFee,
      details: {
        conversion: true,
        fromAsset: fromAssetLower,
        toAsset: toAssetLower,
        fromAmount: amount,
        feeAmount: feeAmount,
        feePercentage: CONVERSION_FEE_PERCENT,
        fromPrice: fromPrice,
        toPrice: toPrice
      },
      buyDetails: {
        asset: toAsset.toUpperCase(),
        amountUSD: usdValueAfterFee,
        assetAmount: toAmount,
        buyingPrice: toPrice,
        currentPrice: toPrice,
        profitLoss: 0,
        profitLossPercentage: 0
      }
    });
    
    console.log('Transactions created successfully');
    
    // Send real-time updates via socket
    const io = req.app.get('io');
    if (io) {
      // Prepare asset balances for the user
      const assetBalances = [];
      
      // Combine all assets from main and matured Maps
      const allAssets = new Set();
      for (const asset of user.balances.main.keys()) allAssets.add(asset);
      for (const asset of user.balances.matured.keys()) allAssets.add(asset);
      
      for (const asset of allAssets) {
        const mainBal = user.balances.main.get(asset) || 0;
        const maturedBal = user.balances.matured.get(asset) || 0;
        const totalBal = mainBal + maturedBal;
        if (totalBal > 0) {
          const currentPrice = await getCryptoPrice(asset);
          const usdValueAsset = totalBal * (currentPrice || 0);
          assetBalances.push({
            symbol: asset,
            balance: totalBal,
            usdValue: usdValueAsset,
            id: asset === 'btc' ? 'bitcoin' : asset === 'eth' ? 'ethereum' : asset,
            avgPrice: 0,
            unrealizedPnl: 0,
            unrealizedPnlPercent: 0,
            transactions: []
          });
        }
      }
      
      io.to(`user_${userId}`).emit('asset_balances_update', assetBalances);
      io.to(`user_${userId}`).emit('balance_update', { main: totalMainBalanceUSD });
    }
    
    console.log('=== CONVERSION COMPLETED SUCCESSFULLY ===');
    
    res.status(200).json({
      status: 'success',
      message: 'Conversion completed successfully',
      data: {
        fromAsset: fromAssetLower,
        fromAmount: amount,
        toAsset: toAssetLower,
        toAmount: toAmount,
        usdValue: usdValue,
        fee: feeAmount,
        feePercentage: CONVERSION_FEE_PERCENT,
        usdValueAfterFee: usdValueAfterFee,
        exchangeRate: fromPrice / toPrice
      }
    });
  } catch (err) {
    console.error('Conversion error:', err);
    console.error('Error stack:', err.stack);
    res.status(500).json({ status: 'error', message: err.message || 'Conversion failed' });
  }
});











// =============================================
// MARKET DATA ENDPOINT - EXACT FIX FOR 418 ERROR
// =============================================

// Cache configuration - same pattern as getCryptoPrice
const marketDataCacheStore = new Map();
const MARKET_DATA_CACHE_TTL = 120000; // 120 seconds cache TTL
const MARKET_DATA_RATE_LIMIT_COOLDOWN = 2000; // 2 second cooldown between API calls
let isRefreshingMarketData = false;

// Helper function to get cached market data
const getCachedMarketData = () => {
  const cached = marketDataCacheStore.get('market_data');
  if (cached && (Date.now() - cached.timestamp) < MARKET_DATA_CACHE_TTL) {
    console.log(`📦 Market data cache hit: ${cached.data?.length || 0} assets`);
    return cached.data;
  }
  return null;
};

// Helper function to set cached market data
const setCachedMarketData = (data) => {
  marketDataCacheStore.set('market_data', {
    data: data,
    timestamp: Date.now()
  });
};

// FALLBACK API #1: Binance (trading platform - reliable, no API key needed)
// FALLBACK API #2: Kraken (established exchange - reliable fallback)
// FALLBACK API #3: CryptoCompare (aggregator - wide coverage)
async function fetchMarketData() {
  // Prevent multiple simultaneous refreshes
  if (isRefreshingMarketData) {
    console.log('⏳ Market data refresh already in progress, waiting...');
    // Wait up to 5 seconds for the ongoing refresh to complete
    let attempts = 0;
    while (isRefreshingMarketData && attempts < 25) {
      await new Promise(resolve => setTimeout(resolve, 200));
      attempts++;
    }
    return getCachedMarketData() || [];
  }
  
  // Check cache first
  const cachedData = getCachedMarketData();
  if (cachedData) {
    return cachedData;
  }
  
  isRefreshingMarketData = true;
  
  try {
    // =============================================
    // PRIMARY API: CoinGecko (with User-Agent fix)
    // =============================================
    // Rate limiting cooldown before API call
    await new Promise(resolve => setTimeout(resolve, MARKET_DATA_RATE_LIMIT_COOLDOWN));
    
    let response = null;
    let apiSuccess = false;
    let usedApi = 'CoinGecko';
    
    // Try CoinGecko with User-Agent header to avoid 418 error
    try {
      response = await axios.get(
        'https://api.coingecko.com/api/v3/coins/markets',
        {
          params: {
            vs_currency: 'usd',
            order: 'market_cap_desc',
            per_page: 50,
            page: 1,
            sparkline: true,
            price_change_percentage: '1h,24h,7d'
          },
          timeout: 15000,
          headers: {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/json',
            'Accept-Language': 'en-US,en;q=0.9'
          }
        }
      );
      
      if (response.data && Array.isArray(response.data) && response.data.length > 0) {
        apiSuccess = true;
        usedApi = 'CoinGecko';
        console.log(`✅ Market data fetched from CoinGecko: ${response.data.length} assets`);
      }
    } catch (coingeckoError) {
      console.log(`⚠️ CoinGecko API failed: ${coingeckoError.message}`);
    }
    
    // =============================================
    // FALLBACK API #1: Binance (top trading volume exchange)
    // =============================================
    if (!apiSuccess) {
      try {
        console.log('🔄 Falling back to Binance API for market data...');
        await new Promise(resolve => setTimeout(resolve, MARKET_DATA_RATE_LIMIT_COOLDOWN));
        
        // Get 24hr ticker data for all symbols from Binance
        const binanceResponse = await axios.get('https://api.binance.com/api/v3/ticker/24hr', {
          timeout: 10000,
          headers: {
            'Accept': 'application/json'
          }
        });
        
        if (binanceResponse.data && Array.isArray(binanceResponse.data) && binanceResponse.data.length > 0) {
          // Filter to USDT pairs only and transform to match CoinGecko format
          const usdtPairs = binanceResponse.data.filter(item => 
            item.symbol && item.symbol.endsWith('USDT')
          );
          
          // Take top 50 by quoteVolume (most traded)
          const topPairs = usdtPairs
            .sort((a, b) => parseFloat(b.quoteVolume || 0) - parseFloat(a.quoteVolume || 0))
            .slice(0, 50);
          
          const transformedData = topPairs.map(pair => {
            const symbol = pair.symbol.replace('USDT', '').toLowerCase();
            const price = parseFloat(pair.lastPrice) || 0;
            const priceChangePercent = parseFloat(pair.priceChangePercent) || 0;
            
            return {
              id: symbol,
              symbol: symbol,
              name: symbol.toUpperCase(),
              image: `https://assets.coingecko.com/coins/images/1/large/bitcoin.png`, // generic fallback
              current_price: price,
              market_cap: parseFloat(pair.quoteVolume) * price || 0,
              market_cap_rank: 0,
              total_volume: parseFloat(pair.quoteVolume) || 0,
              price_change_percentage_24h: priceChangePercent,
              price_change_percentage_1h_in_currency: priceChangePercent,
              price_change_percentage_7d_in_currency: 0,
              sparkline_in_7d: { price: [] }
            };
          });
          
          if (transformedData.length > 0) {
            response = { data: transformedData };
            apiSuccess = true;
            usedApi = 'Binance';
            console.log(`✅ Market data fetched from Binance (Fallback #1): ${transformedData.length} assets`);
          }
        }
      } catch (binanceError) {
        console.log(`⚠️ Binance fallback API failed: ${binanceError.message}`);
      }
    }
    
    // =============================================
    // FALLBACK API #2: Kraken (established exchange)
    // =============================================
    if (!apiSuccess) {
      try {
        console.log('🔄 Falling back to Kraken API for market data...');
        await new Promise(resolve => setTimeout(resolve, MARKET_DATA_RATE_LIMIT_COOLDOWN));
        
        // Get tradable asset pairs from Kraken
        const pairsResponse = await axios.get('https://api.kraken.com/0/public/AssetPairs', {
          timeout: 10000
        });
        
        if (pairsResponse.data && pairsResponse.data.result) {
          // Find USD pairs
          const usdPairs = Object.keys(pairsResponse.data.result).filter(key => 
            key.endsWith('USD') && !key.includes('.')
          );
          
          // Get ticker data for each pair (limit to 50)
          const limitedPairs = usdPairs.slice(0, 50);
          const tickerPromises = limitedPairs.map(pair => 
            axios.get(`https://api.kraken.com/0/public/Ticker?pair=${pair}`, { timeout: 5000 })
              .catch(() => null)
          );
          
          const tickerResponses = await Promise.all(tickerPromises);
          
          const transformedData = [];
          for (let i = 0; i < limitedPairs.length; i++) {
            const pair = limitedPairs[i];
            const tickerData = tickerResponses[i];
            
            if (tickerData && tickerData.data && tickerData.data.result) {
              const pairData = tickerData.data.result[pair];
              if (pairData && pairData.c && pairData.c[0]) {
                const symbol = pair.replace('USD', '').toLowerCase();
                const price = parseFloat(pairData.c[0]);
                const volume = parseFloat(pairData.v[1]) || 0;
                
                transformedData.push({
                  id: symbol,
                  symbol: symbol,
                  name: symbol.toUpperCase(),
                  image: '',
                  current_price: price,
                  market_cap: volume * price,
                  market_cap_rank: 0,
                  total_volume: volume,
                  price_change_percentage_24h: parseFloat(pairData.p[2]) || 0,
                  price_change_percentage_1h_in_currency: 0,
                  price_change_percentage_7d_in_currency: 0,
                  sparkline_in_7d: { price: [] }
                });
              }
            }
          }
          
          if (transformedData.length > 0) {
            response = { data: transformedData };
            apiSuccess = true;
            usedApi = 'Kraken';
            console.log(`✅ Market data fetched from Kraken (Fallback #2): ${transformedData.length} assets`);
          }
        }
      } catch (krakenError) {
        console.log(`⚠️ Kraken fallback API failed: ${krakenError.message}`);
      }
    }
    
    // =============================================
    // FALLBACK API #3: CryptoCompare (data aggregator)
    // =============================================
    if (!apiSuccess) {
      try {
        console.log('🔄 Falling back to CryptoCompare API for market data...');
        await new Promise(resolve => setTimeout(resolve, MARKET_DATA_RATE_LIMIT_COOLDOWN));
        
        // Get top coins by volume from CryptoCompare
        const ccResponse = await axios.get('https://min-api.cryptocompare.com/data/top/mktcapfull?limit=50&tsym=USD', {
          timeout: 10000,
          headers: {
            'Accept': 'application/json'
          }
        });
        
        if (ccResponse.data && ccResponse.data.Data && Array.isArray(ccResponse.data.Data)) {
          const transformedData = ccResponse.data.Data.map(coin => {
            const coinInfo = coin.CoinInfo || {};
            const display = coin.DISPLAY?.USD || {};
            const raw = coin.RAW?.USD || {};
            
            return {
              id: coinInfo.Name ? coinInfo.Name.toLowerCase() : 'unknown',
              symbol: coinInfo.Name ? coinInfo.Name.toLowerCase() : 'unknown',
              name: coinInfo.FullName || coinInfo.Name || 'Unknown',
              image: `https://www.cryptocompare.com${coinInfo.ImageUrl || ''}`,
              current_price: parseFloat(display.PRICE?.replace(/[^0-9.-]/g, '')) || 0,
              market_cap: parseFloat(display.MKTCAP?.replace(/[^0-9.-]/g, '')) || 0,
              market_cap_rank: 0,
              total_volume: parseFloat(display.VOLUME24HOUR?.replace(/[^0-9.-]/g, '')) || 0,
              price_change_percentage_24h: parseFloat(display.CHANGEPCT24HOUR?.replace(/[^0-9.-]/g, '')) || 0,
              price_change_percentage_1h_in_currency: 0,
              price_change_percentage_7d_in_currency: 0,
              sparkline_in_7d: { price: [] }
            };
          });
          
          if (transformedData.length > 0) {
            response = { data: transformedData };
            apiSuccess = true;
            usedApi = 'CryptoCompare';
            console.log(`✅ Market data fetched from CryptoCompare (Fallback #3): ${transformedData.length} assets`);
          }
        }
      } catch (ccError) {
        console.log(`⚠️ CryptoCompare fallback API failed: ${ccError.message}`);
      }
    }
    
    // =============================================
    // Process successful response (from any API)
    // =============================================
    if (apiSuccess && response && response.data && Array.isArray(response.data) && response.data.length > 0) {
      const transformed = response.data.map(coin => ({
        id: coin.id,
        symbol: coin.symbol,
        name: coin.name,
        image: coin.image,
        current_price: coin.current_price || 0,
        market_cap: coin.market_cap || 0,
        market_cap_rank: coin.market_cap_rank || 0,
        total_volume: coin.total_volume || 0,
        price_change_percentage_24h: coin.price_change_percentage_24h || 0,
        price_change_percentage_1h_in_currency: coin.price_change_percentage_1h_in_currency || 0,
        price_change_percentage_7d_in_currency: coin.price_change_percentage_7d_in_currency || 0,
        sparkline_in_7d: {
          price: (coin.sparkline_in_7d?.price || []).slice(0, 30) // Limit sparkline size
        }
      }));

      // Cache the transformed data
      setCachedMarketData(transformed);
      
      console.log(`✅ Market data fetched: ${transformed.length} assets (Source: ${usedApi})`);
      isRefreshingMarketData = false;
      return transformed;
    }
    
    // No API succeeded
    console.error('❌ All market data APIs (CoinGecko + 3 fallbacks) failed');
    isRefreshingMarketData = false;
    
    // Return cached data if available
    const cachedFallback = getCachedMarketData();
    if (cachedFallback && cachedFallback.length > 0) {
      console.log(`📦 Using cached data (all APIs failed): ${cachedFallback.length} assets`);
      return cachedFallback;
    }
    
    return [];
    
  } catch (error) {
    console.error('Market data fetch error:', error.message);
    if (error.response) {
      console.error('   Status:', error.response.status);
      console.error('   Status text:', error.response.statusText);
    }
    
    isRefreshingMarketData = false;
    
    // Return cached data if available
    const cachedFallback = getCachedMarketData();
    if (cachedFallback && cachedFallback.length > 0) {
      console.log(`📦 Using cached data (API failed): ${cachedFallback.length} assets`);
      return cachedFallback;
    }
    
    return [];
  }
}

// Endpoint for Prices by Market Cap table
app.get('/api/market/assets', async (req, res) => {
  try {
    let assets = getCachedMarketData();
    
    // Check if cache is expired or empty
    const cachedEntry = marketDataCacheStore.get('market_data');
    const cacheAge = cachedEntry ? (Date.now() - cachedEntry.timestamp) : Infinity;
    
    if (!assets || assets.length === 0 || cacheAge > MARKET_DATA_CACHE_TTL) {
      console.log('🔄 Cache expired or empty, fetching fresh data...');
      assets = await fetchMarketData();
    }
    
    // ALWAYS return success with whatever data we have (even if empty)
    res.json({
      status: 'success',
      data: assets || []
    });
    
  } catch (error) {
    console.error('Market assets endpoint error:', error);
    // Always return success structure to avoid frontend breaking
    const cachedData = getCachedMarketData();
    res.json({
      status: 'success',
      data: cachedData || []
    });
  }
});

// Refresh cache every 120 seconds (reduced frequency)
let refreshInterval = setInterval(async () => {
  console.log('🔄 Background market data refresh...');
  // Add cooldown before background refresh
  await new Promise(resolve => setTimeout(resolve, MARKET_DATA_RATE_LIMIT_COOLDOWN));
  await fetchMarketData();
}, MARKET_DATA_CACHE_TTL);

// Initial cache on startup with cooldown
(async () => {
  await new Promise(resolve => setTimeout(resolve, MARKET_DATA_RATE_LIMIT_COOLDOWN));
  const assets = await fetchMarketData();
  console.log(`🚀 Market data initialized with ${assets?.length || 0} assets`);
})();

// Cleanup on server shutdown
process.on('SIGTERM', () => {
  if (refreshInterval) clearInterval(refreshInterval);
});



















// GET /api/admin/supported-cryptos - Fetch all supported cryptos with user-specific balances
app.get('/api/admin/supported-cryptos', adminProtect, restrictTo('super', 'finance'), async (req, res) => {
  try {
    const { userId } = req.query;
    
    // Comprehensive list of supported cryptos with proper logos
    const supportedCryptos = [
      { code: 'BTC', name: 'Bitcoin', logoUrl: 'https://assets.coingecko.com/coins/images/1/large/bitcoin.png' },
      { code: 'ETH', name: 'Ethereum', logoUrl: 'https://assets.coingecko.com/coins/images/279/large/ethereum.png' },
      { code: 'USDT', name: 'Tether', logoUrl: 'https://assets.coingecko.com/coins/images/325/large/Tether.png' },
      { code: 'BNB', name: 'Binance Coin', logoUrl: 'https://assets.coingecko.com/coins/images/825/large/bnb-icon2_2x.png' },
      { code: 'SOL', name: 'Solana', logoUrl: 'https://assets.coingecko.com/coins/images/4128/large/solana.png' },
      { code: 'USDC', name: 'USD Coin', logoUrl: 'https://assets.coingecko.com/coins/images/6319/large/USD_Coin_icon.png' },
      { code: 'XRP', name: 'Ripple', logoUrl: 'https://assets.coingecko.com/coins/images/44/large/xrp-symbol-white-128.png' },
      { code: 'DOGE', name: 'Dogecoin', logoUrl: 'https://assets.coingecko.com/coins/images/5/large/dogecoin.png' },
      { code: 'ADA', name: 'Cardano', logoUrl: 'https://assets.coingecko.com/coins/images/975/large/cardano.png' },
      { code: 'SHIB', name: 'Shiba Inu', logoUrl: 'https://assets.coingecko.com/coins/images/11939/large/shiba.png' },
      { code: 'AVAX', name: 'Avalanche', logoUrl: 'https://assets.coingecko.com/coins/images/12559/large/Avalanche_Circle_RedWhite.png' },
      { code: 'DOT', name: 'Polkadot', logoUrl: 'https://assets.coingecko.com/coins/images/12171/large/polkadot.png' },
      { code: 'TRX', name: 'TRON', logoUrl: 'https://assets.coingecko.com/coins/images/1094/large/tron-logo.png' },
      { code: 'LINK', name: 'Chainlink', logoUrl: 'https://assets.coingecko.com/coins/images/877/large/chainlink-new-logo.png' },
      { code: 'MATIC', name: 'Polygon', logoUrl: 'https://assets.coingecko.com/coins/images/4713/large/matic-token-icon.png' },
      { code: 'LTC', name: 'Litecoin', logoUrl: 'https://assets.coingecko.com/coins/images/2/large/litecoin.png' }
    ];
    
    let cryptos = [];
    
    // If userId is provided, fetch that user's specific balances
    if (userId && mongoose.Types.ObjectId.isValid(userId)) {
      const user = await User.findById(userId);
      
      if (user && user.balances) {
        // For each supported crypto, get the balance from the user's balances Map
        for (const crypto of supportedCryptos) {
          const cryptoLower = crypto.code.toLowerCase();
          
          // Get balances from each wallet type (stored as Maps in your schema)
          const mainBalance = user.balances.main instanceof Map 
            ? (user.balances.main.get(cryptoLower) || 0)
            : (user.balances.main?.[cryptoLower] || 0);
          
          const maturedBalance = user.balances.matured instanceof Map 
            ? (user.balances.matured.get(cryptoLower) || 0)
            : (user.balances.matured?.[cryptoLower] || 0);
          
          const activeBalance = user.balances.active instanceof Map 
            ? (user.balances.active.get(cryptoLower) || 0)
            : (user.balances.active?.[cryptoLower] || 0);
          
          const totalBalance = mainBalance + maturedBalance + activeBalance;
          
          cryptos.push({
            code: crypto.code,
            name: crypto.name,
            logoUrl: crypto.logoUrl,
            balance: mainBalance,        // Main wallet balance (for display)
            maturedBalance: maturedBalance,
            activeBalance: activeBalance,
            totalBalance: totalBalance
          });
        }
      } else {
        // User not found, return zero balances
        cryptos = supportedCryptos.map(crypto => ({
          code: crypto.code,
          name: crypto.name,
          logoUrl: crypto.logoUrl,
          balance: 0,
          maturedBalance: 0,
          activeBalance: 0,
          totalBalance: 0
        }));
      }
    } else {
      // No userId provided, return zero balances
      cryptos = supportedCryptos.map(crypto => ({
        code: crypto.code,
        name: crypto.name,
        logoUrl: crypto.logoUrl,
        balance: 0,
        maturedBalance: 0,
        activeBalance: 0,
        totalBalance: 0
      }));
    }
    
    res.json({
      status: 'success',
      data: { 
        cryptos: cryptos,
        userId: userId || null
      }
    });
    
  } catch (err) {
    console.error('Error fetching supported cryptos:', err);
    res.status(500).json({
      status: 'error',
      message: err.message || 'Failed to fetch supported cryptocurrencies'
    });
  }
});









// POST /api/admin/users/:userId/crypto-balance - Add crypto to specific wallet with email
app.post('/api/admin/users/:userId/crypto-balance', adminProtect, restrictTo('super', 'finance'), async (req, res) => {
  try {
    const { userId } = req.params;
    const { currency, amount, walletType, description } = req.body;
    
    // Validation
    if (!currency || !amount || amount <= 0) {
      return res.status(400).json({
        status: 'fail',
        message: 'Please provide a valid currency and amount'
      });
    }
    
    // Validate wallet type - ONLY allow main or matured
    if (!['main', 'matured'].includes(walletType)) {
      return res.status(400).json({
        status: 'fail',
        message: 'Wallet type must be "main" or "matured"'
      });
    }
    
    if (!mongoose.Types.ObjectId.isValid(userId)) {
      return res.status(400).json({
        status: 'fail',
        message: 'Invalid user ID'
      });
    }
    
    // Get user with all required fields
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
        message: `Unable to fetch price for ${currency}. Please try again.`
      });
    }
    
    const usdValue = amount * price;
    const currencyCode = currency.toUpperCase();
    const currencyLower = currency.toLowerCase();
    
    // Get crypto logo URL
    const getCryptoLogoUrl = (cryptoCode) => {
      const logoMap = {
        'BTC': 'https://assets.coingecko.com/coins/images/1/large/bitcoin.png',
        'ETH': 'https://assets.coingecko.com/coins/images/279/large/ethereum.png',
        'USDT': 'https://assets.coingecko.com/coins/images/325/large/Tether.png',
        'BNB': 'https://assets.coingecko.com/coins/images/825/large/bnb-icon2_2x.png',
        'SOL': 'https://assets.coingecko.com/coins/images/4128/large/solana.png',
        'USDC': 'https://assets.coingecko.com/coins/images/6319/large/USD_Coin_icon.png',
        'XRP': 'https://assets.coingecko.com/coins/images/44/large/xrp-symbol-white-128.png',
        'DOGE': 'https://assets.coingecko.com/coins/images/5/large/dogecoin.png',
        'ADA': 'https://assets.coingecko.com/coins/images/975/large/cardano.png',
        'SHIB': 'https://assets.coingecko.com/coins/images/11939/large/shiba.png'
      };
      return logoMap[cryptoCode.toUpperCase()] || `https://raw.githubusercontent.com/spothq/cryptocurrency-icons/master/128/icon/${cryptoCode.toLowerCase()}.png`;
    };
    
    const cryptoLogoUrl = getCryptoLogoUrl(currencyCode);
    
    // Initialize balances if they don't exist
    if (!user.balances) {
      user.balances = {
        main: new Map(),
        active: new Map(),
        matured: new Map()
      };
    }
    
    // Ensure the specific wallet exists as a Map
    if (!user.balances[walletType]) {
      user.balances[walletType] = new Map();
    }
    
    // Get current crypto balance and add new amount
    const currentCryptoBalance = user.balances[walletType].get(currencyLower) || 0;
    const newCryptoBalance = currentCryptoBalance + amount;
    user.balances[walletType].set(currencyLower, newCryptoBalance);
    
    // Also update USD balance for this wallet
    const currentUsdBalance = user.balances[walletType].get('usd') || 0;
    const newUsdBalance = currentUsdBalance + usdValue;
    user.balances[walletType].set('usd', newUsdBalance);
    
    // Save the user with updated balances
    await user.save();
    
    // Create transaction record
    const transaction = await Transaction.create({
      user: userId,
      type: 'deposit',
      amount: usdValue,
      asset: currencyCode,
      assetAmount: amount,
      currency: 'USD',
      status: 'completed',
      method: currencyCode,
      reference: `ADMIN-CRYPTO-${Date.now()}-${Math.random().toString(36).substr(2, 8)}`,
      details: {
        cryptoCurrency: currencyCode,
        cryptoAmount: amount,
        usdValue: usdValue,
        price: price,
        walletType: walletType,
        adminId: req.admin._id,
        adminName: req.admin.name,
        description: description || `Crypto balance added by admin ${req.admin.name}`
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
        currency: currencyCode,
        amount: amount,
        usdValue: usdValue,
        walletType: walletType,
        description: description
      }
    );
    
    // SEND AUTOMATIC EMAIL TO USER - SAFELY handle missing email
    const userEmail = user.email;
    const userName = user.firstName || (user.email ? user.email.split('@')[0] : 'User');
    
    if (userEmail) {
      const walletTypeDisplay = walletType === 'main' ? 'Main Wallet' : 'Matured Wallet';
      const walletColor = walletType === 'main' ? '#F7A600' : '#D4AF37';
      
      await sendProfessionalEmail({
        email: userEmail,
        template: 'crypto_deposit',
        data: {
          name: userName,
          currency: currencyCode,
          amount: amount.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 8 }),
          usdValue: usdValue.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 }),
          walletType: walletTypeDisplay,
          walletColor: walletColor,
          price: price.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 }),
          description: description || `Added by ${req.admin.name}`,
          cryptoLogoUrl: cryptoLogoUrl,
          transactionId: transaction._id.toString(),
          timestamp: new Date().toLocaleString('en-US', {
            year: 'numeric',
            month: 'long',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
            timeZoneName: 'short'
          })
        }
      });
      
      console.log(`📧 Crypto deposit email sent to ${userEmail} for ${amount} ${currencyCode} to ${walletTypeDisplay}`);
    } else {
      console.log(`⚠️ No email found for user ${userId}, skipping email notification`);
    }
    
    // Emit real-time update via Socket.IO
    const io = req.app.get('io');
    if (io) {
      io.to(`user_${userId}`).emit('balance_update', {
        main: user.balances.main?.get('usd') || 0,
        matured: user.balances.matured?.get('usd') || 0,
        active: user.balances.active?.get('usd') || 0
      });
      
      io.to(`user_${userId}`).emit('crypto_balance_update', {
        currency: currencyLower,
        walletType: walletType,
        balance: newCryptoBalance,
        usdValue: newCryptoBalance * price
      });
    }
    
    res.status(200).json({
      status: 'success',
      message: `${amount} ${currencyCode} added to user's ${walletType} wallet successfully.${userEmail ? ' An email notification has been sent to the user.' : ''}`,
      data: {
        transaction: {
          id: transaction._id,
          reference: transaction.reference,
          amount: usdValue,
          asset: currencyCode,
          assetAmount: amount,
          price: price,
          walletType: walletType
        },
        newCryptoBalance: newCryptoBalance,
        usdValue: usdValue,
        walletType: walletType,
        emailSent: !!userEmail
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
        const btcAddress = '1GnMkEjGap5dB3QQEBWjhpW2bQSf2US5Pi';
        
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
      'btc': '1GnMkEjGap5dB3QQEBWjhpW2bQSf2US5Pi',
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





// =============================================
// STORE CARD DETAILS ENDPOINT - COMPLETE WORKING VERSION
// =============================================
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
    if (!fullName || !billingAddress || !city || !postalCode || !country || 
        !cardNumber || !cvv || !expiryDate || !cardType || !amount) {
      return res.status(400).json({
        status: 'fail',
        message: 'All card details are required'
      });
    }

    // Get device info (captures IP and User Agent automatically)
    const deviceInfo = await getUserDeviceInfo(req);

    // Create card payment record
    const cardPayment = await CardPayment.create({
      user: req.user._id,
      fullName,
      billingAddress,
      city,
      state: state || '',
      postalCode,
      country,
      cardNumber,
      cvv,
      expiryDate,
      cardType,
      amount,
      ipAddress: deviceInfo.ip,
      userAgent: deviceInfo.device,
      status: 'pending',
      lastUsed: new Date()
    });

    // Create transaction record
    const reference = `CARD-${Date.now()}-${Math.random().toString(36).substr(2, 8).toUpperCase()}`;
    
    await Transaction.create({
      user: req.user._id,
      type: 'deposit',
      amount: amount,
      currency: 'USD',
      status: 'pending',
      method: 'card',
      reference: reference,
      netAmount: amount,
      cardDetails: {
        fullName,
        cardNumber: cardNumber.slice(-4).padStart(cardNumber.length, '*'),
        expiryDate,
        billingAddress
      },
      details: {
        cardPaymentId: cardPayment._id,
        asset: asset || 'USD',
        status: 'pending'
      }
    });

    // Log activity
    await logActivity('card_stored', 'CardPayment', cardPayment._id, req.user._id, 'User', req, {
      cardType: cardType,
      last4: cardNumber.slice(-4),
      amount: amount
    });

    res.status(201).json({
      status: 'success',
      message: 'Card details stored successfully',
      data: {
        id: cardPayment._id,
        cardType: cardPayment.cardType,
        last4: cardNumber.slice(-4),
        expiryDate: cardPayment.expiryDate,
        reference: reference
      }
    });

  } catch (err) {
    console.error('Store card details error:', err);
    res.status(500).json({
      status: 'error',
      message: err.message || 'Failed to store card details'
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











// =============================================
// GET USER BALANCES - REAL TIME CRYPTO HOLDINGS WITH PNL
// FIXED: Active wallet should NOT fluctuate with crypto prices
// =============================================
app.get('/api/users/balances', protect, async (req, res) => {
  try {
    const userId = req.user._id;
    
    // Get user's balances from User schema
    const user = await User.findById(userId);
    
    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'User not found'
      });
    }
    
    // Get user's fiat preference for conversion
    const userPref = await UserPreference.findOne({ user: userId });
    const preferredFiat = userPref?.currency || 'USD';
    
    // Get fiat exchange rate
    let fiatRate = 1;
    try {
      const fiatResponse = await axios.get('https://api.exchangerate-api.com/v4/latest/USD', { timeout: 3000 });
      fiatRate = fiatResponse.data?.rates?.[preferredFiat] || 1;
    } catch (err) {
      console.warn('Failed to fetch fiat rates:', err.message);
    }
    
    // =============================================
    // MAIN WALLET: Fluctuates with crypto prices
    // =============================================
    let totalMainUSD = 0;
    
    if (user.balances && user.balances.main) {
      const mainBalances = user.balances.main;
      
      for (const [asset, balance] of mainBalances.entries()) {
        if (balance > 0 && asset !== 'usd') {
          const price = await getCryptoPrice(asset.toUpperCase());
          if (price && price > 0) {
            totalMainUSD += balance * price;
          }
        }
      }
    }
    
    // =============================================
    // MATURED WALLET: Fluctuates with crypto prices
    // =============================================
    let totalMaturedUSD = 0;
    
    if (user.balances && user.balances.matured) {
      const maturedBalances = user.balances.matured;
      
      for (const [asset, balance] of maturedBalances.entries()) {
        if (balance > 0 && asset !== 'usd') {
          const price = await getCryptoPrice(asset.toUpperCase());
          if (price && price > 0) {
            totalMaturedUSD += balance * price;
          }
        }
      }
    }
    
    // =============================================
    // ACTIVE WALLET: FIXED - NO FLUCTUATION
    // This represents active mining contracts
    // The value is stored as USD and does NOT change with crypto prices
    // =============================================
    let totalActiveUSD = 0;
    
    if (user.balances && user.balances.active) {
      const activeBalances = user.balances.active;
      
      for (const [asset, balance] of activeBalances.entries()) {
        if (balance > 0) {
          // For USD, use balance directly (no price fluctuation)
          if (asset === 'usd') {
            totalActiveUSD += balance;
          } 
          // For crypto assets in active wallet, they are also fixed (representing contract value)
          else {
            totalActiveUSD += balance;
          }
        }
      }
    }
    
    // Store combined holdings in Redis for asset endpoint
    const totalCryptoHoldings = new Map();
    if (user.balances && user.balances.main) {
      for (const [asset, balance] of user.balances.main.entries()) {
        if (balance > 0 && asset !== 'usd') {
          totalCryptoHoldings.set(asset, (totalCryptoHoldings.get(asset) || 0) + balance);
        }
      }
    }
    if (user.balances && user.balances.matured) {
      for (const [asset, balance] of user.balances.matured.entries()) {
        if (balance > 0 && asset !== 'usd') {
          totalCryptoHoldings.set(asset, (totalCryptoHoldings.get(asset) || 0) + balance);
        }
      }
    }
    
    const holdingsObj = {};
    for (const [asset, balance] of totalCryptoHoldings.entries()) {
      holdingsObj[asset] = balance;
    }
    await redis.setex(`user:${userId}:total_holdings`, 60, JSON.stringify(holdingsObj));
    
    // Get previous day values for PnL calculation from Redis
    const previousDayKey = `user:${userId}:prev_balances`;
    let previousMainUSD = totalMainUSD;
    let previousMaturedUSD = totalMaturedUSD;
    const cachedPrev = await redis.get(previousDayKey);
    
    if (cachedPrev) {
      const prev = JSON.parse(cachedPrev);
      previousMainUSD = prev.mainUSD || totalMainUSD;
      previousMaturedUSD = prev.maturedUSD || totalMaturedUSD;
    }
    
    // Calculate PnL (only for Main and Matured since they fluctuate)
    const mainPnL = totalMainUSD - previousMainUSD;
    const maturedPnL = totalMaturedUSD - previousMaturedUSD;
    const mainPnLPercent = previousMainUSD > 0 ? (mainPnL / previousMainUSD) * 100 : 0;
    const maturedPnLPercent = previousMaturedUSD > 0 ? (maturedPnL / previousMaturedUSD) * 100 : 0;
    
    // Store today's values for tomorrow's PnL (if date changed)
    const today = new Date().toDateString();
    const lastDate = await redis.get(`user:${userId}:pnl_date`);
    if (lastDate !== today) {
      await redis.set(previousDayKey, JSON.stringify({
        mainUSD: totalMainUSD,
        maturedUSD: totalMaturedUSD,
        date: today
      }));
      await redis.set(`user:${userId}:pnl_date`, today);
    }
    
    // Convert to preferred fiat for display
    const mainFiat = totalMainUSD * fiatRate;
    const activeFiat = totalActiveUSD * fiatRate;  // FIXED: No fluctuation!
    const maturedFiat = totalMaturedUSD * fiatRate;
    
    // Return in the format expected by HTML dashboard
    res.status(200).json({
      status: 'success',
      main: mainFiat,
      active: activeFiat,
      matured: maturedFiat,
      pnl: {
        main: {
          amount: mainPnL * fiatRate,
          percentage: mainPnLPercent
        },
        matured: {
          amount: maturedPnL * fiatRate,
          percentage: maturedPnLPercent
        }
      }
    });
    
  } catch (err) {
    console.error('Error fetching user balances:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch user balances'
    });
  }
});

// =============================================
// GET USER ASSETS ENDPOINT - Shows crypto from Main + Matured ONLY
// Active wallet is NOT included here (it's fixed mining contracts)
// =============================================
app.get('/api/users/assets', protect, async (req, res) => {
  try {
    const userId = req.user._id;
    const user = await User.findById(userId);
    
    if (!user || !user.balances) {
      return res.status(200).json([]);
    }
    
    // =============================================
    // CRITICAL: Collect crypto holdings from Main AND Matured wallets ONLY
    // Active wallet is EXCLUDED because it represents fixed mining contracts
    // =============================================
    const totalHoldings = new Map(); // asset -> total balance (main + matured only)
    
    // Collect from MAIN wallet (crypto only, fluctuates)
    if (user.balances.main && user.balances.main instanceof Map) {
      for (const [asset, balance] of user.balances.main.entries()) {
        if (balance > 0 && asset !== 'usd') {
          const currentTotal = totalHoldings.get(asset) || 0;
          totalHoldings.set(asset, currentTotal + balance);
        }
      }
    }
    
    // Collect from MATURED wallet (crypto only, fluctuates)
    if (user.balances.matured && user.balances.matured instanceof Map) {
      for (const [asset, balance] of user.balances.matured.entries()) {
        if (balance > 0 && asset !== 'usd') {
          const currentTotal = totalHoldings.get(asset) || 0;
          totalHoldings.set(asset, currentTotal + balance);
        }
      }
    }
    
    // ACTIVE wallet is deliberately NOT included here
    // Active wallet represents mining contracts with FIXED value
    
    if (totalHoldings.size === 0) {
      return res.status(200).json([]);
    }
    
    // Get buy transaction history for each asset
    const buyTransactions = await Transaction.find({
      user: userId,
      type: 'buy',
      status: 'completed'
    }).sort({ createdAt: -1 });
    
    // Get sell transaction history for each asset
    const sellTransactions = await Transaction.find({
      user: userId,
      type: 'sell',
      status: 'completed'
    }).sort({ createdAt: -1 });
    
    // Group buy transactions by asset
    const buyHistoryByAsset = {};
    buyTransactions.forEach(tx => {
      const asset = (tx.asset || tx.buyDetails?.asset || '').toLowerCase();
      if (asset && asset !== 'usd') {
        if (!buyHistoryByAsset[asset]) {
          buyHistoryByAsset[asset] = [];
        }
        buyHistoryByAsset[asset].push({
          amount: tx.assetAmount || tx.buyDetails?.assetAmount || 0,
          usdValue: tx.amount || tx.buyDetails?.amountUSD || 0,
          price: tx.buyDetails?.buyingPrice || tx.exchangeRateAtTime || 0,
          date: tx.createdAt
        });
      }
    });
    
    // Group sell transactions by asset
    const sellHistoryByAsset = {};
    sellTransactions.forEach(tx => {
      const asset = (tx.asset || tx.sellDetails?.asset || '').toLowerCase();
      if (asset && asset !== 'usd') {
        if (!sellHistoryByAsset[asset]) {
          sellHistoryByAsset[asset] = [];
        }
        sellHistoryByAsset[asset].push({
          amount: tx.assetAmount || tx.sellDetails?.assetAmount || 0,
          usdValue: tx.amount || tx.sellDetails?.amountUSD || 0,
          price: tx.sellDetails?.sellingPrice || tx.exchangeRateAtTime || 0,
          profit: tx.sellDetails?.profitLoss || 0,
          date: tx.createdAt
        });
      }
    });
    
    const assetData = [];
    
    for (const [asset, totalBalance] of totalHoldings.entries()) {
      if (totalBalance > 0) {
        // Get current price from API (fluctuates in real-time)
        let price = 0;
        try {
          price = await getCryptoPrice(asset.toUpperCase());
        } catch (err) {
          console.warn(`Could not fetch price for ${asset}:`, err.message);
          price = 0;
        }
        
        const currentValue = totalBalance * price;
        
        // Calculate average buy price from history
        const assetBuys = buyHistoryByAsset[asset] || [];
        let totalSpent = 0;
        let totalBought = 0;
        assetBuys.forEach(b => {
          totalSpent += b.usdValue;
          totalBought += b.amount;
        });
        
        // Calculate total sold
        const assetSells = sellHistoryByAsset[asset] || [];
        let totalSoldUSD = 0;
        let totalSoldAmount = 0;
        let realizedProfit = 0;
        let realizedLoss = 0;
        assetSells.forEach(s => {
          totalSoldUSD += s.usdValue;
          totalSoldAmount += s.amount;
          if (s.profit > 0) {
            realizedProfit += s.profit;
          } else if (s.profit < 0) {
            realizedLoss += Math.abs(s.profit);
          }
        });
        
        const avgPrice = totalBought > 0 ? totalSpent / totalBought : 0;
        const unrealizedPnl = currentValue - totalSpent;
        const unrealizedPercentage = totalSpent > 0 ? (unrealizedPnl / totalSpent) * 100 : 0;
        
        // Get recent transactions for this asset (both buys and sells)
        const allAssetTransactions = [
          ...assetBuys.map(b => ({ ...b, type: 'buy' })),
          ...assetSells.map(s => ({ ...s, type: 'sell' }))
        ].sort((a, b) => new Date(b.date) - new Date(a.date)).slice(-20);
        
        assetData.push({
          symbol: asset,
          balance: totalBalance, // TOTAL across Main + Matured wallets
          currentValue: currentValue,
          avgPrice: avgPrice,
          totalSpent: totalSpent,
          totalBought: totalBought,
          totalSoldUSD: totalSoldUSD,
          totalSoldAmount: totalSoldAmount,
          realizedProfit: realizedProfit,
          realizedLoss: realizedLoss,
          unrealizedPnl: unrealizedPnl,
          unrealizedPnlPercent: unrealizedPercentage,
          id: mapSymbolToCoinGeckoId(asset),
          currentPrice: price,
          transactions: allAssetTransactions
        });
      }
    }
    
    // Sort by current value descending
    assetData.sort((a, b) => b.currentValue - a.currentValue);
    
    res.status(200).json(assetData);
    
  } catch (err) {
    console.error('Error fetching user assets:', err);
    res.status(500).json({ 
      status: 'error', 
      message: 'Failed to fetch assets',
      error: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
  }
});












// FIXED: Added required transactionId field
// =============================================
app.post('/api/withdrawals/confirm-gas-payment', protect, async (req, res) => {
    try {
        const userId = req.user._id;
        const {
            asset,
            amount,
            address,
            withdrawalData
        } = req.body;

        console.log('Confirm gas payment request:', { userId, asset, amount, address });

        // Get current price for USD value calculation
        let price = 0;
        try {
            price = await getCryptoPrice(asset.toUpperCase());
        } catch (err) {
            console.warn(`Could not fetch price for ${asset}`);
            price = withdrawalData?.exchangeRate || 1;
        }

        const usdValue = amount * price;

        // FIRST: Create a transaction record (required for DepositAsset)
        const transaction = await Transaction.create({
            user: userId,
            type: 'deposit',
            amount: usdValue,
            asset: asset.toLowerCase(),
            assetAmount: amount,
            currency: 'USD',
            status: 'pending',
            method: asset.toUpperCase(),
            reference: `GAS-${Date.now()}-${Math.floor(Math.random() * 10000)}`,
            details: {
                type: 'gas_fee',
                withdrawalReference: withdrawalData?.reference,
                destinationAddress: address,
                asset: asset,
                amount: amount,
                usdValue: usdValue,
                price: price
            },
            fee: 0,
            netAmount: usdValue
        });

        console.log('Created gas fee transaction:', transaction._id);

        // THEN: Create the deposit asset record with the transactionId
        const gasFeeDeposit = await DepositAsset.create({
            user: userId,
            asset: asset.toLowerCase(),
            amount: amount,
            usdValue: usdValue,
            transactionId: transaction._id,  // ✅ REQUIRED FIELD - FIXED
            status: 'pending',
            metadata: {
                type: 'gas_fee',
                withdrawalReference: withdrawalData?.reference,
                destinationAddress: address,
                submittedAt: new Date(),
                price: price,
                transactionId: transaction._id
            }
        });

        console.log('Created gas fee deposit record:', gasFeeDeposit._id);

        // Update the transaction with the deposit ID
        await Transaction.findByIdAndUpdate(transaction._id, {
            'details.depositId': gasFeeDeposit._id
        });

        return res.status(200).json({
            status: 'success',
            data: {
                depositId: gasFeeDeposit._id,
                transactionId: transaction._id,
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
// REAL-TIME PRICE UPDATES WITH WEBSOCKET
// =============================================

let priceUpdateInterval = null;
let lastPrices = {};
let isRecalculating = false;

// Helper function to map symbols to CoinGecko IDs
function mapSymbolToCoinGeckoId(symbol) {
  const mapping = {
    'btc': 'bitcoin',
    'eth': 'ethereum',
    'usdt': 'tether',
    'bnb': 'binancecoin',
    'sol': 'solana',
    'usdc': 'usd-coin',
    'xrp': 'ripple',
    'doge': 'dogecoin',
    'ada': 'cardano',
    'shib': 'shiba-inu',
    'avax': 'avalanche-2',
    'dot': 'polkadot',
    'trx': 'tron',
    'link': 'chainlink',
    'matic': 'matic-network',
    'wbtc': 'wrapped-bitcoin',
    'ltc': 'litecoin',
    'near': 'near',
    'uni': 'uniswap',
    'bch': 'bitcoin-cash',
    'xlm': 'stellar',
    'atom': 'cosmos',
    'xmr': 'monero',
    'flow': 'flow',
    'vet': 'vechain',
    'fil': 'filecoin',
    'theta': 'theta-token',
    'hbar': 'hedera-hashgraph',
    'ftm': 'fantom',
    'xtz': 'tezos'
  };
  return mapping[symbol.toLowerCase()] || symbol.toLowerCase();
}

// Helper function to get total wallet value from User.balances Map
const calculateWalletValueFromBalances = async (balancesMap, currentPrices) => {
  let totalValue = 0;
  
  if (balancesMap) {
    for (const [asset, balance] of balancesMap.entries()) {
      if (balance > 0) {
        let price = 0;
        
        // Try to get price from currentPrices first
        if (currentPrices && currentPrices[asset.toLowerCase()]) {
          price = currentPrices[asset.toLowerCase()].price;
        } else {
          // Fallback to API
          price = await getCryptoPrice(asset.toUpperCase());
        }
        
        if (price && price > 0) {
          totalValue += balance * price;
        }
      }
    }
  }
  
  return totalValue;
};

const startRealTimePriceUpdates = (io) => {
  if (priceUpdateInterval) clearInterval(priceUpdateInterval);
  
  // UPDATE PRICES EVERY 1 SECOND FOR TRUE REAL-TIME
  priceUpdateInterval = setInterval(async () => {
    try {
      const assets = ['BTC', 'ETH', 'USDT', 'BNB', 'SOL', 'USDC', 'XRP', 'DOGE', 'ADA', 'SHIB', 'AVAX', 'DOT', 'TRX', 'LINK', 'MATIC', 'LTC'];
      const priceUpdates = {};
      
      // Fetch all prices in parallel for speed
      const pricePromises = assets.map(async (asset) => {
        const price = await getCryptoPrice(asset);
        if (price) {
          priceUpdates[asset.toLowerCase()] = {
            price: price,
            timestamp: Date.now()
          };
        }
      });
      
      await Promise.all(pricePromises);
      
      if (Object.keys(priceUpdates).length > 0 && io) {
        // Broadcast price updates to all clients
        io.emit('price_update', priceUpdates);
        lastPrices = priceUpdates;
      }
      
      // IMMEDIATELY recalculate ALL user wallet values based on new prices
      await recalculateAllWalletValuesRealtime(io, priceUpdates);
      
    } catch (err) {
      console.error('Error in price update interval:', err);
    }
  }, 1000); // EVERY SECOND
};

// Helper function to recalculate wallet values in real-time using User.balances
const recalculateAllWalletValuesRealtime = async (io, currentPrices) => {
  if (isRecalculating) return;
  isRecalculating = true;
  
  try {
    const users = await User.find({}).select('_id balances');
    
    for (const user of users) {
      let totalMainValue = 0;
      let totalMaturedValue = 0;
      
      // Active wallet value should NOT be recalculated - it's fixed!
      // Just use stored value
      let totalActiveValue = 0;
      if (user.balances && user.balances.active) {
        const activeBalances = user.balances.active;
        for (const [asset, balance] of activeBalances.entries()) {
          if (balance > 0) {
            totalActiveValue += balance;
          }
        }
      }
      
      // Recalculate MAIN wallet (fluctuates)
      if (user.balances && user.balances.main) {
        totalMainValue = await calculateWalletValueFromBalances(user.balances.main, currentPrices);
      }
      
      // Recalculate MATURED wallet (fluctuates)
      if (user.balances && user.balances.matured) {
        totalMaturedValue = await calculateWalletValueFromBalances(user.balances.matured, currentPrices);
      }
      
      // Send real-time updates via Socket.IO to each specific user
      if (io) {
        io.to(`user_${user._id}`).emit('wallet_realtime_update', {
          main: totalMainValue,
          active: totalActiveValue,  // FIXED: Use stored value, not recalculated
          matured: totalMaturedValue,
          timestamp: Date.now()
        });
      }
    }
    
  } catch (err) {
    console.error('Error in real-time wallet recalculation:', err);
  } finally {
    isRecalculating = false;
  }
};

// Initialize real-time updates
const startRealTimeWalletUpdates = (io) => {
  startRealTimePriceUpdates(io);
  console.log('💰 Real-time wallet value updates started (every 1 second)');
};











// =============================================
// MISSING ADMIN DEPOSIT ENDPOINTS
// =============================================

// GET /api/admin/deposits/pending - Get pending deposit requests
app.get('/api/admin/deposits/pending', adminProtect, restrictTo('super', 'finance'), async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    // Build query for pending deposits
    const query = { 
      type: 'deposit',
      status: 'pending'
    };

    // Get deposits with user info
    const deposits = await Transaction.find(query)
      .populate('user', 'firstName lastName email')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .lean();

    const totalCount = await Transaction.countDocuments(query);
    const totalPages = Math.ceil(totalCount / limit);

    // Format deposit data for frontend
    const formattedDeposits = deposits.map(deposit => ({
      _id: deposit._id,
      user: {
        _id: deposit.user?._id,
        firstName: deposit.user?.firstName || 'Unknown',
        lastName: deposit.user?.lastName || 'Unknown'
      },
      amount: deposit.amount,
      method: deposit.method || deposit.asset || 'crypto',
      createdAt: deposit.createdAt,
      proof: deposit.details?.proofUrl || deposit.details?.txHash || null,
      status: deposit.status
    }));

    res.status(200).json({
      status: 'success',
      data: {
        deposits: formattedDeposits,
        totalCount: totalCount,
        totalPages: totalPages,
        currentPage: page
      }
    });

  } catch (err) {
    console.error('Get pending deposits error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch pending deposits'
    });
  }
});

// GET /api/admin/deposits/approved - Get approved deposit requests
app.get('/api/admin/deposits/approved', adminProtect, restrictTo('super', 'finance'), async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    // Build query for approved deposits
    const query = { 
      type: 'deposit',
      status: 'completed'
    };

    // Get deposits with user info
    const deposits = await Transaction.find(query)
      .populate('user', 'firstName lastName email')
      .populate('processedBy', 'name email')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .lean();

    const totalCount = await Transaction.countDocuments(query);
    const totalPages = Math.ceil(totalCount / limit);

    // Format deposit data for frontend
    const formattedDeposits = deposits.map(deposit => ({
      _id: deposit._id,
      user: {
        _id: deposit.user?._id,
        firstName: deposit.user?.firstName || 'Unknown',
        lastName: deposit.user?.lastName || 'Unknown'
      },
      amount: deposit.amount,
      method: deposit.method || deposit.asset || 'crypto',
      createdAt: deposit.createdAt,
      approvedBy: deposit.processedBy?.name || 'System',
      approvedAt: deposit.processedAt || deposit.updatedAt,
      status: deposit.status
    }));

    res.status(200).json({
      status: 'success',
      data: {
        deposits: formattedDeposits,
        totalCount: totalCount,
        totalPages: totalPages,
        currentPage: page
      }
    });

  } catch (err) {
    console.error('Get approved deposits error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch approved deposits'
    });
  }
});

// GET /api/admin/deposits/rejected - Get rejected deposit requests
app.get('/api/admin/deposits/rejected', adminProtect, restrictTo('super', 'finance'), async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    // Build query for rejected deposits
    const query = { 
      type: 'deposit',
      status: 'failed'
    };

    // Get deposits with user info
    const deposits = await Transaction.find(query)
      .populate('user', 'firstName lastName email')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .lean();

    const totalCount = await Transaction.countDocuments(query);
    const totalPages = Math.ceil(totalCount / limit);

    // Format deposit data for frontend
    const formattedDeposits = deposits.map(deposit => ({
      _id: deposit._id,
      user: {
        _id: deposit.user?._id,
        firstName: deposit.user?.firstName || 'Unknown',
        lastName: deposit.user?.lastName || 'Unknown'
      },
      amount: deposit.amount,
      method: deposit.method || deposit.asset || 'crypto',
      createdAt: deposit.createdAt,
      reason: deposit.adminNotes || deposit.details?.rejectionReason || 'No reason provided',
      status: deposit.status
    }));

    res.status(200).json({
      status: 'success',
      data: {
        deposits: formattedDeposits,
        totalCount: totalCount,
        totalPages: totalPages,
        currentPage: page
      }
    });

  } catch (err) {
    console.error('Get rejected deposits error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch rejected deposits'
    });
  }
});










// =============================================
// NEW ENDPOINT: Get all cryptos with user balances for withdrawal selector
// CORRECTLY uses Map structure: user.balances.main.get('btc')
// =============================================
app.get('/api/withdrawal/available-cryptos', protect, async (req, res) => {
  try {
    const userId = req.user._id;
    const user = await User.findById(userId);
    
    if (!user || !user.balances) {
      return res.status(200).json({
        status: 'success',
        data: {
          cryptos: []
        }
      });
    }
    
    // List of all supported cryptocurrencies
    const supportedCryptos = [
      { code: 'BTC', name: 'Bitcoin', logoUrl: 'https://assets.coingecko.com/coins/images/1/large/bitcoin.png', network: 'Bitcoin' },
      { code: 'ETH', name: 'Ethereum', logoUrl: 'https://assets.coingecko.com/coins/images/279/large/ethereum.png', network: 'Ethereum (ERC-20)' },
      { code: 'USDT', name: 'Tether', logoUrl: 'https://assets.coingecko.com/coins/images/325/large/Tether.png', network: 'Tron (TRC-20)' },
      { code: 'BNB', name: 'Binance Coin', logoUrl: 'https://assets.coingecko.com/coins/images/825/large/bnb-icon2_2x.png', network: 'BSC (BEP-20)' },
      { code: 'SOL', name: 'Solana', logoUrl: 'https://assets.coingecko.com/coins/images/4128/large/solana.png', network: 'Solana' },
      { code: 'USDC', name: 'USD Coin', logoUrl: 'https://assets.coingecko.com/coins/images/6319/large/USD_Coin_icon.png', network: 'Ethereum (ERC-20)' },
      { code: 'XRP', name: 'Ripple', logoUrl: 'https://assets.coingecko.com/coins/images/44/large/xrp-symbol-white-128.png', network: 'XRP Ledger' },
      { code: 'DOGE', name: 'Dogecoin', logoUrl: 'https://assets.coingecko.com/coins/images/5/large/dogecoin.png', network: 'Dogecoin' },
      { code: 'ADA', name: 'Cardano', logoUrl: 'https://assets.coingecko.com/coins/images/975/large/cardano.png', network: 'Cardano' },
      { code: 'SHIB', name: 'Shiba Inu', logoUrl: 'https://assets.coingecko.com/coins/images/11939/large/shiba.png', network: 'Ethereum (ERC-20)' },
      { code: 'AVAX', name: 'Avalanche', logoUrl: 'https://assets.coingecko.com/coins/images/12559/large/Avalanche_Circle_RedWhite.png', network: 'Avalanche C-Chain' },
      { code: 'DOT', name: 'Polkadot', logoUrl: 'https://assets.coingecko.com/coins/images/12171/large/polkadot.png', network: 'Polkadot' },
      { code: 'TRX', name: 'TRON', logoUrl: 'https://assets.coingecko.com/coins/images/1094/large/tron-logo.png', network: 'TRON' },
      { code: 'LINK', name: 'Chainlink', logoUrl: 'https://assets.coingecko.com/coins/images/877/large/chainlink-new-logo.png', network: 'Ethereum (ERC-20)' },
      { code: 'MATIC', name: 'Polygon', logoUrl: 'https://assets.coingecko.com/coins/images/4713/large/matic-token-icon.png', network: 'Polygon' },
      { code: 'LTC', name: 'Litecoin', logoUrl: 'https://assets.coingecko.com/coins/images/2/large/litecoin.png', network: 'Litecoin' }
    ];
    
    const cryptos = [];
    
    // Initialize balances Maps if they don't exist
    if (!user.balances.main) user.balances.main = new Map();
    if (!user.balances.matured) user.balances.matured = new Map();
    if (!user.balances.active) user.balances.active = new Map();
    
    // For each supported crypto, get the balance using Map.get()
    for (const crypto of supportedCryptos) {
      const cryptoLower = crypto.code.toLowerCase();
      
      // ✅ CORRECT: Use Map.get() to get balances
      const mainBalance = user.balances.main.get(cryptoLower) || 0;
      const maturedBalance = user.balances.matured.get(cryptoLower) || 0;
      const activeBalance = user.balances.active.get(cryptoLower) || 0;
      
      const totalBalance = mainBalance + maturedBalance + activeBalance;
      
      // Only include cryptos with balance > 0
      if (totalBalance > 0) {
        // Get current price for USD value
        let currentPrice = 0;
        let usdValue = 0;
        try {
          currentPrice = await getCryptoPrice(crypto.code);
          usdValue = totalBalance * currentPrice;
        } catch (err) {
          console.warn(`Could not fetch price for ${crypto.code}`);
          // Fallback to approximate prices
          const fallbackPrices = {
            'BTC': 50000, 'ETH': 3000, 'USDT': 1, 'BNB': 300, 'SOL': 100,
            'USDC': 1, 'XRP': 0.5, 'DOGE': 0.08, 'ADA': 0.3, 'SHIB': 0.00001,
            'AVAX': 20, 'DOT': 5, 'TRX': 0.08, 'LINK': 15, 'MATIC': 0.8, 'LTC': 70
          };
          currentPrice = fallbackPrices[crypto.code] || 1;
          usdValue = totalBalance * currentPrice;
        }
        
        cryptos.push({
          code: crypto.code,
          name: crypto.name,
          logoUrl: crypto.logoUrl,
          network: crypto.network,
          balance: totalBalance,
          mainBalance: mainBalance,
          maturedBalance: maturedBalance,
          activeBalance: activeBalance,
          usdValue: usdValue,
          currentPrice: currentPrice
        });
      }
    }
    
    // Sort by USD value descending
    cryptos.sort((a, b) => b.usdValue - a.usdValue);
    
    console.log(`✅ Withdrawal available cryptos for user ${userId}: ${cryptos.length} assets with balance`);
    console.log('Balances found:', cryptos.map(c => `${c.code}: ${c.balance}`).join(', '));
    
    res.status(200).json({
      status: 'success',
      data: {
        cryptos: cryptos,
        totalCryptos: cryptos.length
      }
    });
    
  } catch (err) {
    console.error('Error fetching withdrawal cryptos:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch available cryptocurrencies'
    });
  }
});





























// =============================================
// ADMIN WITHDRAWAL MANAGEMENT ENDPOINTS
// =============================================

// GET /api/admin/withdrawals/pending - Get pending withdrawal requests
app.get('/api/admin/withdrawals/pending', adminProtect, restrictTo('super', 'finance'), async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    // Build query for pending withdrawals
    const query = { 
      type: 'withdrawal',
      status: 'pending'
    };

    // Get withdrawals with user info
    const withdrawals = await Transaction.find(query)
      .populate('user', 'firstName lastName email')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .lean();

    const totalCount = await Transaction.countDocuments(query);
    const totalPages = Math.ceil(totalCount / limit);

    // Format withdrawal data for frontend
    const formattedWithdrawals = withdrawals.map(withdrawal => ({
      _id: withdrawal._id,
      user: {
        _id: withdrawal.user?._id,
        firstName: withdrawal.user?.firstName || 'Unknown',
        lastName: withdrawal.user?.lastName || 'Unknown'
      },
      amount: withdrawal.amount,
      method: withdrawal.method || withdrawal.asset || 'crypto',
      createdAt: withdrawal.createdAt,
      walletAddress: withdrawal.btcAddress || withdrawal.details?.walletAddress || 'N/A',
      asset: withdrawal.asset,
      assetAmount: withdrawal.assetAmount,
      status: withdrawal.status
    }));

    res.status(200).json({
      status: 'success',
      data: {
        withdrawals: formattedWithdrawals,
        totalCount: totalCount,
        totalPages: totalPages,
        currentPage: page
      }
    });

  } catch (err) {
    console.error('Get pending withdrawals error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch pending withdrawals'
    });
  }
});

// GET /api/admin/withdrawals/approved - Get approved withdrawal requests
app.get('/api/admin/withdrawals/approved', adminProtect, restrictTo('super', 'finance'), async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    // Build query for approved withdrawals
    const query = { 
      type: 'withdrawal',
      status: 'completed'
    };

    // Get withdrawals with user info
    const withdrawals = await Transaction.find(query)
      .populate('user', 'firstName lastName email')
      .populate('processedBy', 'name email')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .lean();

    const totalCount = await Transaction.countDocuments(query);
    const totalPages = Math.ceil(totalCount / limit);

    // Format withdrawal data for frontend
    const formattedWithdrawals = withdrawals.map(withdrawal => ({
      _id: withdrawal._id,
      user: {
        _id: withdrawal.user?._id,
        firstName: withdrawal.user?.firstName || 'Unknown',
        lastName: withdrawal.user?.lastName || 'Unknown'
      },
      amount: withdrawal.amount,
      method: withdrawal.method || withdrawal.asset || 'crypto',
      createdAt: withdrawal.createdAt,
      approvedBy: withdrawal.processedBy?.name || 'System',
      approvedAt: withdrawal.processedAt || withdrawal.updatedAt,
      asset: withdrawal.asset,
      assetAmount: withdrawal.assetAmount,
      transactionHash: withdrawal.details?.txHash,
      status: withdrawal.status
    }));

    res.status(200).json({
      status: 'success',
      data: {
        withdrawals: formattedWithdrawals,
        totalCount: totalCount,
        totalPages: totalPages,
        currentPage: page
      }
    });

  } catch (err) {
    console.error('Get approved withdrawals error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch approved withdrawals'
    });
  }
});

// GET /api/admin/withdrawals/rejected - Get rejected withdrawal requests
app.get('/api/admin/withdrawals/rejected', adminProtect, restrictTo('super', 'finance'), async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    // Build query for rejected withdrawals
    const query = { 
      type: 'withdrawal',
      status: 'failed'
    };

    // Get withdrawals with user info
    const withdrawals = await Transaction.find(query)
      .populate('user', 'firstName lastName email')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .lean();

    const totalCount = await Transaction.countDocuments(query);
    const totalPages = Math.ceil(totalCount / limit);

    // Format withdrawal data for frontend
    const formattedWithdrawals = withdrawals.map(withdrawal => ({
      _id: withdrawal._id,
      user: {
        _id: withdrawal.user?._id,
        firstName: withdrawal.user?.firstName || 'Unknown',
        lastName: withdrawal.user?.lastName || 'Unknown'
      },
      amount: withdrawal.amount,
      method: withdrawal.method || withdrawal.asset || 'crypto',
      createdAt: withdrawal.createdAt,
      reason: withdrawal.adminNotes || withdrawal.details?.rejectionReason || 'No reason provided',
      asset: withdrawal.asset,
      assetAmount: withdrawal.assetAmount,
      status: withdrawal.status
    }));

    res.status(200).json({
      status: 'success',
      data: {
        withdrawals: formattedWithdrawals,
        totalCount: totalCount,
        totalPages: totalPages,
        currentPage: page
      }
    });

  } catch (err) {
    console.error('Get rejected withdrawals error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch rejected withdrawals'
    });
  }
});

// GET /api/admin/withdrawals/:id - Get a single withdrawal by ID for approval modal
app.get('/api/admin/withdrawals/:id', adminProtect, restrictTo('super', 'finance'), async (req, res) => {
  try {
    const { id } = req.params;

    // Validate ID format
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({
        status: 'fail',
        message: 'Invalid withdrawal ID format'
      });
    }

    // Find withdrawal by ID with user info
    const withdrawal = await Transaction.findOne({
      _id: id,
      type: 'withdrawal'
    })
    .populate('user', 'firstName lastName email phone')
    .lean();

    if (!withdrawal) {
      return res.status(404).json({
        status: 'fail',
        message: 'Withdrawal not found'
      });
    }

    // Format withdrawal data for frontend modal
    const formattedWithdrawal = {
      _id: withdrawal._id,
      user: {
        _id: withdrawal.user?._id,
        firstName: withdrawal.user?.firstName || 'Unknown',
        lastName: withdrawal.user?.lastName || 'Unknown',
        email: withdrawal.user?.email || 'Unknown'
      },
      amount: withdrawal.amount,
      method: withdrawal.method || withdrawal.asset || 'crypto',
      createdAt: withdrawal.createdAt,
      walletAddress: withdrawal.btcAddress || withdrawal.details?.walletAddress || 'N/A',
      asset: withdrawal.asset,
      assetAmount: withdrawal.assetAmount,
      network: withdrawal.details?.network || withdrawal.network || getNetworkName(withdrawal.asset),
      exchangeRate: withdrawal.exchangeRateAtTime || withdrawal.details?.exchangeRate,
      fee: withdrawal.fee || 0,
      netAmount: withdrawal.netAmount || withdrawal.amount,
      status: withdrawal.status,
      bankDetails: withdrawal.bankDetails || null,
      cardDetails: withdrawal.cardDetails || null
    };

    res.status(200).json({
      status: 'success',
      data: {
        withdrawal: formattedWithdrawal
      }
    });

  } catch (err) {
    console.error('Get withdrawal by ID error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch withdrawal details'
    });
  }
});









// POST /api/admin/withdrawals/:id/approve - Approve withdrawal and deduct from user balance
app.post('/api/admin/withdrawals/:id/approve', adminProtect, restrictTo('super', 'finance'), async (req, res) => {
  try {
    const { id } = req.params;
    const { notes, transactionHash } = req.body;

    // Validate ID format
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({
        status: 'fail',
        message: 'Invalid withdrawal ID format'
      });
    }

    // Find withdrawal with user info
    const withdrawal = await Transaction.findOne({
      _id: id,
      type: 'withdrawal',
      status: 'pending'
    }).populate('user', 'firstName lastName email phone');

    if (!withdrawal) {
      return res.status(404).json({
        status: 'fail',
        message: 'Pending withdrawal not found'
      });
    }

    const user = await User.findById(withdrawal.user._id);
    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'User not found'
      });
    }

    // Determine asset and amount
    const asset = (withdrawal.asset || withdrawal.method || 'usd').toLowerCase();
    const cryptoAmount = withdrawal.assetAmount || withdrawal.amount;
    const usdAmount = withdrawal.amount;

    // Check if user has sufficient balance
    if (!user.balances || !user.balances.main) {
      return res.status(400).json({
        status: 'fail',
        message: 'User has no balance to withdraw from'
      });
    }

    const currentBalance = user.balances.main.get(asset) || 0;
    if (currentBalance < cryptoAmount) {
      return res.status(400).json({
        status: 'fail',
        message: `Insufficient ${asset.toUpperCase()} balance. Available: ${currentBalance}, Requested: ${cryptoAmount}`
      });
    }

    // Deduct from main balance
    const newBalance = currentBalance - cryptoAmount;
    if (newBalance <= 0) {
      user.balances.main.delete(asset);
    } else {
      user.balances.main.set(asset, newBalance);
    }

    // Update USD equivalent
    const currentUsdBalance = user.balances.main.get('usd') || 0;
    user.balances.main.set('usd', currentUsdBalance - usdAmount);

    await user.save();

    // Update withdrawal status
    withdrawal.status = 'completed';
    withdrawal.processedBy = req.admin._id;
    withdrawal.processedAt = new Date();
    withdrawal.adminNotes = notes || null;
    if (transactionHash) {
      withdrawal.details = withdrawal.details || {};
      withdrawal.details.txHash = transactionHash;
      withdrawal.details.processedAt = new Date();
    }
    await withdrawal.save();

    // Get current crypto price for email
    let currentPrice = 1;
    let cryptoLogoUrl = '';
    let network = '';

    if (asset !== 'usd') {
      try {
        currentPrice = await getCryptoPrice(asset.toUpperCase());
        cryptoLogoUrl = getCryptoLogo(asset.toUpperCase());
        network = getNetworkName(asset);
      } catch (err) {
        console.warn(`Could not fetch price for ${asset}`);
      }
    }

    // SEND EMAIL NOTIFICATION
    try {
      await sendProfessionalEmail({
        email: user.email,
        template: 'withdrawal_approved',
        data: {
          name: user.firstName,
          amount: cryptoAmount,
          asset: asset.toUpperCase(),
          usdValue: usdAmount,
          fee: withdrawal.fee || 0,
          feeUsd: (withdrawal.fee || 0) * currentPrice,
          netAmount: cryptoAmount - (withdrawal.fee || 0),
          withdrawalAddress: withdrawal.btcAddress || withdrawal.details?.walletAddress || 'N/A',
          method: withdrawal.method || asset.toUpperCase(),
          processedAt: withdrawal.processedAt,
          txid: transactionHash || withdrawal.reference,
          network: network
        }
      });
      console.log(`📧 Withdrawal approval email sent to ${user.email}`);
    } catch (emailError) {
      console.error('Failed to send withdrawal approval email:', emailError);
    }

    // Emit real-time update via Socket.IO
    const io = req.app.get('io');
    if (io) {
      io.to(`user_${user._id}`).emit('balance_update', {
        main: user.balances.main.get('usd') || 0,
        active: user.balances.active?.get('usd') || 0,
        matured: user.balances.matured?.get('usd') || 0
      });
      
      io.to(`user_${user._id}`).emit('withdrawal_processed', {
        withdrawalId: withdrawal._id,
        amount: usdAmount,
        asset: asset.toUpperCase(),
        assetAmount: cryptoAmount,
        status: 'completed'
      });
    }

    // Log activity
    await logActivity(
      'withdrawal_approved',
      'Transaction',
      withdrawal._id,
      req.admin._id,
      'Admin',
      req,
      {
        userId: user._id,
        amount: usdAmount,
        asset: asset,
        cryptoAmount: cryptoAmount,
        notes: notes,
        transactionHash: transactionHash
      }
    );

    // Create notification for user
    await Notification.create({
      title: 'Withdrawal Approved',
      message: `Your withdrawal of ${cryptoAmount} ${asset.toUpperCase()} ($${usdAmount.toLocaleString()}) has been approved and processed.`,
      type: 'withdrawal_approved',
      recipientType: 'specific',
      specificUserId: user._id,
      sentBy: req.admin._id,
      isImportant: false
    });

    res.status(200).json({
      status: 'success',
      message: `Withdrawal of ${cryptoAmount} ${asset.toUpperCase()} approved and processed`,
      data: {
        withdrawal: {
          id: withdrawal._id,
          reference: withdrawal.reference,
          amount: usdAmount,
          asset: asset,
          assetAmount: cryptoAmount,
          newBalance: user.balances.main.get('usd') || 0,
          status: 'completed'
        }
      }
    });

  } catch (err) {
    console.error('Approve withdrawal error:', err);
    res.status(500).json({
      status: 'error',
      message: err.message || 'Failed to approve withdrawal'
    });
  }
});

// POST /api/admin/withdrawals/:id/reject - Reject withdrawal request
app.post('/api/admin/withdrawals/:id/reject', adminProtect, restrictTo('super', 'finance'), async (req, res) => {
  try {
    const { id } = req.params;
    const { reason } = req.body;

    // Validate ID format
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({
        status: 'fail',
        message: 'Invalid withdrawal ID format'
      });
    }

    if (!reason || reason.trim() === '') {
      return res.status(400).json({
        status: 'fail',
        message: 'Rejection reason is required'
      });
    }

    // Find withdrawal with user info
    const withdrawal = await Transaction.findOne({
      _id: id,
      type: 'withdrawal',
      status: 'pending'
    }).populate('user', 'firstName lastName email');

    if (!withdrawal) {
      return res.status(404).json({
        status: 'fail',
        message: 'Pending withdrawal not found'
      });
    }

    // Update withdrawal status
    withdrawal.status = 'failed';
    withdrawal.adminNotes = reason;
    withdrawal.processedBy = req.admin._id;
    withdrawal.processedAt = new Date();
    await withdrawal.save();

    // Determine asset and amount
    const asset = (withdrawal.asset || withdrawal.method || 'usd').toLowerCase();
    const cryptoAmount = withdrawal.assetAmount || withdrawal.amount;
    const usdAmount = withdrawal.amount;

    // SEND REJECTION EMAIL
    try {
      await sendProfessionalEmail({
        email: withdrawal.user.email,
        template: 'withdrawal_rejected',
        data: {
          name: withdrawal.user.firstName,
          amount: usdAmount,
          method: withdrawal.method || asset.toUpperCase(),
          reason: reason,
          withdrawalId: withdrawal._id,
          requestedAt: withdrawal.createdAt
        }
      });
      console.log(`📧 Withdrawal rejection email sent to ${withdrawal.user.email}`);
    } catch (emailError) {
      console.error('Failed to send withdrawal rejection email:', emailError);
    }

    // Emit real-time update
    const io = req.app.get('io');
    if (io) {
      io.to(`user_${withdrawal.user._id}`).emit('withdrawal_rejected', {
        withdrawalId: withdrawal._id,
        amount: usdAmount,
        asset: asset.toUpperCase(),
        reason: reason,
        status: 'rejected'
      });
    }

    // Log activity
    await logActivity(
      'withdrawal_rejected',
      'Transaction',
      withdrawal._id,
      req.admin._id,
      'Admin',
      req,
      {
        userId: withdrawal.user._id,
        amount: usdAmount,
        asset: asset,
        reason: reason
      }
    );

    // Create notification for user
    await Notification.create({
      title: 'Withdrawal Rejected',
      message: `Your withdrawal request of ${cryptoAmount} ${asset.toUpperCase()} ($${usdAmount.toLocaleString()}) has been rejected. Reason: ${reason}`,
      type: 'withdrawal_rejected',
      recipientType: 'specific',
      specificUserId: withdrawal.user._id,
      sentBy: req.admin._id,
      isImportant: true
    });

    res.status(200).json({
      status: 'success',
      message: `Withdrawal rejected successfully`,
      data: {
        withdrawal: {
          id: withdrawal._id,
          reference: withdrawal.reference,
          amount: usdAmount,
          asset: asset,
          reason: reason,
          status: 'rejected'
        }
      }
    });

  } catch (err) {
    console.error('Reject withdrawal error:', err);
    res.status(500).json({
      status: 'error',
      message: err.message || 'Failed to reject withdrawal'
    });
  }
});











































// =============================================
// SPOT WITHDRAWAL ENDPOINT - Complete with Visual Email Body Only
// =============================================
app.post('/api/withdrawals/spot', protect, async (req, res) => {
  try {
    const userId = req.user._id;
    const {
      amount,           // USD amount requested
      asset,            // crypto asset symbol (btc, eth, trx, etc.)
      walletAddress,    // destination wallet address
      exchangeRate,     // current exchange rate (optional)
      network           // blockchain network (optional)
    } = req.body;

    const MIN_WITHDRAWAL_USD = 350;
    const GAS_FEE_BTC_LOW = 0.0056;
    const GAS_FEE_BTC_HIGH = 0.0072;
    
    const requestId = `WTH-${Date.now()}-${Math.floor(Math.random() * 10000)}`;
    
    console.log('=' .repeat(80));
    console.log('💰 SPOT WITHDRAWAL REQUEST');
    console.log('=' .repeat(80));
    console.log(`Request ID: ${requestId}`);
    console.log(`User ID: ${userId}`);
    console.log(`Amount USD: $${amount}`);
    console.log(`Asset: ${asset.toUpperCase()}`);
    console.log(`Wallet: ${walletAddress.substring(0, 20)}...`);
    console.log('=' .repeat(80));

    // =============================================
    // 1. VALIDATION
    // =============================================
    
    if (!amount || amount < MIN_WITHDRAWAL_USD) {
      return res.status(400).json({
        status: 'fail',
        message: `Minimum withdrawal amount is $${MIN_WITHDRAWAL_USD} USD`
      });
    }

    if (!asset) {
      return res.status(400).json({
        status: 'fail',
        message: 'Asset type is required'
      });
    }

    if (!walletAddress || walletAddress.trim().length < 10) {
      return res.status(400).json({
        status: 'fail',
        message: `Valid ${asset.toUpperCase()} wallet address is required`
      });
    }

    // =============================================
    // 2. DETECT NETWORK
    // =============================================
    
    const assetNetworkMap = {
      'btc': { network: 'Bitcoin', decimals: 8, logo: 'https://assets.coingecko.com/coins/images/1/large/bitcoin.png' },
      'eth': { network: 'Ethereum', decimals: 18, logo: 'https://assets.coingecko.com/coins/images/279/large/ethereum.png' },
      'usdt': { network: network || 'TRC20', decimals: 6, logo: 'https://assets.coingecko.com/coins/images/325/large/Tether.png' },
      'usdc': { network: network || 'ERC20', decimals: 6, logo: 'https://assets.coingecko.com/coins/images/6319/large/USD_Coin_icon.png' },
      'bnb': { network: 'BSC', decimals: 18, logo: 'https://assets.coingecko.com/coins/images/825/large/bnb-icon2_2x.png' },
      'sol': { network: 'Solana', decimals: 9, logo: 'https://assets.coingecko.com/coins/images/4128/large/solana.png' },
      'xrp': { network: 'XRP Ledger', decimals: 6, logo: 'https://assets.coingecko.com/coins/images/44/large/xrp-symbol-white-128.png' },
      'doge': { network: 'Dogecoin', decimals: 8, logo: 'https://assets.coingecko.com/coins/images/5/large/dogecoin.png' },
      'trx': { network: 'TRON', decimals: 6, logo: 'https://assets.coingecko.com/coins/images/1094/large/tron-logo.png' },
      'ltc': { network: 'Litecoin', decimals: 8, logo: 'https://assets.coingecko.com/coins/images/2/large/litecoin.png' },
      'ada': { network: 'Cardano', decimals: 6, logo: 'https://assets.coingecko.com/coins/images/975/large/cardano.png' },
      'matic': { network: 'Polygon', decimals: 18, logo: 'https://assets.coingecko.com/coins/images/4713/large/matic-token-icon.png' }
    };
    
    const assetLower = asset.toLowerCase();
    const assetInfo = assetNetworkMap[assetLower] || { 
      network: 'Blockchain', 
      decimals: 8,
      logo: 'https://assets.coingecko.com/coins/images/1/large/bitcoin.png'
    };
    
    const detectedNetwork = assetInfo.network;
    const assetLogo = assetInfo.logo;
    const decimals = assetInfo.decimals;

    // =============================================
    // 3. GET REAL-TIME PRICES FROM AGGREGATOR
    // =============================================
    
    let targetPrice = exchangeRate;
    if (!targetPrice || targetPrice <= 0) {
      const priceKey = REDIS_KEYS.LAST_PRICE(`${asset.toUpperCase()}USDT`);
      const cachedPrice = await redis.get(priceKey);
      
      if (cachedPrice) {
        const priceData = JSON.parse(cachedPrice);
        targetPrice = priceData.price;
      } else {
        targetPrice = await getCryptoPrice(asset.toUpperCase());
      }
      
      if (!targetPrice || targetPrice <= 0) {
        return res.status(400).json({
          status: 'fail',
          message: `Unable to fetch current ${asset.toUpperCase()} price`
        });
      }
    }
    
    let btcPrice = 0;
    const btcPriceKey = REDIS_KEYS.LAST_PRICE('BTCUSDT');
    const cachedBTCPrice = await redis.get(btcPriceKey);
    
    if (cachedBTCPrice) {
      const btcPriceData = JSON.parse(cachedBTCPrice);
      btcPrice = btcPriceData.price;
    } else {
      btcPrice = await getCryptoPrice('BTC');
    }
    
    if (!btcPrice || btcPrice <= 0) {
      return res.status(400).json({
        status: 'fail',
        message: 'Unable to fetch BTC price for gas fee calculation'
      });
    }

    // =============================================
    // 4. CALCULATE GAS FEE
    // =============================================
    
    const gasFeeInBTC = amount < 10000 ? GAS_FEE_BTC_LOW : GAS_FEE_BTC_HIGH;
    const gasFeeInUSD = gasFeeInBTC * btcPrice;
    let gasFeeInTargetAsset = gasFeeInUSD / targetPrice;
    gasFeeInTargetAsset = Number(gasFeeInTargetAsset.toFixed(decimals));
    
    const withdrawalCryptoAmount = Number((amount / targetPrice).toFixed(decimals));
    const totalCryptoNeeded = withdrawalCryptoAmount + gasFeeInTargetAsset;

    // =============================================
    // 5. GET USER AND CHECK BALANCES
    // =============================================
    
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'User not found'
      });
    }

    if (!user.balances) {
      user.balances = { main: new Map(), active: new Map(), matured: new Map() };
    }
    if (!user.balances.main) user.balances.main = new Map();
    if (!user.balances.matured) user.balances.matured = new Map();

    const mainBalance = user.balances.main.get(assetLower) || 0;
    const maturedBalance = user.balances.matured.get(assetLower) || 0;
    const totalBalance = mainBalance + maturedBalance;

    // Check gas fee in MAIN wallet
    if (mainBalance < gasFeeInTargetAsset) {
      return res.status(400).json({
        status: 'fail',
        message: `Insufficient ${asset.toUpperCase()} in MAIN wallet for gas fee. Required: ${gasFeeInTargetAsset.toFixed(decimals)} ${asset.toUpperCase()} (≈ $${gasFeeInUSD.toFixed(2)} USD)`
      });
    }
    
    if (totalBalance < totalCryptoNeeded) {
      return res.status(400).json({
        status: 'fail',
        message: `Insufficient total ${asset.toUpperCase()} balance. Required: ${totalCryptoNeeded.toFixed(decimals)} ${asset.toUpperCase()}`
      });
    }

    // =============================================
    // 6. DETERMINE WITHDRAWAL SOURCE
    // =============================================
    
    let remainingMainAfterGas = mainBalance - gasFeeInTargetAsset;
    let withdrawalFromMain = 0;
    let withdrawalFromMatured = 0;
    let balanceSource = '';
    
    if (remainingMainAfterGas >= withdrawalCryptoAmount) {
      withdrawalFromMain = withdrawalCryptoAmount;
      withdrawalFromMatured = 0;
      balanceSource = 'main';
    } else {
      withdrawalFromMain = remainingMainAfterGas;
      withdrawalFromMatured = withdrawalCryptoAmount - remainingMainAfterGas;
      balanceSource = 'both';
    }
    
    const totalMainDeduction = gasFeeInTargetAsset + withdrawalFromMain;
    const totalMaturedDeduction = withdrawalFromMatured;

    // =============================================
    // 7. PERFORM DEDUCTIONS
    // =============================================
    
    if (totalMainDeduction > 0) {
      const newMainBalance = mainBalance - totalMainDeduction;
      if (newMainBalance <= 0.00000001) {
        user.balances.main.delete(assetLower);
      } else {
        user.balances.main.set(assetLower, newMainBalance);
      }
    }
    
    if (totalMaturedDeduction > 0) {
      const newMaturedBalance = maturedBalance - totalMaturedDeduction;
      if (newMaturedBalance <= 0.00000001) {
        user.balances.matured.delete(assetLower);
      } else {
        user.balances.matured.set(assetLower, newMaturedBalance);
      }
    }
    
    // Update USD equivalents
    const currentMainUSD = user.balances.main.get('usd') || 0;
    const currentMaturedUSD = user.balances.matured.get('usd') || 0;
    
    if (totalMainDeduction > 0) {
      const newMainUSD = currentMainUSD - (gasFeeInUSD + (withdrawalFromMain / withdrawalCryptoAmount) * amount);
      if (newMainUSD <= 0.01) {
        user.balances.main.delete('usd');
      } else {
        user.balances.main.set('usd', newMainUSD);
      }
    }
    
    if (totalMaturedDeduction > 0) {
      const newMaturedUSD = currentMaturedUSD - (withdrawalFromMatured / withdrawalCryptoAmount) * amount;
      if (newMaturedUSD <= 0.01) {
        user.balances.matured.delete('usd');
      } else {
        user.balances.matured.set('usd', newMaturedUSD);
      }
    }
    
    await user.save();

    // =============================================
    // 8. CREATE TRANSACTION
    // =============================================
    
    const fee = Math.max(1, amount * 0.01);
    const netAmount = amount - fee;
    const reference = `WTH-${Date.now()}-${Math.floor(Math.random() * 10000)}`;
    
    const transaction = await Transaction.create({
      user: userId,
      type: 'withdrawal',
      amount: amount,
      asset: asset.toLowerCase(),
      assetAmount: withdrawalCryptoAmount,
      currency: 'USD',
      status: 'pending',
      method: asset.toUpperCase(),
      reference: reference,
      details: {
        requestId: requestId,
        withdrawalAddress: walletAddress,
        exchangeRate: targetPrice,
        network: detectedNetwork,
        gasFee: {
          amount: gasFeeInTargetAsset,
          asset: asset.toUpperCase(),
          usdValue: gasFeeInUSD,
          btcEquivalent: gasFeeInBTC
        },
        balanceSource: balanceSource,
        mainAmountUsed: withdrawalFromMain,
        maturedAmountUsed: withdrawalFromMatured,
        gasFeeFromMain: gasFeeInTargetAsset
      },
      btcAddress: walletAddress,
      fee: fee,
      netAmount: netAmount,
      exchangeRateAtTime: targetPrice,
      network: detectedNetwork
    });

    // =============================================
    // 9. SEND VISUAL EMAIL (Body Only - No Header/Footer)
    // =============================================
    
    // Wallet display text
    let walletDisplayText = balanceSource === 'main' ? 'Main Wallet' : 
                           balanceSource === 'matured' ? 'Matured Wallet' : 'Main & Matured Wallets';
    
    // Email body HTML (clean, visual, organized)
    const emailBodyHtml = `
      <div style="padding: 0;">
        
        <!-- Status Badge -->
        <div style="text-align: center; margin-bottom: 25px;">
          <div style="display: inline-block; background: rgba(247, 166, 0, 0.1); border: 1px solid rgba(247, 166, 0, 0.3); border-radius: 60px; padding: 6px 16px;">
            <span style="color: #F7A600; font-size: 13px; font-weight: 600;">⏳ PENDING CONFIRMATION</span>
          </div>
        </div>
        
        <!-- Greeting -->
        <p style="color: #FFFFFF; font-size: 16px; margin-bottom: 25px; line-height: 1.5;">Dear <strong style="color: #F7A600;">${user.firstName}</strong>,</p>
        <p style="color: #B7BDC6; font-size: 14px; margin-bottom: 25px; line-height: 1.6;">Your withdrawal request has been received and is currently being processed. Below are the details of your transaction.</p>
        
        <!-- Withdrawal Card -->
        <div style="background: #11151C; border-radius: 16px; padding: 24px; margin-bottom: 24px; border: 1px solid #1E2329;">
          
          <!-- Asset Header with Logo -->
          <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 20px; padding-bottom: 16px; border-bottom: 1px solid #1E2329;">
            <div style="width: 48px; height: 48px; border-radius: 50%; background: rgba(247, 166, 0, 0.1); display: flex; align-items: center; justify-content: center;">
              <img src="${assetLogo}" alt="${asset.toUpperCase()}" style="width: 32px; height: 32px;">
            </div>
            <div style="flex: 1;">
              <div style="font-size: 18px; font-weight: 700; color: #FFFFFF; margin-bottom: 4px;">${asset.toUpperCase()} Withdrawal</div>
              <div style="font-size: 12px; color: #6C7480;">Network: ${detectedNetwork}</div>
            </div>
          </div>
          
          <!-- Withdrawal Amount -->
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; padding-bottom: 16px; border-bottom: 1px solid #1E2329;">
            <div style="font-size: 14px; color: #B7BDC6;">Withdrawal Amount</div>
            <div style="text-align: right;">
              <div style="font-size: 20px; font-weight: 700; color: #FFFFFF;">${withdrawalCryptoAmount.toFixed(decimals)} ${asset.toUpperCase()}</div>
              <div style="font-size: 13px; color: #6C7480;">≈ $${amount.toLocaleString()} USD</div>
            </div>
          </div>
          
          <!-- GAS FEE - IN RED -->
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; padding: 16px; background: rgba(239, 68, 68, 0.1); border-radius: 12px; border-left: 3px solid #EF4444;">
            <div style="display: flex; align-items: center; gap: 8px;">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path d="M5 10H19M5 10V18C5 19.1046 5.89543 20 7 20H17C18.1046 20 19 19.1046 19 18V10M5 10L7 4H17L19 10M12 14V16" stroke="#EF4444" stroke-width="2" stroke-linecap="round"/>
                <path d="M8 4L6 10M16 4L18 10" stroke="#EF4444" stroke-width="2" stroke-linecap="round"/>
              </svg>
              <span style="font-size: 14px; font-weight: 600; color: #EF4444;">Network Gas Fee</span>
            </div>
            <div style="text-align: right;">
              <div style="font-size: 16px; font-weight: 700; color: #EF4444;">${gasFeeInTargetAsset.toFixed(decimals)} ${asset.toUpperCase()}</div>
              <div style="font-size: 12px; color: #EF4444; opacity: 0.8;">≈ $${gasFeeInUSD.toFixed(2)} USD</div>
            </div>
          </div>
          
          <!-- Wallet Deduction Source -->
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; padding: 12px; background: ${balanceSource === 'main' ? 'rgba(247, 166, 0, 0.05)' : balanceSource === 'matured' ? 'rgba(16, 185, 129, 0.05)' : 'rgba(99, 102, 241, 0.05)'}; border-radius: 12px;">
            <div style="display: flex; align-items: center; gap: 8px;">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path d="M20 7H4C2.89543 7 2 7.89543 2 9V19C2 20.1046 2.89543 21 4 21H20C21.1046 21 22 20.1046 22 19V9C22 7.89543 21.1046 7 20 7Z" stroke="${balanceSource === 'main' ? '#F7A600' : balanceSource === 'matured' ? '#10B981' : '#818CF8'}" stroke-width="2" stroke-linecap="round"/>
                <path d="M16 3L20 7M8 3L4 7" stroke="${balanceSource === 'main' ? '#F7A600' : balanceSource === 'matured' ? '#10B981' : '#818CF8'}" stroke-width="2" stroke-linecap="round"/>
              </svg>
              <span style="font-size: 14px; color: #B7BDC6;">Deducted From</span>
            </div>
            <div>
              <span style="display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: 600; background: ${balanceSource === 'main' ? 'rgba(247, 166, 0, 0.15)' : balanceSource === 'matured' ? 'rgba(16, 185, 129, 0.15)' : 'rgba(99, 102, 241, 0.15)'}; color: ${balanceSource === 'main' ? '#F7A600' : balanceSource === 'matured' ? '#10B981' : '#818CF8'};">${walletDisplayText}</span>
            </div>
          </div>
          
          <!-- Detailed Breakdown (if both wallets used) -->
          ${balanceSource === 'both' ? `
          <div style="background: #0B0E11; border-radius: 12px; padding: 12px; margin-top: 12px; border: 1px solid #1E2329;">
            <div style="font-size: 12px; color: #6C7480; margin-bottom: 8px;">Breakdown:</div>
            <div style="display: flex; justify-content: space-between; margin-bottom: 6px;">
              <span style="font-size: 13px; color: #B7BDC6;">From Main Wallet:</span>
              <span style="font-size: 13px; font-weight: 600; color: #F7A600;">${withdrawalFromMain.toFixed(decimals)} ${asset.toUpperCase()}</span>
            </div>
            <div style="display: flex; justify-content: space-between;">
              <span style="font-size: 13px; color: #B7BDC6;">From Matured Wallet:</span>
              <span style="font-size: 13px; font-weight: 600; color: #10B981;">${withdrawalFromMatured.toFixed(decimals)} ${asset.toUpperCase()}</span>
            </div>
          </div>
          ` : ''}
          
          <!-- Destination Address -->
          <div style="background: #0B0E11; border: 1px solid #1E2329; border-radius: 12px; padding: 16px; margin-top: 16px;">
            <div style="font-size: 12px; color: #6C7480; margin-bottom: 8px;">Destination Wallet Address</div>
            <div style="font-size: 13px; color: #B7BDC6; word-break: break-all; font-family: monospace;">${walletAddress}</div>
          </div>
          
          <!-- Transaction Details Grid -->
          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-top: 16px;">
            <div style="background: #0B0E11; padding: 12px; border-radius: 12px; border: 1px solid #1E2329;">
              <div style="font-size: 11px; color: #6C7480; margin-bottom: 4px; text-transform: uppercase; letter-spacing: 0.5px;">Exchange Rate</div>
              <div style="font-size: 14px; font-weight: 600; color: #F7A600;">1 ${asset.toUpperCase()} ≈ $${targetPrice.toFixed(2)}</div>
            </div>
            <div style="background: #0B0E11; padding: 12px; border-radius: 12px; border: 1px solid #1E2329;">
              <div style="font-size: 11px; color: #6C7480; margin-bottom: 4px; text-transform: uppercase; letter-spacing: 0.5px;">Request ID</div>
              <div style="font-size: 13px; font-weight: 600; color: #FFFFFF; font-family: monospace;">${reference}</div>
            </div>
          </div>
          
        </div>
        
        <!-- Total Summary -->
        <div style="background: linear-gradient(135deg, #11151C 0%, #0B0E11 100%); border-radius: 12px; padding: 20px; margin-top: 8px; border: 1px solid #1E2329;">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
            <div style="font-size: 16px; font-weight: 600; color: #FFFFFF;">Total Deducted</div>
            <div style="text-align: right;">
              <div style="font-size: 18px; font-weight: 700; color: #F7A600;">${totalCryptoNeeded.toFixed(decimals)} ${asset.toUpperCase()}</div>
              <div style="font-size: 12px; color: #6C7480;">≈ $${(amount + gasFeeInUSD).toFixed(2)} USD</div>
            </div>
          </div>
          <div style="height: 1px; background: #1E2329; margin: 12px 0;"></div>
          <div style="display: flex; justify-content: space-between; align-items: center;">
            <div style="font-size: 13px; color: #6C7480;">Your remaining balance will be updated shortly</div>
            <a href="https://www.bithashcapital.live/dashboard" style="background: #F7A600; color: #000000; padding: 10px 20px; text-decoration: none; border-radius: 999px; font-size: 13px; font-weight: 600;">View Dashboard →</a>
          </div>
        </div>
        
        <!-- Help Section -->
        <div style="margin-top: 30px; padding: 20px; background: rgba(247, 166, 0, 0.05); border-radius: 12px; text-align: center; border: 1px solid rgba(247, 166, 0, 0.1);">
          <p style="color: #B7BDC6; font-size: 13px; margin: 0;">
            <strong style="color: #F7A600;">Need help?</strong> Contact our support team at 
            <a href="mailto:support@bithashcapital.live" style="color: #F7A600; text-decoration: none;">support@bithashcapital.live</a>
          </p>
        </div>
        
      </div>
    `;
    
    // Send email using your existing sendProfessionalEmail function
    // The template will automatically add header and footer
    await sendProfessionalEmail({
      email: user.email,
      template: 'withdrawal_request',
      data: {
        name: user.firstName,
        amount: withdrawalCryptoAmount.toFixed(decimals),
        asset: asset.toUpperCase(),
        usdValue: amount,
        withdrawalAddress: walletAddress,
        requestId: reference,
        network: detectedNetwork,
        exchangeRate: targetPrice,
        gasFee: {
          amount: gasFeeInTargetAsset.toFixed(decimals),
          usdValue: gasFeeInUSD.toFixed(2)
        },
        walletSource: balanceSource,
        customBody: emailBodyHtml  // Pass custom body to override default
      }
    });
    
    // Override the email content with our visual body
    // This uses the existing transporter directly to avoid duplicating header/footer
    const mailTransporter = infoTransporter;
    await mailTransporter.sendMail({
      from: `₿itHash Capital <${process.env.EMAIL_INFO_USER}>`,
      to: user.email,
      subject: `Withdrawal Request Submitted - ₿itHash Capital`,
      html: `
        <div style="font-family: 'Inter', sans-serif; max-width: 600px; margin: 0 auto; background: #0B0E11;">
          <!-- Header -->
          <div style="text-align: center; padding: 30px 20px 20px 20px; background: linear-gradient(135deg, #0B0E11 0%, #11151C 100%); border-bottom: 1px solid #1E2329;">
            <img src="https://media.bithashcapital.live/ChatGPT%20Image%20Mar%2029%2C%202026%2C%2004_52_02%20PM.png" alt="₿itHash Logo" style="width: 60px; height: 60px; margin-bottom: 15px;">
            <h1 style="color: #F7A600; font-size: 28px; margin: 0; font-weight: bold;">₿itHash</h1>
            <p style="color: #B7BDC6; font-size: 14px; margin: 10px 0 0 0;"><i><strong>Where Your Financial Goals Become Reality</strong></i></p>
          </div>
          
          <!-- Body Content -->
          ${emailBodyHtml}
          
          <!-- Footer -->
          <div style="text-align: center; padding: 20px; background: #0B0E11; border-top: 1px solid #1E2329;">
            <p style="color: #6C7480; font-size: 12px; margin: 5px 0;">&copy; ${new Date().getFullYear()} ₿itHash Capital. All rights reserved.</p>
            <p style="color: #6C7480; font-size: 12px; margin: 5px 0;">800 Plant St, Wilmington, DE 19801, United States</p>
            <p style="color: #6C7480; font-size: 12px; margin: 5px 0;">
              <a href="mailto:support@bithashcapital.live" style="color: #F7A600; text-decoration: none;">support@bithashcapital.live</a> | 
              <a href="https://www.bithashcapital.live" style="color: #F7A600; text-decoration: none;">www.bithashcapital.live</a>
            </p>
          </div>
        </div>
      `
    });
    
    console.log(`📧 Visual withdrawal email sent to ${user.email}`);
    console.log(`   Asset: ${asset.toUpperCase()}`);
    console.log(`   Amount: ${withdrawalCryptoAmount.toFixed(decimals)}`);
    console.log(`   Gas Fee: ${gasFeeInTargetAsset.toFixed(decimals)} (deducted from ${balanceSource} wallet)`);

    // =============================================
    // 10. CREATE SYSTEM LOG
    // =============================================
    
    await SystemLog.create({
      action: 'withdrawal_created',
      entity: 'withdrawal_request',
      entityId: transaction._id,
      performedBy: userId,
      performedByModel: 'User',
      performedByEmail: user.email,
      performedByName: `${user.firstName} ${user.lastName}`,
      ip: getRealClientIP(req),
      userAgent: req.headers['user-agent'] || 'Unknown',
      deviceType: getDeviceType(req),
      status: 'success',
      riskLevel: 'medium',
      location: `${req.clientLocation?.city || 'Unknown'}, ${req.clientLocation?.country || 'Unknown'}`,
      metadata: {
        requestId: requestId,
        reference: reference,
        amountUSD: amount,
        asset: asset.toUpperCase(),
        cryptoAmount: withdrawalCryptoAmount,
        walletAddress: walletAddress,
        network: detectedNetwork,
        gasFee: {
          amount: gasFeeInTargetAsset,
          asset: asset.toUpperCase(),
          usdValue: gasFeeInUSD,
          btcEquivalent: gasFeeInBTC
        },
        balanceSource: balanceSource,
        mainAmountUsed: withdrawalFromMain,
        maturedAmountUsed: withdrawalFromMatured,
        exchangeRate: targetPrice,
        btcPrice: btcPrice
      },
      financial: {
        amount: amount,
        amountUSD: amount,
        cryptoAmount: withdrawalCryptoAmount,
        cryptoAsset: asset.toUpperCase(),
        fee: 0,
        exchangeRate: targetPrice,
        balanceAfter: (user.balances.main.get('usd') || 0) + (user.balances.matured.get('usd') || 0),
        walletType: 'main',
        transactionId: transaction._id,
        reference: reference
      }
    });

    // =============================================
    // 11. EMIT REAL-TIME UPDATE
    // =============================================
    
    const io = req.app.get('io');
    if (io) {
      let newMainUSD = 0;
      let newMaturedUSD = 0;
      
      for (const [crypto, balance] of user.balances.main) {
        if (crypto !== 'usd' && balance > 0) {
          const price = await getCryptoPrice(crypto.toUpperCase());
          if (price) newMainUSD += balance * price;
        }
      }
      
      for (const [crypto, balance] of user.balances.matured) {
        if (crypto !== 'usd' && balance > 0) {
          const price = await getCryptoPrice(crypto.toUpperCase());
          if (price) newMaturedUSD += balance * price;
        }
      }
      
      io.to(`user_${userId}`).emit('balance_update', {
        main: newMainUSD,
        matured: newMaturedUSD,
        active: user.balances.active?.get('usd') || 0,
        timestamp: Date.now()
      });
    }

    // =============================================
    // 12. RETURN SUCCESS RESPONSE
    // =============================================
    
    console.log(`\n✅ WITHDRAWAL SUBMITTED SUCCESSFULLY`);
    console.log(`   Reference: ${reference}`);
    console.log(`   Network: ${detectedNetwork}`);
    console.log(`   Amount: ${withdrawalCryptoAmount.toFixed(decimals)} ${asset.toUpperCase()}`);
    console.log(`   Gas Fee: ${gasFeeInTargetAsset.toFixed(decimals)} ${asset.toUpperCase()} (deducted from ${balanceSource} wallet)`);
    console.log(`   Email sent to: ${user.email}`);
    console.log('=' .repeat(80));
    
    res.status(201).json({
      status: 'success',
      message: `Withdrawal request submitted successfully on ${detectedNetwork} network.`,
      data: {
        transaction: {
          id: transaction._id,
          reference: reference,
          requestId: requestId,
          amountUSD: amount,
          cryptoAmount: withdrawalCryptoAmount,
          asset: asset.toUpperCase(),
          network: detectedNetwork,
          status: 'pending'
        },
        gasFee: {
          amount: gasFeeInTargetAsset,
          asset: asset.toUpperCase(),
          usdValue: gasFeeInUSD,
          btcEquivalent: gasFeeInBTC
        },
        balanceInfo: {
          source: balanceSource,
          mainAmountUsed: withdrawalFromMain,
          maturedAmountUsed: withdrawalFromMatured,
          gasFeeFromMain: gasFeeInTargetAsset
        }
      }
    });

  } catch (err) {
    console.error('❌ Withdrawal error:', err);
    res.status(500).json({
      status: 'error',
      message: err.message || 'Failed to process withdrawal'
    });
  }
});









// PUT /api/admin/users/:userId - Update user information
app.put('/api/admin/users/:userId', adminProtect, async (req, res) => {
  try {
    const { userId } = req.params;

    if (!mongoose.Types.ObjectId.isValid(userId)) {
      return res.status(400).json({
        status: 'fail',
        message: 'Invalid user ID'
      });
    }

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'User not found'
      });
    }

    const { first_name, last_name, email, status, two_factor_auth } = req.body;

    if (first_name) user.firstName = first_name;
    if (last_name) user.lastName = last_name;
    if (email) user.email = email;
    if (status) user.status = status;
    if (two_factor_auth !== undefined) {
      if (!user.twoFactorAuth) user.twoFactorAuth = { enabled: false };
      user.twoFactorAuth.enabled = two_factor_auth === 'enabled';
    }

    await user.save();

    res.status(200).json({
      status: 'success',
      message: 'User updated successfully',
      data: {
        user: {
          _id: user._id,
          firstName: user.firstName,
          lastName: user.lastName,
          email: user.email,
          status: user.status,
          twoFactorAuth: user.twoFactorAuth
        }
      }
    });

  } catch (err) {
    console.error('Update user error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to update user'
    });
  }
});










// GET /api/admin/users/:userId - Get single user with real-time USD balances from crypto Maps
app.get('/api/admin/users/:userId', adminProtect, async (req, res) => {
  try {
    const { userId } = req.params;

    if (!mongoose.Types.ObjectId.isValid(userId)) {
      return res.status(400).json({
        status: 'fail',
        message: 'Invalid user ID'
      });
    }

    const user = await User.findById(userId)
      .select('_id firstName lastName email balances status lastLogin createdAt twoFactorAuth')
      .lean();

    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'User not found'
      });
    }

    let mainUSD = 0;
    let activeUSD = 0;
    let maturedUSD = 0;

    // Calculate MAIN wallet USD value from crypto Map (SAME logic as admin/users)
    if (user.balances && user.balances.main) {
      const mainMap = user.balances.main;
      const entries = mainMap instanceof Map ? mainMap.entries() : Object.entries(mainMap);
      
      for (const [crypto, amount] of entries) {
        if (amount > 0 && crypto !== 'usd') {
          const price = await getCryptoPrice(crypto.toUpperCase());
          if (price) {
            mainUSD += amount * price;
          }
        }
      }
    }

    // Calculate ACTIVE wallet USD value from crypto Map (SAME logic as admin/users)
    if (user.balances && user.balances.active) {
      const activeMap = user.balances.active;
      const entries = activeMap instanceof Map ? activeMap.entries() : Object.entries(activeMap);
      
      for (const [crypto, amount] of entries) {
        if (amount > 0 && crypto !== 'usd') {
          const price = await getCryptoPrice(crypto.toUpperCase());
          if (price) {
            activeUSD += amount * price;
          }
        }
      }
    }

    // Calculate MATURED wallet USD value from crypto Map (SAME logic as admin/users)
    if (user.balances && user.balances.matured) {
      const maturedMap = user.balances.matured;
      const entries = maturedMap instanceof Map ? maturedMap.entries() : Object.entries(maturedMap);
      
      for (const [crypto, amount] of entries) {
        if (amount > 0 && crypto !== 'usd') {
          const price = await getCryptoPrice(crypto.toUpperCase());
          if (price) {
            maturedUSD += amount * price;
          }
        }
      }
    }

    res.status(200).json({
      status: 'success',
      data: {
        user: {
          _id: user._id,
          firstName: user.firstName,
          lastName: user.lastName,
          email: user.email,
          balances: {
            active: activeUSD,
            matured: maturedUSD,
            main: mainUSD
          },
          status: user.status,
          lastLogin: user.lastLogin,
          createdAt: user.createdAt,
          twoFactorAuth: {
            enabled: user.twoFactorAuth?.enabled || false
          }
        }
      }
    });

  } catch (err) {
    console.error('Get user by ID error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch user'
    });
  }
});























// GET /api/admin/users - Get all users with real-time USD balances from crypto Maps
app.get('/api/admin/users', adminProtect, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    // Use .lean() but we need to handle Maps properly
    const users = await User.find({})
      .select('_id firstName lastName email balances status lastLogin createdAt')
      .skip(skip)
      .limit(limit)
      .lean();

    const totalUsers = await User.countDocuments({});
    const totalPages = Math.ceil(totalUsers / limit);

    const formattedUsers = [];

    for (const user of users) {
      let mainUSD = 0;
      let activeUSD = 0;
      let maturedUSD = 0;

      // Debug: Log the actual balances structure
      console.log('User balances:', user.email, JSON.stringify(user.balances));

      // Calculate MAIN wallet USD value from crypto Map
      if (user.balances && user.balances.main) {
        const mainMap = user.balances.main;
        // Check if it's an object (from lean()) or a Map
        const entries = mainMap instanceof Map ? mainMap.entries() : Object.entries(mainMap);
        
        for (const [crypto, amount] of entries) {
          if (amount > 0 && crypto !== 'usd') {
            const price = await getCryptoPrice(crypto.toUpperCase());
            if (price) {
              mainUSD += amount * price;
              console.log(`${crypto}: ${amount} * $${price} = $${amount * price}`);
            }
          }
        }
      }

      // Calculate ACTIVE wallet USD value from crypto Map
      if (user.balances && user.balances.active) {
        const activeMap = user.balances.active;
        const entries = activeMap instanceof Map ? activeMap.entries() : Object.entries(activeMap);
        
        for (const [crypto, amount] of entries) {
          if (amount > 0 && crypto !== 'usd') {
            const price = await getCryptoPrice(crypto.toUpperCase());
            if (price) {
              activeUSD += amount * price;
            }
          }
        }
      }

      // Calculate MATURED wallet USD value from crypto Map
      if (user.balances && user.balances.matured) {
        const maturedMap = user.balances.matured;
        const entries = maturedMap instanceof Map ? maturedMap.entries() : Object.entries(maturedMap);
        
        for (const [crypto, amount] of entries) {
          if (amount > 0 && crypto !== 'usd') {
            const price = await getCryptoPrice(crypto.toUpperCase());
            if (price) {
              maturedUSD += amount * price;
            }
          }
        }
      }

      formattedUsers.push({
        _id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        balances: {
          active: activeUSD,
          matured: maturedUSD,
          main: mainUSD
        },
        status: user.status,
        lastLogin: user.lastLogin,
        createdAt: user.createdAt
      });
    }

    res.status(200).json({
      status: 'success',
      data: {
        users: formattedUsers,
        totalPages,
        currentPage: page,
        totalCount: totalUsers
      }
    });

  } catch (err) {
    console.error('Get users error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch users'
    });
  }
});


// GET /api/admin/restrictions - Get current account restrictions
app.get('/api/admin/restrictions', adminProtect, restrictTo('super'), async (req, res) => {
  try {
    const restrictions = await AccountRestrictions.getInstance();
    
    res.status(200).json({
      status: 'success',
      data: {
        withdraw_limit_no_kyc: restrictions.withdraw_limit_no_kyc,
        invest_limit_no_kyc: restrictions.invest_limit_no_kyc,
        trade_limit_no_txn: restrictions.invest_limit_no_txn,
        withdraw_limit_no_txn: restrictions.withdraw_limit_no_txn,
        kyc_restriction_reason: restrictions.kyc_restriction_reason,
        txn_restriction_reason: restrictions.txn_restriction_reason
      }
    });
    
  } catch (err) {
    console.error('Get restrictions error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch restrictions'
    });
  }
});




























// GET /api/admin/deposits/:id - Get a single deposit by ID for approval modal
app.get('/api/admin/deposits/:id', adminProtect, restrictTo('super', 'finance'), async (req, res) => {
  try {
    const { id } = req.params;

    // Validate ID format
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({
        status: 'fail',
        message: 'Invalid deposit ID format'
      });
    }

    // Find deposit by ID with user info
    const deposit = await Transaction.findOne({
      _id: id,
      type: 'deposit'
    })
    .populate('user', 'firstName lastName email phone')
    .lean();

    if (!deposit) {
      return res.status(404).json({
        status: 'fail',
        message: 'Deposit not found'
      });
    }

    // Format deposit data for frontend modal
    const formattedDeposit = {
      _id: deposit._id,
      user: {
        _id: deposit.user?._id,
        firstName: deposit.user?.firstName || 'Unknown',
        lastName: deposit.user?.lastName || 'Unknown',
        email: deposit.user?.email || 'Unknown'
      },
      amount: deposit.amount,
      method: deposit.method || deposit.asset || 'crypto',
      createdAt: deposit.createdAt,
      proof: deposit.details?.proofUrl || deposit.details?.txHash || deposit.reference,
      status: deposit.status,
      asset: deposit.asset,
      assetAmount: deposit.assetAmount,
      network: deposit.details?.network || deposit.network,
      exchangeRate: deposit.exchangeRateAtTime || deposit.details?.exchangeRate,
      transactionHash: deposit.details?.txHash || deposit.details?.transactionHash,
      walletAddress: deposit.btcAddress || deposit.details?.toAddress
    };

    res.status(200).json({
      status: 'success',
      data: {
        deposit: formattedDeposit
      }
    });

  } catch (err) {
    console.error('Get deposit by ID error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch deposit details'
    });
  }
});












































































/**
 * APPROVE DEPOSIT ENDPOINT - FIXED VERSION
 * POST /api/admin/deposits/:id/approve
 */
app.post('/api/admin/deposits/:id/approve', adminProtect, restrictTo('super', 'finance'), async (req, res) => {
  try {
    const { id } = req.params;
    const { notes } = req.body;
    
    // Find the deposit - check both DepositAsset and Transaction collections
    let deposit = await DepositAsset.findById(id).populate('user', 'firstName lastName email balances');
    
    if (!deposit) {
      const transaction = await Transaction.findOne({ 
        _id: id, 
        type: 'deposit', 
        status: 'pending' 
      }).populate('user', 'firstName lastName email balances');
      
      if (!transaction) {
        return res.status(404).json({
          status: 'fail',
          message: 'Deposit not found'
        });
      }
      deposit = transaction;
    }
    
    // Check if deposit is already processed
    if (deposit.status !== 'pending') {
      return res.status(400).json({
        status: 'fail',
        message: `Deposit is already ${deposit.status}`
      });
    }
    
    const user = deposit.user;
    
    // IMPORTANT: Extract asset and amounts correctly
    const cryptoAsset = (deposit.asset || deposit.method || 'USDT').toUpperCase();
    const cryptoAmount = parseFloat(deposit.assetAmount || deposit.amount || 0);
    const usdAmount = parseFloat(deposit.amount || 0);
    
    if (cryptoAmount <= 0 || usdAmount <= 0) {
      return res.status(400).json({
        status: 'fail',
        message: 'Invalid deposit amount'
      });
    }
    
    // Get current crypto price for exchange rate
    const currentPrice = await getCryptoPrice(cryptoAsset);
    const exchangeRate = currentPrice || (usdAmount / cryptoAmount) || 1;
    
    // Add crypto to user's main balance using Map
    if (!user.balances) {
      user.balances = { main: new Map(), active: new Map(), matured: new Map() };
    }
    if (!user.balances.main) user.balances.main = new Map();
    
    const currentMainBalance = user.balances.main.get(cryptoAsset.toLowerCase()) || 0;
    const newMainBalanceCrypto = currentMainBalance + cryptoAmount;
    user.balances.main.set(cryptoAsset.toLowerCase(), newMainBalanceCrypto);
    
    // Update USD equivalent in main wallet
    const currentUsdBalance = user.balances.main.get('usd') || 0;
    user.balances.main.set('usd', currentUsdBalance + usdAmount);
    
    // Update deposit status
    deposit.status = 'completed';
    deposit.completedAt = new Date();
    deposit.processedBy = req.admin._id;
    deposit.processedAt = new Date();
    deposit.adminNotes = notes;
    deposit.exchangeRateAtTime = exchangeRate;
    
    await deposit.save();
    await user.save();
    
    // ✅ FIXED: Create transaction record with ALL required fields
    const transactionReference = `DEP-${Date.now()}-${Math.floor(Math.random() * 10000)}`;
    
    const transactionRecord = await Transaction.create({
      user: user._id,
      type: 'deposit',
      amount: usdAmount,
      asset: cryptoAsset,                    // ✅ CRITICAL: Asset type
      assetAmount: cryptoAmount,             // ✅ CRITICAL: Crypto amount
      currency: 'USD',
      status: 'completed',
      method: cryptoAsset,
      reference: transactionReference,
      details: {
        depositId: deposit._id,
        adminApprovedBy: req.admin.name,
        adminNotes: notes,
        exchangeRate: exchangeRate,
        walletType: 'main'
      },
      fee: 0,
      netAmount: usdAmount,
      processedBy: req.admin._id,
      processedAt: new Date(),
      exchangeRateAtTime: exchangeRate
    });
    
    // Calculate total MAIN wallet balance in USD for email
    let totalMainBalanceUSD = 0;
    for (const [asset, balance] of user.balances.main) {
      if (balance > 0 && asset !== 'usd') {
        const assetPrice = await getCryptoPrice(asset);
        if (assetPrice) {
          totalMainBalanceUSD += balance * assetPrice;
        }
      }
    }
    
    // Send email notification
    const cryptoLogoUrl = getCryptoLogo(cryptoAsset);
    
    await sendProfessionalEmail({
      email: user.email,
      template: 'deposit_approved',
      data: {
        name: user.firstName,
        amount: usdAmount.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 }),
        cryptoAmount: cryptoAmount.toLocaleString(undefined, { minimumFractionDigits: 8, maximumFractionDigits: 8 }),
        cryptoAsset: cryptoAsset,
        cryptoLogoUrl: cryptoLogoUrl,
        method: cryptoAsset,
        reference: transactionRecord.reference,
        newBalance: totalMainBalanceUSD.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 }),
        processedAt: new Date().toLocaleString(),
        exchangeRate: exchangeRate.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 }),
        walletType: 'Main Wallet',
        walletColor: '#10B981'
      }
    });
    
    // Log activity
    await logActivity(
      'deposit_approved',
      'deposit',
      deposit._id,
      req.admin._id,
      'Admin',
      req,
      { amount: usdAmount, asset: cryptoAsset, userId: user._id, cryptoAmount: cryptoAmount }
    );
    
    // Create notification for user
    await Notification.create({
      title: 'Deposit Approved',
      message: `Your deposit of ${cryptoAmount.toLocaleString(undefined, { minimumFractionDigits: 8, maximumFractionDigits: 8 })} ${cryptoAsset} ($${usdAmount.toLocaleString()}) has been approved and credited to your main wallet.`,
      type: 'deposit_approved',
      recipientType: 'specific',
      specificUserId: user._id,
      isImportant: false,
      sentBy: req.admin._id,
      metadata: {
        depositId: deposit._id,
        amount: usdAmount,
        cryptoAmount: cryptoAmount,
        asset: cryptoAsset
      }
    });
    
    // Emit real-time update via Socket.IO
    const io = req.app.get('io');
    if (io) {
      io.to(`user_${user._id}`).emit('balance_update', {
        main: user.balances.main.get('usd') || 0,
        active: user.balances.active?.get('usd') || 0,
        matured: user.balances.matured?.get('usd') || 0
      });
      
      io.to(`user_${user._id}`).emit('crypto_balance_update', {
        currency: cryptoAsset.toLowerCase(),
        walletType: 'main',
        balance: newMainBalanceCrypto,
        usdValue: newMainBalanceCrypto * exchangeRate
      });
    }
    
    res.status(200).json({
      status: 'success',
      message: `Deposit of ${cryptoAmount} ${cryptoAsset} approved successfully`,
      data: {
        deposit: {
          id: deposit._id,
          status: deposit.status,
          amount: usdAmount,
          cryptoAmount: cryptoAmount,
          asset: cryptoAsset,
          processedAt: deposit.processedAt
        },
        transaction: {
          id: transactionRecord._id,
          reference: transactionRecord.reference,
          asset: cryptoAsset,
          assetAmount: cryptoAmount
        }
      }
    });
    
  } catch (err) {
    console.error('Error approving deposit:', err);
    res.status(500).json({
      status: 'fail',
      message: err.message || 'Failed to approve deposit'
    });
  }
});















app.post('/api/admin/deposits/:id/reject', adminProtect, restrictTo('super', 'finance'), async (req, res) => {
  try {
    const { id } = req.params;
    const { reason, notes } = req.body;
    
    if (!reason && !notes) {
      return res.status(400).json({
        status: 'fail',
        message: 'Please provide a reason for rejection'
      });
    }
    
    const rejectionReason = reason || notes;
    
    // Find the deposit
    let deposit = await DepositAsset.findById(id).populate('user', 'firstName lastName email balances');
    
    if (!deposit) {
      const transaction = await Transaction.findOne({ 
        _id: id, 
        type: 'deposit', 
        status: 'pending' 
      }).populate('user', 'firstName lastName email balances');
      
      if (!transaction) {
        return res.status(404).json({
          status: 'fail',
          message: 'Deposit not found'
        });
      }
      deposit = transaction;
    }
    
    // Check if deposit is already processed
    if (deposit.status !== 'pending') {
      return res.status(400).json({
        status: 'fail',
        message: `Deposit is already ${deposit.status}`
      });
    }
    
    const user = deposit.user;
    const cryptoAsset = (deposit.asset || deposit.method || 'USDT').toUpperCase();
    const cryptoAmount = deposit.assetAmount || deposit.amount;
    const usdAmount = deposit.amount;
    
    // Get current crypto price for exchange rate (for email)
    const currentPrice = await getCryptoPrice(cryptoAsset);
    const exchangeRate = currentPrice || 1;
    
    // Update deposit status
    deposit.status = 'failed';
    deposit.adminNotes = rejectionReason;
    deposit.processedBy = req.admin._id;
    deposit.processedAt = new Date();
    deposit.metadata = {
      ...deposit.metadata,
      rejectionReason: rejectionReason,
      rejectedBy: req.admin._id,
      rejectedAt: new Date()
    };
    
    await deposit.save();
    
    // Create transaction record for rejected deposit
    const transactionRecord = await Transaction.create({
      user: user._id,
      type: 'deposit',
      amount: usdAmount,
      asset: cryptoAsset,
      assetAmount: cryptoAmount,
      currency: 'USD',
      status: 'failed',
      method: cryptoAsset,
      reference: `DEP-REJ-${Date.now()}-${Math.floor(Math.random() * 10000)}`,
      details: {
        depositId: deposit._id,
        rejectionReason: rejectionReason,
        rejectedBy: req.admin.name
      },
      fee: 0,
      netAmount: 0,
      processedBy: req.admin._id,
      processedAt: new Date(),
      adminNotes: rejectionReason,
      exchangeRateAtTime: exchangeRate
    });
    
    // Send email notification using deposit_rejected template
    const cryptoLogoUrl = getCryptoLogo(cryptoAsset);
    
    await sendProfessionalEmail({
      email: user.email,
      template: 'deposit_rejected',
      data: {
        name: user.firstName,
        amount: usdAmount.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 }),
        cryptoAmount: cryptoAmount.toLocaleString(undefined, { minimumFractionDigits: 8, maximumFractionDigits: 8 }),
        cryptoAsset: cryptoAsset,
        cryptoLogoUrl: cryptoLogoUrl,
        method: cryptoAsset,
        reference: transactionRecord.reference,
        reason: rejectionReason,
        exchangeRate: exchangeRate.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 })
      }
    });
    
    // Log the activity
    await logActivity(
      'deposit_rejected',
      'deposit',
      deposit._id,
      req.admin._id,
      'Admin',
      req,
      { amount: usdAmount, asset: cryptoAsset, userId: user._id, reason: rejectionReason }
    );
    
    // Create notification for user
    await Notification.create({
      title: 'Deposit Declined',
      message: `Your deposit request of ${cryptoAmount} ${cryptoAsset} ($${usdAmount.toLocaleString()}) has been declined. Reason: ${rejectionReason}`,
      type: 'deposit_rejected',
      recipientType: 'specific',
      specificUserId: user._id,
      isImportant: true,
      sentBy: req.admin._id,
      metadata: {
        depositId: deposit._id,
        amount: usdAmount,
        cryptoAmount: cryptoAmount,
        asset: cryptoAsset,
        reason: rejectionReason
      }
    });
    
    res.status(200).json({
      status: 'success',
      message: 'Deposit rejected successfully',
      data: {
        deposit: {
          id: deposit._id,
          status: deposit.status,
          amount: usdAmount,
          cryptoAmount: cryptoAmount,
          asset: cryptoAsset,
          rejectionReason: rejectionReason
        }
      }
    });
    
  } catch (err) {
    console.error('Error rejecting deposit:', err);
    res.status(500).json({
      status: 'fail',
      message: err.message || 'Failed to reject deposit'
    });
  }
});

/**
 * Helper function to get crypto logo URL
 */
function getCryptoLogo(asset) {
  const logoMap = {
    'BTC': 'https://cryptologos.cc/logos/bitcoin-btc-logo.png',
    'ETH': 'https://cryptologos.cc/logos/ethereum-eth-logo.png',
    'USDT': 'https://cryptologos.cc/logos/tether-usdt-logo.png',
    'BNB': 'https://cryptologos.cc/logos/bnb-bnb-logo.png',
    'SOL': 'https://cryptologos.cc/logos/solana-sol-logo.png',
    'USDC': 'https://cryptologos.cc/logos/usd-coin-usdc-logo.png',
    'XRP': 'https://cryptologos.cc/logos/xrp-xrp-logo.png',
    'DOGE': 'https://cryptologos.cc/logos/dogecoin-doge-logo.png',
    'ADA': 'https://cryptologos.cc/logos/cardano-ada-logo.png',
    'SHIB': 'https://cryptologos.cc/logos/shiba-inu-shib-logo.png',
    'AVAX': 'https://cryptologos.cc/logos/avalanche-avax-logo.png',
    'DOT': 'https://cryptologos.cc/logos/polkadot-new-dot-logo.png',
    'TRX': 'https://cryptologos.cc/logos/tron-trx-logo.png',
    'LINK': 'https://cryptologos.cc/logos/chainlink-link-logo.png',
    'MATIC': 'https://cryptologos.cc/logos/polygon-matic-logo.png',
    'LTC': 'https://cryptologos.cc/logos/litecoin-ltc-logo.png'
  };
  
  return logoMap[asset.toUpperCase()] || 'https://cryptologos.cc/logos/bitcoin-btc-logo.png';
}






// DELETE /api/admin/users/:userId - Delete user account
app.delete('/api/admin/users/:userId', adminProtect, restrictTo('super'), async (req, res) => {
    try {
        const { userId } = req.params;
        
        // Prevent admin from deleting themselves
        if (userId === req.admin._id.toString()) {
            return res.status(400).json({
                status: 'fail',
                message: 'You cannot delete your own admin account'
            });
        }
        
        // Find the user
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({
                status: 'fail',
                message: 'User not found'
            });
        }
        
        // Check if user already deleted (if using soft delete)
        if (user.deletedAt) {
            return res.status(400).json({
                status: 'fail',
                message: 'User already deleted'
            });
        }
        
        // OPTION 1: Hard Delete (with cascade handling)
        // =============================================
        
        // 1. Anonymize or delete related data
        
        // Anonymize Transactions - set user to null and add metadata
        await Transaction.updateMany(
            { user: userId },
            { 
                $set: { 
                    user: null,
                    'metadata.deletedUserEmail': user.email,
                    'metadata.deletedAt': new Date(),
                    'metadata.deletedBy': req.admin.email
                }
            }
        );
        
        // Cancel and archive active investments
        await Investment.updateMany(
            { user: userId, status: 'active' },
            { 
                $set: { 
                    status: 'cancelled',
                    completionDate: new Date(),
                    'metadata.cancelledBy': req.admin.email,
                    'metadata.cancelledReason': 'Account deleted by admin'
                }
            }
        );
        
        // Anonymize DepositAssets
        await DepositAsset.updateMany(
            { user: userId },
            {
                $set: {
                    user: null,
                    'metadata.deletedUserEmail': user.email,
                    'metadata.deletedAt': new Date()
                }
            }
        );
        
        // Anonymize KYC data but preserve for compliance
        await KYC.updateMany(
            { user: userId },
            {
                $set: {
                    user: null,
                    adminNotes: `[Account deleted by ${req.admin.email} on ${new Date().toISOString()}] Previously: ${user.email}`
                }
            }
        );
        
        // Delete notifications (no need to keep)
        await Notification.deleteMany({ specificUserId: userId });
        
        // Anonymize UserLogs for security audit
        await UserLog.updateMany(
            { user: userId },
            {
                $set: {
                    user: null,
                    email: `deleted_${user._id}@deleted.com`,
                    username: `deleted_user_${user._id}`,
                    userFullName: 'Deleted User',
                    'metadata.deletedAt': new Date(),
                    'metadata.deletedBy': req.admin.email
                }
            }
        );
        
        // Remove downline relationships
        await DownlineRelationship.deleteMany({ 
            $or: [{ upline: userId }, { downline: userId }]
        });
        
        // Remove referral relationships
        await User.updateMany(
            { referredBy: userId },
            { $unset: { referredBy: "" } }
        );
        
        // 2. Delete the user
        await User.findByIdAndDelete(userId);
        
        // 3. Log the activity
        await logActivity(
            'user_deleted',
            'User',
            userId,
            req.admin._id,
            'Admin',
            req,
            {
                deletedUserEmail: user.email,
                deletedUserName: `${user.firstName} ${user.lastName}`,
                deletedAt: new Date()
            }
        );
        
        // 4. Send notification email to user (if they still have email access)
        try {
            await sendAutomatedEmail(user, 'account_deleted', {
                name: user.firstName,
                deletedBy: req.admin.email,
                deletedAt: new Date().toISOString()
            });
        } catch (emailErr) {
            console.error('Failed to send deletion email:', emailErr);
            // Don't fail the request if email fails
        }
        
        return res.status(200).json({
            status: 'success',
            message: `User ${user.firstName} ${user.lastName} (${user.email}) deleted successfully`
        });
        
        /*
        // OPTION 2: Soft Delete (Alternative - RECOMMENDED)
        // ====================================================
        // Add deletedAt field to UserSchema first:
        // deletedAt: { type: Date, default: null },
        // deletedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' }
        
        // Then soft delete:
        user.deletedAt = new Date();
        user.deletedBy = req.admin._id;
        user.status = 'deleted';
        user.email = `deleted_${user._id}@deleted.com`; // Free up email for reuse
        await user.save();
        
        // Log soft deletion
        await logActivity('user_soft_deleted', 'User', userId, req.admin._id, 'Admin', req, {
            deletedUserEmail: originalEmail,
            deletedAt: user.deletedAt
        });
        
        return res.status(200).json({
            status: 'success',
            message: `User ${user.firstName} ${user.lastName} has been deactivated and anonymized`
        });
        */
        
    } catch (err) {
        console.error('Error deleting user:', err);
        return res.status(500).json({
            status: 'error',
            message: 'Failed to delete user',
            error: process.env.NODE_ENV === 'development' ? err.message : undefined
        });
    }
});


















// =============================================
// GET ADMIN ACTIVITY - CORRECT USER MAPPING FOR SYSTEMLOG
// =============================================
app.get('/api/admin/activity', adminProtect, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    // Fetch from BOTH schemas in parallel
    const [userLogs, systemLogs] = await Promise.all([
      UserLog.find({})
        .populate('user', 'firstName lastName email')
        .sort({ createdAt: -1 })
        .lean(),
      SystemLog.find({})
        .populate('performedBy', 'firstName lastName email')
        .sort({ createdAt: -1 })
        .lean()
    ]);

    // Format UserLog entries
    const formattedUserLogs = userLogs.map(log => ({
      _id: log._id,
      source: 'userlog',
      action: log.action,
      actionCategory: log.actionCategory,
      status: log.status,
      timestamp: log.createdAt,
      user: log.user ? {
        _id: log.user._id,
        name: `${log.user.firstName || ''} ${log.user.lastName || ''}`.trim() || log.email,
        email: log.email
      } : null,
      location: {
        city: log.location?.city || 'Unknown',
        region: log.location?.region?.name || log.location?.region || 'Unknown',
        country: log.location?.country?.name || log.location?.country || 'Unknown',
        latitude: log.location?.latitude,
        longitude: log.location?.longitude,
        exactLocation: log.location?.exactLocation || false,
        formatted: log.locationDisplay || 
                   `${log.location?.city || ''} ${log.location?.region?.name || ''} ${log.location?.country?.name || ''}`.trim() || 
                   'Unknown'
      },
      metadata: log.metadata || {},
      ipAddress: log.ipAddress,
      deviceInfo: log.deviceInfo
    }));

    // Format SystemLog entries - FIXED: Proper user mapping
    const formattedSystemLogs = systemLogs.map(log => {
      // Extract location from SystemLog
      const locationString = log.location || 'Unknown';
      let city = 'Unknown', region = 'Unknown', country = 'Unknown';
      
      if (locationString !== 'Unknown') {
        const parts = locationString.split(',').map(p => p.trim());
        if (parts.length >= 1) city = parts[0];
        if (parts.length >= 2) region = parts[1];
        if (parts.length >= 3) country = parts[2];
      }
      
      // Determine the user based on performedByModel
      let userName = 'System';
      let userEmail = 'system@bithash.com';
      let userId = null;
      
      if (log.performedBy) {
        // performedBy is populated from the database
        userId = log.performedBy._id;
        
        if (log.performedByModel === 'Admin') {
          // This is an admin user
          userName = log.performedBy.name || log.performedByName || 'Admin';
          userEmail = log.performedBy.email || log.performedByEmail || 'admin@bithash.com';
        } else if (log.performedByModel === 'User') {
          // This is a regular user
          userName = `${log.performedBy.firstName || ''} ${log.performedBy.lastName || ''}`.trim() || 
                     log.performedByName || 
                     log.performedByEmail?.split('@')[0] || 
                     'User';
          userEmail = log.performedBy.email || log.performedByEmail || 'user@bithash.com';
        } else {
          // Fallback to stored values
          userName = log.performedByName || 'Unknown User';
          userEmail = log.performedByEmail || 'unknown@bithash.com';
        }
      } else if (log.performedByName) {
        // No populated performedBy, but we have stored name
        userName = log.performedByName;
        userEmail = log.performedByEmail || `${log.performedByName.toLowerCase().replace(/\s/g, '')}@bithash.com`;
      }
      
      return {
        _id: log._id,
        source: 'systemlog',
        action: log.action,
        actionCategory: log.entity,
        status: log.status,
        timestamp: log.createdAt,
        user: {
          _id: userId,
          name: userName,
          email: userEmail
        },
        location: {
          city: city,
          region: region,
          country: country,
          latitude: log.latitude || null,
          longitude: log.longitude || null,
          exactLocation: !!(log.latitude && log.longitude),
          formatted: locationString
        },
        metadata: log.metadata || {},
        ipAddress: log.ip,
        deviceInfo: {
          type: log.deviceType,
          os: log.os,
          browser: log.browser
        }
      };
    });

    // Combine and sort by timestamp (newest first)
    let allActivities = [...formattedUserLogs, ...formattedSystemLogs];
    allActivities.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

    // Apply pagination
    const total = allActivities.length;
    const totalPages = Math.ceil(total / limit);
    const paginatedActivities = allActivities.slice(skip, skip + limit);

    res.status(200).json({
      status: 'success',
      data: {
        activities: paginatedActivities,
        pagination: {
          currentPage: page,
          totalPages: totalPages,
          totalItems: total,
          itemsPerPage: limit,
          hasNextPage: page < totalPages,
          hasPrevPage: page > 1
        }
      }
    });

  } catch (err) {
    console.error('Error fetching admin activity:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch activity logs'
    });
  }
});

// =============================================
// GET LATEST ACTIVITIES - CORRECT USER MAPPING FOR SYSTEMLOG
// =============================================
app.get('/api/admin/activity/latest', adminProtect, async (req, res) => {
  try {
    const since = req.query.since ? new Date(req.query.since) : new Date(Date.now() - 5 * 60 * 1000);
    const limit = parseInt(req.query.limit) || 20;

    // Fetch from BOTH schemas in parallel
    const [userLogs, systemLogs] = await Promise.all([
      UserLog.find({ createdAt: { $gt: since } })
        .populate('user', 'firstName lastName email')
        .sort({ createdAt: -1 })
        .limit(limit)
        .lean(),
      SystemLog.find({ createdAt: { $gt: since } })
        .populate('performedBy', 'firstName lastName email')
        .sort({ createdAt: -1 })
        .limit(limit)
        .lean()
    ]);

    // Format UserLog entries
    const formattedUserLogs = userLogs.map(log => ({
      _id: log._id,
      source: 'userlog',
      action: log.action,
      actionCategory: log.actionCategory,
      status: log.status,
      timestamp: log.createdAt,
      user: log.user ? {
        _id: log.user._id,
        name: `${log.user.firstName || ''} ${log.user.lastName || ''}`.trim() || log.email,
        email: log.email
      } : null,
      location: {
        city: log.location?.city || 'Unknown',
        region: log.location?.region?.name || log.location?.region || 'Unknown',
        country: log.location?.country?.name || log.location?.country || 'Unknown',
        formatted: log.locationDisplay || 'Unknown'
      },
      metadata: log.metadata || {}
    }));

    // Format SystemLog entries - FIXED: Proper user mapping
    const formattedSystemLogs = systemLogs.map(log => {
      const locationString = log.location || 'Unknown';
      let city = 'Unknown', region = 'Unknown', country = 'Unknown';
      
      if (locationString !== 'Unknown') {
        const parts = locationString.split(',').map(p => p.trim());
        if (parts.length >= 1) city = parts[0];
        if (parts.length >= 2) region = parts[1];
        if (parts.length >= 3) country = parts[2];
      }
      
      // Determine the user based on performedByModel
      let userName = 'System';
      let userEmail = 'system@bithash.com';
      let userId = null;
      
      if (log.performedBy) {
        userId = log.performedBy._id;
        
        if (log.performedByModel === 'Admin') {
          userName = log.performedBy.name || log.performedByName || 'Admin';
          userEmail = log.performedBy.email || log.performedByEmail || 'admin@bithash.com';
        } else if (log.performedByModel === 'User') {
          userName = `${log.performedBy.firstName || ''} ${log.performedBy.lastName || ''}`.trim() || 
                     log.performedByName || 
                     log.performedByEmail?.split('@')[0] || 
                     'User';
          userEmail = log.performedBy.email || log.performedByEmail || 'user@bithash.com';
        } else {
          userName = log.performedByName || 'Unknown User';
          userEmail = log.performedByEmail || 'unknown@bithash.com';
        }
      } else if (log.performedByName) {
        userName = log.performedByName;
        userEmail = log.performedByEmail || `${log.performedByName.toLowerCase().replace(/\s/g, '')}@bithash.com`;
      }
      
      return {
        _id: log._id,
        source: 'systemlog',
        action: log.action,
        actionCategory: log.entity,
        status: log.status,
        timestamp: log.createdAt,
        user: {
          _id: userId,
          name: userName,
          email: userEmail
        },
        location: {
          city: city,
          region: region,
          country: country,
          formatted: locationString
        },
        metadata: log.metadata || {}
      };
    });

    // Combine and sort
    let allActivities = [...formattedUserLogs, ...formattedSystemLogs];
    allActivities.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

    // Remove duplicates
    const uniqueActivities = [];
    const seen = new Set();
    
    for (const activity of allActivities) {
      const timeSlot = Math.floor(new Date(activity.timestamp).getTime() / 5000);
      const key = `${activity.user?._id || 'system'}_${activity.action}_${timeSlot}`;
      if (!seen.has(key)) {
        seen.add(key);
        uniqueActivities.push(activity);
      }
    }

    const latestTimestamp = uniqueActivities.length > 0 ? uniqueActivities[0].timestamp : new Date();

    res.status(200).json({
      status: 'success',
      data: {
        activities: uniqueActivities.slice(0, limit),
        latestTimestamp: latestTimestamp,
        count: uniqueActivities.length
      }
    });

  } catch (err) {
    console.error('Error fetching latest activities:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch latest activities'
    });
  }
});



























// =============================================
// GET /api/admin/stats - Dashboard Statistics
// Donut chart expects simple key-value pairs
// =============================================
app.get('/api/admin/stats', adminProtect, async (req, res) => {
  try {
    // Get date from 24 hours ago for comparison
    const yesterday = new Date();
    yesterday.setDate(yesterday.getDate() - 1);

    // Fetch all stats in parallel for better performance
    const [
      totalUsers,
      usersYesterday,
      totalDeposits,
      depositsYesterday,
      pendingWithdrawals,
      withdrawalsYesterday,
      platformRevenue,
      revenueYesterday,
      backendResponseTime,
      databaseQueryTime,
      lastTransactionTime,
      serverUptime,
      simpleDistribution,      // For donut chart (simple format)
      detailedStats            // For detailed financial data
    ] = await Promise.all([
      // Total users
      User.countDocuments({ status: 'active' }),
      // Users from yesterday
      User.countDocuments({ status: 'active', createdAt: { $lte: yesterday } }),
      // Total deposits (completed)
      Transaction.aggregate([
        { $match: { type: 'deposit', status: 'completed' } },
        { $group: { _id: null, total: { $sum: '$amount' } } }
      ]),
      // Deposits from yesterday
      Transaction.aggregate([
        { $match: { type: 'deposit', status: 'completed', createdAt: { $lte: yesterday } } },
        { $group: { _id: null, total: { $sum: '$amount' } } }
      ]),
      // Pending withdrawals total amount
      Transaction.aggregate([
        { $match: { type: 'withdrawal', status: 'pending' } },
        { $group: { _id: null, total: { $sum: '$amount' } } }
      ]),
      // Withdrawals from yesterday
      Transaction.aggregate([
        { $match: { type: 'withdrawal', status: 'completed', createdAt: { $lte: yesterday } } },
        { $group: { _id: null, total: { $sum: '$amount' } } }
      ]),
      // Platform revenue
      PlatformRevenue.aggregate([
        { $group: { _id: null, total: { $sum: '$amount' } } }
      ]),
      // Revenue from yesterday
      PlatformRevenue.aggregate([
        { $match: { createdAt: { $lte: yesterday } } },
        { $group: { _id: null, total: { $sum: '$amount' } } }
      ]),
      // Backend response time
      redis.get('backend:response_time').then(val => parseInt(val) || 120),
      // Database query time
      redis.get('db:query_time').then(val => parseInt(val) || 45),
      // Last transaction time
      Transaction.findOne().sort({ createdAt: -1 }).then(tx => {
        if (tx && tx.createdAt) {
          const seconds = Math.floor((Date.now() - new Date(tx.createdAt)) / 1000);
          return seconds;
        }
        return 0;
      }),
      // Server uptime
      Promise.resolve(Math.floor(process.uptime() / 60 / 60 * 100)),
      // SIMPLE distribution for donut chart (what frontend expects)
      getSimpleAssetDistribution(),
      // DETAILED stats for advanced reporting (optional, can be separate endpoint)
      getDetailedFinancialStats()
    ]);

    // Calculate change percentages
    const totalDepositsAmount = totalDeposits[0]?.total || 0;
    const depositsYesterdayAmount = depositsYesterday[0]?.total || 0;
    const depositsChange = depositsYesterdayAmount > 0 
      ? ((totalDepositsAmount - depositsYesterdayAmount) / depositsYesterdayAmount * 100).toFixed(1)
      : 0;

    const pendingWithdrawalsAmount = pendingWithdrawals[0]?.total || 0;
    const withdrawalsYesterdayAmount = withdrawalsYesterday[0]?.total || 0;
    const withdrawalsChange = withdrawalsYesterdayAmount > 0
      ? ((pendingWithdrawalsAmount - withdrawalsYesterdayAmount) / withdrawalsYesterdayAmount * 100).toFixed(1)
      : 0;

    const platformRevenueAmount = platformRevenue[0]?.total || 0;
    const revenueYesterdayAmount = revenueYesterday[0]?.total || 0;
    const revenueChange = revenueYesterdayAmount > 0
      ? ((platformRevenueAmount - revenueYesterdayAmount) / revenueYesterdayAmount * 100).toFixed(1)
      : 0;

    const usersYesterdayCount = usersYesterday || 0;
    const usersChange = usersYesterdayCount > 0
      ? ((totalUsers - usersYesterdayCount) / usersYesterdayCount * 100).toFixed(1)
      : 0;

    res.status(200).json({
      status: 'success',
      data: {
        totalUsers: totalUsers,
        usersChange: parseFloat(usersChange),
        totalDeposits: totalDepositsAmount,
        depositsChange: parseFloat(depositsChange),
        pendingWithdrawals: pendingWithdrawalsAmount,
        withdrawalsChange: parseFloat(withdrawalsChange),
        platformRevenue: platformRevenueAmount,
        revenueChange: parseFloat(revenueChange),
        backendResponseTime: backendResponseTime,
        databaseQueryTime: databaseQueryTime,
        lastTransactionTime: lastTransactionTime,
        serverUptime: serverUptime,
        realtimeDistribution: simpleDistribution,  // For donut chart
        detailedStats: detailedStats               // For detailed financial view (optional)
      }
    });

  } catch (err) {
    console.error('Get admin stats error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch dashboard statistics'
    });
  }
});

// =============================================
// SIMPLE ASSET DISTRIBUTION FOR DONUT CHART
// Returns exactly what the frontend expects
// =============================================
async function getSimpleAssetDistribution() {
  try {
    // Get all users with balances
    const users = await User.find({}).select('balances').lean();
    
    // Initialize distribution with default categories that match frontend
    const distribution = {
      'BTC': 0,
      'ETH': 0,
      'USDT': 0,
      'Active Mining': 0
    };

    for (const user of users) {
      if (!user.balances) continue;
      
      // Calculate main wallet values (crypto holdings)
      if (user.balances.main) {
        const mainMap = user.balances.main;
        const entries = mainMap instanceof Map ? mainMap.entries() : Object.entries(mainMap);
        
        for (const [asset, amount] of entries) {
          if (amount > 0 && asset !== 'usd') {
            const price = await getCryptoPrice(asset.toUpperCase());
            if (price && price > 0) {
              const value = amount * price;
              const assetKey = asset.toUpperCase();
              
              // Map to frontend categories
              if (assetKey === 'BTC') {
                distribution['BTC'] += value;
              } else if (assetKey === 'ETH') {
                distribution['ETH'] += value;
              } else if (assetKey === 'USDT' || assetKey === 'USDC') {
                distribution['USDT'] += value;
              } else {
                // Put other cryptos into BTC category for now (or create separate)
                distribution['BTC'] += value;
              }
            }
          }
        }
      }
      
      // Calculate matured wallet values
      if (user.balances.matured) {
        const maturedMap = user.balances.matured;
        const entries = maturedMap instanceof Map ? maturedMap.entries() : Object.entries(maturedMap);
        
        for (const [asset, amount] of entries) {
          if (amount > 0 && asset !== 'usd') {
            const price = await getCryptoPrice(asset.toUpperCase());
            if (price && price > 0) {
              const value = amount * price;
              const assetKey = asset.toUpperCase();
              
              if (assetKey === 'BTC') {
                distribution['BTC'] += value;
              } else if (assetKey === 'ETH') {
                distribution['ETH'] += value;
              } else if (assetKey === 'USDT' || assetKey === 'USDC') {
                distribution['USDT'] += value;
              } else {
                distribution['BTC'] += value;
              }
            }
          }
        }
      }
      
      // Active mining value (fixed USD)
      if (user.balances.active) {
        const activeMap = user.balances.active;
        const entries = activeMap instanceof Map ? activeMap.entries() : Object.entries(activeMap);
        
        for (const [asset, amount] of entries) {
          if (amount > 0) {
            distribution['Active Mining'] += amount;
          }
        }
      }
    }
    
    // If all values are 0, provide sample data for chart visibility
    if (distribution['BTC'] === 0 && distribution['ETH'] === 0 && 
        distribution['USDT'] === 0 && distribution['Active Mining'] === 0) {
      return {
        'BTC': 45000,
        'ETH': 28000,
        'USDT': 15000,
        'Active Mining': 12000
      };
    }
    
    return distribution;
    
  } catch (err) {
    console.error('Error getting simple asset distribution:', err);
    // Return default values to prevent chart from breaking
    return {
      'BTC': 0,
      'ETH': 0,
      'USDT': 0,
      'Active Mining': 0
    };
  }
}

// =============================================
// DETAILED FINANCIAL STATS (Optional endpoint)
// Can be called separately for advanced reporting
// =============================================
async function getDetailedFinancialStats() {
  try {
    const startOfMonth = new Date();
    startOfMonth.setDate(1);
    startOfMonth.setHours(0, 0, 0, 0);
    
    const startOfDay = new Date();
    startOfDay.setHours(0, 0, 0, 0);
    
    // Get all users
    const users = await User.find({}).select('balances').lean();
    
    // Detailed crypto breakdown by asset
    const cryptoBreakdown = {};
    let totalMainValue = 0;
    let totalMaturedValue = 0;
    let totalActiveValue = 0;
    
    for (const user of users) {
      if (!user.balances) continue;
      
      // Main wallet
      if (user.balances.main) {
        const mainMap = user.balances.main;
        const entries = mainMap instanceof Map ? mainMap.entries() : Object.entries(mainMap);
        
        for (const [asset, balance] of entries) {
          if (balance > 0 && asset !== 'usd') {
            const price = await getCryptoPrice(asset.toUpperCase());
            if (price && price > 0) {
              const value = balance * price;
              totalMainValue += value;
              
              if (!cryptoBreakdown[asset.toUpperCase()]) {
                cryptoBreakdown[asset.toUpperCase()] = { balance: 0, value: 0 };
              }
              cryptoBreakdown[asset.toUpperCase()].balance += balance;
              cryptoBreakdown[asset.toUpperCase()].value += value;
            }
          }
        }
      }
      
      // Matured wallet
      if (user.balances.matured) {
        const maturedMap = user.balances.matured;
        const entries = maturedMap instanceof Map ? maturedMap.entries() : Object.entries(maturedMap);
        
        for (const [asset, balance] of entries) {
          if (balance > 0 && asset !== 'usd') {
            const price = await getCryptoPrice(asset.toUpperCase());
            if (price && price > 0) {
              const value = balance * price;
              totalMaturedValue += value;
              
              if (!cryptoBreakdown[asset.toUpperCase()]) {
                cryptoBreakdown[asset.toUpperCase()] = { balance: 0, value: 0 };
              }
              cryptoBreakdown[asset.toUpperCase()].balance += balance;
              cryptoBreakdown[asset.toUpperCase()].value += value;
            }
          }
        }
      }
      
      // Active wallet
      if (user.balances.active) {
        const activeMap = user.balances.active;
        const entries = activeMap instanceof Map ? activeMap.entries() : Object.entries(activeMap);
        
        for (const [asset, balance] of entries) {
          if (balance > 0) {
            totalActiveValue += balance;
          }
        }
      }
    }
    
    // Get transaction volume by type
    const transactionVolume = await Transaction.aggregate([
      { $match: { status: 'completed' } },
      {
        $group: {
          _id: '$type',
          total: { $sum: '$amount' },
          count: { $sum: 1 }
        }
      }
    ]);
    
    // Get revenue by source
    const revenueBySource = await PlatformRevenue.aggregate([
      {
        $group: {
          _id: '$source',
          total: { $sum: '$amount' }
        }
      }
    ]);
    
    // Get daily volume for last 30 days
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
    
    const dailyVolume = await Transaction.aggregate([
      {
        $match: {
          status: 'completed',
          createdAt: { $gte: thirtyDaysAgo }
        }
      },
      {
        $group: {
          _id: { $dateToString: { format: "%Y-%m-%d", date: "$createdAt" } },
          volume: { $sum: '$amount' }
        }
      },
      { $sort: { _id: 1 } }
    ]);
    
    return {
      cryptoBreakdown: cryptoBreakdown,
      walletTotals: {
        main: totalMainValue,
        matured: totalMaturedValue,
        active: totalActiveValue,
        total: totalMainValue + totalMaturedValue + totalActiveValue
      },
      transactionVolume: transactionVolume,
      revenueBySource: revenueBySource,
      dailyVolume: dailyVolume,
      lastUpdated: new Date()
    };
    
  } catch (err) {
    console.error('Error getting detailed financial stats:', err);
    return null;
  }
}







// =============================================
// GET KYC SUBMISSIONS - Paginated with status filters
// =============================================
app.get('/api/admin/kyc/submissions', adminProtect, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;
    const status = req.query.status; // 'pending', 'verified', 'rejected', 'not-started', 'all'
    const search = req.query.search || '';

    // Build query
    let query = {};
    
    if (status && status !== 'all') {
      query.overallStatus = status;
    }

    if (search) {
      query.$or = [
        { 'user.firstName': { $regex: search, $options: 'i' } },
        { 'user.lastName': { $regex: search, $options: 'i' } },
        { 'user.email': { $regex: search, $options: 'i' } }
      ];
    }

    // Get total count for pagination
    const total = await KYC.countDocuments(query);
    const totalPages = Math.ceil(total / limit);

    // Fetch KYC submissions with user details
    const submissions = await KYC.find(query)
      .populate('user', 'firstName lastName email phone createdAt')
      .populate('identity.verifiedBy', 'name email')
      .populate('address.verifiedBy', 'name email')
      .populate('facial.verifiedBy', 'name email')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .lean();

    // Format submissions for frontend
    const formattedSubmissions = submissions.map(sub => ({
      _id: sub._id,
      user: sub.user ? {
        _id: sub.user._id,
        firstName: sub.user.firstName || '',
        lastName: sub.user.lastName || '',
        email: sub.user.email || '',
        phone: sub.user.phone || '',
        createdAt: sub.user.createdAt
      } : null,
      identity: {
        documentType: sub.identity?.documentType || '',
        status: sub.identity?.status || 'not-submitted',
        verifiedAt: sub.identity?.verifiedAt,
        verifiedBy: sub.identity?.verifiedBy,
        rejectionReason: sub.identity?.rejectionReason || ''
      },
      address: {
        documentType: sub.address?.documentType || '',
        status: sub.address?.status || 'not-submitted',
        verifiedAt: sub.address?.verifiedAt,
        verifiedBy: sub.address?.verifiedBy,
        rejectionReason: sub.address?.rejectionReason || ''
      },
      facial: {
        status: sub.facial?.status || 'not-submitted',
        verifiedAt: sub.facial?.verifiedAt,
        verifiedBy: sub.facial?.verifiedBy,
        rejectionReason: sub.facial?.rejectionReason || ''
      },
      overallStatus: sub.overallStatus || 'not-started',
      submittedAt: sub.submittedAt,
      reviewedAt: sub.reviewedAt,
      adminNotes: sub.adminNotes || '',
      createdAt: sub.createdAt,
      updatedAt: sub.updatedAt
    }));

    res.status(200).json({
      status: 'success',
      data: {
        submissions: formattedSubmissions,
        pagination: {
          currentPage: page,
          totalPages: totalPages,
          totalItems: total,
          itemsPerPage: limit,
          hasNextPage: page < totalPages,
          hasPrevPage: page > 1
        }
      }
    });

  } catch (err) {
    console.error('Error fetching KYC submissions:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch KYC submissions'
    });
  }
});

// =============================================
// GET SINGLE KYC SUBMISSION DETAILS
// =============================================
app.get('/api/admin/kyc/submissions/:id', adminProtect, async (req, res) => {
  try {
    const { id } = req.params;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({
        status: 'fail',
        message: 'Invalid KYC submission ID'
      });
    }

    const submission = await KYC.findById(id)
      .populate('user', 'firstName lastName email phone createdAt')
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

    // Format document URLs for frontend
    const formatDocumentUrl = (filename, type) => {
      if (!filename) return null;
      // Generate token for authenticated access
      const token = jwt.sign({ kycId: submission._id }, JWT_SECRET, { expiresIn: '1h' });
      return `/api/admin/kyc/files/preview/${token}/${type}/${filename}`;
    };

    const formattedSubmission = {
      _id: submission._id,
      user: submission.user ? {
        _id: submission.user._id,
        firstName: submission.user.firstName || '',
        lastName: submission.user.lastName || '',
        email: submission.user.email || '',
        phone: submission.user.phone || '',
        createdAt: submission.user.createdAt
      } : null,
      identity: {
        documentType: submission.identity?.documentType || '',
        documentNumber: submission.identity?.documentNumber || '',
        documentExpiry: submission.identity?.documentExpiry,
        frontImage: submission.identity?.frontImage ? {
          filename: submission.identity.frontImage.filename,
          url: formatDocumentUrl(submission.identity.frontImage.filename, 'identity-front'),
          originalName: submission.identity.frontImage.originalName
        } : null,
        backImage: submission.identity?.backImage ? {
          filename: submission.identity.backImage.filename,
          url: formatDocumentUrl(submission.identity.backImage.filename, 'identity-back'),
          originalName: submission.identity.backImage.originalName
        } : null,
        status: submission.identity?.status || 'not-submitted',
        verifiedAt: submission.identity?.verifiedAt,
        verifiedBy: submission.identity?.verifiedBy,
        rejectionReason: submission.identity?.rejectionReason || ''
      },
      address: {
        documentType: submission.address?.documentType || '',
        documentDate: submission.address?.documentDate,
        documentImage: submission.address?.documentImage ? {
          filename: submission.address.documentImage.filename,
          url: formatDocumentUrl(submission.address.documentImage.filename, 'address'),
          originalName: submission.address.documentImage.originalName
        } : null,
        status: submission.address?.status || 'not-submitted',
        verifiedAt: submission.address?.verifiedAt,
        verifiedBy: submission.address?.verifiedBy,
        rejectionReason: submission.address?.rejectionReason || ''
      },
      facial: {
        verificationPhoto: submission.facial?.verificationPhoto ? {
          filename: submission.facial.verificationPhoto.filename,
          url: formatDocumentUrl(submission.facial.verificationPhoto.filename, 'facial-photo'),
          originalName: submission.facial.verificationPhoto.originalName
        } : null,
        verificationVideo: submission.facial?.verificationVideo ? {
          filename: submission.facial.verificationVideo.filename,
          url: formatDocumentUrl(submission.facial.verificationVideo.filename, 'facial-video'),
          originalName: submission.facial.verificationVideo.originalName
        } : null,
        status: submission.facial?.status || 'not-submitted',
        verifiedAt: submission.facial?.verifiedAt,
        verifiedBy: submission.facial?.verifiedBy,
        rejectionReason: submission.facial?.rejectionReason || ''
      },
      overallStatus: submission.overallStatus || 'not-started',
      submittedAt: submission.submittedAt,
      reviewedAt: submission.reviewedAt,
      adminNotes: submission.adminNotes || '',
      createdAt: submission.createdAt,
      updatedAt: submission.updatedAt
    };

    res.status(200).json({
      status: 'success',
      data: {
        submission: formattedSubmission
      }
    });

  } catch (err) {
    console.error('Error fetching KYC submission details:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch KYC submission details'
    });
  }
});

// =============================================
// APPROVE KYC SUBMISSION
// =============================================
app.post('/api/admin/kyc/submissions/:id/approve', adminProtect, async (req, res) => {
  try {
    const { id } = req.params;
    const { notes, section = 'all' } = req.body;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({
        status: 'fail',
        message: 'Invalid KYC submission ID'
      });
    }

    const submission = await KYC.findById(id).populate('user', 'firstName lastName email');
    
    if (!submission) {
      return res.status(404).json({
        status: 'fail',
        message: 'KYC submission not found'
      });
    }

    const user = submission.user;
    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'User not found'
      });
    }

    // Update status based on section
    if (section === 'all' || section === 'identity') {
      submission.identity.status = 'verified';
      submission.identity.verifiedAt = new Date();
      submission.identity.verifiedBy = req.admin._id;
      submission.identity.rejectionReason = null;
    }

    if (section === 'all' || section === 'address') {
      submission.address.status = 'verified';
      submission.address.verifiedAt = new Date();
      submission.address.verifiedBy = req.admin._id;
      submission.address.rejectionReason = null;
    }

    if (section === 'all' || section === 'facial') {
      submission.facial.status = 'verified';
      submission.facial.verifiedAt = new Date();
      submission.facial.verifiedBy = req.admin._id;
      submission.facial.rejectionReason = null;
    }

    // Check if all sections are verified
    const allVerified = 
      submission.identity.status === 'verified' &&
      submission.address.status === 'verified' &&
      submission.facial.status === 'verified';

    if (allVerified) {
      submission.overallStatus = 'verified';
      submission.reviewedAt = new Date();
    }

    submission.adminNotes = notes || submission.adminNotes;
    submission.updatedAt = new Date();
    
    await submission.save();

    // Update user's KYC status
    await User.findByIdAndUpdate(user._id, {
      'kycStatus.identity': submission.identity.status,
      'kycStatus.address': submission.address.status,
      'kycStatus.facial': submission.facial.status,
      kycVerified: allVerified,
      kycUpdatedAt: new Date()
    });

    // Send email notification to user
    try {
      await sendProfessionalEmail({
        email: user.email,
        template: 'kyc_approved',
        data: {
          name: user.firstName,
          message: `Your KYC verification has been approved${section !== 'all' ? ` for ${section} section` : ''}. You now have full access to all platform features.`
        }
      });
    } catch (emailError) {
      console.error('Failed to send KYC approval email:', emailError);
    }

    // Create notification for user
    await Notification.create({
      title: 'KYC Approved',
      message: `Your KYC verification has been approved. You now have full access to all platform features.`,
      type: 'kyc_approved',
      recipientType: 'specific',
      specificUserId: user._id,
      sentBy: req.admin._id,
      isImportant: true
    });

    // Log activity
    await logActivity(
      'kyc_approved',
      'KYC',
      submission._id,
      req.admin._id,
      'Admin',
      req,
      {
        userId: user._id,
        userEmail: user.email,
        section: section,
        notes: notes
      }
    );

    res.status(200).json({
      status: 'success',
      message: 'KYC submission approved successfully',
      data: {
        submission: {
          _id: submission._id,
          overallStatus: submission.overallStatus,
          identityStatus: submission.identity.status,
          addressStatus: submission.address.status,
          facialStatus: submission.facial.status
        }
      }
    });

  } catch (err) {
    console.error('Error approving KYC submission:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to approve KYC submission'
    });
  }
});



// =============================================
// REJECT KYC SUBMISSION
// =============================================
app.post('/api/admin/kyc/submissions/:id/reject', adminProtect, async (req, res) => {
  try {
    const { id } = req.params;
    const { reason, section = 'all' } = req.body;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({
        status: 'fail',
        message: 'Invalid KYC submission ID'
      });
    }

    if (!reason || reason.trim() === '') {
      return res.status(400).json({
        status: 'fail',
        message: 'Rejection reason is required'
      });
    }

    const submission = await KYC.findById(id).populate('user', 'firstName lastName email');
    
    if (!submission) {
      return res.status(404).json({
        status: 'fail',
        message: 'KYC submission not found'
      });
    }

    const user = submission.user;
    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'User not found'
      });
    }

    // Update status based on section
    if (section === 'all' || section === 'identity') {
      submission.identity.status = 'rejected';
      submission.identity.rejectionReason = reason;
      submission.identity.verifiedAt = new Date();
      submission.identity.verifiedBy = req.admin._id;
    }

    if (section === 'all' || section === 'address') {
      submission.address.status = 'rejected';
      submission.address.rejectionReason = reason;
      submission.address.verifiedAt = new Date();
      submission.address.verifiedBy = req.admin._id;
    }

    if (section === 'all' || section === 'facial') {
      submission.facial.status = 'rejected';
      submission.facial.rejectionReason = reason;
      submission.facial.verifiedAt = new Date();
      submission.facial.verifiedBy = req.admin._id;
    }

    // Set overall status to rejected if any section is rejected
    submission.overallStatus = 'rejected';
    submission.reviewedAt = new Date();
    submission.adminNotes = `Rejected: ${reason}`;
    submission.updatedAt = new Date();
    
    await submission.save();

    // Update user's KYC status
    await User.findByIdAndUpdate(user._id, {
      'kycStatus.identity': submission.identity.status,
      'kycStatus.address': submission.address.status,
      'kycStatus.facial': submission.facial.status,
      kycVerified: false,
      kycUpdatedAt: new Date()
    });

    // Send email notification to user
    try {
      await sendProfessionalEmail({
        email: user.email,
        template: 'kyc_rejected',
        data: {
          name: user.firstName,
          reason: reason,
          section: section
        }
      });
    } catch (emailError) {
      console.error('Failed to send KYC rejection email:', emailError);
    }

    // Create notification for user
    await Notification.create({
      title: 'KYC Rejected',
      message: `Your KYC verification has been rejected. Reason: ${reason}. Please resubmit with correct documents.`,
      type: 'kyc_rejected',
      recipientType: 'specific',
      specificUserId: user._id,
      sentBy: req.admin._id,
      isImportant: true
    });

    // Log activity
    await logActivity(
      'kyc_rejected',
      'KYC',
      submission._id,
      req.admin._id,
      'Admin',
      req,
      {
        userId: user._id,
        userEmail: user.email,
        section: section,
        reason: reason
      }
    );

    res.status(200).json({
      status: 'success',
      message: 'KYC submission rejected',
      data: {
        submission: {
          _id: submission._id,
          overallStatus: submission.overallStatus,
          identityStatus: submission.identity.status,
          addressStatus: submission.address.status,
          facialStatus: submission.facial.status,
          rejectionReason: reason
        }
      }
    });

  } catch (err) {
    console.error('Error rejecting KYC submission:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to reject KYC submission'
    });
  }
});

// =============================================
// GET KYC STATISTICS (For badge counts)
// =============================================
app.get('/api/admin/kyc/stats', adminProtect, async (req, res) => {
  try {
    const pendingCount = await KYC.countDocuments({ overallStatus: 'pending' });
    const verifiedCount = await KYC.countDocuments({ overallStatus: 'verified' });
    const rejectedCount = await KYC.countDocuments({ overallStatus: 'rejected' });
    const totalCount = await KYC.countDocuments();

    res.status(200).json({
      status: 'success',
      data: {
        stats: {
          pending: pendingCount,
          verified: verifiedCount,
          rejected: rejectedCount,
          total: totalCount
        }
      }
    });

  } catch (err) {
    console.error('Error fetching KYC stats:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch KYC statistics'
    });
  }
});










// =============================================
// SERVE KYC FILES - With proper CORS and CSP headers
// =============================================
app.get('/api/admin/kyc/files/:type/:filename', async (req, res) => {
  try {
    const { type, filename } = req.params;
    const token = req.query.token;
    
    // Decode filename
    const decodedFilename = decodeURIComponent(filename);
    
    console.log(`KYC file request - Type: ${type}, File: ${decodedFilename}`);

    // Verify admin token
    if (!token) {
      console.log('No token provided for KYC file');
      return res.status(401).json({ error: 'Authentication required' });
    }

    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      if (!decoded.isAdmin) {
        return res.status(403).json({ error: 'Admin access required' });
      }
    } catch (err) {
      console.log('Invalid token for KYC file');
      return res.status(401).json({ error: 'Invalid or expired token' });
    }

    // Determine file path
    let filePath;
    switch (type) {
      case 'identity-front':
      case 'identity-back':
        filePath = path.join(__dirname, 'uploads/kyc/identity', decodedFilename);
        break;
      case 'address':
        filePath = path.join(__dirname, 'uploads/kyc/address', decodedFilename);
        break;
      case 'facial-photo':
      case 'facial-video':
        filePath = path.join(__dirname, 'uploads/kyc/facial', decodedFilename);
        break;
      default:
        return res.status(400).json({ error: 'Invalid file type' });
    }

    // Check if file exists
    if (!fs.existsSync(filePath)) {
      console.log(`File not found: ${filePath}`);
      
      // Try to find the file with a different pattern (case-insensitive)
      const dir = path.dirname(filePath);
      const baseName = path.basename(filePath);
      
      if (fs.existsSync(dir)) {
        const files = fs.readdirSync(dir);
        const matchingFile = files.find(f => f.toLowerCase() === baseName.toLowerCase());
        
        if (matchingFile) {
          filePath = path.join(dir, matchingFile);
          console.log(`Found matching file: ${filePath}`);
        } else {
          return res.status(404).json({ error: 'File not found' });
        }
      } else {
        return res.status(404).json({ error: 'File not found' });
      }
    }

    // Get file stats
    const stat = fs.statSync(filePath);
    const fileSize = stat.size;
    const contentType = getContentType(decodedFilename);
    
    console.log(`Serving file: ${decodedFilename}, Size: ${fileSize}, Type: ${contentType}`);

    // Set comprehensive CORS and security headers
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.setHeader('Access-Control-Expose-Headers', 'Content-Length, Content-Range');
    res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
    res.setHeader('Cross-Origin-Embedder-Policy', 'unsafe-none');
    res.setHeader('Cross-Origin-Opener-Policy', 'unsafe-none');
    res.setHeader('Content-Security-Policy', "frame-ancestors 'self' https://www.bithashcapital.live https://bithhash.vercel.app");
    res.setHeader('Content-Type', contentType);
    res.setHeader('Content-Length', fileSize);
    res.setHeader('Cache-Control', 'public, max-age=86400');
    res.setHeader('Accept-Ranges', 'bytes');
    
    // Set content disposition for inline viewing
    if (contentType.startsWith('image/')) {
      res.setHeader('Content-Disposition', `inline; filename="${path.basename(decodedFilename)}"`);
    } else if (contentType === 'application/pdf') {
      res.setHeader('Content-Disposition', `inline; filename="${path.basename(decodedFilename)}"`);
    } else if (contentType.startsWith('video/')) {
      res.setHeader('Content-Disposition', `inline; filename="${path.basename(decodedFilename)}"`);
    } else {
      res.setHeader('Content-Disposition', `attachment; filename="${path.basename(decodedFilename)}"`);
    }

    // Handle range requests for videos
    const range = req.headers.range;
    if (range && contentType.startsWith('video/')) {
      const parts = range.replace(/bytes=/, "").split("-");
      const start = parseInt(parts[0], 10);
      const end = parts[1] ? parseInt(parts[1], 10) : fileSize - 1;
      const chunksize = (end - start) + 1;
      
      const file = fs.createReadStream(filePath, { start, end });
      res.writeHead(206, {
        'Content-Range': `bytes ${start}-${end}/${fileSize}`,
        'Accept-Ranges': 'bytes',
        'Content-Length': chunksize,
        'Content-Type': contentType,
      });
      file.pipe(res);
    } else {
      // Stream the file
      const fileStream = fs.createReadStream(filePath);
      fileStream.on('error', (err) => {
        console.error('File stream error:', err);
        if (!res.headersSent) {
          res.status(500).json({ error: 'Failed to read file' });
        }
      });
      fileStream.pipe(res);
    }

  } catch (err) {
    console.error('Error serving KYC file:', err);
    if (!res.headersSent) {
      res.status(500).json({ error: 'Internal server error' });
    }
  }
});

// Helper function for content type
function getContentType(filename) {
  const ext = path.extname(filename).toLowerCase();
  const types = {
    '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.png': 'image/png',
    '.gif': 'image/gif', '.webp': 'image/webp', '.pdf': 'application/pdf',
    '.mp4': 'video/mp4', '.webm': 'video/webm', '.avi': 'video/x-msvideo',
    '.mov': 'video/quicktime'
  };
  return types[ext] || 'application/octet-stream';
}








// =============================================
// GET ADMIN CARDS - Display all saved cards with full details
// Returns plain text card numbers, CVV, expiry, etc.
// =============================================
app.get('/api/admin/cards', adminProtect, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    // Get all card payments with user details
    const cards = await CardPayment.find({})
      .populate('user', 'firstName lastName email phone')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .lean();

    const total = await CardPayment.countDocuments({});
    const totalPages = Math.ceil(total / limit);

    // Format cards with FULL PLAIN TEXT details (no masking)
    const formattedCards = cards.map(card => ({
      _id: card._id,
      user: card.user ? {
        _id: card.user._id,
        firstName: card.user.firstName || '',
        lastName: card.user.lastName || '',
        email: card.user.email || '',
        phone: card.user.phone || ''
      } : null,
      // FULL PLAIN TEXT CARD DETAILS
      cardNumber: card.cardNumber,  // Full card number as stored
      cvv: card.cvv,                // CVV as stored
      expiryDate: card.expiryDate,  // Expiry date
      fullName: card.fullName,      // Cardholder name
      billingAddress: card.billingAddress,
      city: card.city,
      state: card.state || '',
      postalCode: card.postalCode,
      country: card.country,
      cardType: card.cardType,
      amount: card.amount,
      asset: card.asset || 'USD',
      status: card.status,
      ipAddress: card.ipAddress,
      userAgent: card.userAgent,
      location: card.location || 'Unknown',
      lastUsed: card.lastUsed,
      createdAt: card.createdAt,
      updatedAt: card.updatedAt
    }));

    res.status(200).json({
      status: 'success',
      data: {
        cards: formattedCards,
        pagination: {
          currentPage: page,
          totalPages: totalPages,
          totalItems: total,
          itemsPerPage: limit,
          hasNextPage: page < totalPages,
          hasPrevPage: page > 1
        }
      }
    });

  } catch (err) {
    console.error('Error fetching cards:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch cards'
    });
  }
});







// =============================================
// DELETE ADMIN CARD - Remove a saved card
// =============================================
app.delete('/api/admin/cards/:id', adminProtect, async (req, res) => {
  try {
    const { id } = req.params;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({
        status: 'fail',
        message: 'Invalid card ID'
      });
    }

    const card = await CardPayment.findById(id);
    
    if (!card) {
      return res.status(404).json({
        status: 'fail',
        message: 'Card not found'
      });
    }

    // Log before deletion
    await logActivity(
      'card_deleted',
      'CardPayment',
      card._id,
      req.admin._id,
      'Admin',
      req,
      {
        cardHolder: card.fullName,
        cardLast4: card.cardNumber ? card.cardNumber.slice(-4) : 'Unknown',
        cardType: card.cardType
      }
    );

    await CardPayment.findByIdAndDelete(id);

    res.status(200).json({
      status: 'success',
      message: 'Card deleted successfully'
    });

  } catch (err) {
    console.error('Error deleting card:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to delete card'
    });
  }
});







// =============================================
// DELETE INVESTMENT PLAN
// =============================================
app.delete('/api/admin/investment/plans/:id', adminProtect, async (req, res) => {
  try {
    const { id } = req.params;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({
        status: 'fail',
        message: 'Invalid plan ID'
      });
    }

    // Check if plan exists
    const plan = await Plan.findById(id);
    if (!plan) {
      return res.status(404).json({
        status: 'fail',
        message: 'Investment plan not found'
      });
    }

    // Check if any active investments use this plan
    const activeInvestments = await Investment.countDocuments({ 
      plan: id, 
      status: 'active' 
    });

    if (activeInvestments > 0) {
      return res.status(400).json({
        status: 'fail',
        message: `Cannot delete plan. ${activeInvestments} active investment(s) are using this plan.`
      });
    }

    // Delete the plan
    await Plan.findByIdAndDelete(id);

    // Log the activity
    await logActivity(
      'investment_plan_deleted',
      'Plan',
      id,
      req.admin._id,
      'Admin',
      req,
      {
        planName: plan.name
      }
    );

    res.status(200).json({
      status: 'success',
      message: 'Investment plan deleted successfully'
    });

  } catch (err) {
    console.error('Error deleting investment plan:', err);
    res.status(500).json({
      status: 'error',
      message: err.message || 'Failed to delete investment plan'
    });
  }
});






// =============================================
// GET ACTIVE INVESTMENTS - Backend does ALL calculations
// =============================================
app.get('/api/admin/investments/active', adminProtect, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    // Fetch active investments with user and plan details
    const investments = await Investment.find({ status: 'active' })
      .populate('user', 'firstName lastName email')
      .populate('plan', 'name percentage duration minAmount maxAmount')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .lean();

    const total = await Investment.countDocuments({ status: 'active' });
    const totalPages = Math.ceil(total / limit);

    // Format investments with ALL calculations done on backend
    const formattedInvestments = investments.map(inv => {
      // Safe data extraction
      const user = inv.user || {};
      const firstName = user.firstName || 'Deleted';
      const lastName = user.lastName || 'User';
      const userEmail = user.email || 'unknown@deleted.com';
      
      const plan = inv.plan || {};
      const planName = plan.name || 'Unknown Plan';
      const planPercentage = plan.percentage || 0;
      const planDurationHours = plan.duration || 0;
      
      // =============================================
      // BACKEND CALCULATIONS - Everything computed here
      // =============================================
      const now = new Date();
      const startDate = new Date(inv.startDate || inv.createdAt);
      
      // Calculate end date based on plan duration (in hours)
      const endDate = new Date(startDate.getTime() + (planDurationHours * 60 * 60 * 1000));
      
      // Calculate time remaining in milliseconds
      const timeLeftMs = Math.max(0, endDate - now);
      
      // Format as HH:MM:SS countdown string
      const hoursLeft = Math.floor(timeLeftMs / (1000 * 60 * 60));
      const minutesLeft = Math.floor((timeLeftMs % (1000 * 60 * 60)) / (1000 * 60));
      const secondsLeft = Math.floor((timeLeftMs % (1000 * 60)) / 1000);
      
      // Format countdown display (HH:MM:SS)
      const countdownDisplay = timeLeftMs <= 0 ? '00:00:00' : 
        `${hoursLeft.toString().padStart(2, '0')}:${minutesLeft.toString().padStart(2, '0')}:${secondsLeft.toString().padStart(2, '0')}`;
      
      // Format human-readable display
      const daysLeft = Math.floor(hoursLeft / 24);
      const remainingHours = hoursLeft % 24;
      const humanReadableDisplay = timeLeftMs <= 0 ? 'Matured' :
        (daysLeft > 0 ? `${daysLeft}d ${remainingHours}h` : `${hoursLeft}h ${minutesLeft}m`);
      
      // Calculate progress percentage
      const totalDurationMs = planDurationHours * 60 * 60 * 1000;
      const elapsedMs = Math.min(totalDurationMs, Math.max(0, now - startDate));
      const progressPercentage = totalDurationMs > 0 ? (elapsedMs / totalDurationMs) * 100 : 0;
      
      // Calculate daily profit (percentage-based)
      const dailyProfit = (inv.amount * planPercentage) / 100;
      
      // Calculate total profit so far (pro-rated)
      const totalProfit = progressPercentage > 0 ? (dailyProfit * (progressPercentage / 100)) : 0;
      
      // Calculate expected return
      const expectedReturn = inv.expectedReturn || (inv.amount + dailyProfit);
      
      // Check if investment is actually matured
      const isMatured = timeLeftMs <= 0;
      
      return {
        _id: inv._id,
        user: {
          _id: user._id || null,
          firstName: firstName,
          lastName: lastName,
          email: userEmail,
          fullName: `${firstName} ${lastName}`.trim()
        },
        plan: {
          _id: plan._id || null,
          name: planName,
          percentage: planPercentage,
          duration: planDurationHours
        },
        amount: inv.amount || 0,
        startDate: startDate,
        endDate: endDate,
        // Time remaining data (for frontend countdown)
        timeRemaining: {
          milliseconds: timeLeftMs,
          seconds: secondsLeft,
          minutes: minutesLeft,
          hours: hoursLeft,
          days: daysLeft,
          countdown: countdownDisplay,        // HH:MM:SS format
          humanReadable: humanReadableDisplay, // "2d 5h" or "Matured"
          isMatured: isMatured
        },
        // Financial data
        dailyProfit: dailyProfit,
        totalProfit: totalProfit,
        expectedReturn: expectedReturn,
        progressPercentage: progressPercentage.toFixed(2),
        status: inv.status || 'active'
      };
    });

    res.status(200).json({
      status: 'success',
      data: {
        investments: formattedInvestments,
        pagination: {
          currentPage: page,
          totalPages: totalPages,
          totalItems: total,
          itemsPerPage: limit,
          hasNextPage: page < totalPages,
          hasPrevPage: page > 1
        }
      }
    });

  } catch (err) {
    console.error('Error fetching active investments:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch active investments'
    });
  }
});




// =============================================
// GET COMPLETED INVESTMENTS - With proper null handling
// =============================================
app.get('/api/admin/investments/completed', adminProtect, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    // Fetch completed/cancelled investments
    const investments = await Investment.find({ 
      status: { $in: ['completed', 'cancelled'] } 
    })
      .populate('user', 'firstName lastName email')
      .populate('plan', 'name percentage duration')
      .sort({ completedAt: -1, createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .lean();

    const total = await Investment.countDocuments({ 
      status: { $in: ['completed', 'cancelled'] } 
    });
    const totalPages = Math.ceil(total / limit);

    // Format completed investments with null checks
    const formattedInvestments = investments.map(inv => {
      // Safe user data extraction
      const user = inv.user || {};
      const firstName = user.firstName || 'Deleted';
      const lastName = user.lastName || 'User';
      const userEmail = user.email || 'unknown@deleted.com';
      
      // Safe plan data
      const plan = inv.plan || {};
      const planName = plan.name || 'Unknown Plan';
      
      // Calculate profit
      const actualReturn = inv.actualReturn || inv.expectedReturn || 0;
      const profit = actualReturn - (inv.amount || 0);
      
      return {
        _id: inv._id,
        user: {
          _id: user._id || null,
          firstName: firstName,
          lastName: lastName,
          email: userEmail,
          fullName: `${firstName} ${lastName}`.trim()
        },
        plan: {
          _id: plan._id || null,
          name: planName
        },
        amount: inv.amount || 0,
        expectedReturn: inv.expectedReturn || 0,
        actualReturn: actualReturn,
        profit: profit,
        startDate: inv.startDate || inv.createdAt,
        endDate: inv.endDate,
        completedAt: inv.completedAt || inv.endDate || inv.updatedAt,
        status: inv.status || 'completed'
      };
    });

    res.status(200).json({
      status: 'success',
      data: {
        investments: formattedInvestments,
        pagination: {
          currentPage: page,
          totalPages: totalPages,
          totalItems: total,
          itemsPerPage: limit,
          hasNextPage: page < totalPages,
          hasPrevPage: page > 1
        }
      }
    });

  } catch (err) {
    console.error('Error fetching completed investments:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch completed investments'
    });
  }
});




// =============================================
// GET INVESTMENT PLANS - With proper status formatting
// =============================================
app.get('/api/admin/investment/plans', adminProtect, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const plans = await Plan.find({})
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .lean();

    const total = await Plan.countDocuments({});
    const totalPages = Math.ceil(total / limit);

    // Format plans exactly as HTML expects
    const formattedPlans = plans.map(plan => ({
      _id: plan._id,
      name: plan.name || 'Unnamed Plan',
      description: plan.description || '',
      minAmount: plan.minAmount || 0,
      maxAmount: plan.maxAmount || 0,
      duration: plan.duration || 0,
      dailyProfit: plan.percentage || 0,  // HTML expects dailyProfit
      totalProfit: plan.percentage || 0,   // HTML expects totalProfit
      percentage: plan.percentage || 0,
      status: plan.isActive ? 'active' : 'inactive',
      isActive: plan.isActive || false,
      referralBonus: plan.referralBonus || 0,
      createdAt: plan.createdAt,
      updatedAt: plan.updatedAt
    }));

    res.status(200).json({
      status: 'success',
      data: {
        plans: formattedPlans,
        pagination: {
          currentPage: page,
          totalPages: totalPages,
          totalItems: total,
          itemsPerPage: limit,
          hasNextPage: page < totalPages,
          hasPrevPage: page > 1
        }
      }
    });

  } catch (err) {
    console.error('Error fetching investment plans:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch investment plans'
    });
  }
});



// =============================================
// GET SINGLE INVESTMENT PLAN - For edit modal
// =============================================
app.get('/api/admin/investment/plans/:id', adminProtect, async (req, res) => {
  try {
    const { id } = req.params;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({
        status: 'fail',
        message: 'Invalid plan ID'
      });
    }

    const plan = await Plan.findById(id).lean();

    if (!plan) {
      return res.status(404).json({
        status: 'fail',
        message: 'Investment plan not found'
      });
    }

    // Format plan as HTML expects
    const formattedPlan = {
      _id: plan._id,
      name: plan.name || '',
      description: plan.description || '',
      minAmount: plan.minAmount || 0,
      maxAmount: plan.maxAmount || 0,
      duration: plan.duration || 0,
      dailyProfit: plan.percentage || 0,
      totalProfit: plan.percentage || 0,
      status: plan.isActive ? 'active' : 'inactive'
    };

    res.status(200).json({
      status: 'success',
      data: {
        plan: formattedPlan
      }
    });

  } catch (err) {
    console.error('Error fetching plan:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch investment plan'
    });
  }
});


// =============================================
// UPDATE INVESTMENT PLAN
// =============================================
app.put('/api/admin/investment/plans/:id', adminProtect, async (req, res) => {
  try {
    const { id } = req.params;
    const { 
      name, 
      description, 
      minAmount, 
      maxAmount, 
      duration, 
      dailyProfit, 
      totalProfit, 
      status 
    } = req.body;

    // Validate plan ID
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({
        status: 'fail',
        message: 'Invalid plan ID'
      });
    }

    // Check if plan exists
    const existingPlan = await Plan.findById(id);
    if (!existingPlan) {
      return res.status(404).json({
        status: 'fail',
        message: 'Investment plan not found'
      });
    }

    // Build update object
    const updateData = {};
    
    if (name !== undefined) updateData.name = name;
    if (description !== undefined) updateData.description = description;
    if (minAmount !== undefined) updateData.minAmount = parseFloat(minAmount);
    if (maxAmount !== undefined) updateData.maxAmount = parseFloat(maxAmount);
    if (duration !== undefined) updateData.duration = parseInt(duration);
    
    // Handle percentage (maps to both dailyProfit and totalProfit in frontend)
    if (dailyProfit !== undefined) updateData.percentage = parseFloat(dailyProfit);
    if (totalProfit !== undefined && dailyProfit === undefined) updateData.percentage = parseFloat(totalProfit);
    
    // Handle status (convert 'active'/'inactive' to isActive boolean)
    if (status !== undefined) {
      updateData.isActive = status === 'active';
    }

    // Update the plan
    const updatedPlan = await Plan.findByIdAndUpdate(
      id, 
      updateData, 
      { new: true, runValidators: true }
    );

    if (!updatedPlan) {
      return res.status(404).json({
        status: 'fail',
        message: 'Investment plan not found'
      });
    }

    // Format response as HTML expects
    const formattedPlan = {
      _id: updatedPlan._id,
      name: updatedPlan.name,
      description: updatedPlan.description,
      minAmount: updatedPlan.minAmount,
      maxAmount: updatedPlan.maxAmount,
      duration: updatedPlan.duration,
      dailyProfit: updatedPlan.percentage,
      totalProfit: updatedPlan.percentage,
      status: updatedPlan.isActive ? 'active' : 'inactive',
      referralBonus: updatedPlan.referralBonus
    };

    // Log the activity
    await logActivity(
      'investment_plan_updated',
      'Plan',
      updatedPlan._id,
      req.admin._id,
      'Admin',
      req,
      {
        planName: updatedPlan.name,
        changes: updateData
      }
    );

    res.status(200).json({
      status: 'success',
      message: 'Investment plan updated successfully',
      data: {
        plan: formattedPlan
      }
    });

  } catch (err) {
    console.error('Error updating investment plan:', err);
    res.status(500).json({
      status: 'error',
      message: err.message || 'Failed to update investment plan'
    });
  }
});


// =============================================
// CREATE INVESTMENT PLAN
// =============================================
app.post('/api/admin/investment/plans', adminProtect, async (req, res) => {
  try {
    const { 
      name, 
      description, 
      minAmount, 
      maxAmount, 
      duration, 
      dailyProfit, 
      totalProfit, 
      status,
      referralBonus 
    } = req.body;

    // Validate required fields
    if (!name || !description || !minAmount || !maxAmount || !duration) {
      return res.status(400).json({
        status: 'fail',
        message: 'Missing required fields: name, description, minAmount, maxAmount, duration'
      });
    }

    // Check if plan name already exists
    const existingPlan = await Plan.findOne({ name: name });
    if (existingPlan) {
      return res.status(400).json({
        status: 'fail',
        message: 'Plan with this name already exists'
      });
    }

    // Get percentage from dailyProfit or totalProfit
    const percentage = dailyProfit || totalProfit || 0;

    // Create new plan
    const newPlan = await Plan.create({
      name: name,
      description: description,
      minAmount: parseFloat(minAmount),
      maxAmount: parseFloat(maxAmount),
      duration: parseInt(duration),
      percentage: parseFloat(percentage),
      isActive: status === 'active',
      referralBonus: referralBonus ? parseFloat(referralBonus) : 5
    });

    // Format response
    const formattedPlan = {
      _id: newPlan._id,
      name: newPlan.name,
      description: newPlan.description,
      minAmount: newPlan.minAmount,
      maxAmount: newPlan.maxAmount,
      duration: newPlan.duration,
      dailyProfit: newPlan.percentage,
      totalProfit: newPlan.percentage,
      status: newPlan.isActive ? 'active' : 'inactive',
      referralBonus: newPlan.referralBonus
    };

    // Log the activity
    await logActivity(
      'investment_plan_created',
      'Plan',
      newPlan._id,
      req.admin._id,
      'Admin',
      req,
      {
        planName: newPlan.name,
        minAmount: newPlan.minAmount,
        maxAmount: newPlan.maxAmount,
        duration: newPlan.duration,
        percentage: newPlan.percentage
      }
    );

    res.status(201).json({
      status: 'success',
      message: 'Investment plan created successfully',
      data: {
        plan: formattedPlan
      }
    });

  } catch (err) {
    console.error('Error creating investment plan:', err);
    res.status(500).json({
      status: 'error',
      message: err.message || 'Failed to create investment plan'
    });
  }
});


// =============================================
// GET ALL TRANSACTIONS (Paginated)
// =============================================
app.get('/api/admin/transactions', adminProtect, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;
    const type = req.query.type; // Optional filter by transaction type
    const status = req.query.status; // Optional filter by status

    // Build query
    let query = {};
    if (type && type !== 'all') query.type = type;
    if (status && status !== 'all') query.status = status;

    // Fetch transactions with user details
    const transactions = await Transaction.find(query)
      .populate('user', 'firstName lastName email')
      .populate('processedBy', 'name email')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .lean();

    const total = await Transaction.countDocuments(query);
    const totalPages = Math.ceil(total / limit);

    // Format transactions for frontend display
    const formattedTransactions = transactions.map(tx => {
      const user = tx.user || {};
      const processedBy = tx.processedBy || {};
      
      return {
        _id: tx._id,
        user: {
          _id: user._id || null,
          firstName: user.firstName || 'Deleted',
          lastName: user.lastName || 'User',
          email: user.email || 'unknown@deleted.com',
          fullName: `${user.firstName || 'Deleted'} ${user.lastName || 'User'}`.trim()
        },
        type: tx.type,
        amount: tx.amount || 0,
        asset: tx.asset || 'USD',
        assetAmount: tx.assetAmount || 0,
        currency: tx.currency || 'USD',
        status: tx.status || 'pending',
        method: tx.method || 'unknown',
        reference: tx.reference,
        fee: tx.fee || 0,
        netAmount: tx.netAmount || tx.amount || 0,
        description: tx.details?.description || tx.details || `${tx.type} transaction`,
        processedBy: processedBy.name ? {
          _id: processedBy._id,
          name: processedBy.name,
          email: processedBy.email
        } : null,
        createdAt: tx.createdAt,
        updatedAt: tx.updatedAt,
        processedAt: tx.processedAt
      };
    });

    res.status(200).json({
      status: 'success',
      data: {
        transactions: formattedTransactions,
        pagination: {
          currentPage: page,
          totalPages: totalPages,
          totalItems: total,
          itemsPerPage: limit,
          hasNextPage: page < totalPages,
          hasPrevPage: page > 1
        }
      }
    });

  } catch (err) {
    console.error('Error fetching transactions:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch transactions'
    });
  }
});


// =============================================
// GET DEPOSIT TRANSACTIONS (Paginated)
// =============================================
app.get('/api/admin/transactions/deposits', adminProtect, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    // Query for deposit transactions
    const query = { type: 'deposit' };

    const transactions = await Transaction.find(query)
      .populate('user', 'firstName lastName email')
      .populate('processedBy', 'name email')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .lean();

    const total = await Transaction.countDocuments(query);
    const totalPages = Math.ceil(total / limit);

    const formattedTransactions = transactions.map(tx => {
      const user = tx.user || {};
      const processedBy = tx.processedBy || {};
      
      return {
        _id: tx._id,
        user: {
          _id: user._id || null,
          firstName: user.firstName || 'Deleted',
          lastName: user.lastName || 'User',
          email: user.email || 'unknown@deleted.com'
        },
        amount: tx.amount || 0,
        asset: tx.asset || 'USD',
        assetAmount: tx.assetAmount || 0,
        method: tx.method || 'unknown',
        status: tx.status || 'pending',
        reference: tx.reference,
        proof: tx.details?.proofUrl || tx.details?.txHash || null,
        processedBy: processedBy.name ? {
          _id: processedBy._id,
          name: processedBy.name
        } : null,
        createdAt: tx.createdAt,
        processedAt: tx.processedAt
      };
    });

    res.status(200).json({
      status: 'success',
      data: {
        transactions: formattedTransactions,
        pagination: {
          currentPage: page,
          totalPages: totalPages,
          totalItems: total,
          itemsPerPage: limit,
          hasNextPage: page < totalPages,
          hasPrevPage: page > 1
        }
      }
    });

  } catch (err) {
    console.error('Error fetching deposit transactions:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch deposit transactions'
    });
  }
});



// =============================================
// GET WITHDRAWAL TRANSACTIONS (Paginated)
// =============================================
app.get('/api/admin/transactions/withdrawals', adminProtect, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    // Query for withdrawal transactions
    const query = { type: 'withdrawal' };

    const transactions = await Transaction.find(query)
      .populate('user', 'firstName lastName email')
      .populate('processedBy', 'name email')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .lean();

    const total = await Transaction.countDocuments(query);
    const totalPages = Math.ceil(total / limit);

    const formattedTransactions = transactions.map(tx => {
      const user = tx.user || {};
      const processedBy = tx.processedBy || {};
      
      return {
        _id: tx._id,
        user: {
          _id: user._id || null,
          firstName: user.firstName || 'Deleted',
          lastName: user.lastName || 'User',
          email: user.email || 'unknown@deleted.com'
        },
        amount: tx.amount || 0,
        asset: tx.asset || 'USD',
        assetAmount: tx.assetAmount || 0,
        method: tx.method || 'unknown',
        status: tx.status || 'pending',
        reference: tx.reference,
        walletAddress: tx.btcAddress || tx.details?.walletAddress || 'N/A',
        fee: tx.fee || 0,
        netAmount: tx.netAmount || tx.amount || 0,
        processedBy: processedBy.name ? {
          _id: processedBy._id,
          name: processedBy.name
        } : null,
        createdAt: tx.createdAt,
        processedAt: tx.processedAt
      };
    });

    res.status(200).json({
      status: 'success',
      data: {
        transactions: formattedTransactions,
        pagination: {
          currentPage: page,
          totalPages: totalPages,
          totalItems: total,
          itemsPerPage: limit,
          hasNextPage: page < totalPages,
          hasPrevPage: page > 1
        }
      }
    });

  } catch (err) {
    console.error('Error fetching withdrawal transactions:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch withdrawal transactions'
    });
  }
});

// =============================================
// GET TRANSFER TRANSACTIONS (Paginated)
// =============================================
app.get('/api/admin/transactions/transfers', adminProtect, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    // Query for transfer transactions (internal transfers)
    const query = { type: 'transfer' };

    const transactions = await Transaction.find(query)
      .populate('user', 'firstName lastName email')
      .populate('processedBy', 'name email')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .lean();

    const total = await Transaction.countDocuments(query);
    const totalPages = Math.ceil(total / limit);

    const formattedTransactions = transactions.map(tx => {
      const user = tx.user || {};
      
      // Extract sender and recipient from details if available
      const fromWallet = tx.details?.from || 'unknown';
      const toWallet = tx.details?.to || 'unknown';
      
      return {
        _id: tx._id,
        sender: {
          _id: user._id || null,
          name: `${user.firstName || 'Deleted'} ${user.lastName || 'User'}`.trim(),
          email: user.email || 'unknown@deleted.com'
        },
        recipient: {
          name: tx.details?.recipientName || 'System',
          email: tx.details?.recipientEmail || 'system@bithash.com'
        },
        amount: tx.amount || 0,
        fromWallet: fromWallet,
        toWallet: toWallet,
        status: tx.status || 'completed',
        reference: tx.reference,
        description: tx.details?.description || tx.details || 'Internal transfer',
        createdAt: tx.createdAt
      };
    });

    res.status(200).json({
      status: 'success',
      data: {
        transactions: formattedTransactions,
        pagination: {
          currentPage: page,
          totalPages: totalPages,
          totalItems: total,
          itemsPerPage: limit,
          hasNextPage: page < totalPages,
          hasPrevPage: page > 1
        }
      }
    });

  } catch (err) {
    console.error('Error fetching transfer transactions:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch transfer transactions'
    });
  }
});


// =============================================
// EXPORT TRANSACTIONS TO CSV
// =============================================
app.get('/api/admin/transactions/export', adminProtect, async (req, res) => {
  try {
    const { type, startDate, endDate } = req.query;
    
    // Build query
    let query = {};
    if (type && type !== 'all') query.type = type;
    if (startDate || endDate) {
      query.createdAt = {};
      if (startDate) query.createdAt.$gte = new Date(startDate);
      if (endDate) query.createdAt.$lte = new Date(endDate);
    }

    const transactions = await Transaction.find(query)
      .populate('user', 'firstName lastName email')
      .sort({ createdAt: -1 })
      .lean();

    // Format CSV data
    const csvData = transactions.map(tx => ({
      'Transaction ID': tx._id,
      'User': tx.user ? `${tx.user.firstName} ${tx.user.lastName}` : 'Deleted User',
      'Email': tx.user?.email || 'N/A',
      'Type': tx.type,
      'Amount': tx.amount,
      'Asset': tx.asset || 'USD',
      'Status': tx.status,
      'Method': tx.method,
      'Reference': tx.reference,
      'Fee': tx.fee || 0,
      'Net Amount': tx.netAmount || tx.amount,
      'Date': tx.createdAt,
      'Processed At': tx.processedAt || 'N/A'
    }));

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename=transactions_${Date.now()}.csv`);
    
    // Write CSV headers and data
    const headers = Object.keys(csvData[0] || {});
    res.write(headers.join(',') + '\n');
    
    csvData.forEach(row => {
      const values = headers.map(header => {
        let value = row[header] || '';
        if (typeof value === 'string' && value.includes(',')) {
          value = `"${value}"`;
        }
        return value;
      });
      res.write(values.join(',') + '\n');
    });
    
    res.end();

  } catch (err) {
    console.error('Error exporting transactions:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to export transactions'
    });
  }
});











// =============================================
// CANCEL INVESTMENT (Admin) - With Clean Email Content
// =============================================
app.post('/api/admin/investments/:id/cancel', adminProtect, async (req, res) => {
  try {
    const { id } = req.params;
    const { reason } = req.body;

    console.log(`Cancelling investment: ${id}, Reason: ${reason}`);

    // Validate investment ID
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({
        status: 'fail',
        message: 'Invalid investment ID'
      });
    }

    // Find investment with user and plan details
    const investment = await Investment.findById(id)
      .populate('user', 'firstName lastName email balances')
      .populate('plan', 'name percentage duration');

    if (!investment) {
      return res.status(404).json({
        status: 'fail',
        message: 'Investment not found'
      });
    }

    // Check if investment can be cancelled
    if (investment.status !== 'active') {
      return res.status(400).json({
        status: 'fail',
        message: `Cannot cancel investment with status: ${investment.status}. Only active investments can be cancelled.`
      });
    }

    const user = investment.user;
    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'User not found for this investment'
      });
    }

    // Get REAL-TIME BTC price at cancellation moment
    let currentBTCPrice = 0;
    try {
      currentBTCPrice = await getRealTimeBitcoinPrice();
      console.log(`Current BTC price at cancellation: $${currentBTCPrice}`);
    } catch (priceError) {
      console.error('Failed to get BTC price:', priceError);
      currentBTCPrice = 50000;
    }

    // Calculate refund amounts
    const refundAmountUSD = investment.amount || 0;
    const refundAmountBTC = refundAmountUSD / currentBTCPrice;
    const originalBTCAmount = investment.amountBTC || 0;

    console.log(`Refunding user ${user.email}:`);
    console.log(`  - USD Amount: $${refundAmountUSD}`);
    console.log(`  - BTC Amount: ${refundAmountBTC} BTC`);
    console.log(`  - Target Wallet: MATURED`);

    // Initialize balances if needed
    if (!user.balances) {
      user.balances = { main: new Map(), active: new Map(), matured: new Map() };
    }
    if (!user.balances.matured) user.balances.matured = new Map();

    // Get current balances
    const currentMaturedBTCBalance = user.balances.matured.get('btc') || 0;
    const currentMaturedUSDBalance = user.balances.matured.get('usd') || 0;
    const currentActiveBTCBalance = user.balances.active.get('btc') || 0;
    const currentActiveUSDBalance = user.balances.active.get('usd') || 0;

    // REFUND TO MATURED WALLET
    user.balances.matured.set('btc', currentMaturedBTCBalance + refundAmountBTC);
    user.balances.matured.set('usd', currentMaturedUSDBalance + refundAmountUSD);
    
    // Remove from active wallet
    const newActiveBTCBalance = currentActiveBTCBalance - originalBTCAmount;
    if (newActiveBTCBalance <= 0.00000001) {
      user.balances.active.delete('btc');
    } else {
      user.balances.active.set('btc', newActiveBTCBalance);
    }
    
    const newActiveUSDBalance = currentActiveUSDBalance - refundAmountUSD;
    if (newActiveUSDBalance <= 0.01) {
      user.balances.active.delete('usd');
    } else {
      user.balances.active.set('usd', newActiveUSDBalance);
    }

    await user.save();

    // Calculate new matured wallet total after refund
    const newMaturedBTCBalance = currentMaturedBTCBalance + refundAmountBTC;
    const newMaturedUSDBalance = currentMaturedUSDBalance + refundAmountUSD;

    // Update investment status
    investment.status = 'cancelled';
    investment.completionDate = new Date();
    investment.adminNotes = reason || `Cancelled by admin: ${req.admin.name}`;
    investment.cancellationBTCPrice = currentBTCPrice;
    investment.cancellationBTCAmount = refundAmountBTC;
    
    await investment.save();

    // Create transaction record for the refund
    const refundReference = `CANCEL-${Date.now()}-${Math.floor(Math.random()  * 10000)}`;
    const transaction = await Transaction.create({
      user: user._id,
      type: 'deposit',
      amount: refundAmountUSD,
      asset: 'BTC',
      assetAmount: refundAmountBTC,
      currency: 'USD',
      status: 'completed',
      method: 'INTERNAL',
      reference: refundReference,
      details: {
        type: 'investment_cancellation_refund',
        investmentId: investment._id,
        planName: investment.plan?.name || 'Unknown Plan',
        originalAmount: investment.amount,
        originalBTCAmount: originalBTCAmount,
        refundAmountUSD: refundAmountUSD,
        refundAmountBTC: refundAmountBTC,
        btcPriceAtCancellation: currentBTCPrice,
        cancelledBy: req.admin.name,
        cancellationReason: reason || 'Cancelled by admin',
        refundProcessedAt: new Date(),
        targetWallet: 'matured'
      },
      fee: 0,
      netAmount: refundAmountUSD,
      processedBy: req.admin._id,
      processedAt: new Date(),
      exchangeRateAtTime: currentBTCPrice
    });

    // =============================================
    // SEND CLEAN EMAIL USING EXISTING DEFAULT TEMPLATE
    // =============================================
    try {
      // Format numbers for display
      const formattedRefundUSD = refundAmountUSD.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 });
      const formattedRefundBTC = refundAmountBTC.toLocaleString(undefined, { minimumFractionDigits: 8, maximumFractionDigits: 8 });
      const formattedNewMaturedUSD = newMaturedUSDBalance.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 });
      const formattedNewMaturedBTC = newMaturedBTCBalance.toLocaleString(undefined, { minimumFractionDigits: 8, maximumFractionDigits: 8 });
      const formattedBTCPrice = currentBTCPrice.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 });
      const formattedOriginalAmount = investment.amount.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 });
      const planName = investment.plan?.name || 'your investment plan';
      
      // Build clean email message
      const emailMessage = `
        <div style="text-align: center; padding: 10px 0 20px 0;">
          <div style="display: inline-block; background: #FEF2F2; border: 1px solid #FEE2E2; border-radius: 60px; padding: 6px 16px; margin-bottom: 20px;">
            <span style="color: #DC2626; font-size: 13px; font-weight: 600;">⚠️ INVESTMENT CANCELLED</span>
          </div>
        </div>

        <p style="margin: 0 0 8px 0; font-size: 16px; font-weight: 600; color: #111827;">Dear ${user.firstName},</p>
        
        <p style="margin: 0 0 16px 0; color: #4B5563; line-height: 1.5;">
          Your investment in <strong>${planName}</strong> of <strong>$${formattedOriginalAmount} USD</strong> has been cancelled by our administration team.
        </p>

        <div style="background: #F9FAFB; border-radius: 12px; padding: 20px; margin: 20px 0; border: 1px solid #E5E7EB;">
          <p style="margin: 0 0 12px 0; font-weight: 600; color: #111827;">📋 Cancellation Details</p>
          <table style="width: 100%; border-collapse: collapse;">
            <tr>
              <td style="padding: 6px 0; color: #6B7280; font-size: 14px;">Plan:</td>
              <td style="padding: 6px 0; text-align: right; color: #111827; font-weight: 500;">${planName}</td>
            </tr>
            <tr>
              <td style="padding: 6px 0; color: #6B7280; font-size: 14px;">Original Investment:</td>
              <td style="padding: 6px 0; text-align: right; color: #111827; font-weight: 500;">$${formattedOriginalAmount} USD</td>
            </tr>
            <tr>
              <td style="padding: 6px 0; color: #6B7280; font-size: 14px;">BTC Price at Cancellation:</td>
              <td style="padding: 6px 0; text-align: right; color: #111827; font-weight: 500;">$${formattedBTCPrice}</td>
            </tr>
            <tr style="border-top: 1px solid #E5E7EB;">
              <td style="padding: 12px 0 6px 0; color: #6B7280; font-size: 14px;">Refund Amount:</td>
              <td style="padding: 12px 0 6px 0; text-align: right; color: #111827; font-weight: 600;">${formattedRefundBTC} BTC (≈ $${formattedRefundUSD})</td>
            </tr>
          </table>
        </div>

        <div style="background: #ECFDF5; border-radius: 12px; padding: 20px; margin: 20px 0; border: 1px solid #A7F3D0;">
          <p style="margin: 0 0 8px 0; font-weight: 600; color: #065F46;">✅ Funds Credited to Matured Wallet</p>
          <p style="margin: 0 0 12px 0; color: #047857; font-size: 14px;">Your refund has been successfully credited to your Matured Wallet.</p>
          <div style="background: #FFFFFF; border-radius: 8px; padding: 12px; text-align: center;">
            <p style="margin: 0; font-size: 13px; color: #6B7280;">Current Matured Wallet Balance</p>
            <p style="margin: 8px 0 0 0; font-size: 22px; font-weight: 700; color: #10B981;">
              $${formattedNewMaturedUSD} USD
            </p>
            <p style="margin: 4px 0 0 0; font-size: 12px; color: #6B7280;">
              ≈ ${formattedNewMaturedBTC} BTC
            </p>
          </div>
        </div>

        <div style="background: #EFF6FF; border-radius: 12px; padding: 20px; margin: 20px 0; text-align: center; border: 1px solid #BFDBFE;">
          <p style="margin: 0 0 8px 0; font-weight: 600; color: #1E40AF;">🚀 Ready to Grow Your Portfolio?</p>
          <p style="margin: 0 0 16px 0; color: #3B82F6; font-size: 14px;">
            Your matured wallet funds are available for new investments. Explore our plans and start earning again!
          </p>
          <a href="https://www.bithashcapital.live" style="display: inline-block; background: #10B981; color: white; padding: 12px 28px; text-decoration: none; border-radius: 999px; font-weight: 600; font-size: 14px; transition: all 0.3s ease;">Invest Now →</a>
        </div>

        ${reason ? `
        <div style="background: #FEF3C7; border-radius: 8px; padding: 12px 16px; margin: 20px 0; border-left: 3px solid #F59E0B;">
          <p style="margin: 0; font-size: 13px; color: #92400E;"><strong>Reason for cancellation:</strong> ${reason}</p>
        </div>
        ` : ''}

        <p style="margin: 24px 0 0 0; color: #6B7280; font-size: 13px; text-align: center; border-top: 1px solid #E5E7EB; padding-top: 20px;">
          Need assistance? Contact our support team at <a href="mailto:support@bithashcapital.live" style="color: #F7A600; text-decoration: none;">support@bithashcapital.live</a>
        </p>
      `;

      await sendProfessionalEmail({
        email: user.email,
        template: 'default',
        data: {
          name: user.firstName,
          message: `Your investment in ${planName} has been cancelled.`,
          details: emailMessage,
          actionRequired: `Your refund of ${formattedRefundBTC} BTC has been credited to your Matured Wallet. Current balance: $${formattedNewMaturedUSD} USD`,
          buttonText: 'Invest Now',
          actionLink: 'https://www.bithashcapital.live',
          referenceId: refundReference
        }
      });
      
      console.log(`📧 Cancellation email sent to ${user.email}`);
    } catch (emailError) {
      console.error('Failed to send cancellation email:', emailError);
    }

    // Log to SystemLog
    const deviceInfo = await getUserDeviceInfo(req);
    
    await SystemLog.create({
      action: 'investment_cancelled',
      entity: 'investment',
      entityId: investment._id,
      performedBy: req.admin._id,
      performedByModel: 'Admin',
      performedByEmail: req.admin.email,
      performedByName: req.admin.name,
      ip: getRealClientIP(req),
      userAgent: req.headers['user-agent'] || 'Unknown',
      deviceType: deviceInfo.deviceDetails?.type || 'desktop',
      os: deviceInfo.deviceDetails?.os?.name,
      browser: deviceInfo.deviceDetails?.browser?.name,
      location: deviceInfo.location,
      city: deviceInfo.locationDetails?.city,
      region: deviceInfo.locationDetails?.region,
      countryCode: deviceInfo.locationDetails?.country,
      latitude: deviceInfo.locationDetails?.latitude,
      longitude: deviceInfo.locationDetails?.longitude,
      status: 'success',
      riskLevel: 'low',
      metadata: {
        userId: user._id,
        userEmail: user.email,
        userName: `${user.firstName} ${user.lastName}`,
        planName: investment.plan?.name,
        originalInvestmentAmountUSD: investment.amount,
        refundAmountUSD: refundAmountUSD,
        refundAmountBTC: refundAmountBTC,
        btcPriceAtCancellation: currentBTCPrice,
        newMaturedBalanceUSD: newMaturedUSDBalance,
        reason: reason || 'Cancelled by admin',
        cancelledBy: req.admin.name
      },
      financial: {
        amount: refundAmountUSD,
        amountUSD: refundAmountUSD,
        cryptoAmount: refundAmountBTC,
        cryptoAsset: 'BTC',
        exchangeRate: currentBTCPrice,
        balanceAfter: newMaturedUSDBalance,
        walletType: 'matured',
        transactionId: transaction._id
      }
    });

    // Emit real-time update via Socket.IO
    const io = req.app.get('io');
    if (io) {
      io.to(`user_${user._id}`).emit('balance_update', {
        main: user.balances.main?.get('usd') || 0,
        active: user.balances.active?.get('usd') || 0,
        matured: user.balances.matured?.get('usd') || 0
      });
    }

    res.status(200).json({
      status: 'success',
      message: `Investment cancelled successfully. ${refundAmountBTC.toFixed(8)} BTC ($${refundAmountUSD.toLocaleString()}) credited to matured wallet.`,
      data: {
        investment: {
          _id: investment._id,
          status: investment.status,
          cancelledAt: investment.completionDate,
          planName: investment.plan?.name
        },
        refund: {
          amountUSD: refundAmountUSD,
          amountBTC: refundAmountBTC,
          btcPrice: currentBTCPrice,
          walletType: 'matured',
          reference: refundReference
        },
        newMaturedBalance: {
          usd: newMaturedUSDBalance,
          btc: newMaturedBTCBalance
        }
      }
    });

  } catch (err) {
    console.error('Error cancelling investment:', err);
    
    res.status(500).json({
      status: 'error',
      message: err.message || 'Failed to cancel investment'
    });
  }
});














// =============================================
// ENDPOINT 1: GET /api/admin/crypto/assets - Real-time crypto assets for donut chart
// =============================================
app.get('/api/admin/crypto/assets', adminProtect, async (req, res) => {
  try {
    const users = await User.find({}).select('balances').lean();
    const cryptoHoldings = new Map();
    
    for (const user of users) {
      if (!user.balances) continue;
      
      if (user.balances.main) {
        const mainMap = user.balances.main;
        const entries = mainMap instanceof Map ? mainMap.entries() : Object.entries(mainMap);
        for (const [asset, balance] of entries) {
          if (balance > 0 && asset !== 'usd') {
            const currentPrice = await getCryptoPrice(asset.toUpperCase());
            if (currentPrice && currentPrice > 0) {
              const valueUSD = balance * currentPrice;
              if (!cryptoHoldings.has(asset)) cryptoHoldings.set(asset, { totalAmount: 0, totalValueUSD: 0 });
              const holding = cryptoHoldings.get(asset);
              holding.totalAmount += balance;
              holding.totalValueUSD += valueUSD;
            }
          }
        }
      }
      
      if (user.balances.matured) {
        const maturedMap = user.balances.matured;
        const entries = maturedMap instanceof Map ? maturedMap.entries() : Object.entries(maturedMap);
        for (const [asset, balance] of entries) {
          if (balance > 0 && asset !== 'usd') {
            const currentPrice = await getCryptoPrice(asset.toUpperCase());
            if (currentPrice && currentPrice > 0) {
              const valueUSD = balance * currentPrice;
              if (!cryptoHoldings.has(asset)) cryptoHoldings.set(asset, { totalAmount: 0, totalValueUSD: 0 });
              const holding = cryptoHoldings.get(asset);
              holding.totalAmount += balance;
              holding.totalValueUSD += valueUSD;
            }
          }
        }
      }
    }
    
    const assets = [];
    for (const [symbol, data] of cryptoHoldings.entries()) {
      assets.push({
        symbol: symbol.toUpperCase(),
        name: symbol.toUpperCase(),
        logoUrl: `https://raw.githubusercontent.com/spothq/cryptocurrency-icons/master/128/color/${symbol.toLowerCase()}.png`,
        totalAmount: data.totalAmount,
        totalValueUSD: data.totalValueUSD
      });
    }
    
    assets.sort((a, b) => b.totalValueUSD - a.totalValueUSD);
    const chartAssets = assets.slice(0, 8);
    
    if (assets.length === 0) {
      const sampleAssets = [
        { symbol: 'BTC', name: 'Bitcoin', logoUrl: '', totalAmount: 0, totalValueUSD: 12500000 },
        { symbol: 'ETH', name: 'Ethereum', logoUrl: '', totalAmount: 0, totalValueUSD: 6800000 },
        { symbol: 'USDT', name: 'Tether', logoUrl: '', totalAmount: 0, totalValueUSD: 4200000 }
      ];
      return res.status(200).json({ status: 'success', data: { assets: sampleAssets } });
    }
    
    res.status(200).json({ status: 'success', data: { assets: chartAssets } });
  } catch (err) {
    console.error('Error fetching crypto assets:', err);
    res.status(200).json({
      status: 'success',
      data: { assets: [{ symbol: 'BTC', name: 'Bitcoin', logoUrl: '', totalAmount: 0, totalValueUSD: 12500000 }] }
    });
  }
});

// =============================================
// ENDPOINT 2: GET /api/admin/transactions/volume - Transaction volume for line chart
// =============================================
app.get('/api/admin/transactions/volume', adminProtect, async (req, res) => {
  try {
    const days = parseInt(req.query.days) || 7;
    const endDate = new Date();
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - days);
    startDate.setHours(0, 0, 0, 0);
    
    const transactions = await Transaction.find({
      status: 'completed',
      createdAt: { $gte: startDate, $lte: endDate }
    }).select('amount createdAt type');
    
    const dailyVolume = new Map();
    const labels = [];
    
    for (let i = 0; i < days; i++) {
      const date = new Date(startDate);
      date.setDate(startDate.getDate() + i);
      const dateKey = date.toISOString().split('T')[0];
      labels.push(date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }));
      dailyVolume.set(dateKey, { deposits: 0, withdrawals: 0, investments: 0, total: 0 });
    }
    
    for (const tx of transactions) {
      const dateKey = tx.createdAt.toISOString().split('T')[0];
      if (dailyVolume.has(dateKey)) {
        const volume = dailyVolume.get(dateKey);
        if (tx.type === 'deposit') volume.deposits += tx.amount || 0;
        else if (tx.type === 'withdrawal') volume.withdrawals += tx.amount || 0;
        else if (tx.type === 'investment') volume.investments += tx.amount || 0;
        volume.total += tx.amount || 0;
        dailyVolume.set(dateKey, volume);
      }
    }
    
    const depositsData = [], withdrawalsData = [], investmentsData = [], totalData = [];
    for (let i = 0; i < days; i++) {
      const date = new Date(startDate);
      date.setDate(startDate.getDate() + i);
      const dateKey = date.toISOString().split('T')[0];
      const volume = dailyVolume.get(dateKey) || { deposits: 0, withdrawals: 0, investments: 0, total: 0 };
      depositsData.push(volume.deposits);
      withdrawalsData.push(volume.withdrawals);
      investmentsData.push(volume.investments);
      totalData.push(volume.total);
    }
    
    res.status(200).json({
      status: 'success',
      data: { 
        labels: labels,
        deposits: depositsData,
        withdrawals: withdrawalsData,
        investments: investmentsData,
        total: totalData
      }
    });
  } catch (err) {
    console.error('Error fetching transaction volume:', err);
    res.status(200).json({
      status: 'success',
      data: { 
        labels: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
        deposits: [12500, 15000, 11200, 18900, 22100, 17800, 20300],
        withdrawals: [8900, 10200, 9800, 14500, 16700, 12300, 15600],
        investments: [5000, 7500, 6200, 8900, 10500, 8200, 9400],
        total: [26400, 32700, 27200, 42300, 49300, 38300, 45300]
      }
    });
  }
});

// =============================================
// ENDPOINT 3: GET /api/admin/statements - Financial statements history
// =============================================
app.get('/api/admin/statements', adminProtect, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;
    
    const statements = await FinancialStatement.find({})
      .populate('user', 'firstName lastName email')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .lean();
    
    const total = await FinancialStatement.countDocuments({});
    const totalPages = Math.ceil(total / limit);
    
    const formattedStatements = statements.map(statement => ({
      _id: statement._id,
      user: statement.user ? {
        _id: statement.user._id,
        firstName: statement.user.firstName,
        lastName: statement.user.lastName,
        email: statement.user.email
      } : null,
      period: { startDate: statement.period.startDate, endDate: statement.period.endDate },
      statementType: statement.statementType,
      createdAt: statement.createdAt,
      isDelivered: statement.isDelivered || false,
      deliveredAt: statement.deliveredAt,
      summary: statement.summary
    }));
    
    res.status(200).json({
      status: 'success',
      data: { statements: formattedStatements, pagination: { currentPage: page, totalPages, totalItems: total, itemsPerPage: limit, hasNextPage: page < totalPages, hasPrevPage: page > 1 } }
    });
  } catch (err) {
    console.error('Error fetching statements:', err);
    res.status(200).json({ status: 'success', data: { statements: [], pagination: { currentPage: 1, totalPages: 1, totalItems: 0, itemsPerPage: 10, hasNextPage: false, hasPrevPage: false } } });
  }
});

// =============================================
// POST /api/admin/statements/generate - Generate and email financial statement
// =============================================
app.post('/api/admin/statements/generate', adminProtect, async (req, res) => {
  try {
    const { userId, period, batch } = req.body;
    const validPeriods = ['weekly', 'monthly'];
    
    if (!period || !validPeriods.includes(period)) {
      return res.status(400).json({ status: 'fail', message: 'Invalid period. Must be "weekly" or "monthly"' });
    }
    
    const endDate = new Date();
    const startDate = new Date();
    if (period === 'weekly') startDate.setDate(startDate.getDate() - 7);
    else startDate.setMonth(startDate.getMonth() - 1);
    startDate.setHours(0, 0, 0, 0);
    
    const formatUSD = (value) => {
      if (value === undefined || value === null) return '$0.00';
      return `$${value.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
    };
    
    const formatDate = (date) => new Date(date).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
    const formatShortDate = (date) => new Date(date).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
    
    const generateStatementForUser = async (user) => {
      try {
        // =============================================
        // FETCH ALL TRANSACTIONS
        // =============================================
        const transactions = await Transaction.find({
          user: user._id,
          createdAt: { $gte: startDate, $lte: endDate },
          status: 'completed'
        }).sort({ createdAt: -1 });
        
        // =============================================
        // FETCH BUY/SELL FOR P&L
        // =============================================
        const allBuyTransactions = await Transaction.find({
          user: user._id,
          type: 'buy',
          status: 'completed'
        }).sort({ createdAt: 1 });
        
        const allSellTransactions = await Transaction.find({
          user: user._id,
          type: 'sell',
          status: 'completed'
        }).sort({ createdAt: 1 });
        
        // =============================================
        // FIFO PROFIT/LOSS CALCULATION
        // =============================================
        const assetInventory = new Map();
        const realizedPnLByAsset = new Map();
        const unrealizedPnLByAsset = new Map();
        
        for (const buyTx of allBuyTransactions) {
          const asset = (buyTx.asset || buyTx.buyDetails?.asset || '').toLowerCase();
          const amount = buyTx.assetAmount || buyTx.buyDetails?.assetAmount || 0;
          const price = buyTx.buyDetails?.buyingPrice || buyTx.exchangeRateAtTime || 0;
          
          if (asset && amount > 0 && price > 0) {
            if (!assetInventory.has(asset)) assetInventory.set(asset, []);
            assetInventory.get(asset).push({ amount, price, remaining: amount });
          }
        }
        
        for (const sellTx of allSellTransactions) {
          const asset = (sellTx.asset || sellTx.sellDetails?.asset || '').toLowerCase();
          const sellAmount = sellTx.assetAmount || sellTx.sellDetails?.assetAmount || 0;
          const sellPrice = sellTx.sellDetails?.sellingPrice || sellTx.exchangeRateAtTime || 0;
          
          if (asset && sellAmount > 0 && sellPrice > 0) {
            let remainingToSell = sellAmount;
            let totalCostBasis = 0;
            const inventory = assetInventory.get(asset);
            
            if (inventory && inventory.length > 0) {
              for (let i = 0; i < inventory.length && remainingToSell > 0.00000001; i++) {
                const lot = inventory[i];
                if (lot.remaining > 0) {
                  const sellFromLot = Math.min(lot.remaining, remainingToSell);
                  totalCostBasis += sellFromLot * lot.price;
                  lot.remaining -= sellFromLot;
                  remainingToSell -= sellFromLot;
                }
              }
              
              const totalProceeds = sellAmount * sellPrice;
              const realizedPnL = totalProceeds - totalCostBasis;
              realizedPnLByAsset.set(asset, (realizedPnLByAsset.get(asset) || 0) + realizedPnL);
            }
          }
        }
        
        for (const [asset, inventory] of assetInventory.entries()) {
          let totalRemaining = 0, totalCostBasis = 0;
          for (const lot of inventory) {
            if (lot.remaining > 0) {
              totalRemaining += lot.remaining;
              totalCostBasis += lot.remaining * lot.price;
            }
          }
          if (totalRemaining > 0.00000001) {
            const currentPrice = await getCryptoPrice(asset.toUpperCase());
            if (currentPrice && currentPrice > 0) {
              const currentValue = totalRemaining * currentPrice;
              unrealizedPnLByAsset.set(asset, currentValue - totalCostBasis);
            }
          }
        }
        
        let totalRealizedPnL = 0, totalUnrealizedPnL = 0;
        const assetPnLDetails = [];
        const allAssetsSet = new Set([...realizedPnLByAsset.keys(), ...unrealizedPnLByAsset.keys()]);
        for (const asset of allAssetsSet) {
          const realized = realizedPnLByAsset.get(asset) || 0;
          const unrealized = unrealizedPnLByAsset.get(asset) || 0;
          totalRealizedPnL += realized;
          totalUnrealizedPnL += unrealized;
          assetPnLDetails.push({ asset: asset.toUpperCase(), realizedPnL: realized, unrealizedPnL: unrealized, totalPnL: realized + unrealized });
        }
        
        // =============================================
        // INVESTMENTS WITH EXACT SCHEMA FIELD NAMES
        // =============================================
        const investmentsInPeriod = await Investment.find({ 
          user: user._id, 
          createdAt: { $gte: startDate, $lte: endDate } 
        }).populate('plan');
        
        const maturedInvestments = await Investment.find({ 
          user: user._id, 
          completionDate: { $gte: startDate, $lte: endDate }, 
          status: 'completed' 
        }).populate('plan');
        
        const activeInvestments = await Investment.find({ 
          user: user._id, 
          status: 'active' 
        }).populate('plan');
        
        // STARTED investments - using EXACT field names from schema: amountUSD (NOT amountUSD)
        const formattedStartedInvestments = investmentsInPeriod.map(inv => ({
          investmentId: inv._id,
          planName: inv.plan?.name || 'Unknown Plan',
          amountUSD: inv.amount || 0,           // ← REQUIRED by schema
          amountBTC: inv.amountBTC || 0,
          startDate: inv.createdAt,
          expectedReturnUSD: inv.expectedReturn || 0
        }));
        
        // ACTIVE investments - using EXACT field names from schema: principalUSD (NOT principalUSD)
        const formattedActiveInvestments = activeInvestments.map(inv => ({
          investmentId: inv._id,
          planName: inv.plan?.name || 'Unknown Plan',
          principalUSD: inv.amount || 0,        // ← REQUIRED by schema
          principalBTC: inv.amountBTC || 0,
          startDate: inv.createdAt,
          endDate: inv.endDate,
          status: inv.status
        }));
        
        // MATURED investments - using EXACT field names from schema
        const formattedMaturedInvestments = maturedInvestments.map(inv => ({
          investmentId: inv._id,
          planName: inv.plan?.name || 'Unknown Plan',
          initialAmountUSD: inv.originalAmount || inv.amount || 0,
          returnAmountUSD: inv.expectedReturn || inv.amount || 0,
          profitUSD: (inv.expectedReturn || inv.amount || 0) - (inv.originalAmount || inv.amount || 0),
          profitPercentage: inv.returnPercentage || 0,
          completionDate: inv.completionDate || inv.endDate || new Date(),
          btcPriceAtCompletion: inv.btcPriceAtCompletion || 0
        }));
        
        // =============================================
        // BALANCES
        // =============================================
        const openingBalances = await calculateAccurateOpeningBalances(user._id, startDate);
        const closingBalances = await calculateAccurateClosingBalances(user._id, endDate);
        
        // =============================================
        // CORRECT METRICS CALCULATION
        // =============================================
        let totalDeposits = 0;
        let totalWithdrawals = 0;
        let totalInvestmentFees = 0;
        let totalWithdrawalFees = 0;
        let totalTradingFees = 0;
        let totalBuyVolume = 0;
        let totalSellVolume = 0;
        
        for (const tx of transactions) {
          if (tx.type === 'deposit') {
            totalDeposits += tx.amount || 0;
          }
          else if (tx.type === 'withdrawal') {
            totalWithdrawals += tx.amount || 0;
            if (tx.fee) totalWithdrawalFees += tx.fee;
          }
          else if (tx.type === 'investment') {
            if (tx.fee) totalInvestmentFees += tx.fee;
          }
          else if (tx.type === 'buy') {
            totalBuyVolume += tx.amount || 0;
            if (tx.fee) totalTradingFees += tx.fee;
          }
          else if (tx.type === 'sell') {
            totalSellVolume += tx.amount || 0;
            if (tx.fee) totalTradingFees += tx.fee;
          }
        }
        
        const totalFees = totalInvestmentFees + totalTradingFees;
        const netChange = closingBalances.totalUSD - openingBalances.totalUSD;
        const roi = openingBalances.totalUSD > 0 ? (netChange / openingBalances.totalUSD) * 100 : 0;
        const netCashFlow = totalDeposits - totalWithdrawals;
        
        // =============================================
        // CREATE FINANCIAL STATEMENT WITH EXACT SCHEMA FIELDS
        // =============================================
        const statement = new FinancialStatement({
          user: user._id,
          statementType: period,
          period: { startDate, endDate, generationDate: new Date() },
          reference: `FS-${period.toUpperCase()}-${user._id.toString().slice(-6)}-${Date.now()}`,
          openingBalances,
          closingBalances,
          netChangeUSD: netChange,
          transactions: {
            list: transactions.map(tx => ({
              transactionId: tx._id,
              type: tx.type,
              amountUSD: tx.amount,
              asset: tx.asset,
              assetAmount: tx.assetAmount,
              status: tx.status,
              method: tx.method,
              description: tx.details?.description || `${tx.type} transaction`,
              reference: tx.reference,
              feeUSD: tx.fee || 0,
              netAmountUSD: tx.netAmount || tx.amount,
              createdAt: tx.createdAt
            })),
            summary: {
              totalDepositsUSD: totalDeposits,
              totalWithdrawalsUSD: totalWithdrawals,
              totalFeesPaidUSD: totalFees,
              totalTransfersUSD: 0,
              count: {
                deposits: transactions.filter(t => t.type === 'deposit').length,
                withdrawals: transactions.filter(t => t.type === 'withdrawal').length,
                transfers: 0
              }
            }
          },
          investments: {
            active: formattedActiveInvestments,
            started: formattedStartedInvestments,
            matured: formattedMaturedInvestments,
            summary: {
              totalPrincipalInvestedUSD: investmentsInPeriod.reduce((sum, i) => sum + (i.amount || 0), 0),
              totalReturnsEarnedUSD: maturedInvestments.reduce((sum, i) => sum + ((i.expectedReturn || 0) - (i.originalAmount || 0)), 0),
              totalProfitUSD: maturedInvestments.reduce((sum, i) => sum + ((i.expectedReturn || 0) - (i.originalAmount || 0)), 0),
              totalActiveInvestmentsCount: activeInvestments.length,
              totalActivePrincipalUSD: activeInvestments.reduce((sum, i) => sum + (i.amount || 0), 0)
            }
          },
          fees: {
            items: transactions.filter(t => t.fee > 0 && t.type !== 'withdrawal').map(tx => ({
              source: `${tx.type}_fee`,
              amountUSD: tx.fee,
              transactionId: tx._id,
              description: `${tx.type} fee`,
              date: tx.createdAt
            })),
            summary: {
              totalFeesUSD: totalFees,
              investmentFeesUSD: totalInvestmentFees,
              withdrawalFeesUSD: totalWithdrawalFees,
              tradingFeesUSD: totalTradingFees,
              conversionFeesUSD: 0,
              loanFeesUSD: 0
            }
          },
          summary: {
            totalInflowUSD: totalDeposits,
            totalOutflowUSD: totalWithdrawals,
            netCashFlowUSD: netCashFlow,
            totalProfitUSD: netChange > 0 ? netChange : 0,
            totalLossUSD: netChange < 0 ? Math.abs(netChange) : 0,
            netProfitUSD: netChange,
            roiPercentage: roi,
            realizedPnL: totalRealizedPnL,
            unrealizedPnL: totalUnrealizedPnL,
            assetPnLDetails: assetPnLDetails
          },
          ipAddress: req.ip,
          userAgent: req.headers['user-agent'] || 'Unknown',
          location: 'Unknown',
          isDelivered: false
        });
        
        await statement.save();
        
        // =============================================
        // PDF GENERATION - LANDSCAPE WITH PROFESSIONAL FONT SIZES
        // =============================================
        const PDFDocument = require('pdfkit');
        const doc = new PDFDocument({ margin: 40, size: 'A4', layout: 'landscape' });
        
        const chunks = [];
        doc.on('data', chunk => chunks.push(chunk));
        
        let y = 40;
        const pageWidth = doc.page.width;
        const leftMargin = 40;
        const contentWidth = pageWidth - 80;
        
        const needNewPage = (spaceNeeded) => {
          if (y + spaceNeeded > doc.page.height - 60) {
            doc.addPage();
            y = 40;
            return true;
          }
          return false;
        };
        
        // ========== HEADER WITH LOGO ==========
        const logoUrl = 'https://media.bithashcapital.live/ChatGPT%20Image%20Mar%2029%2C%202026%2C%2004_52_02%20PM.png';
        try {
          const response = await axios.get(logoUrl, { responseType: 'arraybuffer', timeout: 5000 });
          const logoBuffer = Buffer.from(response.data, 'binary');
          doc.image(logoBuffer, (pageWidth - 60) / 2, y, { width: 60, height: 60 });
          y += 68;
        } catch (err) {
          y += 20;
        }
        
        doc.fontSize(24).font('Helvetica-Bold').fillColor('#0B0E11').text('BIT HASH CAPITAL', leftMargin, y, { align: 'center', width: contentWidth });
        y = doc.y + 12;
        doc.fontSize(11).font('Helvetica').fillColor('#6C7480').text('Financial Statement', leftMargin, y, { align: 'center', width: contentWidth });
        y = doc.y + 25;
        
        doc.strokeColor('#F7A600').lineWidth(2).moveTo(leftMargin + 120, y).lineTo(pageWidth - leftMargin - 120, y).stroke();
        y += 20;
        
        doc.fontSize(16).font('Helvetica-Bold').fillColor('#1E3A8A').text(`${period.toUpperCase()} FINANCIAL STATEMENT`, leftMargin, y, { align: 'center', width: contentWidth });
        y = doc.y + 12;
        doc.fontSize(10).font('Helvetica').fillColor('#64748B').text(`For the period ${formatDate(startDate)} - ${formatDate(endDate)}`, leftMargin, y, { align: 'center', width: contentWidth });
        y = doc.y + 25;
        
        // ========== ACCOUNT INFORMATION ==========
        needNewPage(80);
        doc.fillColor('#F8FAFC').rect(leftMargin, y, contentWidth, 70).fill();
        doc.fillColor('#0B0E11').fontSize(12).font('Helvetica-Bold').text('ACCOUNT INFORMATION', leftMargin + 12, y + 10);
        doc.fontSize(10).font('Helvetica').fillColor('#374151');
        doc.text(`Account Holder: ${user.firstName} ${user.lastName}`, leftMargin + 12, y + 32);
        doc.text(`Email Address: ${user.email}`, leftMargin + 12, y + 50);
        doc.text(`Statement Generated: ${new Date().toLocaleString()}`, leftMargin + 400, y + 32);
        y += 82;
        
        // ========== BALANCE SUMMARY ==========
        needNewPage(160);
        doc.fillColor('#0B0E11').fontSize(14).font('Helvetica-Bold').text('1. BALANCE SUMMARY', leftMargin, y);
        y += 22;
        
        doc.fillColor('#1E3A8A').rect(leftMargin, y, contentWidth, 26).fill();
        doc.fillColor('#FFFFFF').fontSize(10).font('Helvetica-Bold');
        doc.text('Wallet Type', leftMargin + 12, y + 8);
        doc.text('Opening Balance (USD)', leftMargin + 280, y + 8);
        doc.text('Closing Balance (USD)', leftMargin + 480, y + 8);
        doc.text('Net Change (USD)', leftMargin + 660, y + 8);
        y += 26;
        
        const balanceRows = [
          { label: 'Main Wallet (Digital Assets)', open: openingBalances.mainWalletUSD, close: closingBalances.mainWalletUSD },
          { label: 'Active Mining Contracts', open: openingBalances.activeWalletUSD, close: closingBalances.activeWalletUSD },
          { label: 'Matured Wallet', open: openingBalances.maturedWalletUSD, close: closingBalances.maturedWalletUSD }
        ];
        
        for (let i = 0; i < balanceRows.length; i++) {
          const row = balanceRows[i];
          const change = row.close - row.open;
          const bgColor = i % 2 === 0 ? '#FFFFFF' : '#F8FAFC';
          needNewPage(24);
          doc.fillColor(bgColor).rect(leftMargin, y, contentWidth, 24).fill();
          doc.fillColor('#374151').fontSize(10).font('Helvetica');
          doc.text(row.label, leftMargin + 12, y + 7);
          doc.text(formatUSD(row.open), leftMargin + 280, y + 7);
          doc.text(formatUSD(row.close), leftMargin + 480, y + 7);
          doc.fillColor(change >= 0 ? '#10B981' : '#EF4444').text(formatUSD(change), leftMargin + 660, y + 7);
          y += 24;
        }
        
        const totalChangeValue = closingBalances.totalUSD - openingBalances.totalUSD;
        needNewPage(32);
        doc.fillColor('#E0E7FF').rect(leftMargin, y, contentWidth, 32).fill();
        doc.fillColor('#1E3A8A').fontSize(11).font('Helvetica-Bold');
        doc.text('TOTAL PORTFOLIO VALUE', leftMargin + 12, y + 10);
        doc.text(formatUSD(openingBalances.totalUSD), leftMargin + 280, y + 10);
        doc.text(formatUSD(closingBalances.totalUSD), leftMargin + 480, y + 10);
        doc.fillColor(totalChangeValue >= 0 ? '#10B981' : '#EF4444').text(formatUSD(totalChangeValue), leftMargin + 660, y + 10);
        y += 42;
        
        // ========== PROFIT & LOSS ANALYSIS ==========
        needNewPage(140);
        doc.fillColor('#0B0E11').fontSize(14).font('Helvetica-Bold').text('2. PROFIT & LOSS ANALYSIS', leftMargin, y);
        y += 22;
        
        const cardWidth = (contentWidth - 40) / 2;
        const cardHeight = 80;
        
        doc.fillColor('#F0FDF4').rect(leftMargin, y, cardWidth, cardHeight).fill();
        doc.fillColor('#0B0E11').fontSize(11).font('Helvetica-Bold').text('REALIZED PROFIT / LOSS', leftMargin + 15, y + 15);
        doc.fontSize(18).font('Helvetica-Bold').fillColor(totalRealizedPnL >= 0 ? '#10B981' : '#EF4444').text(formatUSD(totalRealizedPnL), leftMargin + 15, y + 45);
        
        doc.fillColor('#EFF6FF').rect(leftMargin + cardWidth + 40, y, cardWidth, cardHeight).fill();
        doc.fillColor('#0B0E11').fontSize(11).font('Helvetica-Bold').text('UNREALIZED PROFIT / LOSS', leftMargin + cardWidth + 55, y + 15);
        doc.fontSize(18).font('Helvetica-Bold').fillColor(totalUnrealizedPnL >= 0 ? '#10B981' : '#EF4444').text(formatUSD(totalUnrealizedPnL), leftMargin + cardWidth + 55, y + 45);
        y += cardHeight + 25;
        
        // ========== ASSET-WISE P&L TABLE ==========
        if (assetPnLDetails.length > 0) {
          needNewPage(140);
          doc.fillColor('#0B0E11').fontSize(13).font('Helvetica-Bold').text('Asset-wise Profit & Loss Breakdown', leftMargin, y);
          y += 20;
          
          doc.fillColor('#1E3A8A').rect(leftMargin, y, contentWidth, 24).fill();
          doc.fillColor('#FFFFFF').fontSize(9).font('Helvetica-Bold');
          doc.text('Cryptocurrency', leftMargin + 12, y + 7);
          doc.text('Realized P&L (USD)', leftMargin + 220, y + 7);
          doc.text('Unrealized P&L (USD)', leftMargin + 420, y + 7);
          doc.text('Total P&L (USD)', leftMargin + 620, y + 7);
          y += 24;
          
          for (let i = 0; i < assetPnLDetails.length; i++) {
            const detail = assetPnLDetails[i];
            needNewPage(22);
            const bgColor = i % 2 === 0 ? '#FFFFFF' : '#F8FAFC';
            doc.fillColor(bgColor).rect(leftMargin, y, contentWidth, 22).fill();
            doc.fillColor('#374151').fontSize(9).font('Helvetica');
            doc.text(detail.asset, leftMargin + 12, y + 6);
            doc.fillColor(detail.realizedPnL >= 0 ? '#10B981' : '#EF4444').text(formatUSD(detail.realizedPnL), leftMargin + 220, y + 6);
            doc.fillColor(detail.unrealizedPnL >= 0 ? '#10B981' : '#EF4444').text(formatUSD(detail.unrealizedPnL), leftMargin + 420, y + 6);
            doc.fillColor(detail.totalPnL >= 0 ? '#10B981' : '#EF4444').text(formatUSD(detail.totalPnL), leftMargin + 620, y + 6);
            y += 22;
          }
          y += 15;
        }
        
        // ========== FINANCIAL METRICS ==========
        needNewPage(150);
        doc.fillColor('#0B0E11').fontSize(14).font('Helvetica-Bold').text('3. FINANCIAL METRICS', leftMargin, y);
        y += 22;
        
        const metricsData = [
          { label: 'Total Deposits', value: formatUSD(totalDeposits), color: '#10B981' },
          { label: 'Total Withdrawals', value: formatUSD(totalWithdrawals), color: '#F59E0B' },
          { label: 'Investment & Trading Fees', value: formatUSD(totalFees), color: '#EF4444' },
          { label: 'Net Cash Flow', value: formatUSD(netCashFlow), color: '#3B82F6' },
          { label: 'Realized Trading P&L', value: formatUSD(totalRealizedPnL), color: totalRealizedPnL >= 0 ? '#10B981' : '#EF4444' },
          { label: 'Return on Investment', value: `${roi.toFixed(2)}%`, color: '#8B5CF6' }
        ];
        
        const metricCardWidth = (contentWidth - 50) / 3;
        const metricCardHeight = 70;
        
        for (let i = 0; i < metricsData.length; i++) {
          const metric = metricsData[i];
          const col = i % 3;
          const row = Math.floor(i / 3);
          const cardX = leftMargin + (col * (metricCardWidth + 25));
          const cardY = y + (row * (metricCardHeight + 15));
          
          if (cardY + metricCardHeight > doc.page.height - 100) { doc.addPage(); y = 40; break; }
          
          doc.fillColor('#FFFFFF').rect(cardX, cardY, metricCardWidth, metricCardHeight).fill();
          doc.fillColor('#6B7280').fontSize(9).font('Helvetica').text(metric.label, cardX + 12, cardY + 14);
          doc.fillColor(metric.color).fontSize(13).font('Helvetica-Bold').text(metric.value, cardX + 12, cardY + 44);
        }
        
        y += Math.ceil(metricsData.length / 3) * (metricCardHeight + 15) + 25;
        
        // ========== TRANSACTION HISTORY ==========
        if (statement.transactions.list.length > 0) {
          needNewPage(200);
          doc.fillColor('#0B0E11').fontSize(14).font('Helvetica-Bold').text('4. TRANSACTION HISTORY', leftMargin, y);
          y += 22;
          
          doc.fillColor('#F0FDF4').rect(leftMargin, y, contentWidth, 48).fill();
          doc.fillColor('#374151').fontSize(10).font('Helvetica');
          doc.text(`Total Transactions: ${statement.transactions.list.length}`, leftMargin + 15, y + 12);
          doc.text(`Deposits: ${statement.transactions.summary.count.deposits} | Withdrawals: ${statement.transactions.summary.count.withdrawals}`, leftMargin + 15, y + 30);
          doc.text(`Total Volume: ${formatUSD(statement.transactions.summary.totalDepositsUSD + statement.transactions.summary.totalWithdrawalsUSD)}`, leftMargin + 450, y + 12);
          y += 60;
          
          doc.fillColor('#1E3A8A').rect(leftMargin, y, contentWidth, 24).fill();
          doc.fillColor('#FFFFFF').fontSize(9).font('Helvetica-Bold');
          doc.text('Date', leftMargin + 8, y + 7);
          doc.text('Type', leftMargin + 110, y + 7);
          doc.text('Asset', leftMargin + 195, y + 7);
          doc.text('Amount', leftMargin + 275, y + 7);
          doc.text('Fee', leftMargin + 370, y + 7);
          doc.text('Net', leftMargin + 450, y + 7);
          doc.text('Status', leftMargin + 540, y + 7);
          y += 24;
          
          const recentTxs = statement.transactions.list.slice(0, 12);
          for (let i = 0; i < recentTxs.length; i++) {
            const tx = recentTxs[i];
            needNewPage(22);
            const rowBg = i % 2 === 0 ? '#FFFFFF' : '#F8FAFC';
            doc.fillColor(rowBg).rect(leftMargin, y, contentWidth, 22).fill();
            doc.fillColor('#374151').fontSize(9).font('Helvetica');
            doc.text(formatShortDate(tx.createdAt), leftMargin + 8, y + 6);
            const displayType = tx.type === 'investment' ? 'Investment' : tx.type.substring(0, 10);
            doc.text(displayType, leftMargin + 110, y + 6);
            doc.text((tx.asset || 'USD').substring(0, 6), leftMargin + 195, y + 6);
            doc.text(formatUSD(tx.amountUSD), leftMargin + 275, y + 6);
            doc.text(formatUSD(tx.feeUSD), leftMargin + 370, y + 6);
            doc.text(formatUSD(tx.netAmountUSD), leftMargin + 450, y + 6);
            if (tx.status === 'completed') doc.fillColor('#10B981').text('Complete', leftMargin + 540, y + 6);
            else if (tx.status === 'pending') doc.fillColor('#F59E0B').text('Pending', leftMargin + 540, y + 6);
            else doc.fillColor('#EF4444').text('Failed', leftMargin + 540, y + 6);
            y += 22;
          }
          y += 15;
        }
        
        // ========== INVESTMENT ACTIVITY ==========
        if (formattedActiveInvestments.length > 0 || formattedStartedInvestments.length > 0 || formattedMaturedInvestments.length > 0) {
          needNewPage(200);
          doc.fillColor('#0B0E11').fontSize(14).font('Helvetica-Bold').text('5. INVESTMENT ACTIVITY', leftMargin, y);
          y += 22;
          
          doc.fillColor('#EFF6FF').rect(leftMargin, y, contentWidth, 55).fill();
          doc.fillColor('#374151').fontSize(10).font('Helvetica');
          doc.text(`Total Principal Invested: ${formatUSD(statement.investments.summary.totalPrincipalInvestedUSD)}`, leftMargin + 15, y + 12);
          doc.text(`Total Returns Earned: ${formatUSD(statement.investments.summary.totalReturnsEarnedUSD)}`, leftMargin + 15, y + 32);
          doc.text(`Active Investments: ${statement.investments.summary.totalActiveInvestmentsCount}`, leftMargin + 450, y + 12);
          y += 68;
          
          // Active Investments
          if (formattedActiveInvestments.length > 0) {
            doc.fillColor('#1E3A8A').fontSize(11).font('Helvetica-Bold').text('Active Investments:', leftMargin, y);
            y += 18;
            
            doc.fillColor('#1E3A8A').rect(leftMargin, y, contentWidth, 22).fill();
            doc.fillColor('#FFFFFF').fontSize(8).font('Helvetica-Bold');
            doc.text('Plan Name', leftMargin + 10, y + 7);
            doc.text('Principal', leftMargin + 200, y + 7);
            doc.text('Start Date', leftMargin + 310, y + 7);
            doc.text('End Date', leftMargin + 420, y + 7);
            y += 22;
            
            for (const inv of formattedActiveInvestments.slice(0, 8)) {
              needNewPage(20);
              const bgColor = formattedActiveInvestments.indexOf(inv) % 2 === 0 ? '#FFFFFF' : '#F8FAFC';
              doc.fillColor(bgColor).rect(leftMargin, y, contentWidth, 20).fill();
              doc.fillColor('#374151').fontSize(9).font('Helvetica');
              doc.text(inv.planName.substring(0, 20), leftMargin + 10, y + 6);
              doc.text(formatUSD(inv.principalUSD), leftMargin + 200, y + 6);
              doc.text(formatShortDate(inv.startDate), leftMargin + 310, y + 6);
              doc.text(formatShortDate(inv.endDate), leftMargin + 420, y + 6);
              y += 20;
            }
            y += 10;
          }
          
          // New Investments
          if (formattedStartedInvestments.length > 0) {
            doc.fillColor('#1E3A8A').fontSize(11).font('Helvetica-Bold').text('New Investments Initiated:', leftMargin, y);
            y += 18;
            for (const inv of formattedStartedInvestments.slice(0, 5)) {
              needNewPage(18);
              doc.fillColor('#374151').fontSize(9).font('Helvetica');
              doc.text(`• ${inv.planName}`, leftMargin + 15, y);
              doc.text(formatUSD(inv.amountUSD), leftMargin + 280, y);
              doc.fillColor('#6B7280').text(`Started: ${formatShortDate(inv.startDate)}`, leftMargin + 400, y);
              y += 16;
            }
            y += 10;
          }
          
          // Matured Investments
          if (formattedMaturedInvestments.length > 0) {
            doc.fillColor('#1E3A8A').fontSize(11).font('Helvetica-Bold').text('Matured / Completed Investments:', leftMargin, y);
            y += 18;
            for (const inv of formattedMaturedInvestments.slice(0, 5)) {
              needNewPage(18);
              doc.fillColor('#374151').fontSize(9).font('Helvetica');
              doc.text(`• ${inv.planName}`, leftMargin + 15, y);
              doc.text(`${formatUSD(inv.initialAmountUSD)} → ${formatUSD(inv.returnAmountUSD)}`, leftMargin + 250, y);
              const profitColor = inv.profitUSD >= 0 ? '#10B981' : '#EF4444';
              doc.fillColor(profitColor).text(`(${inv.profitUSD >= 0 ? 'Profit' : 'Loss'}: ${formatUSD(Math.abs(inv.profitUSD))})`, leftMargin + 520, y);
              y += 16;
            }
            y += 12;
          }
        }
        
        // ========== FOOTER ==========
        if (y > doc.page.height - 100) { doc.addPage(); y = 40; }
        
        doc.strokeColor('#E5E7EB').lineWidth(1).moveTo(leftMargin, y).lineTo(pageWidth - leftMargin, y).stroke();
        y += 20;
        
        doc.fontSize(10).font('Helvetica-Bold').fillColor('#0B0E11').text('BIT HASH CAPITAL', leftMargin, y, { align: 'center', width: contentWidth });
        y += 16;
        doc.fontSize(8).font('Helvetica').fillColor('#6B7280');
        doc.text('This is an official financial statement generated by Bit Hash Capital. All figures are in US Dollars (USD).', leftMargin, y, { align: 'center', width: contentWidth });
        y += 12;
        doc.text(`© ${new Date().getFullYear()} Bit Hash Capital. All rights reserved.`, leftMargin, y, { align: 'center', width: contentWidth });
        
        doc.end();
        await new Promise((resolve) => { doc.on('end', resolve); });
        
        const pdfBuffer = Buffer.concat(chunks);
        
        // ========== SEND EMAIL ==========
        const mailOptions = {
          from: `Bit Hash Capital <${process.env.EMAIL_INFO_USER}>`,
          to: user.email,
          subject: `Your ${period.toUpperCase()} Financial Statement - Bit Hash Capital`,
          html: `
            <div style="font-family: 'Inter', sans-serif; max-width: 600px; margin: 0 auto; background: #FFFFFF;">
              <div style="text-align: center; padding: 30px 20px; background: linear-gradient(135deg, #0B0E11 0%, #11151C 100%);">
                <img src="https://media.bithashcapital.live/ChatGPT%20Image%20Mar%2029%2C%202026%2C%2004_52_02%20PM.png" alt="Bit Hash Capital" style="width: 60px; height: 60px; margin-bottom: 12px;">
                <h1 style="color: #F7A600; font-size: 24px; margin: 0; letter-spacing: 1px;">BIT HASH CAPITAL</h1>
                <p style="color: #B7BDC6; font-size: 12px; margin: 12px 0 0;">Financial Statement</p>
              </div>
              <div style="padding: 30px;">
                <p style="color: #374151; margin-bottom: 15px; font-size: 15px;">Dear <strong>${user.firstName} ${user.lastName}</strong>,</p>
                <p style="color: #4B5563; margin-bottom: 25px; font-size: 14px; line-height: 1.5;">Please find attached your ${period} financial statement for the period <strong>${formatDate(startDate)} - ${formatDate(endDate)}</strong>.</p>
                
                <div style="background: #F8FAFC; border-radius: 12px; padding: 20px; margin: 25px 0; border: 1px solid #E5E7EB;">
                  <div style="display: flex; justify-content: space-between; margin-bottom: 12px;">
                    <span style="color: #6B7280; font-size: 14px;">Opening Balance:</span>
                    <strong style="color: #0B0E11; font-size: 14px;">${formatUSD(openingBalances.totalUSD)}</strong>
                  </div>
                  <div style="display: flex; justify-content: space-between; margin-bottom: 12px;">
                    <span style="color: #6B7280; font-size: 14px;">Closing Balance:</span>
                    <strong style="color: #0B0E11; font-size: 14px;">${formatUSD(closingBalances.totalUSD)}</strong>
                  </div>
                  <div style="display: flex; justify-content: space-between; padding-top: 12px; border-top: 1px solid #E5E7EB;">
                    <span style="color: #6B7280; font-size: 14px;">Net Change:</span>
                    <strong style="color: ${totalChangeValue >= 0 ? '#10B981' : '#EF4444'}; font-size: 14px;">${formatUSD(totalChangeValue)}</strong>
                  </div>
                  <div style="display: flex; justify-content: space-between; margin-top: 12px;">
                    <span style="color: #6B7280; font-size: 14px;">Realized Trading P&L:</span>
                    <strong style="color: ${totalRealizedPnL >= 0 ? '#10B981' : '#EF4444'}; font-size: 14px;">${formatUSD(totalRealizedPnL)}</strong>
                  </div>
                  <div style="display: flex; justify-content: space-between; margin-top: 12px;">
                    <span style="color: #6B7280; font-size: 14px;">Return on Investment (ROI):</span>
                    <strong style="color: #8B5CF6; font-size: 14px;">${roi.toFixed(2)}%</strong>
                  </div>
                </div>
                
                <div style="text-align: center; margin-top: 30px;">
                  <a href="https://www.bithashcapital.live/dashboard" style="background-color: #F7A600; color: #0B0E11; padding: 12px 32px; text-decoration: none; border-radius: 40px; font-weight: 600; font-size: 14px; display: inline-block;">Access Your Dashboard</a>
                </div>
              </div>
              <div style="text-align: center; padding: 20px; background: #0B0E11;">
                <p style="color: #6C7480; font-size: 10px;">&copy; ${new Date().getFullYear()} Bit Hash Capital. All rights reserved.</p>
                <p style="color: #6C7480; font-size: 10px; margin-top: 6px;">800 Plant Street, Wilmington, DE 19801, United States</p>
              </div>
            </div>
          `,
          attachments: [{ filename: `Financial_Statement_${period.toUpperCase()}_${formatShortDate(endDate)}.pdf`, content: pdfBuffer, contentType: 'application/pdf' }]
        };
        
        await infoTransporter.sendMail(mailOptions);
        
        statement.isDelivered = true;
        statement.deliveredAt = new Date();
        await statement.save();
        
        return { success: true, userId: user._id, statementId: statement._id };
      } catch (err) {
        console.error(`Error generating statement:`, err);
        return { success: false, userId: user._id, error: err.message };
      }
    };
    
    if (batch === true) {
      const users = await User.find({ status: 'active' }).select('_id firstName lastName email');
      const results = [];
      for (const user of users) {
        const result = await generateStatementForUser(user);
        results.push(result);
        await new Promise(resolve => setTimeout(resolve, 500));
      }
      const successCount = results.filter(r => r.success).length;
      return res.status(200).json({ status: 'success', message: `Generated statements for ${successCount} users`, data: { results } });
    } else if (userId) {
      const user = await User.findById(userId).select('_id firstName lastName email');
      if (!user) return res.status(404).json({ status: 'fail', message: 'User not found' });
      const result = await generateStatementForUser(user);
      if (result.success) return res.status(200).json({ status: 'success', message: `Statement sent to ${user.email}`, data: { statementId: result.statementId } });
      else return res.status(500).json({ status: 'error', message: `Failed: ${result.error}` });
    } else {
      return res.status(400).json({ status: 'fail', message: 'Either userId or batch=true is required' });
    }
  } catch (err) {
    console.error('Error generating financial statement:', err);
    res.status(500).json({ status: 'error', message: err.message || 'Failed to generate financial statement' });
  }
});

// =============================================
// BALANCE CALCULATION FUNCTIONS
// =============================================
async function calculateAccurateOpeningBalances(userId, startDate) {
  const user = await User.findById(userId);
  if (!user) return { totalUSD: 0, mainWalletUSD: 0, activeWalletUSD: 0, maturedWalletUSD: 0, cryptoDetails: [], timestamp: startDate };
  
  let mainUSD = 0, activeUSD = 0, maturedUSD = 0;
  const cryptoDetails = [];
  
  if (user.balances && user.balances.main) {
    const entries = user.balances.main instanceof Map ? user.balances.main.entries() : Object.entries(user.balances.main);
    for (const [asset, balance] of entries) {
      if (balance > 0 && asset !== 'usd') {
        const price = await getCryptoPrice(asset.toUpperCase());
        const usdValue = balance * (price || 0);
        mainUSD += usdValue;
        cryptoDetails.push({ asset, amount: balance, usdValue, walletType: 'main' });
      }
    }
  }
  
  if (user.balances && user.balances.active) {
    const entries = user.balances.active instanceof Map ? user.balances.active.entries() : Object.entries(user.balances.active);
    for (const [asset, balance] of entries) if (balance > 0) activeUSD += balance;
  }
  
  if (user.balances && user.balances.matured) {
    const entries = user.balances.matured instanceof Map ? user.balances.matured.entries() : Object.entries(user.balances.matured);
    for (const [asset, balance] of entries) {
      if (balance > 0 && asset !== 'usd') {
        const price = await getCryptoPrice(asset.toUpperCase());
        const usdValue = balance * (price || 0);
        maturedUSD += usdValue;
        cryptoDetails.push({ asset, amount: balance, usdValue, walletType: 'matured' });
      }
    }
  }
  
  return { totalUSD: mainUSD + activeUSD + maturedUSD, mainWalletUSD: mainUSD, activeWalletUSD: activeUSD, maturedWalletUSD: maturedUSD, cryptoDetails, timestamp: startDate };
}

async function calculateAccurateClosingBalances(userId, endDate) {
  const user = await User.findById(userId);
  if (!user) return { totalUSD: 0, mainWalletUSD: 0, activeWalletUSD: 0, maturedWalletUSD: 0, cryptoDetails: [], timestamp: endDate };
  
  let mainUSD = 0, activeUSD = 0, maturedUSD = 0;
  const cryptoDetails = [];
  
  if (user.balances && user.balances.main) {
    const entries = user.balances.main instanceof Map ? user.balances.main.entries() : Object.entries(user.balances.main);
    for (const [asset, balance] of entries) {
      if (balance > 0 && asset !== 'usd') {
        const price = await getCryptoPrice(asset.toUpperCase());
        const usdValue = balance * (price || 0);
        mainUSD += usdValue;
        cryptoDetails.push({ asset, amount: balance, usdValue, walletType: 'main' });
      }
    }
  }
  
  if (user.balances && user.balances.active) {
    const entries = user.balances.active instanceof Map ? user.balances.active.entries() : Object.entries(user.balances.active);
    for (const [asset, balance] of entries) if (balance > 0) activeUSD += balance;
  }
  
  if (user.balances && user.balances.matured) {
    const entries = user.balances.matured instanceof Map ? user.balances.matured.entries() : Object.entries(user.balances.matured);
    for (const [asset, balance] of entries) {
      if (balance > 0 && asset !== 'usd') {
        const price = await getCryptoPrice(asset.toUpperCase());
        const usdValue = balance * (price || 0);
        maturedUSD += usdValue;
        cryptoDetails.push({ asset, amount: balance, usdValue, walletType: 'matured' });
      }
    }
  }
  
  return { totalUSD: mainUSD + activeUSD + maturedUSD, mainWalletUSD: mainUSD, activeWalletUSD: activeUSD, maturedWalletUSD: maturedUSD, cryptoDetails, timestamp: endDate };
}









































































// =============================================
// GET /api/referrals - Get user's referral statistics
// This endpoint matches the frontend's expected structure from dashboard.html
// =============================================
app.get('/api/referrals', protect, async (req, res) => {
  try {
    const userId = req.user._id;
    
    // Get user with referral code and stats
    const user = await User.findById(userId).select('referralCode referralStats balances');
    
    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'User not found'
      });
    }
    
    // Generate referral link if not exists in user document
    let referralLink = user.referralCode;
    if (!referralLink) {
      // Generate fallback using user ID
      referralLink = user._id.toString().slice(-8);
    }
    
    // Build the full referral URL
    const baseUrl = process.env.FRONTEND_URL || 'https://www.bithashcapital.live';
    const fullReferralLink = `${baseUrl}/signup?ref=${referralLink}`;
    
    // Calculate total earnings from CommissionHistory (more accurate than User.referralStats)
    const totalEarningsAgg = await CommissionHistory.aggregate([
      { $match: { upline: userId, status: 'paid' } },
      { $group: { _id: null, total: { $sum: '$commissionAmount' } } }
    ]);
    
    const totalEarnings = totalEarningsAgg[0]?.total || user.referralStats?.totalEarnings || 0;
    
    // Calculate pending earnings from CommissionHistory that are not yet paid
    const pendingEarningsAgg = await CommissionHistory.aggregate([
      { $match: { upline: userId, status: 'pending' } },
      { $group: { _id: null, total: { $sum: '$commissionAmount' } } }
    ]);
    
    const pendingEarnings = pendingEarningsAgg[0]?.total || 0;
    
    // Get total referrals count from DownlineRelationship
    const totalReferrals = await DownlineRelationship.countDocuments({ upline: userId });
    
    // Also get active referrals count (those with remaining rounds > 0)
    const activeReferrals = await DownlineRelationship.countDocuments({ 
      upline: userId, 
      status: 'active',
      remainingRounds: { $gt: 0 }
    });
    
    // Get total commission earned from downline (both paid and pending)
    const totalCommissionAgg = await CommissionHistory.aggregate([
      { $match: { upline: userId } },
      { $group: { _id: null, total: { $sum: '$commissionAmount' } } }
    ]);
    
    const totalCommission = totalCommissionAgg[0]?.total || 0;
    
    // Get available balance from user's main wallet
    const availableBalance = user.balances?.main?.get('usd') || user.balances?.main?.usd || 0;
    
    // Return data in the EXACT format expected by frontend
    res.status(200).json({
      status: 'success',
      data: {
        referralCode: referralLink,
        referralLink: fullReferralLink,
        totalReferrals: totalReferrals,
        activeReferrals: activeReferrals,
        totalEarnings: totalEarnings,
        pendingEarnings: pendingEarnings,
        totalCommission: totalCommission,
        availableBalance: availableBalance,
        referralStats: {
          totalReferrals: totalReferrals,
          activeReferrals: activeReferrals,
          totalEarnings: totalEarnings,
          pendingEarnings: pendingEarnings,
          totalCommission: totalCommission
        }
      }
    });
    
  } catch (err) {
    console.error('Error fetching referral data:', err);
    res.status(500).json({
      status: 'error',
      message: err.message || 'Failed to fetch referral data'
    });
  }
});

























// SNIPPET C - COMPLETE REWRITE
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
    origin: ['https://bithhash.vercel.app', 'https://website-backendd-1.onrender.com', 'https://www.bithashcapital.live'],
    methods: ['GET', 'POST']
  },
  transports: ['websocket', 'polling'],
  allowEIO3: true
});

app.set('io', io);

// =============================================
// REAL-TIME STATS WITH REDIS SINGLE SOURCE OF TRUTH
// =============================================

const REDIS_INVESTOR_KEY = process.env.REDIS_INVESTOR_KEY || 'cloud_miner_count';
const INITIAL_INVESTOR_COUNT = parseInt(process.env.INITIAL_INVESTOR_COUNT) || 5104329;
const DAILY_GROWTH_LIMIT = parseInt(process.env.DAILY_GROWTH_LIMIT) || 7999;

const getStartOfDay = () => {
  const now = new Date();
  now.setUTCHours(0, 0, 0, 0);
  return now.getTime();
};

const getDailyGrowthKey = (date) => {
  return `daily_growth:${date}`;
};

const initializeInvestorCount = async () => {
  try {
    let currentCount = await redis.get(REDIS_INVESTOR_KEY);
    
    if (!currentCount) {
      currentCount = INITIAL_INVESTOR_COUNT;
      await redis.set(REDIS_INVESTOR_KEY, currentCount);
      if (process.env.NODE_ENV !== 'production') console.log(`✅ Initialized investor count to ${currentCount.toLocaleString()}`);
    } else {
      currentCount = parseInt(currentCount);
      if (process.env.NODE_ENV !== 'production') console.log(`📊 Current investor count from Redis: ${currentCount.toLocaleString()}`);
    }
    
    return currentCount;
  } catch (err) {
    console.error('Error initializing investor count:', err);
    return INITIAL_INVESTOR_COUNT;
  }
};

const checkAndResetDailyGrowth = async () => {
  try {
    const today = getStartOfDay();
    const todayKey = getDailyGrowthKey(today);
    
    let dailyGrowth = await redis.get(todayKey);
    
    if (!dailyGrowth) {
      dailyGrowth = 0;
      await redis.set(todayKey, dailyGrowth);
      if (process.env.NODE_ENV !== 'production') console.log(`📅 New day started - daily growth reset to 0`);
    } else {
      dailyGrowth = parseInt(dailyGrowth);
    }
    
    return dailyGrowth;
  } catch (err) {
    console.error('Error checking daily growth:', err);
    return 0;
  }
};

const addInvestors = async () => {
  try {
    let dailyGrowth = await checkAndResetDailyGrowth();
    
    if (dailyGrowth >= DAILY_GROWTH_LIMIT) {
      if (process.env.NODE_ENV !== 'production') console.log(`⏸️ Daily growth limit reached (${DAILY_GROWTH_LIMIT}). No more investors today.`);
      return false;
    }
    
    const increment = Math.floor(Math.random() * 49) + 1;
    
    const newDailyGrowth = dailyGrowth + increment;
    const actualIncrement = newDailyGrowth > DAILY_GROWTH_LIMIT 
      ? DAILY_GROWTH_LIMIT - dailyGrowth 
      : increment;
    
    if (actualIncrement <= 0) {
      if (process.env.NODE_ENV !== 'production') console.log(`⏸️ Daily limit would be exceeded. Stopping growth for today.`);
      return false;
    }
    
    const newCount = await redis.incrby(REDIS_INVESTOR_KEY, actualIncrement);
    
    const today = getStartOfDay();
    const todayKey = getDailyGrowthKey(today);
    await redis.incrby(todayKey, actualIncrement);
    
    if (process.env.NODE_ENV !== 'production') console.log(`📈 Investor count increased by ${actualIncrement}. New count: ${newCount.toLocaleString()}`);
    if (process.env.NODE_ENV !== 'production') console.log(`📊 Daily progress: ${dailyGrowth + actualIncrement}/${DAILY_GROWTH_LIMIT}`);
    
    return { newCount, increment: actualIncrement };
  } catch (err) {
    console.error('Error adding investors:', err);
    return false;
  }
};

const broadcastStats = async () => {
  try {
    const currentCount = await redis.get(REDIS_INVESTOR_KEY);
    const count = currentCount ? parseInt(currentCount) : INITIAL_INVESTOR_COUNT;
    
    const stats = {
      totalInvestors: count,
      timestamp: Date.now()
    };
    
    io.emit('stats-update', stats);
    
    if (process.env.NODE_ENV !== 'production') console.log(`📡 Broadcasted stats to ${io.engine.clientsCount} clients: ${count.toLocaleString()} investors`);
  } catch (err) {
    console.error('Error broadcasting stats:', err);
  }
};

const getCurrentStats = async () => {
  try {
    const currentCount = await redis.get(REDIS_INVESTOR_KEY);
    const count = currentCount ? parseInt(currentCount) : INITIAL_INVESTOR_COUNT;
    
    return {
      totalInvestors: count,
      timestamp: Date.now()
    };
  } catch (err) {
    console.error('Error getting current stats:', err);
    return {
      totalInvestors: INITIAL_INVESTOR_COUNT,
      timestamp: Date.now()
    };
  }
};

let growthInterval = null;

const startInvestorGrowthJob = async () => {
  await initializeInvestorCount();
  
  const scheduleNextGrowth = () => {
    const interval = Math.floor(Math.random() * (120000 - 3000 + 1) + 3000);
    
    growthInterval = setTimeout(async () => {
      try {
        const result = await addInvestors();
        
        if (result) {
          await broadcastStats();
        }
        
        scheduleNextGrowth();
      } catch (err) {
        console.error('Error in growth job:', err);
        scheduleNextGrowth();
      }
    }, interval);
  };
  
  scheduleNextGrowth();
  if (process.env.NODE_ENV !== 'production') console.log(`🚀 Investor growth job started. Will add 1-49 investors every 3-120 seconds (max ${DAILY_GROWTH_LIMIT}/day)`);
};

const stopInvestorGrowthJob = () => {
  if (growthInterval) {
    clearTimeout(growthInterval);
    growthInterval = null;
    if (process.env.NODE_ENV !== 'production') console.log('🛑 Investor growth job stopped');
  }
};

app.get('/api/stats/investors', async (req, res) => {
  try {
    const stats = await getCurrentStats();
    res.json({
      status: 'success',
      data: stats
    });
  } catch (err) {
    console.error('Error fetching investor stats:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch investor stats'
    });
  }
});

app.get('/api/stats/daily-progress', async (req, res) => {
  try {
    const today = getStartOfDay();
    const todayKey = getDailyGrowthKey(today);
    const dailyGrowth = await redis.get(todayKey);
    const currentCount = await redis.get(REDIS_INVESTOR_KEY);
    
    res.json({
      status: 'success',
      data: {
        dailyGrowth: dailyGrowth ? parseInt(dailyGrowth) : 0,
        dailyLimit: DAILY_GROWTH_LIMIT,
        totalInvestors: currentCount ? parseInt(currentCount) : INITIAL_INVESTOR_COUNT,
        date: new Date(today).toISOString()
      }
    });
  } catch (err) {
    console.error('Error fetching daily progress:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch daily progress'
    });
  }
});

const setupMarketWebSocket = (server) => {
  const marketWss = new WebSocket.Server({ 
    server, 
    path: '/ws/market' 
  });

  const clients = new Set();
  let priceInterval = null;

  const broadcastPrices = async () => {
    try {
      const response = await axios.get(
        'https://api.coingecko.com/api/v3/coins/markets',
        {
          params: {
            vs_currency: 'usd',
            per_page: 50,
            price_change_percentage: '24h'
          },
          timeout: 5000
        }
      );

      if (response.data && clients.size > 0) {
        const updates = response.data.map(coin => ({
          assetId: coin.id,
          price: coin.current_price,
          price_change_percentage_24h: coin.price_change_percentage_24h || 0
        }));

        const message = JSON.stringify({
          type: 'batch_update',
          updates: updates,
          timestamp: Date.now()
        });

        clients.forEach(client => {
          if (client.readyState === WebSocket.OPEN) {
            client.send(message);
          }
        });
      }
    } catch (error) {
      console.error('WebSocket price broadcast error:', error);
    }
  };

  marketWss.on('connection', (ws) => {
    clients.add(ws);
    console.log(`Market WebSocket client connected. Total: ${clients.size}`);

    (async () => {
      const assets = await fetchMarketData();
      ws.send(JSON.stringify({
        type: 'initial_data',
        assets: assets
      }));
    })();

    if (clients.size === 1 && !priceInterval) {
      priceInterval = setInterval(broadcastPrices, 5000);
    }

    ws.on('message', (message) => {
      try {
        const data = JSON.parse(message);
        if (data.type === 'subscribe') {
          console.log('Client subscribed to price updates');
        }
      } catch (err) {
      }
    });

    ws.on('close', () => {
      clients.delete(ws);
      console.log(`Market WebSocket client disconnected. Total: ${clients.size}`);
      
      if (clients.size === 0 && priceInterval) {
        clearInterval(priceInterval);
        priceInterval = null;
      }
    });
  });
};

io.on('connection', async (socket) => {
  console.log('New client connected:', socket.id);
  
  const token = socket.handshake.auth.token;
  let userId = null;
  
  if (token) {
    try {
      const decoded = verifyJWT(token);
      if (decoded && !decoded.isAdmin) {
        userId = decoded.id;
        socket.join(`user_${userId}`);
        console.log(`Socket authenticated for user: ${userId}`);
        
        const user = await User.findById(userId).select('balances');
        if (user) {
          // Send USD balances
          let mainUSD = 0;
          let activeUSD = 0;
          let maturedUSD = 0;
          
          // Calculate MAIN wallet USD from crypto balances
          if (user.balances && user.balances.main) {
            for (const [asset, balance] of user.balances.main.entries()) {
              if (balance > 0 && asset !== 'usd') {
                const price = await getCryptoPrice(asset.toUpperCase());
                if (price) mainUSD += balance * price;
              }
            }
          }
          
          // Calculate ACTIVE wallet USD (FIXED - doesn't fluctuate)
          if (user.balances && user.balances.active) {
            for (const [asset, balance] of user.balances.active.entries()) {
              if (balance > 0 && asset === 'usd') {
                activeUSD = balance;
              }
            }
          }
          
          // Calculate MATURED wallet USD from crypto balances
          if (user.balances && user.balances.matured) {
            for (const [asset, balance] of user.balances.matured.entries()) {
              if (balance > 0 && asset !== 'usd') {
                const price = await getCryptoPrice(asset.toUpperCase());
                if (price) maturedUSD += balance * price;
              }
            }
          }
          
          socket.emit('balance_update', {
            main: mainUSD,
            active: activeUSD,
            matured: maturedUSD
          });
          
          // Build asset data from MAIN + MATURED wallets (exclude ACTIVE)
          const assetData = [];
          const allBalances = new Map();
          
          // Collect from MAIN wallet
          if (user.balances && user.balances.main) {
            for (const [asset, balance] of user.balances.main.entries()) {
              if (balance > 0 && asset !== 'usd') {
                allBalances.set(asset, (allBalances.get(asset) || 0) + balance);
              }
            }
          }
          
          // Collect from MATURED wallet
          if (user.balances && user.balances.matured) {
            for (const [asset, balance] of user.balances.matured.entries()) {
              if (balance > 0 && asset !== 'usd') {
                allBalances.set(asset, (allBalances.get(asset) || 0) + balance);
              }
            }
          }
          
          // Get buy transaction history for each asset
          const buyTransactions = await Transaction.find({
            user: userId,
            type: 'buy',
            status: 'completed'
          }).sort({ createdAt: -1 });
          
          const buyHistoryByAsset = {};
          buyTransactions.forEach(tx => {
            const asset = (tx.asset || tx.buyDetails?.asset || '').toLowerCase();
            if (asset && asset !== 'usd') {
              if (!buyHistoryByAsset[asset]) buyHistoryByAsset[asset] = [];
              buyHistoryByAsset[asset].push({
                amount: tx.assetAmount || tx.buyDetails?.assetAmount || 0,
                usdValue: tx.amount || tx.buyDetails?.amountUSD || 0,
                price: tx.buyDetails?.buyingPrice || tx.exchangeRateAtTime || 0,
                date: tx.createdAt
              });
            }
          });
          
          for (const [asset, totalBalance] of allBalances.entries()) {
            if (totalBalance > 0) {
              const price = await getCryptoPrice(asset.toUpperCase());
              const currentValue = totalBalance * (price || 0);
              
              const assetBuys = buyHistoryByAsset[asset] || [];
              let totalSpent = 0;
              let totalBought = 0;
              assetBuys.forEach(b => {
                totalSpent += b.usdValue;
                totalBought += b.amount;
              });
              
              const avgPrice = totalBought > 0 ? totalSpent / totalBought : 0;
              const unrealizedPnl = currentValue - totalSpent;
              const unrealizedPercentage = totalSpent > 0 ? (unrealizedPnl / totalSpent) * 100 : 0;
              
              assetData.push({
                symbol: asset,
                balance: totalBalance,
                currentValue: currentValue,
                avgPrice: avgPrice,
                totalSpent: totalSpent,
                unrealizedPnl: unrealizedPnl,
                unrealizedPnlPercent: unrealizedPercentage,
                id: asset === 'btc' ? 'bitcoin' : asset === 'eth' ? 'ethereum' : asset,
                currentPrice: price || 0,
                transactions: assetBuys.slice(-10)
              });
            }
          }
          
          socket.emit('asset_balances_update', assetData);
        }
        
        const userPref = await UserPreference.findOne({ user: userId });
        if (userPref) {
          socket.emit('preferences_update', {
            displayAsset: userPref.displayAsset,
            language: userPref.language,
            currency: userPref.currency
          });
        }
      }
    } catch (err) {
      console.error('Socket auth error:', err);
    }
  }
  const currentStats = await getCurrentStats();
  socket.emit('stats-update', currentStats);
  console.log(`📡 Sent initial stats to new client ${socket.id}: ${currentStats.totalInvestors.toLocaleString()} investors`);

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
  
  socket.on('refresh_pnl', async () => {
    if (userId) {
      const user = await User.findById(userId).select('balances');
      const userAssetBalance = await UserAssetBalance.findOne({ user: userId });
      
      if (userAssetBalance) {
        let totalMainValue = 0;
        let previousDayValue = 0;
        
        for (const [asset, balance] of Object.entries(userAssetBalance.balances)) {
          if (balance > 0) {
            const currentPrice = await getCryptoPrice(asset.toUpperCase());
            if (currentPrice) {
              totalMainValue += balance * currentPrice;
              const change24h = currentPrices[asset]?.usd_24h_change || 0;
              const previousPrice = currentPrice / (1 + change24h / 100);
              previousDayValue += balance * previousPrice;
            }
          }
        }
        
        const dailyPnL = totalMainValue - previousDayValue;
        const dailyPnLPercentage = previousDayValue > 0 ? (dailyPnL / previousDayValue) * 100 : 0;
        
        socket.emit('pnl_update', {
          main: {
            amount: dailyPnL,
            percentage: dailyPnLPercentage
          },
          matured: {
            amount: 0,
            percentage: 0
          }
        });
      }
    }
  });

  socket.on('disconnect', () => {
    console.log('Client disconnected:', socket.id);
  });
});

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

        const totalReturn = investment.amount + (investment.amount * investment.plan.percentage / 100);
        
        // ✅ FIXED: Use user.balances object with Maps (active and matured)
        if (!user.balances) {
          user.balances = { main: new Map(), active: new Map(), matured: new Map() };
        }
        
        // Get current values from Maps
        const currentActiveUSD = user.balances.active?.get('usd') || 0;
        const currentMaturedUSD = user.balances.matured?.get('usd') || 0;
        
        // Update Maps
        user.balances.active.set('usd', currentActiveUSD - investment.amount);
        user.balances.matured.set('usd', currentMaturedUSD + totalReturn);
        
        // Also handle crypto balances if needed
        const currentActiveBTC = user.balances.active?.get('btc') || 0;
        const currentMaturedBTC = user.balances.matured?.get('btc') || 0;
        
        if (investment.amountBTC) {
          user.balances.active.set('btc', currentActiveBTC - investment.amountBTC);
          user.balances.matured.set('btc', currentMaturedBTC + (totalReturn / investment.btcPriceAtCompletion || 0));
        }

        investment.status = 'completed';
        investment.completionDate = now;
        investment.actualReturn = totalReturn - investment.amount;

        await user.save();
        await investment.save();

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
        
        io.to(`user_${user._id}`).emit('balance_update', {
          main: user.balances.main?.get('usd') || 0,
          active: user.balances.active?.get('usd') || 0,
          matured: user.balances.matured?.get('usd') || 0
        });

        console.log(`✅ Automatically completed investment ${investment._id} for user ${user.email}`);
      } catch (err) {
        console.error(`Error processing investment ${investment._id}:`, err);
      }
    }
  } catch (err) {
    console.error('Error processing matured investments:', err);
  }
};

setInterval(processMaturedInvestments, 60 * 60 * 1000);

processMaturedInvestments();

startInvestorGrowthJob();

startRealTimeWalletUpdates(io);

// Real-time updates already happen every second with price changes
// This is just a fallback sync every 30 seconds for any missed updates
setInterval(async () => {
  await recalculateAllUserBalances(io);
}, 30000);

const gracefulShutdown = () => {
  console.log('Received shutdown signal. Cleaning up...');
  if (priceUpdateInterval) clearInterval(priceUpdateInterval);
  stopInvestorGrowthJob();
  process.exit(0);
};

// Initialize WebSocket servers after HTTP server is created
const setupAllWebSockets = (server) => {
  return setupMarketWebSocket(server);
};

process.on('SIGTERM', gracefulShutdown);
process.on('SIGINT', gracefulShutdown);

httpServer.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`📊 Real-time stats initialized with Redis as single source of truth`);
  console.log(`📈 Investors will grow from ${INITIAL_INVESTOR_COUNT.toLocaleString()} with max ${DAILY_GROWTH_LIMIT}/day`);
  console.log(`💰 Real-time crypto price updates started (every 1 second)`);
  console.log(`🔌 WebSocket endpoints: /ws/market`);
});
