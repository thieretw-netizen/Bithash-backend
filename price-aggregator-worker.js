// =============================================
// PRICE AGGREGATOR WORKER - PRODUCTION GRADE
// Single source of truth for all market data
// =============================================

require('dotenv').config();
const WebSocket = require('ws');
const Redis = require('ioredis');
const axios = require('axios');

// Redis connection
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
  keepAlive: 10000,
  connectTimeout: 10000
});

redis.on('error', (err) => {
  console.error('Redis error in worker:', err);
});

redis.on('connect', () => {
  console.log('✅ Redis connected to worker');
});

// Configuration
const SUPPORTED_PAIRS = [
  'BTCUSDT', 'ETHUSDT', 'BNBUSDT', 'SOLUSDT', 'XRPUSDT', 'ADAUSDT', 'DOGEUSDT',
  'AVAXUSDT', 'DOTUSDT', 'LINKUSDT', 'MATICUSDT', 'SHIBUSDT', 'TRXUSDT', 'UNIUSDT',
  'ATOMUSDT', 'XLMUSDT', 'FILUSDT', 'VETUSDT', 'ALGOUSDT', 'MANAUSDT', 'SANDUSDT',
  'AXSUSDT', 'AAVEUSDT', 'EOSUSDT', 'MKRUSDT', 'DASHUSDT', 'XTZUSDT', 'FTMUSDT',
  'NEARUSDT', 'GRTUSDT', 'HBARUSDT', 'QNTUSDT', 'THETAUSDT', 'ICPUSDT', 'FLOWUSDT',
  'BCHUSDT', 'WBTCUSDT', 'LTCUSDT', 'XMRUSDT', 'ETCUSDT', 'ZECUSDT', 'NEOUSDT', 'IOTAUSDT'
];

const QUOTE_ASSETS = ['USDT', 'USDC', 'EURC', 'USD', 'BNB', 'BTC'];

const TIMEFRAMES = ['1s', '1m', '5m', '15m', '30m', '1h', '2h', '4h', '6h', '8h', '12h', '1d', '3d', '1w'];

let binanceWs = null;
let reconnectAttempts = 0;
let lastHeartbeat = Date.now();
let subscribedPairs = new Set();

// Buffer for messages when Redis is down
let messageBuffer = [];
let isRedisConnected = true;

// =============================================
// REDIS OPERATIONS
// =============================================

async function writeToRedis(key, value, ttlSeconds = null) {
  try {
    if (ttlSeconds) {
      await redis.setex(key, ttlSeconds, JSON.stringify(value));
    } else {
      await redis.set(key, JSON.stringify(value));
    }
    return true;
  } catch (err) {
    console.error(`Failed to write to Redis key ${key}:`, err.message);
    isRedisConnected = false;
    return false;
  }
}

async function writeHashToRedis(hashKey, field, value) {
  try {
    await redis.hset(hashKey, field, JSON.stringify(value));
    return true;
  } catch (err) {
    console.error(`Failed to write hash to Redis:`, err.message);
    return false;
  }
}

async function writeToSortedSet(key, score, value, ttlSeconds = null) {
  try {
    await redis.zadd(key, score, JSON.stringify(value));
    if (ttlSeconds) {
      await redis.expire(key, ttlSeconds);
    }
    return true;
  } catch (err) {
    console.error(`Failed to write to sorted set:`, err.message);
    return false;
  }
}

async function publishToChannel(channel, data) {
  try {
    await redis.publish(channel, JSON.stringify(data));
    return true;
  } catch (err) {
    console.error(`Failed to publish to ${channel}:`, err.message);
    return false;
  }
}

// Flush buffered messages when Redis reconnects
redis.on('ready', () => {
  console.log('Redis ready in worker, flushing buffer...');
  isRedisConnected = true;
  
  const buffered = [...messageBuffer];
  messageBuffer = [];
  
  for (const msg of buffered) {
    if (msg.type === 'ticker') {
      storeTicker(msg.symbol, msg.data);
    } else if (msg.type === 'orderbook') {
      storeOrderBook(msg.symbol, msg.data);
    } else if (msg.type === 'candle') {
      storeCandle(msg.symbol, msg.interval, msg.data);
    }
  }
});

// =============================================
// DATA STORAGE FUNCTIONS
// =============================================

async function storeTicker(symbol, tickerData) {
  const tickerKey = `ticker:${symbol}`;
  const tickerHashKey = `tickers:all`;
  
  const success = await writeToRedis(tickerKey, tickerData, 2);
  if (success) {
    await writeHashToRedis(tickerHashKey, symbol, tickerData);
    await publishToChannel('ticker:updates', { symbol, data: tickerData });
  } else if (!isRedisConnected) {
    messageBuffer.push({ type: 'ticker', symbol, data: tickerData });
  }
}

async function storeOrderBook(symbol, orderbookData) {
  const orderbookKey = `orderbook:${symbol}`;
  
  const success = await writeToRedis(orderbookKey, orderbookData, 1);
  if (success) {
    await publishToChannel('orderbook:updates', { symbol, data: orderbookData });
  } else if (!isRedisConnected) {
    messageBuffer.push({ type: 'orderbook', symbol, data: orderbookData });
  }
}

async function storeRecentTrade(symbol, tradeData) {
  const tradesKey = `trades:${symbol}`;
  const maxTrades = 100;
  
  try {
    let existingTrades = await redis.get(tradesKey);
    let trades = existingTrades ? JSON.parse(existingTrades) : [];
    trades.unshift(tradeData);
    if (trades.length > maxTrades) trades = trades.slice(0, maxTrades);
    await redis.setex(tradesKey, 3, JSON.stringify(trades));
    await publishToChannel('trades:updates', { symbol, data: tradeData });
  } catch (err) {
    console.error(`Failed to store trade for ${symbol}:`, err.message);
  }
}

async function storeCandle(symbol, interval, candleData) {
  const candleKey = `candles:${symbol}:${interval}`;
  const maxCandles = 500;
  
  try {
    let existingCandles = await redis.get(candleKey);
    let candles = existingCandles ? JSON.parse(existingCandles) : [];
    
    const existingIndex = candles.findIndex(c => c.time === candleData.time);
    if (existingIndex !== -1) {
      candles[existingIndex] = candleData;
    } else {
      candles.push(candleData);
      candles.sort((a, b) => a.time - b.time);
      if (candles.length > maxCandles) candles = candles.slice(-maxCandles);
    }
    
    await redis.setex(candleKey, 60, JSON.stringify(candles));
    await publishToChannel('candles:updates', { symbol, interval, data: candleData });
  } catch (err) {
    console.error(`Failed to store candle for ${symbol}:`, err.message);
  }
}

async function storeMarketPair(pairData) {
  try {
    const pairsKey = 'market:pairs';
    let existingPairs = await redis.get(pairsKey);
    let pairs = existingPairs ? JSON.parse(existingPairs) : { data: [] };
    
    const existingIndex = pairs.data.findIndex(p => p.symbol === pairData.symbol);
    if (existingIndex !== -1) {
      pairs.data[existingIndex] = pairData;
    } else {
      pairs.data.push(pairData);
    }
    
    await redis.setex(pairsKey, 300, JSON.stringify(pairs));
  } catch (err) {
    console.error(`Failed to store market pair:`, err.message);
  }
}

// =============================================
// BINANCE WEBSOCKET CONNECTION
// =============================================

function buildSubscriptionParams() {
  const params = [];
  
  for (const pair of SUPPORTED_PAIRS) {
    const lowerPair = pair.toLowerCase();
    params.push(`${lowerPair}@ticker`);
    params.push(`${lowerPair}@depth20@100ms`);
    params.push(`${lowerPair}@trade`);
    
    for (const timeframe of TIMEFRAMES) {
      params.push(`${lowerPair}@kline_${timeframe}`);
    }
  }
  
  return params;
}

function connectBinance() {
  if (binanceWs) {
    try { binanceWs.close(); } catch(e) {}
  }
  
  console.log(`Connecting to Binance WebSocket... (attempt ${reconnectAttempts + 1})`);
  binanceWs = new WebSocket('wss://stream.binance.com:9443/ws');
  
  binanceWs.on('open', () => {
    console.log('✅ Binance WebSocket connected to worker');
    reconnectAttempts = 0;
    lastHeartbeat = Date.now();
    
    const params = buildSubscriptionParams();
    console.log(`Subscribing to ${params.length} streams for ${SUPPORTED_PAIRS.length} pairs`);
    
    const subscribeMsg = {
      method: 'SUBSCRIBE',
      params: params,
      id: 1
    };
    
    binanceWs.send(JSON.stringify(subscribeMsg));
    
    // Start heartbeat ping
    heartbeatInterval = setInterval(() => {
      if (binanceWs && binanceWs.readyState === WebSocket.OPEN) {
        binanceWs.ping();
      }
    }, 30000);
  });
  
  binanceWs.on('message', (data) => {
    try {
      const parsed = JSON.parse(data);
      
      // Handle subscription response
      if (parsed.result !== undefined && parsed.id === 1) {
        console.log('✅ Successfully subscribed to Binance streams');
        return;
      }
      
      // Handle ping/pong
      if (parsed.type === 'ping') {
        if (binanceWs && binanceWs.readyState === WebSocket.OPEN) {
          binanceWs.send(JSON.stringify({ type: 'pong' }));
        }
        return;
      }
      
      // Handle stream data
      if (parsed.stream) {
        const streamParts = parsed.stream.split('@');
        const pair = streamParts[0].toUpperCase();
        const channel = streamParts[1];
        
        if (channel === 'ticker') {
          const tickerData = {
            symbol: pair,
            price: parseFloat(parsed.data.c),
            priceChange: parseFloat(parsed.data.p),
            priceChangePercent: parseFloat(parsed.data.P),
            weightedAvgPrice: parseFloat(parsed.data.w),
            prevClosePrice: parseFloat(parsed.data.x),
            lastPrice: parseFloat(parsed.data.c),
            lastQty: parseFloat(parsed.data.Q),
            bidPrice: parseFloat(parsed.data.b),
            bidQty: parseFloat(parsed.data.B),
            askPrice: parseFloat(parsed.data.a),
            askQty: parseFloat(parsed.data.A),
            openPrice: parseFloat(parsed.data.o),
            highPrice: parseFloat(parsed.data.h),
            lowPrice: parseFloat(parsed.data.l),
            volume: parseFloat(parsed.data.v),
            quoteVolume: parseFloat(parsed.data.q),
            openTime: parsed.data.O,
            closeTime: parsed.data.C,
            stats: {
              priceChangePercent: parseFloat(parsed.data.P),
              highPrice: parseFloat(parsed.data.h),
              lowPrice: parseFloat(parsed.data.l),
              volume: parseFloat(parsed.data.v),
              quoteVolume: parseFloat(parsed.data.q),
              openPrice: parseFloat(parsed.data.o)
            }
          };
          
          storeTicker(pair, tickerData);
        }
        
        else if (channel === 'depth20') {
          const orderbookData = {
            bids: (parsed.data.bids || []).slice(0, 20).map(b => [parseFloat(b[0]), parseFloat(b[1])]),
            asks: (parsed.data.asks || []).slice(0, 20).map(a => [parseFloat(a[0]), parseFloat(a[1])]),
            lastUpdateId: parsed.data.lastUpdateId
          };
          
          storeOrderBook(pair, orderbookData);
        }
        
        else if (channel === 'trade') {
          const tradeData = {
            id: parsed.data.t,
            price: parseFloat(parsed.data.p),
            amount: parseFloat(parsed.data.q),
            time: parsed.data.T,
            isBuyerMaker: parsed.data.m
          };
          
          storeRecentTrade(pair, tradeData);
        }
        
        else if (channel.startsWith('kline_')) {
          const interval = channel.replace('kline_', '');
          const k = parsed.data.k;
          
          const candleData = {
            time: k.t,
            open: parseFloat(k.o),
            high: parseFloat(k.h),
            low: parseFloat(k.l),
            close: parseFloat(k.c),
            volume: parseFloat(k.v),
            closeTime: k.T,
            quoteVolume: parseFloat(k.q),
            trades: k.n,
            isClosed: k.x
          };
          
          storeCandle(pair, interval, candleData);
        }
      }
    } catch (err) {
      console.error('Error parsing Binance message:', err.message);
    }
  });
  
  binanceWs.on('error', (err) => {
    console.error('Binance WebSocket error:', err.message);
  });
  
  binanceWs.on('close', (code, reason) => {
    console.log(`Binance WebSocket closed: ${code} - ${reason || 'no reason'}`);
    const delay = Math.min(5000 * Math.pow(2, reconnectAttempts), 60000);
    reconnectAttempts++;
    console.log(`Reconnecting in ${delay/1000} seconds...`);
    setTimeout(connectBinance, delay);
  });
  
  binanceWs.on('pong', () => {
    lastHeartbeat = Date.now();
  });
}

// =============================================
// HEALTH CHECK & MONITORING
// =============================================

let heartbeatInterval = null;

async function healthCheck() {
  const healthData = {
    status: 'healthy',
    redisConnected: isRedisConnected,
    binanceConnected: binanceWs && binanceWs.readyState === WebSocket.OPEN,
    subscribedPairs: SUPPORTED_PAIRS.length,
    subscribedStreams: buildSubscriptionParams().length,
    bufferSize: messageBuffer.length,
    uptime: process.uptime(),
    timestamp: Date.now()
  };
  
  await redis.setex('worker:health', 10, JSON.stringify(healthData));
  
  if (!healthData.binanceConnected) {
    console.warn('⚠️ Binance WebSocket disconnected, attempting reconnect...');
    if (!binanceWs || binanceWs.readyState !== WebSocket.CONNECTING) {
      connectBinance();
    }
  }
}

// Run health check every 10 seconds
setInterval(healthCheck, 10000);

// =============================================
// FETCH INITIAL PAIR DATA FROM REST API
// =============================================

async function fetchInitialPairs() {
  try {
    console.log('Fetching initial market pairs from Binance REST API...');
    
    const response = await axios.get('https://api.binance.com/api/v3/exchangeInfo', { timeout: 10000 });
    
    const usdtPairs = response.data.symbols.filter(s => 
      s.quoteAsset === 'USDT' && s.status === 'TRADING'
    );
    
    const topPairs = usdtPairs.slice(0, 100);
    
    for (const pair of topPairs) {
      const baseAsset = pair.baseAsset;
      let logoUrl = '';
      
      try {
        const coinRes = await axios.get(`https://api.coingecko.com/api/v3/coins/markets?vs_currency=usd&ids=${baseAsset.toLowerCase()}&sparkline=false`, { timeout: 3000 });
        if (coinRes.data && coinRes.data[0] && coinRes.data[0].image) {
          logoUrl = coinRes.data[0].image;
        }
      } catch (e) {
        // No logo, continue
      }
      
      const pairData = {
        symbol: pair.symbol,
        base: baseAsset,
        quote: 'USDT',
        logoUrl: logoUrl,
        status: 'active'
      };
      
      await storeMarketPair(pairData);
    }
    
    console.log(`✅ Stored ${topPairs.length} market pairs in Redis`);
  } catch (err) {
    console.error('Failed to fetch initial pairs:', err.message);
  }
}

// =============================================
// START THE WORKER
// =============================================

async function start() {
  console.log('🚀 Starting Price Aggregator Worker...');
  console.log(`📊 Will track ${SUPPORTED_PAIRS.length} trading pairs`);
  console.log(`⏱️ Timeframes: ${TIMEFRAMES.join(', ')}`);
  
  // Wait for Redis connection
  await new Promise((resolve) => {
    if (redis.status === 'ready') {
      resolve();
    } else {
      redis.once('ready', resolve);
    }
  });
  
  console.log('✅ Redis ready, fetching initial data...');
  await fetchInitialPairs();
  
  console.log('🔌 Connecting to Binance WebSocket...');
  connectBinance();
  
  console.log('✅ Price Aggregator Worker running');
}

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down worker...');
  if (heartbeatInterval) clearInterval(heartbeatInterval);
  if (binanceWs) binanceWs.close();
  redis.quit();
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('SIGINT received, shutting down worker...');
  if (heartbeatInterval) clearInterval(heartbeatInterval);
  if (binanceWs) binanceWs.close();
  redis.quit();
  process.exit(0);
});

start();
