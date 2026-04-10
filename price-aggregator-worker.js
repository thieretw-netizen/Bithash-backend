// price-aggregator-worker.js
// SINGLE SOURCE OF TRUTH - ONLY WRITER TO REDIS
require('dotenv').config();
const WebSocket = require('ws');
const Redis = require('ioredis');
const axios = require('axios');

const redis = new Redis({
  host: process.env.REDIS_HOST || 'redis-14450.c276.us-east-1-2.ec2.redns.redis-cloud.com',
  port: process.env.REDIS_PORT || 14450,
  password: process.env.REDIS_PASSWORD || 'qjXgsg0YrsLaSumlEW9HkIZbvLjXEwXR',
  retryStrategy: (times) => Math.min(times * 50, 2000)
});

const MAIN_CRYPTOS = ['BTC', 'ETH', 'BNB', 'SOL', 'XRP', 'ADA', 'DOGE', 'AVAX', 'DOT', 'LINK', 'MATIC', 'SHIB', 'TRX', 'UNI', 'ATOM', 'XLM', 'FIL', 'VET', 'ALGO', 'MANA', 'SAND', 'AXS', 'AAVE', 'EOS', 'MKR', 'DASH', 'XTZ', 'FTM', 'NEAR', 'GRT'];
const QUOTE_ASSETS = ['USDT', 'USDC', 'USDQ', 'USDR', 'EURC', 'USD', 'BNB', 'BTC'];
const TIMEFRAMES = ['1s', '15m', '1h', '4h', '1d', '1w'];

let binanceWs = null;
let reconnectAttempts = 0;
let isConnected = false;

// Generate all pairs for all quote assets
function getAllPairs() {
  const pairs = [];
  for (const base of MAIN_CRYPTOS) {
    for (const quote of QUOTE_ASSETS) {
      if (base !== quote) {
        pairs.push(`${base}${quote}`);
      }
    }
  }
  return pairs;
}

// Subscribe to Binance streams for all pairs
function subscribeToStreams(ws) {
  const allPairs = getAllPairs();
  const streams = [];
  
  // Add ticker streams
  for (const pair of allPairs.slice(0, 50)) {
    streams.push(`${pair.toLowerCase()}@ticker`);
    streams.push(`${pair.toLowerCase()}@depth20@100ms`);
    streams.push(`${pair.toLowerCase()}@trade`);
  }
  
  // Add kline streams for all timeframes for top 20 pairs
  const topPairs = allPairs.slice(0, 20);
  for (const timeframe of TIMEFRAMES) {
    for (const pair of topPairs) {
      streams.push(`${pair.toLowerCase()}@kline_${timeframe}`);
    }
  }
  
  const subscribeMsg = {
    method: 'SUBSCRIBE',
    params: streams,
    id: 1
  };
  
  ws.send(JSON.stringify(subscribeMsg));
  console.log(`Subscribed to ${streams.length} Binance streams`);
}

// Store kline/candle in Redis Sorted Set
async function storeCandle(symbol, interval, candle) {
  const key = `candle:${symbol}:${interval}`;
  const timestamp = candle.openTime;
  const candleData = {
    time: timestamp,
    open: parseFloat(candle.open),
    high: parseFloat(candle.high),
    low: parseFloat(candle.low),
    close: parseFloat(candle.close),
    volume: parseFloat(candle.volume)
  };
  
  await redis.zadd(key, timestamp, JSON.stringify(candleData));
  await redis.expire(key, 86400); // Keep 24 hours of candles
  
  // Publish update for real-time chart updates
  await redis.publish('candle:update', JSON.stringify({ symbol, interval, candle: candleData }));
}

// Store 24hr ticker in Redis
async function storeTicker(symbol, data) {
  const key = `ticker:${symbol}`;
  const tickerData = {
    symbol: symbol,
    priceChange: parseFloat(data.p),
    priceChangePercent: parseFloat(data.P),
    weightedAvgPrice: parseFloat(data.w),
    prevClosePrice: parseFloat(data.x),
    lastPrice: parseFloat(data.c),
    lastQty: parseFloat(data.Q),
    bidPrice: parseFloat(data.b),
    askPrice: parseFloat(data.a),
    openPrice: parseFloat(data.o),
    highPrice: parseFloat(data.h),
    lowPrice: parseFloat(data.l),
    volume: parseFloat(data.v),
    quoteVolume: parseFloat(data.q),
    openTime: data.O,
    closeTime: data.C
  };
  
  await redis.setex(key, 2, JSON.stringify(tickerData));
  await redis.publish('ticker:update', JSON.stringify(tickerData));
}

// Store order book depth in Redis
async function storeOrderBook(symbol, data) {
  const key = `orderbook:${symbol}`;
  const orderbookData = {
    bids: data.bids.slice(0, 100).map(b => [parseFloat(b[0]), parseFloat(b[1])]),
    asks: data.asks.slice(0, 100).map(a => [parseFloat(a[0]), parseFloat(a[1])]),
    lastUpdateId: data.lastUpdateId
  };
  
  await redis.setex(key, 1, JSON.stringify(orderbookData));
  await redis.publish('orderbook:update', JSON.stringify({ symbol, ...orderbookData }));
}

// Store recent trade in Redis
async function storeTrade(symbol, trade) {
  const key = `trades:${symbol}`;
  const tradeData = {
    id: trade.t,
    price: parseFloat(trade.p),
    amount: parseFloat(trade.q),
    time: trade.T,
    isBuyerMaker: trade.m
  };
  
  // Add to list, keep last 100 trades
  await redis.lpush(key, JSON.stringify(tradeData));
  await redis.ltrim(key, 0, 99);
  await redis.expire(key, 60);
  await redis.publish('trade:update', JSON.stringify({ symbol, trade: tradeData }));
}

// Store market pairs in Redis (fetched from Binance REST)
async function updateMarketPairs() {
  try {
    const response = await axios.get('https://api.binance.com/api/v3/exchangeInfo', { timeout: 10000 });
    const allSymbols = response.data.symbols;
    
    const pairs = [];
    for (const symbol of allSymbols) {
      if (symbol.status === 'TRADING' && QUOTE_ASSETS.includes(symbol.quoteAsset)) {
        pairs.push({
          symbol: symbol.symbol,
          base: symbol.baseAsset,
          quote: symbol.quoteAsset,
          basePrecision: symbol.baseAssetPrecision,
          quotePrecision: symbol.quoteAssetPrecision,
          minQty: parseFloat(symbol.filters.find(f => f.filterType === 'LOT_SIZE')?.minQty || 0.00001),
          maxQty: parseFloat(symbol.filters.find(f => f.filterType === 'LOT_SIZE')?.maxQty || 10000),
          minNotional: parseFloat(symbol.filters.find(f => f.filterType === 'MIN_NOTIONAL')?.minNotional || 10),
          status: 'active'
        });
      }
    }
    
    await redis.setex('market:pairs', 3600, JSON.stringify({ data: pairs }));
    console.log(`Updated ${pairs.length} market pairs in Redis`);
  } catch (err) {
    console.error('Failed to update market pairs:', err.message);
  }
}

// Connect to Binance WebSocket
function connectBinance() {
  if (binanceWs) {
    try { binanceWs.close(); } catch(e) {}
  }
  
  binanceWs = new WebSocket('wss://stream.binance.com:9443/ws');
  
  binanceWs.on('open', () => {
    console.log('✅ Price Aggregator connected to Binance WebSocket');
    isConnected = true;
    reconnectAttempts = 0;
    subscribeToStreams(binanceWs);
  });
  
  binanceWs.on('message', async (data) => {
    try {
      const parsed = JSON.parse(data);
      if (!parsed.stream) return;
      
      const streamParts = parsed.stream.split('@');
      const symbol = streamParts[0].toUpperCase();
      const channel = streamParts[1];
      const streamData = parsed.data;
      
      if (channel === 'ticker') {
        await storeTicker(symbol, streamData);
      }
      
      if (channel === 'depth20') {
        await storeOrderBook(symbol, streamData);
      }
      
      if (channel === 'trade') {
        await storeTrade(symbol, streamData);
      }
      
      if (channel.startsWith('kline')) {
        const kline = streamData.k;
        const interval = kline.i;
        const isFinal = kline.x; // Candle closed
        
        if (isFinal) {
          await storeCandle(symbol, interval, {
            openTime: kline.t,
            open: kline.o,
            high: kline.h,
            low: kline.l,
            close: kline.c,
            volume: kline.v
          });
        }
      }
    } catch (err) {
      console.error('Error processing Binance message:', err.message);
    }
  });
  
  binanceWs.on('error', (err) => {
    console.error('Binance WebSocket error:', err.message);
    isConnected = false;
  });
  
  binanceWs.on('close', () => {
    console.log('Binance WebSocket closed, reconnecting...');
    isConnected = false;
    const delay = Math.min(5000 * Math.pow(2, reconnectAttempts), 60000);
    reconnectAttempts++;
    setTimeout(connectBinance, delay);
  });
}

// Health check every 5 seconds
setInterval(() => {
  if (!isConnected) {
    console.warn('⚠️ Binance WebSocket disconnected, attempting reconnect...');
    connectBinance();
  }
}, 5000);

// Initial market pairs update
updateMarketPairs();
setInterval(updateMarketPairs, 3600000); // Every hour

// Start the worker
console.log('🚀 Price Aggregator Worker starting...');
connectBinance();
console.log('✅ Price Aggregator Worker running - SINGLE SOURCE OF TRUTH for Redis');
