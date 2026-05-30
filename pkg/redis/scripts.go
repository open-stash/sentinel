package redis

import "github.com/redis/go-redis/v9"

var ratelimiterScript = redis.NewScript(`
-- KEYS[1] = tokens_key
-- KEYS[2] = timestamp_key
-- ARGV[1] = capacity
-- ARGV[2] = refill_rate_per_sec
-- ARGV[3] = now_ms

local tokens_key = KEYS[1]
local ts_key     = KEYS[2]

local capacity           = tonumber(ARGV[1])
local refill_rate_per_sec = tonumber(ARGV[2])
local now                = tonumber(ARGV[3])

local refill_rate_per_ms = refill_rate_per_sec / 1000

-- TTL: time for a full bucket refill + padding
local full_refill_sec = capacity / refill_rate_per_sec
local ttl_ms          = math.floor((full_refill_sec + 10) * 1000)

local tokens      = tonumber(redis.call("GET", tokens_key))
local last_refill = tonumber(redis.call("GET", ts_key))

-- Initialise bucket on first use
if tokens == nil or tokens > capacity then
    tokens      = capacity
    last_refill = now
end

-- Refill tokens based on elapsed time
local elapsed_ms = now - last_refill
if elapsed_ms > 0 then
    tokens      = math.min(capacity, tokens + elapsed_ms * refill_rate_per_ms)
    last_refill = now
end

local allowed          = 0
local retry_after_secs = 0

if tokens >= 1 then
    allowed = 1
    tokens  = tokens - 1
else
    retry_after_secs = math.ceil(1 / refill_rate_per_sec)
end

redis.call("SET", tokens_key, tokens,      "PX", ttl_ms)
redis.call("SET", ts_key,     last_refill, "PX", ttl_ms)

return { allowed, math.floor(tokens), retry_after_secs }
`)
