Crypto = {}
--[[
  crypto.lua
  Shared Crypto & Encoding Utilities — Pure Lua Implementation
  No external libraries required. Uses Lua 5.3+ native bitwise operators.

  Shared utilities used by azure_sas.lua / aws_sigv4.lua:
    SHA-256 (FIPS 180-4) / HMAC-SHA256 (RFC 2104)
    Base64 encode / decode
    URI percent-encoding
    Conversion helpers (to_hex / trim)

  Usage with FiveM:
    -- Register 'server/crypto.lua' at the top of server_scripts in fxmanifest.lua.
    -- It will be loaded automatically via loadfile from azure_sas.lua / aws_sigv4.lua.
    -- Alternatively, reference it directly with require("server/crypto").
--]]

------------------------------------------------------------------------
-- Bitwise helpers
------------------------------------------------------------------------

local M32 = 0xFFFFFFFF          -- 32-bit mask

local function u32(n)           return n & M32 end
local function rrot32(n, b)     return u32((n >> b) | (n << (32 - b))) end

------------------------------------------------------------------------
-- Conversion helpers
------------------------------------------------------------------------

--- Byte string → hex string (lowercase)
function Crypto.to_hex(s)
    return (s:gsub(".", function(c)
        return string.format("%02x", c:byte())
    end))
end

--- Trim leading/trailing whitespace from string
function Crypto.trim(s)
    return s:match("^%s*(.-)%s*$")
end

------------------------------------------------------------------------
-- SHA-256  (FIPS 180-4)
------------------------------------------------------------------------

local K256 = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

--- SHA-256 hash (byte string → 32-byte string)
function Crypto.sha256_bytes(msg)
    local h0, h1, h2, h3, h4, h5, h6, h7 =
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19

    -- Padding
    local len = #msg
    msg = msg .. "\x80"
    while #msg % 64 ~= 56 do msg = msg .. "\x00" end
    local lb  = len * 8
    local lhi = lb >> 32
    local llo = lb & M32
    msg = msg .. string.char(
        (lhi >> 24) & 0xFF, (lhi >> 16) & 0xFF, (lhi >> 8) & 0xFF, lhi & 0xFF,
        (llo >> 24) & 0xFF, (llo >> 16) & 0xFF, (llo >> 8) & 0xFF, llo & 0xFF
    )

    local bytes = { msg:byte(1, #msg) }

    for blk = 0, (#bytes // 64) - 1 do
        local w    = {}
        local base = blk * 64

        -- Message schedule (first 16 words)
        for j = 1, 16 do
            local o = base + (j - 1) * 4
            w[j] = u32(
                (bytes[o+1] << 24) | (bytes[o+2] << 16) |
                (bytes[o+3] <<  8) |  bytes[o+4]
            )
        end
        -- Message schedule (remaining 48 words)
        for j = 17, 64 do
            local s0 = rrot32(w[j-15], 7) ~ rrot32(w[j-15], 18) ~ (w[j-15] >> 3)
            local s1 = rrot32(w[j-2], 17) ~ rrot32(w[j-2], 19)  ~ (w[j-2]  >> 10)
            w[j] = u32(w[j-16] + s0 + w[j-7] + s1)
        end

        local a, b, c, d, e, f, g, hv =
            h0, h1, h2, h3, h4, h5, h6, h7

        -- Compression loop (64 rounds)
        for j = 1, 64 do
            local S1  = rrot32(e, 6)  ~ rrot32(e, 11) ~ rrot32(e, 25)
            local ch  = (e & f) ~ (~e & g)
            local t1  = u32(hv + S1 + ch + K256[j] + w[j])
            local S0  = rrot32(a, 2)  ~ rrot32(a, 13) ~ rrot32(a, 22)
            local maj = (a & b) ~ (a & c) ~ (b & c)
            local t2  = u32(S0 + maj)
            hv = g; g = f; f = e; e = u32(d + t1)
            d  = c; c = b; b = a; a = u32(t1 + t2)
        end

        h0 = u32(h0+a); h1 = u32(h1+b); h2 = u32(h2+c); h3 = u32(h3+d)
        h4 = u32(h4+e); h5 = u32(h5+f); h6 = u32(h6+g); h7 = u32(h7+hv)
    end

    return string.char(
        (h0>>24)&0xFF,(h0>>16)&0xFF,(h0>>8)&0xFF, h0&0xFF,
        (h1>>24)&0xFF,(h1>>16)&0xFF,(h1>>8)&0xFF, h1&0xFF,
        (h2>>24)&0xFF,(h2>>16)&0xFF,(h2>>8)&0xFF, h2&0xFF,
        (h3>>24)&0xFF,(h3>>16)&0xFF,(h3>>8)&0xFF, h3&0xFF,
        (h4>>24)&0xFF,(h4>>16)&0xFF,(h4>>8)&0xFF, h4&0xFF,
        (h5>>24)&0xFF,(h5>>16)&0xFF,(h5>>8)&0xFF, h5&0xFF,
        (h6>>24)&0xFF,(h6>>16)&0xFF,(h6>>8)&0xFF, h6&0xFF,
        (h7>>24)&0xFF,(h7>>16)&0xFF,(h7>>8)&0xFF, h7&0xFF
    )
end

--- SHA-256 hash (string → 64-char hex string)
function Crypto.sha256(msg)
    return Crypto.to_hex(Crypto.sha256_bytes(msg))
end

------------------------------------------------------------------------
-- HMAC-SHA256  (RFC 2104)
------------------------------------------------------------------------

--- HMAC-SHA256 (key and message as byte strings → 32-byte string)
function Crypto.hmac_sha256_bytes(key, msg)
    local BLOCK = 64

    -- Hash the key if it exceeds the block length
    if #key > BLOCK then key = Crypto.sha256_bytes(key) end
    -- Zero-pad key to block length
    key = key .. string.rep("\x00", BLOCK - #key)

    -- Generate ipad / opad
    local ipad_t, opad_t = {}, {}
    for i = 1, BLOCK do
        local byt = key:byte(i)
        ipad_t[i] = string.char(byt ~ 0x36)
        opad_t[i] = string.char(byt ~ 0x5C)
    end
    local ipad = table.concat(ipad_t)
    local opad = table.concat(opad_t)

    -- HMAC = SHA256(opad || SHA256(ipad || msg))
    return Crypto.sha256_bytes(opad .. Crypto.sha256_bytes(ipad .. msg))
end

--- HMAC-SHA256 (key and message as byte strings → 64-char hex string)
function Crypto.hmac_sha256(key, msg)
    return Crypto.to_hex(Crypto.hmac_sha256_bytes(key, msg))
end

------------------------------------------------------------------------
-- Base64
------------------------------------------------------------------------

local B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

--- Base64 encode (binary string → Base64 string)
function Crypto.base64_encode(data)
    local result = {}
    local n   = #data
    local rem = n % 3

    -- Encode in 3-byte blocks (excluding remainder)
    for i = 1, n - rem, 3 do
        local b1, b2, b3 = data:byte(i, i + 2)
        local v = (b1 << 16) | (b2 << 8) | b3
        result[#result+1] = B64:sub( (v >> 18)        + 1,  (v >> 18)        + 1 )
        result[#result+1] = B64:sub(((v >> 12) & 63)  + 1, ((v >> 12) & 63)  + 1 )
        result[#result+1] = B64:sub(((v >>  6) & 63)  + 1, ((v >>  6) & 63)  + 1 )
        result[#result+1] = B64:sub( (v        & 63)  + 1,  (v        & 63)  + 1 )
    end

    -- 2-byte remainder → trailing "="
    if rem == 2 then
        local b1, b2 = data:byte(n - 1, n)
        local v = (b1 << 16) | (b2 << 8)
        result[#result+1] = B64:sub( (v >> 18)        + 1,  (v >> 18)        + 1 )
        result[#result+1] = B64:sub(((v >> 12) & 63)  + 1, ((v >> 12) & 63)  + 1 )
        result[#result+1] = B64:sub(((v >>  6) & 63)  + 1, ((v >>  6) & 63)  + 1 )
        result[#result+1] = "="
    -- 1-byte remainder → trailing "=="
    elseif rem == 1 then
        local b1 = data:byte(n)
        local v  = b1 << 16
        result[#result+1] = B64:sub( (v >> 18)        + 1,  (v >> 18)        + 1 )
        result[#result+1] = B64:sub(((v >> 12) & 63)  + 1, ((v >> 12) & 63)  + 1 )
        result[#result+1] = "=="
    end

    return table.concat(result)
end

--- Base64 decode (Base64 string → binary string)
function Crypto.base64_decode(s)
    -- Remove extra characters like whitespace and newlines
    s = s:gsub("[^A-Za-z0-9%+%/=]", "")

    -- Decode table (character code → 6-bit value)
    local dt = {}
    for i = 0, 25 do dt[65 + i] = i      end  -- A-Z → 0-25
    for i = 0, 25 do dt[97 + i] = 26 + i  end  -- a-z → 26-51
    for i = 0,  9 do dt[48 + i] = 52 + i  end  -- 0-9 → 52-61
    dt[43] = 62   -- '+'
    dt[47] = 63   -- '/'
    dt[61] = 0    -- '=' (padding; treated as 0 in calculation)

    local result = {}
    for i = 1, #s, 4 do
        local c1, c2, c3, c4 = s:byte(i, i + 3)
        local v = (dt[c1] << 18) | (dt[c2] << 12) |
                  (dt[c3] <<  6) |  dt[c4]
        result[#result+1] = string.char((v >> 16) & 0xFF)
        result[#result+1] = string.char((v >>  8) & 0xFF)
        result[#result+1] = string.char( v        & 0xFF)
    end

    -- Remove padding bytes
    local pad = 0
    if     s:sub(-2) == "==" then pad = 2
    elseif s:sub(-1) == "="  then pad = 1 end

    local decoded = table.concat(result)
    if pad > 0 then decoded = decoded:sub(1, -pad - 1) end
    return decoded
end

------------------------------------------------------------------------
-- URI / URL Percent-Encoding
------------------------------------------------------------------------

--- URI encode (unified url_encode for Azure SAS / uri_encode for SigV4)
--- @param s          string   String to encode
--- @param keep_slash boolean  If true, '/' is not encoded (for SigV4 path)
function Crypto.uri_encode(s, keep_slash)
    return s:gsub(
        "([^0-9A-Za-z%-%.%_%~" .. (keep_slash and "/" or "") .. "])",
        function(c)
            return string.format("%%%02X", c:byte())
        end
    )
end
