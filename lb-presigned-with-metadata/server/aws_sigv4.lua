AwsSigV4 = {}
--[[
  aws_sigv4.lua
  AWS Signature Version 4 (SigV4) - Pure Lua Implementation
  No external libraries required. Uses Lua 5.3+ native bitwise operators.

  Dependency: crypto.lua (same directory)
    Shared module providing SHA-256 / HMAC-SHA256 / URI encoding / conversion helpers.

  Usage:
    local SigV4 = require("server/aws_sigv4")  -- or load with loadfile/dofile

    local date     = "20240101"
    local datetime = "20240101T000000Z"
    local bucket   = "my-bucket"
    local region   = "ap-northeast-1"
    local s3_key   = "uploads/photo.jpg"
    local host     = bucket .. ".s3." .. region .. ".amazonaws.com"
    local body     = ""   -- PUT body (pass binary content if applicable)

    local result = SigV4.sign({
        method     = "PUT",
        host       = host,
        path       = "/" .. s3_key,
        query      = "",                              -- no query parameters
        headers    = {
            ["host"]                 = host,
            ["x-amz-date"]           = datetime,
            ["x-amz-content-sha256"] = SigV4.sha256(body),
            ["content-type"]         = "image/jpeg",
        },
        payload    = body,
        access_key = "AKIAIOSFODNN7EXAMPLE",
        secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        region     = region,
        service    = "s3",                            -- service name: "s3", "execute-api", etc.
        date       = date,
        datetime   = datetime,
    })

    -- Attach to HTTP request headers and send the PUT request
    -- Required headers: Authorization, x-amz-date, x-amz-content-sha256
    print(result.authorization)
    -- e.g.: AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20240101/ap-northeast-1/s3/aws4_request,
    --       SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date,
    --       Signature=<64-character hex string>

--]]

------------------------------------------------------------------------
-- Query string builder
------------------------------------------------------------------------

--- Convert a parameter table to a SigV4 canonical query string
--- @param params table  { key = value, ... }
--- @return string canonical query string
function AwsSigV4.BuildCanonicalQuery(params)
    local entries = {}
    for k, v in pairs(params) do
        entries[#entries + 1] = { Crypto.uri_encode(tostring(k)), Crypto.uri_encode(tostring(v)) }
    end
    -- Sort by key ascending; sort by value ascending for identical keys
    table.sort(entries, function(a, b)
        if a[1] == b[1] then return a[2] < b[2] end
        return a[1] < b[1]
    end)
    local parts = {}
    for _, e in ipairs(entries) do
        parts[#parts + 1] = e[1] .. "=" .. e[2]
    end
    return table.concat(parts, "&")
end

------------------------------------------------------------------------
-- SigV4 signing
------------------------------------------------------------------------

--[[
  SigV4Sign(opts) → signature result table

  opts fields:
    method      (string)  HTTP method, e.g. "GET", "PUT"
    host        (string)  Hostname,    e.g. "s3.amazonaws.com"
    path        (string)  URI path,    e.g. "/bucket/key" (defaults to "/")
    query       (string)  Canonical query string, e.g. BuildCanonicalQuery({...}) or ""
    headers     (table)   Header table  required: host, x-amz-date
                           e.g. { ["host"] = "...", ["x-amz-date"] = "20240101T000000Z" }
    payload     (string)  Request body; use "" for GET requests
    access_key  (string)  AWS access key ID
    secret_key  (string)  AWS secret access key
    region      (string)  AWS region,  e.g. "ap-northeast-1"
    service     (string)  AWS service, e.g. "s3", "execute-api"
    date        (string)  Date YYYYMMDD, e.g. "20240101"
    datetime    (string)  Datetime ISO8601, e.g. "20240101T000000Z"

  Return table:
    authorization  (string) Authorization header value
    payload_hash   (string) SHA-256 hash of the payload (hex)
    signed_headers (string) Semicolon-delimited list of signed header names
    signature      (string) Signature value (hex)
--]]
function AwsSigV4.SigV4Sign(opts)
    local method       = opts.method:upper()
    local path         = opts.path or "/"
    local query        = opts.query or ""
    local payload      = opts.payload or ""

    -- 1 Payload hash: use explicit x-amz-content-sha256 header value if provided
    --   (e.g. "UNSIGNED-PAYLOAD" for client-side uploads where body is unknown)
    local payload_hash = (opts.headers and opts.headers["x-amz-content-sha256"])
                         or Crypto.sha256(payload)

    -- 2 Canonical headers: lowercase, trim values, sort by name ascending
    local hdr_list     = {}
    for k, v in pairs(opts.headers) do
        hdr_list[#hdr_list + 1] = { k:lower(), Crypto.trim(v) }
    end
    table.sort(hdr_list, function(a, b) return a[1] < b[1] end)

    local canonical_hdr_lines = {}
    local signed_names = {}
    for _, h in ipairs(hdr_list) do
        canonical_hdr_lines[#canonical_hdr_lines + 1] = h[1] .. ":" .. h[2]
        signed_names[#signed_names + 1] = h[1]
    end
    -- Per spec, the canonical header block requires a trailing newline
    local canonical_headers_str = table.concat(canonical_hdr_lines, "\n") .. "\n"
    local signed_headers_str    = table.concat(signed_names, ";")

    -- 3 Canonical request
    local canonical_request     = table.concat({
        method,
        Crypto.uri_encode(path, true), -- preserve '/' within the path
        query,
        canonical_headers_str,
        signed_headers_str,
        payload_hash,
    }, "\n")

    -- 4 Signing scope & string to sign
    local scope                 = opts.date .. "/" .. opts.region .. "/" ..
        opts.service .. "/aws4_request"

    local string_to_sign        = table.concat({
        "AWS4-HMAC-SHA256",
        opts.datetime,
        scope,
        Crypto.sha256(canonical_request),
    }, "\n")

    -- 5 Derive signing key
    --   HMAC(HMAC(HMAC(HMAC("AWS4"+secret, date), region), service), "aws4_request")
    local signing_key           = Crypto.hmac_sha256_bytes("AWS4" .. opts.secret_key, opts.date)
    signing_key                 = Crypto.hmac_sha256_bytes(signing_key, opts.region)
    signing_key                 = Crypto.hmac_sha256_bytes(signing_key, opts.service)
    signing_key                 = Crypto.hmac_sha256_bytes(signing_key, "aws4_request")

    -- 6 Signature
    local signature             = Crypto.hmac_sha256(signing_key, string_to_sign)

    -- 7 Authorization header
    local authorization         = string.format(
        "AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
        opts.access_key, scope, signed_headers_str, signature
    )

    return {
        authorization  = authorization,
        payload_hash   = payload_hash,
        signed_headers = signed_headers_str,
        signature      = signature,
    }
end
