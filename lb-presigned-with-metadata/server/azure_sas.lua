AzureSas = {}
--[[
  azure_sas.lua
  Azure Blob Storage Service SAS (Shared Access Signature) - Pure Lua Implementation
  No external libraries required. Uses Lua 5.3+ native bitwise operators.

  Generates a Service SAS signed URL for PutBlob using an account key (Base64).
  Signing algorithm: HMAC-SHA256 (RFC 2104), service version: 2020-12-06

  Dependency: crypto.lua (same directory)
    Shared module providing SHA-256 / HMAC-SHA256 / Base64 / URI encoding.

  Usage:
    local AzureSAS = require("server/azure_sas")  -- or load with loadfile/dofile
    local result = AzureSAS.sign({
        account_name   = "mystorageaccount",
        account_key    = "base64encodedaccountkey==",
        container_name = "images",
        blob_name      = "uploads/photo.jpg",
        permissions    = "cw",                   -- c=create, w=write (for PutBlob)
        expiry         = "2025-12-31T23:59:59Z",
        -- start       = "2025-01-01T00:00:00Z", -- optional
        -- protocol    = "https",                 -- optional (default: "https")
    })
    print(result.url)  -- signed URL (ready to use as the PUT request target)
--]]

------------------------------------------------------------------------
-- Constants
------------------------------------------------------------------------

local SAS_VERSION = "2020-12-06" -- Azure Storage service version

------------------------------------------------------------------------
-- Azure Blob Service SAS signing
------------------------------------------------------------------------

--[[
  BlobSasSign(opts) → signature result table

  [Algorithm overview]
    1. Build StringToSign (concatenate 16 fields with "\n")
    2. Decode account key (Base64) to a byte string
    3. Compute HMAC-SHA256(key=byte string, data=StringToSign)
    4. Base64-encode the HMAC result → sig value
    5. Assemble the SAS query string and full URL

  [StringToSign structure (version 2020-12-06)]
    signedPermissions      e.g. "cw"
    signedStart            e.g. "2025-01-01T00:00:00Z" or ""
    signedExpiry           e.g. "2025-12-31T23:59:59Z"
    canonicalizedResource  "/blob/{account}/{container}/{blob}"
    signedIdentifier       ""  (no stored access policy)
    signedIP               ""  (no IP restriction)
    signedProtocol         "https" or ""
    signedVersion          "2020-12-06"
    signedResource         "b"  (blob)
    signedSnapshotTime     ""
    signedEncryptionScope  ""
    rscc / rscd / rsce / rscl / rsct  all ""

  opts fields:
    account_name   (string)  Storage account name    e.g. "mystorageaccount"
    account_key    (string)  Account key (Base64)    AccountKey from config.lua
    container_name (string)  Container name          e.g. "images"
    blob_name      (string)  Blob name (path)        e.g. "uploads/abc.jpg"
    permissions    (string)  Access permissions      "cw" = create+write (recommended for PutBlob)
    expiry         (string)  Expiry time UTC ISO8601 e.g. "2025-12-31T23:59:59Z"
    start          (string)  Start time UTC ISO8601  optional (default: "")
    protocol       (string)  "https" or ""           optional (default: "https")

  Return table:
    url    (string) Full signed URL (use as the PUT request target)
    sasUrl = url + "?" + token
    token  (string) SAS token string (without "?"; use to manually append to a URL)
    sig    (string) Base64-encoded HMAC-SHA256 signature value
--]]
function AzureSas.BlobSasSign(opts)
  assert(opts.account_name, "azure_sas: account_name is required")
  assert(opts.account_key, "azure_sas: account_key is required")
  assert(opts.container_name, "azure_sas: container_name is required")
  assert(opts.blob_name, "azure_sas: blob_name is required")
  assert(opts.permissions, "azure_sas: permissions is required")
  assert(opts.expiry, "azure_sas: expiry is required")

  local version            = opts.version or SAS_VERSION
  local start              = opts.start or ""
  local protocol           = opts.protocol or "https"
  local perms              = opts.permissions

  -- canonicalized resource (fixed format starting with /)
  local canonical_resource = "/blob/" .. opts.account_name .. "/"
      .. opts.container_name .. "/"
      .. opts.blob_name

  --[[
      StringToSign: concatenate 16 fields with "\n" (no trailing newline)
      Reference: https://learn.microsoft.com/azure/storage/common/storage-sas-overview
                Service SAS, version 2020-12-06
    --]]
  local string_to_sign = table.concat({
    perms,              -- signedPermissions
    start,              -- signedStart
    opts.expiry,        -- signedExpiry
    canonical_resource, -- canonicalizedResource
    "",                 -- signedIdentifier
    "",                 -- signedIP
    protocol,           -- signedProtocol
    version,            -- signedVersion
    "b",                -- signedResource  ("b" = blob)
    "",                 -- signedSnapshotTime
    "",                 -- signedEncryptionScope
    "",                 -- rscc  (response-cache-control)
    "",                 -- rscd  (response-content-disposition)
    "",                 -- rsce  (response-content-encoding)
    "",                 -- rscl  (response-content-language)
    "",                 -- rsct  (response-content-type)
  }, "\n")

  -- Account key: Base64 → byte string
  local key_bytes      = Crypto.base64_decode(opts.account_key)

  -- HMAC-SHA256 (byte array key × UTF-8 string) → byte array → Base64
  local sig_bytes      = Crypto.hmac_sha256_bytes(key_bytes, string_to_sign)
  local sig_b64        = Crypto.base64_encode(sig_bytes)

  --[[
      SAS token assembly order (following convention):
        sv, sr, sp, [st,] se, [spr,] sig
      The Base64 sig value must be URL-encoded (convert '+', '/', '=' to %XX)
    --]]
  local parts = {
    "sv=" .. version,
    "sr=b",
    "sp=" .. perms,
  }
  if start ~= "" then
    parts[#parts + 1] = "st=" .. Crypto.uri_encode(start)
  end
  parts[#parts + 1] = "se=" .. Crypto.uri_encode(opts.expiry)
  if protocol ~= "" then
    parts[#parts + 1] = "spr=" .. protocol
  end
  parts[#parts + 1] = "sig=" .. Crypto.uri_encode(sig_b64)

  local token = table.concat(parts, "&")

  local url = string.format(
    "https://%s.blob.core.windows.net/%s/%s",
    opts.account_name, opts.container_name, opts.blob_name
  )

  return {
    url    = url,
    sasUrl = string.format("%s?%s", url, token),
    token  = token,
    sig    = sig_b64,
  }
end
