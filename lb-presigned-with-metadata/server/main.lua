local MIME_TYPES = {
    -- audio
    mp3  = "audio/mpeg",
    mpeg = "audio/mpeg",
    ogg  = "audio/ogg",
    opus = "audio/opus",
    weba = "audio/webm",
    -- video
    mp4  = "video/mp4",
    webm = "video/webm",
    ogv  = "video/ogg",
    -- image
    jpg  = "image/jpeg",
    jpeg = "image/jpeg",
    png  = "image/png",
    webp = "image/webp",
}

local function utc_iso8601(offset_sec)
    return os.date("!%Y-%m-%dT%H:%M:%SZ", os.time() + (offset_sec or 0))
end

lib.callback.register('lb-presigned-with-metadata:getUploadInfo', function(source, data)
    if not data or not data.fileExtension or not data.identifier or not data.name or not data.resourceName then
        Log.error("getUploadInfo: invalid request data from source=%d", source)
        return nil
    end

    if Config.Target == "AzureBlob" then
        local blob_name = string.format("%s/%s/%s/%s%03d.%s",
            data.resourceName, data.identifier,
            os.date("!%Y%m"), os.date("!%H%M%S"), math.random(0, 999), data.fileExtension)

        local az_ok, az_result = pcall(AzureSas.BlobSasSign, {
            account_name   = Config.Azure.AccountName,
            account_key    = Config.Azure.AccountKey,
            container_name = Config.Azure.ContainerName,
            blob_name      = blob_name,
            permissions    = "cwt",
            expiry         = utc_iso8601(600),   -- 10 minutes from now
            protocol       = "https"
        })
        if not az_ok then
            Log.error("AzureSas.BlobSasSign failed (source=%d, blob=%s): %s", source, blob_name, tostring(az_result))
            return nil
        end
        return {
            uploadUrl   = az_result.sasUrl,
            resourceUrl = az_result.url,
            headers     = {
                ["x-ms-blob-type"] = "BlockBlob",
                ["x-ms-tags"] = "identifier="..data.identifier.."&name="..data.name.."&resourceName="..data.resourceName,
                ["Content-Type"]   = MIME_TYPES[data.fileExtension] or "application/octet-stream"
            }
        }
    elseif Config.Target == "AwsS3" then
        local object_key   = string.format("%s/%s/%s/%s%03d.%s",
            data.resourceName, data.identifier,
            os.date("!%Y%m"), os.date("!%H%M%S"), math.random(0, 999), data.fileExtension)
        local host         = Config.AwsS3.BucketName .. ".s3." .. Config.AwsS3.Region .. ".amazonaws.com"
        local datetime     = os.date("!%Y%m%dT%H%M%SZ")
        local date         = os.date("!%Y%m%d")
        local content_type = MIME_TYPES[data.fileExtension] or "application/octet-stream"

        local s3_ok, s3_result = pcall(AwsSigV4.SigV4Sign, {
            method     = "PUT",
            host       = host,
            path       = "/" .. object_key,
            query      = "",
            headers    = {
                ["host"]                 = host,
                ["x-amz-date"]           = datetime,
                ["x-amz-content-sha256"] = "UNSIGNED-PAYLOAD",
                ["x-amz-tagging"]        = "identifier="..data.identifier.."&name="..data.name.."&resourceName="..data.resourceName,
                ["Content-Type"]         = content_type,
            },
            payload    = "",
            access_key = Config.AwsS3.AccessKey,
            secret_key = Config.AwsS3.SecretKey,
            region     = Config.AwsS3.Region,
            service    = "s3",
            date       = date,
            datetime   = datetime,
        })
        if not s3_ok then
            Log.error("AwsSigV4.SigV4Sign failed (source=%d, key=%s): %s", source, object_key, tostring(s3_result))
            return nil
        end
        return {
            uploadUrl   = "https://" .. host .. "/" .. object_key,
            resourceUrl = "https://" .. host .. "/" .. object_key,
            headers     = {
                ["Authorization"]        = s3_result.authorization,
                ["x-amz-date"]           = datetime,
                ["x-amz-content-sha256"] = "UNSIGNED-PAYLOAD",
                ["x-amz-tagging"]        = "identifier="..data.identifier.."&name="..data.name.."&resourceName="..data.resourceName,
                ["Content-Type"]         = content_type,
            }
        }
    else
        Log.error("Unknown Config.Target: '%s'", tostring(Config.Target))
        return nil
    end
end)