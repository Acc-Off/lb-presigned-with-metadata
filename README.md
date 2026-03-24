# lb-presigned-with-metadata

## Overview

Related projects:
- [lbphone/lb-presigned](https://github.com/lbphone/lb-presigned) — A FiveM script to generate presigned URLs for uploading files to R2/S3
- [Acc-Off/lb-presigned-lua](https://github.com/Acc-Off/lb-presigned-lua) — A FiveM script to generate presigned URLs for uploading files to AWS S3/Azure Blob for lb-phone/lb-tablet

Unlike the projects above, **lb-presigned-with-metadata** allows you to attach player metadata (e.g. path, tags) to objects stored in Azure Blob Storage or AWS S3.

This resource uses lb-phone/lb-tablet's BASE64 upload method. The client requests a signed URL from this resource, and the NUI sends the file directly to cloud storage — upload traffic does not pass through the game server.

> [!IMPORTANT]
> This requires LB Phone v2.6.0 or higher, or LB Tablet v1.6.0 or higher.

---

## Installation

### 1. Place the resource

Place `lb-presigned-with-metadata` in your `resources` folder.

### 2. Update server.cfg

Add the following line **before** `ensure lb-phone`:

```
ensure lb-presigned-with-metadata
```

### 3. Configure `lb-presigned-with-metadata\server\config.lua`

#### For Azure Blob Storage

```lua
Config.Target = "AzureBlob" -- "AzureBlob" or "AwsS3"
Config.Azure = {}
Config.Azure.AccountName   = "your_account_name"
Config.Azure.AccountKey    = "your_account_key"
Config.Azure.ContainerName = "your_container_name"
```

#### For AWS S3

```lua
Config.Target = "AwsS3" -- "AzureBlob" or "AwsS3"
Config.AwsS3 = {}
Config.AwsS3.AccessKey  = "your_access_key"
Config.AwsS3.SecretKey  = "your_secret_key"
Config.AwsS3.Region     = "your_region"
Config.AwsS3.BucketName = "your_bucket_name"
```


### 4. Modify lb-phone

> **Note:** If you are using **lb-tablet**, replace all references to `lb-phone` with `lb-tablet` throughout this section.

#### Add the following files

- `lb-phone\client\custom\functions\upload-with-metadata.lua`
- `lb-phone\ui\dist\upload-with-metadata.js`

#### Edit `lb-phone\ui\dist\index.html`

Add the following inside `<head>`:

```html
<script type="text/javascript" crossorigin src="/ui/dist/upload-with-metadata.js"></script>
```

#### Edit `lb-phone\config\config.lua`

Update the upload method values:

```lua
Config.UploadMethod.Video = "UploadWithMetadata"
Config.UploadMethod.Image = "UploadWithMetadata"
Config.UploadMethod.Audio = "UploadWithMetadata"
```

If targeting Azure Blob Storage, add `"windows.net"` to the whitelist:

```lua
Config.UploadWhitelistedDomains = {
    "fivemanage.com",
    "fmfile.com",
    "amazonaws.com", -- lb-presigned (S3)
    "windows.net"
}
```

#### Edit `lb-phone\shared\upload.lua`

Add the `UploadWithMetadata` entry to `UploadMethods`:

```lua
UploadMethods = {
    UploadWithMetadata = {
        Default = {
            url = "https://lb-phone/upload-with-metadata",
            httpMethod = "POST",
            uploadType = "base64",
            bodyTemplate = {
                base64Data = "BASE64_DATA",
                fileExtension = "FILE_EXTENSION",
                playerData = "PLAYER_DATA",
                resourceName = "RESOURCE_NAME"
            },
            error = {
                path = "success",
                value = false
            },
            success = {
                path = "data.url"
            },
            sendPlayer = "metadata",
        }
    },
}
```