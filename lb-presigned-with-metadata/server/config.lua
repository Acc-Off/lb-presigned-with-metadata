Config = {}

Config.Target = "AzureBlob" -- "AzureBlob" or "AwsS3"
Config.Azure = {}
Config.Azure.AccountName = "your_account_name"
Config.Azure.AccountKey = "your_account_key"
Config.Azure.ContainerName = "your_container_name"

Config.AwsS3 = {}
Config.AwsS3.AccessKey = "your_access_key"
Config.AwsS3.SecretKey = "your_secret_key"
Config.AwsS3.Region = "your_region"
Config.AwsS3.BucketName = "your_bucket_name"