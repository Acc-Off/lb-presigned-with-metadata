exports('getUploadInfo', function(fileExtension, identifier, name, resourceName)
    return lib.callback.await('lb-presigned-with-metadata:getUploadInfo', false, { 
        fileExtension = fileExtension,
        identifier = identifier,
        name = name,
        resourceName = resourceName
    })
end)
