local pendingUploads = {}

RegisterNUICallback("upload_finished", function(data, cb)
    local id = data.uploadId
    if pendingUploads[id] then
        pendingUploads[id]:resolve({
            success = data.success,
            error = data.error
        }) 
        pendingUploads[id] = nil
    end
    cb('ok')
end)

RegisterNUICallback("upload-with-metadata", function(body, cb)
    if not body or not body.fileExtension or not body.base64Data or not body.playerData or not body.resourceName then
        return cb({
            success = false,
            error = "Invalid request data"
        })
    end
    local uploadInfo = exports['lb-presigned-with-metadata']:getUploadInfo(body.fileExtension, body.playerData.identifier,
        body.playerData.name, body.resourceName)

    if not uploadInfo then
        return cb({
            success = false,
            error = "Failed to get upload URL"
        })
    end

    local uploadId = math.random(1000, 9999) .. GetGameTimer()
    local p = promise.new()
    pendingUploads[uploadId] = p

    SendNUIMessage({
        action = "execute_upload",
        uploadId = uploadId,
        url = uploadInfo.uploadUrl,
        headers = uploadInfo.headers,
        bodyBase64 = body.base64Data -- base64
    })

    local uploadResult = Citizen.Await(p)

    if not uploadResult.success then
        return cb({
            success = false,
            error = uploadResult.error
        })
    end

    cb({
        success = true,
        data = {
            url = uploadInfo.resourceUrl,
        }
    })
end)
