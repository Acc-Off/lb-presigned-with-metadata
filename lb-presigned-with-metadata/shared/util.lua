local RESOURCE_NAME = GetCurrentResourceName()
local LOG_PREFIX    = ("[%s]"):format(RESOURCE_NAME)

Log = {}

function Log.success(msg, ...)
    print(("^2[SUCCESS]^7 %s %s"):format(LOG_PREFIX, msg:format(...)))
end

function Log.info(msg, ...)
    print(("^5[INFO]^7 %s %s"):format(LOG_PREFIX, msg:format(...)))
end

function Log.warning(msg, ...)
    print(("^3[WARNING]^7 %s %s"):format(LOG_PREFIX, msg:format(...)))
end

function Log.error(msg, ...)
    print(("^1[ERROR]^7 %s %s"):format(LOG_PREFIX, msg:format(...)))
end
