fx_version 'cerulean'
game 'gta5'
lua54 'yes'

title 'lb-presigned-with-metadata'
description 'A FiveM script to upload files to AWS S3/Azure Blob with metadata support for lb-phone/lb-tablet'
author 'Acc-Off'


shared_scripts {
    '@ox_lib/init.lua',
    'shared/*.lua',
}

client_scripts {
    'client/*.lua',
}

server_scripts {
    'server/*.lua',
}

dependency 'ox_lib'