/******************************* Sophos.com/RapidResponse *******************************\
| DESCRIPTION                                                                            |
| Returns the patch level of Exchange servers. We recommend you ensure Exchange is always|
| on the latest version.                                                                 |
|                                                                                        |
| MORE INFO                                                                              |
| https://learn.microsoft.com/en-us/exchange/new-features/build-numbers-and-release-dates|
|                                                                                        |
| Version: 1.2                                                                           |
| Author: Sophos MTR                                                                     |
| github.com/SophosRapidResponse                                                         |
\****************************************************************************************/

SELECT DISTINCT
  product_version
FROM file 
WHERE path = 
  ((
    SELECT data FROM registry 
    WHERE key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ExchangeServer\v15\Setup' 
    AND path = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ExchangeServer\v15\Setup\MsiInstallPath' 
  )||'bin\Microsoft.Exchange.RpcClientAccess.Service.exe')