/******************* Sophos.com/RapidResponse *******************\
| DESCRIPTION                                                    |
| Get the public IP of the device by querying Sophos journals    |
|                                                                |
| Version: 1.0                                                   |
| Author: The Rapid Response Team                                |
| github.com/SophosRapidResponse                                 |
\****************************************************************/


SELECT
	public_ip AS IP,
	'public_ip' AS Source,
	'Get Public IP' AS Query
FROM public_ip