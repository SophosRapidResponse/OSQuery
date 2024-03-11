/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Greps the MASV log file to identify if uploads have taken place via the app    |
|                                                                                |
| Ref: https://massive[.]io                                                      |
|                                                                                |
| Query Type: Endpoint                                                           |
| Author: The Rapid Response Team                                                |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT grep.*
	FROM file
	CROSS JOIN grep ON (grep.path = file.path)
	WHERE 
  file.path LIKE 'C:\Users\%\AppData\Roaming\masv\logs\main.log'
  AND
	grep.pattern IN ('upload','Upload')
