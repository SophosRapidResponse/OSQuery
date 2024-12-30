/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Gets logs of file transfer activity in ScreenConnect from the Application event|
| logs.                                                                          |
|                                                                                |
| Only filenames are recorded in the Application logs. However, analysts can     |
| leverage other sources, such as the Sophos File Journal, to query and obtain   |
| detailed information about the file, including the full file path.             | 
|                                                                                |
| Query Type: Endpoint                                                           |
| Version: 1.0                                                                   |
| Author: @AltShiftPrtScn                                                        |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT 
strftime('%Y-%m-%dT%H:%M:%SZ', datetime) AS date_time,
source,
provider_name,
CASE 
WHEN data LIKE '%Transferred files%' THEN 
	CASE 
       WHEN INSTR(data, 'Version') > 0 THEN 
       SUBSTR(JSON_EXTRACT(data, '$.EventData.Data'), INSTR(JSON_EXTRACT(data, '$.EventData.Data'), ':') + LENGTH(':'),INSTR(JSON_EXTRACT(data, '$.EventData.Data'), 'Version') - INSTR(JSON_EXTRACT(data, '$.EventData.Data'), ':') - LENGTH(':'))
      ELSE JSON_EXTRACT(data, '$.EventData.Data')
	END
END AS file_transfered,
data AS raw_data,
'EVTX' AS data_source,
'EVTX.08.0' AS Query
FROM 
    sophos_windows_events
WHERE 
    source = 'Application'
    AND eventid = 0 
    AND provider_name LIKE '%ScreenConnect%'
    AND data LIKE '%Transferred files%'
    AND time > 0