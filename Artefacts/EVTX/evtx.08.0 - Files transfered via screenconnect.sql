/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Gets logs from file transfer activity in ScreenConnect.                        |
| TACTIC: Command and Control                                                    |
|                                                                                |
| If a threat actor is using the legitimate remote access tool ScreenConnect to  |
| to tranfer files to the victims device, or execute files through               |
| ScreenConnect, these events are recorded in the Application Event log.         |
| Unfortunately only the filename and not the path is recorded. However, using   |
| the Sophos File Journal can reveal this.                                       |
|                                                                                |
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
'EVTX.08.0' AS Query
FROM 
    sophos_windows_events
WHERE 
    source = 'Application'
    AND eventid = 0 
    AND provider_name LIKE '%ScreenConnect%'
    AND data LIKE '%Transferred files%'