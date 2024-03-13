/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Collect PowerShell events from the 'Windows PowerShell' event log and the      |
| 'sophos_powershell_events' log which gives you access to a cleaner version of  |
| 'Microsoft-Windows-PowerShell/Operational'.                                    |
|                                                                                |
| TIP                                                                            |
| Results marked as 'Sus' or 'Bad' are a good place to start but they wont be    |
| everything worth investigating. The 'Bad' ones are snippets of Base64 strings  |
| often seen when Cobalt Strike is involved.                                     |
|                                                                                |
| IMPORTANT                                                                      |
| This query can bring back large script blocks, if you are exporting these to   |
| CSV and opening in Excel then be warned that individual cells in Excel can     |
| hold a maximum of 32,767 characters, any more than this will get cut off, if   |
| you open the file in NotePad for example though, the whole script will be      |
| there. So if you spot a long script that ends abruptly open it in NotePad to   |
| double check.                                                                  |
|                                                                                |
| Query Type: Endpoint                                                           |
| Version: 1.3                                                                   |
| Author: @AltShiftPrtScn                                                        |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT  
   strftime('%Y-%m-%dT%H:%M:%SZ',datetime) AS Datetime,
   CASE 
      WHEN REPLACE(REGEX_MATCH(data, "HostApplication=(.*)EngineVersion=", 1), '\n\t', '') LIKE '% JAB%' THEN 'Bad - JAB'
      WHEN REPLACE(REGEX_MATCH(data, "HostApplication=(.*)EngineVersion=", 1), '\n\t', '') LIKE '% SQB%' THEN 'Bad - SQB' 
      WHEN REPLACE(REGEX_MATCH(data, "HostApplication=(.*)EngineVersion=", 1), '\n\t', '') LIKE '%H4s%' THEN 'Bad - H4s' 
      WHEN REPLACE(REGEX_MATCH(data, "HostApplication=(.*)EngineVersion=", 1), '\n\t', '') LIKE '% -enc%' THEN 'Sus - -enc' 
      WHEN REPLACE(REGEX_MATCH(data, "HostApplication=(.*)EngineVersion=", 1), '\n\t', '') LIKE '%IEX%' THEN 'Sus - IEX' 
      WHEN REPLACE(REGEX_MATCH(data, "HostApplication=(.*)EngineVersion=", 1), '\n\t', '') LIKE '%downloadstring%' THEN 'Sus - downloadstring' 
      WHEN REPLACE(REGEX_MATCH(data, "HostApplication=(.*)EngineVersion=", 1), '\n\t', '') LIKE '%COMSPEC%' THEN 'Sus - COMSPEC' 
      WHEN REPLACE(REGEX_MATCH(data, "HostApplication=(.*)EngineVersion=", 1), '\n\t', '') LIKE '%Admin$%' THEN 'Sus - Admin$' 
      WHEN REPLACE(REGEX_MATCH(data, "HostApplication=(.*)EngineVersion=", 1), '\n\t', '') LIKE '%PsEx%' THEN 'Sus - PsEx' 
      WHEN REPLACE(REGEX_MATCH(data, "HostApplication=(.*)EngineVersion=", 1), '\n\t', '') LIKE '%BTOBTO%' THEN 'Sus - BTO' 
      WHEN REPLACE(REGEX_MATCH(data, "HostApplication=(.*)EngineVersion=", 1), '\n\t', '') LIKE '%Set-MpPreference%' THEN 'Sus - Set-MpPreference' 
      WHEN REPLACE(REGEX_MATCH(data, "HostApplication=(.*)EngineVersion=", 1), '\n\t', '') LIKE '%DisableRealtimeMonitoring%' THEN 'Sus - DisableRealtimeMonitoring' 
      WHEN REPLACE(REGEX_MATCH(data, "HostApplication=(.*)EngineVersion=", 1), '\n\t', '') LIKE '%Base64%' THEN 'Sus - Base64 Encoding pattern' 
      WHEN REPLACE(REGEX_MATCH(data, "HostApplication=(.*)EngineVersion=", 1), '\n\t', '') LIKE '%Start-BitsTransfer%' THEN 'Sus - BitsTransfer' 
      WHEN REPLACE(REGEX_MATCH(data, "HostApplication=(.*)EngineVersion=", 1), '\n\t', '') LIKE '%System.Net.WebClient%' THEN 'Sus - WebClient .NET' 
      WHEN REPLACE(REGEX_MATCH(data, "HostApplication=(.*)EngineVersion=", 1), '\n\t', '') LIKE '%System.Net.Http.HttpClient%' THEN 'Sus - WebClient .NET' 
      WHEN REPLACE(REGEX_MATCH(data, "HostApplication=(.*)EngineVersion=", 1), '\n\t', '') LIKE '%Add-MpPreference -Exclusion%' THEN 'Sus - Modifies Windows Defender Setting' 
      WHEN REPLACE(REGEX_MATCH(data, "HostApplication=(.*)EngineVersion=", 1), '\n\t', '') LIKE '%Invoke-RestMethod%' THEN 'Sus - Invoke-RestMethod'
      WHEN REPLACE(REGEX_MATCH(data, "HostApplication=(.*)EngineVersion=", 1), '\n\t', '') LIKE '%Invoke-WebRequest%' THEN 'Sus - Invoke-WebRequest'
      WHEN REPLACE(REGEX_MATCH(data, "HostApplication=(.*)EngineVersion=", 1), '\n\t', '') LIKE '%invoke-mimikatz%' THEN 'Sus - mimikatz'
      WHEN REPLACE(REGEX_MATCH(data, "HostApplication=(.*)EngineVersion=", 1), '\n\t', '') LIKE '%Invoke-Kerberoast%' THEN 'Sus - PowerSploit'
      WHEN REPLACE(REGEX_MATCH(data, "HostApplication=(.*)EngineVersion=", 1), '\n\t', '') LIKE '% curl %' THEN 'Sus - curl' 
   END AS Sus,
   '-' AS Script_Blocks,
   REPLACE(REGEX_MATCH(data, "HostApplication=(.*)EngineVersion=", 1), '\n\t', '') AS Script,
   '-' AS Path,
   'PowerShell EVTX' AS Data_Source,
   'PowerShell Commands and scripts' AS Query
FROM sophos_windows_events 
WHERE source = 'Windows PowerShell' 
   AND eventid = 400
   AND Script !=''
   AND time > 0

UNION ALL

SELECT 
   strftime('%Y-%m-%dT%H:%M:%SZ',datetime) AS Datetime, 
   CASE
      WHEN script_text LIKE '% JAB%' THEN 'Bad - JAB'
      WHEN script_text LIKE '% SQB%' THEN 'Bad - SQB' 
      WHEN script_text LIKE '%H4s%' THEN 'Bad - H4s' 
      WHEN script_text LIKE '% -enc%' THEN 'Sus - "-enc"' 
      WHEN script_text LIKE '%IEX%' THEN 'Sus - IEX' 
      WHEN script_text LIKE '%downloadstring%' THEN 'Sus - downloadstring' 
      WHEN script_text LIKE '%COMSPEC%' THEN 'Sus - COMSPEC' 
      WHEN script_text LIKE '%Admin$%' THEN 'Sus - Admin$' 
      WHEN script_text LIKE '%PsEx%' THEN 'Sus - PsEx' 
      WHEN script_text LIKE '%BTOBTO%' THEN 'Sus - BTO'
      WHEN script_text LIKE '%DisableRealtimeMonitoring%' THEN 'Sus - DisableRealtimeMonitoring'
      WHEN script_text LIKE '%Base64%' THEN 'Sus - Base64 Encoding pattern'
      WHEN script_text LIKE '%Start-BitsTransfer%' THEN 'Sus - Download method' 
      WHEN script_text LIKE '%System.Net.WebClient%' THEN 'Sus - WebClient .NET' 
      WHEN script_text LIKE '%System.Net.Http.HttpClient%' THEN 'Sus - WebClient .NET' 
      WHEN script_text LIKE '%Add-MpPreference -Exclusion%' THEN 'Sus - Modifies Windows Defender Setting' 
      WHEN script_text LIKE '%Invoke-RestMethod%' THEN 'Sus - Invoke-RestMethod'
      WHEN script_text LIKE '%Invoke-WebRequest%' THEN 'Sus - Invoke-WebRequest'
      WHEN script_text LIKE '%invoke-mimikatz%' THEN 'Sus - mimikatz'
      WHEN script_text LIKE '%Invoke-Kerberoast%' THEN 'Sus - PowerSploit'
      WHEN script_text LIKE '% curl %' THEN 'Sus - curl'
   END AS Sus,
   script_block_count AS Script_Blocks,
   script_text AS Script,
   script_path AS Path,
   'Sophos PowerShell Events' AS Data_Source,
   'PowerShell Commands and scripts' AS Query
FROM sophos_powershell_events 
   WHERE time > 0
