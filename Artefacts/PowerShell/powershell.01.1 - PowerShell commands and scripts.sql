/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Get event IDs 400 and 800 from the Windows PowerShell event log and the        |
| 'sophos_powershell_events' journal within a specified time range.              |
|                                                                                |
| IMPORTANT                                                                      |
| This query can bring back large script blocks, if you are exporting these to   |
| CSV and opening in Excel then be warned that individual cells in Excel can     |
| hold a maximum of 32,767 characters, any more than this will get cut off, if   |
| you open the file in NotePad for example though, the whole script will be      |
| there. So if you spot a long script that ends abruptly open it in NotePad to   |
| double check.                                                                  |
|                                                                                |
| REFERENCE                                                                      |
| https://attack.mitre.org/techniques/T1059/001/                                 |
|                                                                                |
| Query Type: Endpoint                                                           |
| Version: 1.5                                                                   |
| Author: The Rapid Response Team                                                |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

WITH ps_methods(detection,indicator) AS (
    VALUES
    ('download','System.Net.Webclient'),
    ('download','System.Net.Http.HttpClient'),
    ('download','Start-BitsTransfer'),
    ('Base64 Encoded Content','FromBase64String'),
    ('Mimikatz','mimikatz'),
    ('Mimikatz','-dumpcr'),
    ('Mimikatz','sekurlsa::pth'),
    ('Mimikatz','kerberos::ptt'),
    ('Mimikatz','kerberos::golden'),
    ('PowerSploit','Kerberoast'),
    ('Windows Defender','-MpPreference'),
    ('download',' curl '),
    ('download',' Invoke-WebRequest'),
    ('download',' Invoke-RestMethod'),
    ('Bit Job','Start-BitsTransfer'),
    ('encoding',' -enc'),
    ('Shadows Copy',' vssadmin.exe '),
    ('encoding',' -e '),
    ('PsExec','-PSExec'),
    ('Netview',' Invoke-Netview'),
    ('decrypt RC4 algorithm',' Invoke-RC4'),
    ('File Modification',' Set-Content'),
    ('File Deletion',' Remove-Item'),
    ('Compress Files', ' Compress-Archive'),
    ('Execute Commands remotely', ' Invoke-Command'),
    ('PS Remote', ' Invoke-PSRemoting'),
    ('Save to file',' -OutFile ')
),

windows_powershell AS (   
SELECT
'Windows PowerShell' AS data_source,
strftime('%Y-%m-%dT%H:%M:%SZ',swe.datetime) AS date_time,  
swe.eventid AS event_id,
mm.detection || ' : ' ||  mm.indicator AS suspicious,
REGEX_MATCH(swe.data,'UserId=(.*?)(?=\\n)',1) AS username,
CAST(REGEX_MATCH(swe.data,'HostName=(.*?)(?=\\n)',1) AS TEXT) AS hostname,
CAST(REGEX_MATCH(swe.data, 'HostApplication=(.*?)(?=\\n)', 1) AS TEXT) AS command,
CAST(REGEX_MATCH(swe.data, 'ScriptName=(.*?)(?=\\n)', 1) AS TEXT) AS script_path,   
NULL AS script_block_count,
NULL AS script_block, 
'Powershell.01.1' AS query
FROM sophos_windows_events swe
LEFT JOIN ps_methods mm ON command LIKE '%' ||  mm.indicator || '%'
WHERE swe.source = 'Windows PowerShell'
   AND swe.eventid IN ('400','800')
   AND command <> '.'
   AND swe.time >= $$start_time$$
   AND swe.time <= $$end_time$$
GROUP BY datetime
), 

powershell_operational AS (
SELECT 
'PowerShell/Operational' AS data_source,
strftime('%Y-%m-%dT%H:%M:%SZ',datetime) AS date_time, 
NULL AS event_id, 
mm.detection || ' : ' ||  mm.indicator AS suspicious,
NULL AS username,
NULL AS hostname,
NULL AS command,
script_path,   
script_block_count,
script_text AS script_block,
'Powershell.01.1' AS query
FROM sophos_powershell_events 
LEFT JOIN ps_methods mm ON script_block LIKE '%' ||  mm.indicator || '%'
WHERE  time >= $$start_time$$
      AND time <= $$end_time$$
GROUP BY datetime
)

SELECT * FROM windows_powershell

UNION  

SELECT * FROM powershell_operational