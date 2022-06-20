/**************************** Sophos.com/RapidResponse ****************************\
| DESCRIPTION                                                                        |
| The query gets the event id 12 in the Microsoft-Windows-VHDMP-Operational log which|
| can be used to determine the presence and use of a Virtual Hard Drive (VHD) in the |
| system. Also, the query looks at shortcut files associated with an ISO, IMG, VHD or|
| VHDX files as these have been seen often in phishing attacks.                      |
|                                                                                    |
| The events can be FP on servers but suspicious on workstations                     |
|                                                                                    |
| Version: 1.0                                                                       |
| Author: Lee Kikpatrick & Elida Leite                                               |
| github.com/SophosRapidResponse                                                     |
\**********************************************************************************/

SELECT DISTINCT
JSON_EXTRACT(swe.data, '$.EventData.VhdFile') As Filepath,
regex_match(JSON_EXTRACT(swe.data, '$.EventData.VhdFile'),'([^\\]+)\.*$',0) As filename,
strftime('%Y-%m-%dT%H:%M:%SZ',swe.datetime) AS Creation_time,
'-' AS Modified_time,
swe.source,
swe.eventid AS EventID,
'EVTX' AS Data_Source,
'T1566.001 - ISO/Images files' AS Query 
FROM sophos_windows_events swe
WHERE swe.source = 'Microsoft-Windows-VHDMP-Operational' 
AND swe.eventid = 12
AND (swe.data LIKE '%.iso%')
GROUP BY Filepath

UNION

SELECT
f.path AS Filepath,
f.filename,
strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.btime,'unixepoch')) AS Creation_time, 
strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.mtime,'unixepoch')) AS Modified_time, 
'Shortcut Files' AS source,
'-' AS EventID,
'File' AS Data_Source,
'T1566.001 - ISO/Images files' AS Query
FROM file f
WHERE f.path LIKE 'C:\Users\%\AppData\Roaming\Microsoft\%\Recent\%'
AND (f.filename LIKE '%.iso.lnk' OR f.filename LIKE '%.img.lnk' OR f.filename LIKE '%.vhd.lnk' OR f.filename LIKE '%.vhdx.lnk')
GROUP BY Filepath
ORDER BY Creation_time DESC