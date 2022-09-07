/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Gets the content of the Microsoft Protection Log (MPLog) file stored under the |
| directory C:\ProgramData\Microsoft\Windows Defender\Support. The log stores    | 
| data for troubleshooting purposes for Windows Defender but can be leveraged as |
| a forensic artifact on Windows to support forensic investigations              |   
|                                                                                |
| REFERENCE:                                                                     |
| https://www.crowdstrike.com/blog/how-to-use-microsoft-protection-logging-for-  |
| forensic-investigations/                                                       |  
|                                                                                |
| Version: 1.0                                                                   |
| Author: The rapid Response Team | Elida Leite                                  |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/


WITH File_List AS (
    SELECT 
    path,
    filename, 
    btime,
    mtime 
    FROM file 
    WHERE (path LIKE 'C:\ProgramData\Microsoft\Windows Defender\Support\%' AND filename LIKE 'MPLog-%')
   )

SELECT
    f.path as Path,
    f.filename as Filename,
    datetime(f.btime,'unixepoch') AS creation_time,
    datetime(f.mtime,'unixepoch') AS modified_time,
    (SELECT 
	CAST(GROUP_CONCAT(g.line,CHAR(10)) AS TEXT) 
	FROM grep g 
	WHERE g.pattern IN (CHAR(0),CHAR(10),CHAR(32)) AND g.path = f.path 
	) As File_content,
    'File/Grep' AS Data_Source,
    'Microsoft MPLog' AS Query 
FROM File_List f
WHERE File_content != '' 
ORDER BY creation_time DESC