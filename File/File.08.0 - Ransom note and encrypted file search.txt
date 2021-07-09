/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| This looks for files with the same name or extension on the root and one       |
| folder down for every logical drive, as well as every users desktop. This is   |
| best used in looking for ransom notes or encrypted files. The intention is     |
| not to find all of them but just get a quick confirmation about whether or not |
| a computer has been affected by a ransomware attack.                           |
|                                                                                |
| VARIABLE                                                                       |
| filename(string) = ransom note name, or extension of encrypted files           |
|                                                                                |
| TIP                                                                            |
| If looking for a file extenstion make sure to include the wildcard e.g. %.ryk  |
|                                                                                |
| Version: 1.0                                                                   |
| Author: @AltShiftPrtScn & Paul Jacobs                                          |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT DISTINCT
path AS Path,
filename AS Filename,
strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.btime,'unixepoch')) AS 'First_Created_On_Disk(btime)', 
strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.ctime,'unixepoch')) AS 'Last_Status_Change(ctime)', 
strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.mtime,'unixepoch')) AS 'Last_Modified(mtime)', 
strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.atime,'unixepoch')) AS 'Last_Accessed(atime)',
'Logical Drives/File' AS Data_Source,
'File.08.0' AS Query
FROM logical_drives JOIN file f ON filename like '$$filename$$'
AND (path LIKE device_ID ||'\%' OR path LIKE device_ID ||'\%\%' OR path LIKE 'C:\Users\%\Desktop\%')
AND filename != '.'