/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Check for files on disk based on path and timestamp, if they exist collect     |
| basic information including path, timestamps, hashes, size etc.                |
|                                                                                |
| VARIABLES                                                                      |
| begin(date) - time_type greater than or equal to                               |
| end(date) -  time_type less than                                               |
| path1(file path) - file path                                                   |
| path2(file path) - file path                                                   |
| path3(file path) - file path                                                   |
| time_type(string) - btime, ctime, mtime, atime                                 |
|                                                                                |
| TIP                                                                            |
| If you don't want to use all the path variables, just fill the unwanted ones   |
| with garbage data that wont get a match e.g. zzzzz                             |
|                                                                                |
| Version: 1.0                                                                   |
| Author: @AltShiftPrtScn                                                        |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT 
f.path AS Path,
f.directory AS Directory,
f.filename AS Filename,
f.size AS Size,
strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.btime,'unixepoch')) AS 'First_Created_On_Disk(btime)', 
strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.ctime,'unixepoch')) AS 'Last_Status_Change(ctime)', 
strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.mtime,'unixepoch')) AS 'Last_Modified(mtime)', 
strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.atime,'unixepoch')) AS 'Last_Accessed(atime)',
h.sha256 AS SHA256,
h.sha1 AS SHA1,
h.md5 AS MD5,
f.attributes AS Attributes,
f.file_version AS File_Version,
'File/Hash' AS Data_Source,
'File.01.1' AS Query
FROM file f JOIN hash h
ON f.path = h.path
WHERE (f.path LIKE '$$path1$$' OR f.path LIKE '$$path2$$' OR f.path LIKE '$$path3$$') AND f.$$time_type$$ >= CAST($$begin$$ AS INT) AND f.$$time_type$$ < CAST($$end$$ AS INT) AND f.filename != '.'