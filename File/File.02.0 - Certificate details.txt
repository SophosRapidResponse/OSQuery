/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Lists code signing status for files you specify (executables, bundles,         |
| installers, disks), also includes timestamps, hashes, size etc.                |
|                                                                                |
| VARIABLES                                                                      |
| string_type(string) - original_program_name, serial_number, issuer_name,       |
|                       subject_name, result                                     |
| value(string) - search string value                                            |
| path1(file path) - file path                                                   |
| path2(file path) - file path                                                   |
| path3(file path) - file path                                                   |
|                                                                                |
| TIP                                                                            |
| If you don't want to use all the path variables, just fill the unwanted ones   |
| with garbage data that wont get a match e.g. zzzzz                             |
| If you want to match on all certificate strings then just use 'result' for the |
| type and put % for the value.                                                  |
|                                                                                |
| Version: 1.0                                                                   |
| Author: @AltShiftPrtScn                                                        |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT 
f.path AS Path,
a.original_program_name AS Cert_Original_Program_Name,
a.serial_number AS Cert_Serial_Number,
a.issuer_name AS Cert_Issuer_name,
a.subject_name AS Cert_Subject_Name,
a.result AS Cert_Result,
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
'File/Hash/Authenticode' AS Data_Source,
'File.02.0' AS Query
FROM file f 
JOIN hash h ON f.path = h.path
JOIN authenticode a ON f.path = a.path
WHERE (f.path LIKE '$$path1$$' OR f.path LIKE '$$path2$$' OR f.path LIKE '$$path3$$') AND a.$$string_type$$ LIKE '$$value$$' AND f.filename != '.'