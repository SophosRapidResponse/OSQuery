/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Lists code signing status for files you specify (executables, bundles,         |
| installers, disks), also includes timestamps, hashes, size etc.                |
|                                                                                |
| VARIABLES                                                                      |
| cert_type(string) - original_program_name, serial_number, issuer_name,         |
|                       subject_name, result                                     |
| cert_value(string) - string to search for in cert_type                         |
| process_type(string) - pid, name, path, cmdline                                |
| process_value(string) - string to search for in process_type                   |
|                                                                                |
| TIP                                                                            |
| To bring everything back just use 'result' and 'pid' for the types and % as    |
| the value.                                                                     |
|                                                                                |
| Version: 1.0                                                                   |
| Author: @AltShiftPrtScn                                                        |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT 
p.pid AS PID,
p.name AS Process_Name,
p.path AS Path,
p.cmdline AS CMDLine,
a.original_program_name AS Cert_Original_Program_Name,
a.serial_number AS Cert_Serial_Number,
a.issuer_name AS Cert_Issuer_name,
a.subject_name AS Cert_Subject_Name,
a.result AS Cert_Result,
'Processes' AS Data_Source,
'Process.01.2' AS Query
FROM processes p 
JOIN authenticode a ON p.path = a.path
WHERE a.$$cert_type$$ LIKE '$$cert_value$$' AND p.$$process_type$$ LIKE '$$process_value$$'