/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Identifies if the application MASV is installed. Can be used for exfiltration. |
|                                                                                |
| Ref: https://massive[.]io                                                      |
|                                                                                |
| Query Type: Endpoint                                                           |
| Author: The Rapid Response Team                                                |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT 
*
FROM
programs
WHERE 
name LIKE 'MASV%'
