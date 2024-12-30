/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Checks when the Sophos Journals were first created. This is a useful check if  |
| you aren't arn't getting the data you expected.                                |
|                                                                                |
| Version: 1.0                                                                   |
| Author: @AltShiftPrtScn                                                        |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT
strftime('%Y-%m-%dT%H:%M:%SZ',datetime(btime,'unixepoch')) AS Journals_Created,
'File' AS Data_Source,
'Sophos.02.0' AS Query
FROM file WHERE directory LIKE 'C:\ProgramData\Sophos\Endpoint Defense\Data\Event Journals\'