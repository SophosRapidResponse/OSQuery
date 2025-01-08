/*********************** Sophos.com/RapidResponse ***********************\
| DESCRIPTION                                                            |
| Gets a list of applications in Windows Shimcache (AppCompatCache).     |
|                                                                        |
| Version: 1.0                                                           |
| Author: @AltShiftPrtScn                                                |
| github.com/SophosRapidResponse                                         |
\************************************************************************/

SELECT DISTINCT
entry AS execution_order,
path,
strftime('%Y-%m-%dT%H:%M:%SZ',datetime(modified_time,'unixepoch')) AS modified_time,
'Shimcache' AS data_source,
'Shimcache.01.0' AS Query
FROM shimcache