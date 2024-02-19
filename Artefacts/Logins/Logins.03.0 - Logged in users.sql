/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| List of currently logged in users.                                             |
|                                                                                |
| Version: 1.0                                                                   |
| Author: Sophos / @AltShiftPrtScn                                               |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT
strftime('%Y-%m-%dT%H:%M:%SZ', datetime(time,'unixepoch')) datetime,
type,
user,
tty,
sid,
registry_hive,
'Logged In Users' AS Data_Source,
'Logins.03.0' AS Query
FROM logged_in_users