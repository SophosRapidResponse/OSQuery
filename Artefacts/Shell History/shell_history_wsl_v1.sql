 /*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Pulls the bash history for WSL version 1                                       |
|                                                                                |
|                                                                                |
| Query Type: Endpoint                                                           |
| Author: The Rapid Response Team                                                |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/


SELECT grep.*
FROM file
CROSS JOIN grep ON (grep.path = file.path)
WHERE
(
file.path LIKE 'C:\Users\%\AppData\Local\Packages\%\LocalState\rootfs\root\.bash_history'
OR
file.path LIKE 'C:\Users\%\AppData\Local\Packages\%\LocalState\rootfs\home\%\.bash_history'
)
AND grep.pattern = ' '
