/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Lists processes that are listening on ports.                                   |
|                                                                                |
| VARIABLES                                                                      |
| username(username) = username that launched the process                        |
| path(filepath) = path of the running process                                   |
| port(string) = listening port                                                  |
|                                                                                |
| TIP                                                                            |
| If you want to bring back everything use % for each variable                   |
|                                                                                |
| Version: 1.1                                                                   |
| Author: @AltShiftPrtScn                                                        |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT 
    spp.sophos_pid, 
    u.username,
    spp.path, 
    etc_p.alias AS protocol,
    lp.address,
    lp.port,
    spp.local_rep,
    spp.global_rep,
    spp.pua_score,
    spp.ml_score,
    spp.sha256,
    'Listening Ports' AS Data_Source,
    'Process.03.0' AS Query
FROM listening_ports lp
LEFT JOIN sophos_process_properties spp
    ON spp.pid = lp.pid
LEFT JOIN processes p 
    ON p.pid = spp.pid
LEFT JOIN users u 
    ON u.uid = p.uid
LEFT JOIN etc_protocols etc_p
    ON lp.protocol = etc_p.number
WHERE u.username LIKE '$$username$$' AND spp.path LIKE '$$path$$' AND lp.port LIKE '$$port$$'