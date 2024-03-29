/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Create a process tree of running processes on a machine.                       |
|                                                                                |
| Version: 1.1                                                                   |
| Author: Sophos & @AltShiftPrtScn                                               |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

WITH RECURSIVE
proc_tree(pid, level, startTime, cmdLine, procName) AS 
(  
    SELECT 
        p.pid, 
        0, 
        p.start_time, 
        p.cmdLine, 
        p.name
    FROM processes p
    /* Get all processes without running parents (root / orphan processes) */
    WHERE p.parent = 0 OR p.parent NOT IN (SELECT DISTINCT pid FROM processes p2 WHERE p2.start_time <= p.start_time AND pid = p.parent)
    UNION ALL
    /* Add each process with a parent in proc_tree to the table at the level it is down from a root */
    SELECT 
        p.pid, 
        proc_tree.level + 1, 
        p.start_time, 
        p.cmdLine, 
        p.name
    FROM processes p
    JOIN proc_tree 
        ON p.parent = proc_tree.pid
        AND proc_tree.startTime <= p.start_time
    WHERE p.parent != 0
    ORDER BY 2 DESC
)
SELECT
    strftime('%Y-%m-%dT%H:%M:%SZ', datetime(pt.startTime,'unixepoch')) Process_Start_Time,
    /* Add an indentation for every level the process is from it's root */
    CASE
    WHEN pt.level = 0 THEN pt.procName
    ELSE printf('%.' || pt.level ||'c', '>') || ' ' || pt.procName
    END AS Process_Branch,
    spp.sophos_pid AS Sophos_PID,
    pt.cmdLine AS CMDLine,
    spp.sha256 AS SHA256
FROM proc_tree pt
LEFT JOIN sophos_process_properties spp
    ON spp.pid = pt.pid