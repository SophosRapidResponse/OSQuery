/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Lists all tasks in the Windows Task Scheduler.                                 |
|                                                                                |
| VARIABLES                                                                      |
| name(string) - name of the scheduled task                                      |
| action(string) - action executed by the task                                   |
|                                                                                |
| TIP                                                                            |
| This uses an AND operator, so if you only want to use one variable put a % in  |
| the other one.                                                                 |
|                                                                                |
| Version: 1.2                                                                   |
| Author: @AltShiftPrtScn | Elida Leite                                          |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT
	name AS Name,
	action AS Action,
	path AS Path,
	state AS State,
	(SELECT datetime(f.btime,'unixepoch') from file f 
	 	WHERE (f.path = 'C:\Windows\System32\Tasks' || st.path) 
	 	OR (f.path LIKE 'C:\Windows\Tasks' || st.path||'%')
	 ) AS Creation_time,
	strftime('%Y-%m-%dT%H:%M:%SZ',datetime(last_run_time,'unixepoch')) AS 'Last_Run_Time',
	last_run_message AS Last_Run_Message,
	CASE WHEN next_run_time < 0 THEN 'Not scheduled to run again'
	ELSE strftime('%Y-%m-%dT%H:%M:%SZ',datetime(next_run_time,'unixepoch')) END AS 'Next_Run_Time',
	'Scheduled_Tasks' AS Data_Source,
	'Task.01.0' AS Query
FROM scheduled_tasks st
WHERE name LIKE '$$name$$' AND action LIKE '$$action$$'