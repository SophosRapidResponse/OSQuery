/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Identify accounts that belongs to special groups and have valid shells         |
|                                                                                |
|                                                                                |
|                                                                                |
| Version: 1.0                                                                   |
| Author: The Rapid Response Team                                                |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/


SELECT 
    users.username, 
    user_groups.uid, 
    groups.groupname, 
    users.directory As home_directory,
    users.shell As default_shell,
    shadow.password_status,
    'Users/Users_group/Groups/Shadow' AS Data_Source,
    'Account in special groups.01.0' AS Query
FROM user_groups JOIN users USING(uid)
JOIN groups USING (gid)
JOIN shadow USING (username)
WHERE 
    groups.groupname IN ('sudo','root','shadow','disk','wheel') 
    AND username != 'root'
    AND users.shell NOT LIKE '%/sbin/nologin'
