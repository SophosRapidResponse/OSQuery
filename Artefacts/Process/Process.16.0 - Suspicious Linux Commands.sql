/**************************** Sophos.com/RapidResponse ****************************\
| DESCRIPTION                                                                      |
|  Identify potentially malicious activity on a Linux system by retrieving commands|
| commonly used by attackers from the running process events table.                |
|                                                                                  |
| REFERENCE                                                                        |
| https://www.uptycs.com/blog/linux-commands-and-utilities-commonly-used-by-       |
| attackers                                                                        |
| https://bradleyjkemp.dev/sigmadoc/rules/linux/builtin/lnx_shell_susp_commands.yml|
| https://attack.mitre.org/techniques/T1059/004/                                   |
|                                                                                  |
| Query Type: Datalake                                                             |
| Author: The Rapid Response Team | Elida Leite                                    |
| github.com/SophosRapidResponse                                                   |
\**********************************************************************************/


SELECT
    meta_hostname AS hostname,
    replace(replace(CAST(from_unixtime(time) AS VARCHAR),'.000','Z'),' ','T') Datetime,
    name As process_name,
    cmdline,
    parents,
    path,
    gid,
    pids,
    uid,
    euid,
    egid,
    sha256,
    time, 
    'T1059.004 - Suspicious Linux Commands' AS query
FROM xdr_data 
WHERE query_name = 'running_processes_linux_events'
AND (lower(cmdline) like '%base64 -d%' 
	OR lower(cmdline) like '%nc -l%' 
	OR LOWER(cmdline) LIKE '%ncat -%'
	OR lower(cmdline) like '%arp -a %' 
	OR lower(cmdline) like '%chmod %'
	OR lower(cmdline) like '%crontab%' 
	OR lower(cmdline) like '%curl%'
	OR lower(cmdline) like '%ftpget%'
	OR lower(cmdline) like '%tftp%'
	OR lower(cmdline) like '%lwp-download%'
	OR lower(cmdline) like '%sudo %'
	OR lower(cmdline) like '%wget %'
	OR lower(cmdline) like '%/etc/passwd%'
	OR lower(cmdline) like '%/etc/shadow%'
	OR lower(cmdline) like '%~/.bash_history%'
	OR lower(cmdline) like '%useradd %'
	OR lower(cmdline) like '%adduser %'
	OR LOWER(cmdline) LIKE '%xmrig%' 
	OR LOWER(cmdline) LIKE '%krebs%' 
	OR LOWER(cmdline) LIKE '%monero%' 
	OR LOWER(cmdline) LIKE '%miner%'
	OR LOWER(cmdline) LIKE '%chattr%'
	OR LOWER(cmdline) LIKE '%systemctl stop%'
	OR LOWER(cmdline) LIKE '%systemctl disable%'
	OR LOWER(cmdline) LIKE '%ufw disable%'
	OR LOWER(cmdline) LIKE '%kill %'
	OR LOWER(cmdline) LIKE '%pkill %'
	OR LOWER(cmdline) LIKE '%uname -a%'
	OR LOWER(cmdline) LIKE '%authorized_key%'
	OR LOWER(cmdline) LIKE 'python%-m SimpleHTTPServer%'
	OR LOWER(cmdline) LIKE 'python%-m http.server%'
)