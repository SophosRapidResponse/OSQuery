/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| List all current named pipes on the system and lists ones associated with      |
| applications used by attackers. TACTIC: Lateral Movement                       |
|                                                                                |
| REFERENCE                                                                      |
| https://attack.mitre.org/techniques/T1570                                      |
| Author: The Rapid Response Team                                                |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

WITH suspicious_pipes(pipe_name,pattern) AS (VALUES

    ('lsadump','credential_dump_tools'),
    ('cachedump','credential_dump_tools'),
    ('wceservicepipe','credential_dump_tools'),
    ('psexec','PsExec_pipes'),
    ('paexec','PsExec_pipes'),
    ('remcom','PsExec_pipes'),
    ('csexec','PsExec_pipes'),
    ('mojo.5688.8052.183894939787088877','CobaltStrike_pattern'),
    ('mojo.5688.8052.35780273329370473','CobaltStrike_pattern'),
    ('mypipe-f','CobaltStrike_pattern'),
    ('mypipe-h','CobaltStrike_pattern'),
    ('ntsvcs_','CobaltStrike_pattern'),
    ('scerpc_','CobaltStrike_pattern'),
    ('DserNamePipe','CobaltStrike_pattern'),
    ('srvsvc_','CobaltStrike_pattern'),
    ('status_','CobaltStrike_pattern'),
    ('MSSE-','Default Cobalt Strike Artifact Kit binaries'),
    ('msagent_','Default SMB beacon'),
    ('postex_','post exploitation CobaltStrike_pattern'),
    ('spoolss_','CobaltStrike_pattern'),
    ('winsock','CobaltStrike_pattern'),
    ('win_svc','CobaltStrike_pattern'),
    ('^[0-9a-f]{7,10}$','post exploitation before version 4.2 CobaltStrike_pattern'),
    ('dce_86','CobaltStrike_pattern')
)
SELECT
    p.name As named_pipe,
    sp.pattern As suspicious,
    proc.name As process_name,
    proc.cmdline As cmdline,
    proc.path As process_path,
    p.pid,
    strftime('%Y-%m-%dT%H:%M:%SZ', datetime(proc.start_time,'unixepoch')) As process_start_time,
    p.instances As pipe_instances,
    p.max_instances As pipe_max_instances,
    p.flags As pipe_flags,
    hash.sha256 AS process_sha256,
    proc.parent As process_parent_pid,
    pp.path AS parent_process_path,
    pp.name AS parent_process_name,
    'Pipes/Processes' AS Data_Source,
    'Process.09.0' AS Query
FROM pipes p
LEFT JOIN suspicious_pipes sp ON p.name LIKE regex_match(p.name,sp.pipe_name,0)||'%'
JOIN processes AS pp ON pp.pid = proc.parent
JOIN processes proc ON proc.pid = p.pid
LEFT JOIN hash ON hash.path = proc.path