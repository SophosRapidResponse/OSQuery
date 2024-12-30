/*************************** Sophos.com/RapidResponse ********************************\
| DESCRIPTION                                                                         |
| The query uses Yara to check for evidence of Rclone, Ngrok, and Tor in the system by|
| scanning specific directories. It is important to use wildcard (%) after the        |
| directory name. This allows Yara to search the entire directory and all its         |
| subdirectories.                                                                     |
|                                                                                     |
| VARIABLE                                                                            |
| directory (STRING): The directory from which the scan will start.                   |
|                                                                                     |
| Author: The Rapid Response Team | Elida Leite                                       |
| github.com/SophosRapidResponse                                                      |
\**************************************************************************************/

WITH Signature_Rules(Yara_Sig_Rule) AS (
SELECT '
rule rclone_binaries {
meta:
  description = "Detects rclone binary based on known strings"
  filetype    = "exe"
  reference   = "https://rclone.org/"
strings:
   $url = "https://rclone.org"
   $s1 = "The Rclone Authors" ascii wide
condition:
  uint16(0) == 0x5a4d and all of them
}
rule Rclone_Config_Files {
meta:
  description = "Detects Rclone config file"
  filetype    = "conf"
  reference   = "https://rclone.org/"
strings:
  $s1 = "type =" ascii
  $s2 = "user =" ascii 
  $s3 = "pass =" ascii
condition:
 filesize < 10KB and all of them
}
rule ngrok_binaries {
meta:
  description = "Detects Ngrok binary based on known strings"
  filetype    = "exe"
strings:
  $config_url = "https://ngrok.com" nocase
  $s1 = "tcp.ngrok.io"
  $s2 = "ngrokService"
condition:
  uint16(0) == 0x5a4d  and  any of them
}
rule Ngrok_Config_Files {
meta:
  description = "Detects Ngrok config file based on known strings"
strings:
  $s1 = "proto: tcp" ascii
  $s2 = "addr:" ascii fullword
  $s3 = "authtoken:" ascii fullword
condition:
 filesize < 200KB and all of them
}
rule GenericTor{
meta:
    description = "Detect Tor binaries based on known strings"
    filetype    = "exe"
strings:
    $url = "https://www.torproject.org" nocase
    $string1 = "HiddenService"
    $string2 = "control_port"
    $string3 = "/torrc"
 condition:
    uint16(0) == 0x5a4d and 2 of ($url, $string1, $string2, $string3)
}' AS Yara_Sig_Rule
)

SELECT
y.matches AS rule_detected,
y.path,
datetime(file.btime, 'unixepoch') AS creation_time,
datetime(file.mtime, 'unixepoch') AS modified_time,
h.sha256,
'Yara' AS Data_Source,
'Rclone and other tools' AS Query
FROM yara y
JOIN file ON y.path = file.path
LEFT JOIN hash h ON y.path = h.path
WHERE sigrule IN (SELECT Yara_Sig_Rule FROM Signature_Rules)
  AND y.path LIKE '$$directory$$'
  AND count > 0;