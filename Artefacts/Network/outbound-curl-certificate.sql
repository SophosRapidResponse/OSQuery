/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Query to help identify suspicious outbound communication based on certificates |
|                                                                                |
|                                                                                |
|                                                                                |
|                                                                                |
| Query Type: Endpoint                                                           |
| Version: 1.0                                                                   |
| Author: The Rapid Response Team | Lee Kirkpatrick                              |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/


-- Obtain data for non RFC1918 network connections
WITH network_data AS (
    SELECT
        sophos_pid,
        spj.path,
        spj.cmd_line,
        destination,
        destination_port
    FROM sophos_network_journal
    LEFT JOIN sophos_process_journal spj USING (sophos_pid)
    WHERE
        (
            (spj.path NOT LIKE 'C:\ProgramData\Sophos\%' AND spj.path NOT LIKE 'C:\Program Files%\Sophos\%')
            AND NOT (
                destination LIKE '%:%' OR
                destination IN ('127.0.0.1') OR
                in_cidr_block('10.0.0.0/8', destination) OR
                in_cidr_block('172.16.0.0/12', destination) OR
                in_cidr_block('192.168.0.0/16', destination)
            )
        )
    GROUP BY sophos_pid
)

-- Use the sophos_curl_certificate table to obtain certificate details
SELECT
    nd.path,
    nd.cmd_line,
    nd.destination,
    nd.destination_port,
    sc.common_name,
    sc.organization,
    sc.issuer_organization,
    sc.subject_alternative_names,
    sc.valid_to,
    sc.has_expired,
    sc.sha1_fingerprint
FROM
    network_data nd
LEFT JOIN
    sophos_curl_certificate sc ON sc.hostname = nd.destination;
