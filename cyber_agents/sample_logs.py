"""
Sample Log Files for Defensive Testing of All 6 Agents
"""

SAMPLE_NETWORK_LOGS = [
    "2026-09-17T10:15:01Z src_ip=192.168.1.105 dst_ip=10.0.0.5 port=22 proto=TCP SYN action=connect",
    "2026-09-17T10:15:02Z src_ip=192.168.1.105 dst_ip=10.0.0.5 port=23 proto=TCP SYN action=connect",
    "2026-09-17T10:15:03Z src_ip=192.168.1.105 dst_ip=10.0.0.5 port=80 proto=TCP SYN action=connect",
    "2026-09-17T10:15:04Z src_ip=192.168.1.105 dst_ip=10.0.0.5 port=443 proto=TCP SYN action=connect",
    "2026-09-17T10:15:05Z src_ip=192.168.1.105 dst_ip=10.0.0.5 port=3306 proto=TCP SYN action=connect",
    "2026-09-17T10:15:06Z src_ip=192.168.1.105 dst_ip=10.0.0.5 port=4444 proto=TCP SYN action=connect"
]

SAMPLE_SYSTEM_LOGS = [
    "Sep 17 10:20:01 server01 sshd[12345]: Failed password for admin from 192.168.1.105 port 54321 ssh2",
    "Sep 17 10:20:03 server01 sshd[12345]: Failed password for admin from 192.168.1.105 port 54322 ssh2",
    "Sep 17 10:20:05 server01 sshd[12345]: Failed password for root from 192.168.1.105 port 54323 ssh2",
    "Sep 17 10:20:07 server01 sshd[12345]: Failed password for admin from 192.168.1.105 port 54324 ssh2",
    "Sep 17 10:20:09 server01 sudo: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/bash"
]

SAMPLE_APPLICATION_LOGS = [
    "2026-09-17T10:25:01Z 192.168.1.105 GET /api/users?id=1' UNION SELECT username,password FROM users-- HTTP/1.1 500 text/html",
    "2026-09-17T10:25:03Z 192.168.1.105 POST /api/comment HTTP/1.1 200 application/json body=<script>alert('xss')</script>",
    "2026-09-17T10:25:05Z 192.168.1.105 GET /api/download?file=../../etc/passwd HTTP/1.1 403 text/html",
    "2026-09-17T10:25:07Z 192.168.1.105 GET /admin/console HTTP/1.1 403 text/html"
]

SAMPLE_BENIGN_LOGS = [
    "2026-09-17T10:30:01Z src_ip=10.0.0.12 dst_ip=10.0.0.1 port=443 proto=TCP action=connect status=established",
    "Sep 17 10:30:10 server01 sshd[99999]: Accepted password for analyst from 10.0.0.12 port 55000 ssh2",
    "2026-09-17T10:30:20Z 10.0.0.12 GET /api/dashboard HTTP/1.1 200 application/json"
]
