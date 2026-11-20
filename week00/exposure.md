No funcionaron los comandos indicados asi que busque otros.


PS C:\Users\matir> Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort, OwningProcess, @{Name="ProcessName"; Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}} | Format-Table -AutoSize

LocalAddress   LocalPort OwningProcess ProcessName
------------   --------- ------------- -----------
::                 58995          5920 AcerPixyService
::                 49722          1888 services
::1                49675          6100 jhi_service
::                 49672          5540 spoolsv
::                 49669          4112 svchost
::                 49668          2904 svchost
::                 49665          1812 wininit
::                 49664          1916 lsass
::                 46760          3536 AcerSysMonitorService
::1                42050          7568 OneDrive.Sync.Service
::                 33060          8168 mysqld
::                 15150         13492 NitroSense
::                  7680          2672 svchost
::1                 7679         20768 GoogleDriveFS
::                  5141          5952 AcerQAAgent
::                  4449          5912 AcerDIAgent
::                  4343          5904 AcerCCAgent
::                  3306          8168 mysqld
::                   445             4 System
::                   135          1976 svchost
0.0.0.0            63323         16388 SpotifyLauncher
127.0.0.1          58982         10580 Code
127.0.0.1          54433             4 System
127.0.0.1          51782          5944 ADESv2Svc
127.0.0.1          51781          5944 ADESv2Svc
127.0.0.1          51780          5944 ADESv2Svc
127.0.0.1          51779          5944 ADESv2Svc
127.0.0.1          51706         27268 llama-server
127.0.0.1          51334         20920 RiotClientServices
127.0.0.1          51254         10580 Code
127.0.0.1          50870         15068 ollama app
127.0.0.1          50431         23988 Code
0.0.0.0            49722          1888 services
0.0.0.0            49672          5540 spoolsv
0.0.0.0            49669          4112 svchost
0.0.0.0            49668          2904 svchost
0.0.0.0            49665          1812 wininit
0.0.0.0            49664          1916 lsass
127.0.0.1          46933          6440 AcerAgentService
127.0.0.1          46753          3536 AcerSysMonitorService
127.0.0.1          19443          5988 AcerEZService
127.0.0.1          15152          8668 AcerService
127.0.0.1          11434         16324 ollama
127.0.0.1           9993         13492 NitroSense
0.0.0.0             5040          7564 svchost
192.168.56.1         139             4 System
192.168.18.146       139             4 System
0.0.0.0              135          1976 svchost
