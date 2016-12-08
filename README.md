# SAMS - System Analysis of eMail messageS (v0.1_beta)
The automatic analysis of emails containing malware

This project is the evolution idea, that was presented at [ZeroNights x04](http://2014.zeronights.ru/defensive.html#karkul) together with Pavel Kulikov.

## Project purposes:
- To automate the process of handling and analysis of emails, that contain potentially unsafe files.
- To reveal unknown threats and response to them, ISS (information security systems) support.
- To collect and aggregate IOCs for their usage in ISS and SOC monitoring systems.

## SAMS capability:
- Handling and filtering email using certain specific feature.
- Extracting and identification attachment types
- Reviewing and unpacking archived files
- Statical and dynamical analysis:
    - Incidents DB
    - Local IOCs DB (feed TI and research incidents)
    - ClamAV (Касперский Антивирус и Др.Веб*)
    - Yara
    - Cuckoo Sandbox
- Indicators checking in public aggregators IOCs:
    - TotalHash
    - VirusTotal
    - ThreatExpert
- IOCs collecting and aggregation (MongoDB)

## Executable files filtering:
- exe, scr, js, vbs, bat, cmd, com, class, jar, lnk, pif, hta, wsf

## Archive file types support:
- rar, zip, tar, gzip (tgz, gz, bz2), 7z, cab\*, arj\*, ace\*

------------------------------------------------

This version is development state, we do not recommend to use in production

------------------------------------------------

# Installation
modules:
  py7zlib (install module PyLZMA)
  rarfile
  GeoIP (pip install GeoIP after emerge -a dev-libs/geoip)
  pymongo (emerge -a pymongo (v.<3.0))
Install mongo (emerge -a mongodb)
Create folder (queue, analysis/malware, tmp, backup)
