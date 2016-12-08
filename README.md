# SAMS - System Analysis of eMail messageS (v0.1_beta)
The automatic analysis of emails containing malware

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

## Installation
### Modules:
  - pylzma (>=0.4.8)
  - rarfile (>=2.6)
  - GeoIP (>=1.3.2,pip install GeoIP after emerge -a dev-libs/geoip)
  - pymongo (>=3.2.2)
  - python-magic (=0.4.6)
  - python-ldap (>=2.4.19)
  - Yara (3.5.0) - https://github.com/VirusTotal/yara/releases
  - PyClamd (0.3.17) - http://xael.org/pages/pyclamd-en.html

### APPs:
  - MongoDB

## Initial configuration
### Create folder:
  - queue,
  - analysis/malware,
  - tmp,
  - backup
