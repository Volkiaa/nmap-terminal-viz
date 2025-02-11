
Simple go script to visualize nmap XML results in terminal



I use nix, so i declared a shell.nix


Usage:

Clone the repo
nix-shell
go build -o nmap-viz ./cmd/nmap-internal-viz/

## Usage

set your NVD Api Key as an env var
```
export NVD_API-KEY="YOURKEYHERE"
```

Run the script

```
./nmap-viz scan.xml
```

example: ./nmap-viz scanme.nmap.org.xml

## Output

```
./nmap-viz scanme.nmap.org.xml
OPEN                                         ██████████████████████████████████████████████████████████████████████████████████████████████████████                         ] 80.00% (4 / 5)
FILTERED                                         █████████████████████████                                                                                                  ] 20.00% (1 / 5)

Port/Service Details
2025/02/11 16:08:17 Querying the NVD API for CVE Infos for OpenSSH 6.6.1p1 (Might be slow)
        2025/02/11 16:08:55 Querying the NVD API for CVE Infos for Apache httpd 2.4.7 (Might be slow)
Details for  45.33.32.156
  PORT  | PROTOCOL |  STATE   |  SERVICE   | APPLICATION  |          VERSION           | CVES | MOST CRITICAL CVE
--------+----------+----------+------------+--------------+----------------------------+------+--------------------
     22 | tcp      | open     | ssh        | OpenSSH      | 6.6.1p1 Ubuntu 2ubuntu2.13 |    0 |
     25 | tcp      | filtered | smtp       |              |                            |    0 |
     80 | tcp      | open     | http       | Apache httpd | 2.4.7                      |   14 | CVE-2021-44224
   9929 | tcp      | open     | nping-echo | Nping echo   |                            |    0 |
  31337 | tcp      | open     | tcpwrapped |              |                            |    0 |
Port 9929 is open on the following IPs: [45.33.32.156]
Port 31337 is open on the following IPs: [45.33.32.156]
Port 22 is open on the following IPs: [45.33.32.156]
Port 25 is open on the following IPs: [45.33.32.156]
Port 80 is open on the following IPs: [45.33.32.156]
Service ssh@6.6.1p1 Ubuntu 2ubuntu2.13 is running on the following IPs: [45.33.32.156]
Service smtp@ is running on the following IPs: [45.33.32.156]
Service http@2.4.7 is running on the following IPs: [45.33.32.156]
Service nping-echo@ is running on the following IPs: [45.33.32.156]
Service tcpwrapped@ is running on the following IPs: [45.33.32.156]
```

The script will also output a folder named "parsedServices" containing a file for each service and the IPs with
said service running.

```
ls parsedService/
http.txt  nping-echo.txt  smtp.txt  ssh.txt  tcpwrapped.txt

cat parsedService/http.txt
45.33.32.156
```
