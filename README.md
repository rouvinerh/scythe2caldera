# scythe2caldera
Converts SCYTHE profiles from their community threats repository to Caldera profiles. Clone the repository here:
https://github.com/scythe-io/community-threats

NOTE: Only scrapes for `run` module. 

# Usage:
```bash
$ python3 convert.py tactics.json
[+] Generated!
$ ls    
abilities adversaries convert.py mitre_tactics.py tactics.json
```

To reset, run `./reset.sh`