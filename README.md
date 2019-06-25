`usage: MaxPatrolParser    [-h] [-p INPUT_PATH] [-o OUTPUT]
                          [-l LEVEL [LEVEL ...]] [-e] [--cve]

optional arguments:
  -h, --help            show this help message and exit
  -p INPUT_PATH, --input-path INPUT_PATH
                        Path to xml file
  -o OUTPUT, --output OUTPUT
                        Path to output file
  -l LEVEL [LEVEL ...], --level LEVEL [LEVEL ...]
                        Level of vulnerability. Like -l 1 2 4 0 - info 1 - low
                        2 - medium (suspicious) 3 - medium 4 - high
                        (suspicious) 5 - high
  -e, --excel           Output into xlsx file
  --cve                 Saves rows in which cve is presented`
  
 Works fine with reports that have 1500 hosts, consumpting 1gb of RAM 
