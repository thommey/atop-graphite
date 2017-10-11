Allows atop metrics to be piped to a TCP socket and reformatted for graphite.

The advantage of atop vs other monitoring tools is the ability to break down resource usage by user (needs externally synchronized passwd file).

Example:

1. `python3 atop.py`
2. `atop -aPPRG,PAG,MDD,CPL,PRM,DSK,SWP,NET,LVM,PRD,PRC,MEM,cpu 10 | lzma | netcat 127.0.0.1 61000`
