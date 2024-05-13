linops: 10.50.36.204
Winops: 10.50.34.195
un: XTRA1-502-M
pw: PwrvnlOH3ZJbMz4
stack: 19
ip: 10.50.25.150

## New tunneling method

    ssh -MS /tmp/grey student@10.50.25.150 
    **creates a socket in the /tmp directory that hosts info from that IP**
    **to get rid of this, ssh -MS /tmp/grey -O cancel student@10.50.25.150**
    
    ssh -S /tmp/grey dummy -O forward -D9050
    **creates a local forwarder**
    **to get rid of this, ssh -S /tmp/grey dummy -O cancel -D9050**

    ssh -S /tmp/grey dummy -O forward -L1111:192.168.128.100:80
    **creates a local portforward to that ip on port 80**

    ssh -S /tmp/grey dummy -O forward -L1111:192.168.128.100:80 -L2222:192.168.128.100:22
    **if you saw did scans and saw that the .100 had 22, tac on another port forward to ssh**

    netstat -natup **to see if your tunnels worked**
    history **if you've forgotten what ya did.**
    
    
    


## Penetration Testing

    

    
