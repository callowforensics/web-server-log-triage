# web-server-log-triage

This script recursively searches a user specified folder containing web server
logs, and finds potentially nefarious commands. The script will locate, and
decode, plain text URL encoded commands that have been issued to a server; it
also attempts to find SQL injection as well as possible encoded commands
(base64 etc). It is a requirement to enter the log type, as each web-server
application has its own intricacies.

arguments:

  -h, --help            show this help message and exit
  
  --input INPUT, -i INPUT
                        the directory within which the web-server logs are
                        stored.
                        
  --output OUTPUT, -o OUTPUT
                        output directory
                        
  --searchterms SEARCHTERMS, -s SEARCHTERMS
                        search_terms.p file
                        
  --type {iis,apache}, -t {iis,apache}
                        enter either "iis" or "apache"
                        
  --mode {full,lite}, -m {full,lite}
                        Full mode: Collects all logs for IPs identified during
                        the search for commands and pieces them together. Lite
                        mode: Just gives a summary of notable commands found
                        (recommended for searching big logs)

Example:

-i /cases/1234/web_server_logs -o /cases/1234/output -t iis -m full -s search_terms.p
