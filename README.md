wail2ban
========

![Saddest Whale](http://i.imgur.com/NVlsY.png "Saddest Whale")

wail2ban is a windows port of the basic functionality of [fail2ban](http://www.fail2ban.org/), and combining elements of [ts_block](https://github.com/EvanAnderson/ts_block). 


overview
--------

wail2ban is a system that takes incoming failed access events for a customly configurable set of known event ids, and given sufficient failed attacks in a period of time, creates temporary firewall rules to block access. 


installation 
------------

Installing wail2ban is a case of a view simple tasks: 

 * copy all the repository files to a location on the client machine, e.g. `C:\scripts\wail2ban`
 * Using Task Scheduler, import the `start wail2ban onstartup.xml` file to automatically create a scheduled task to start the script when the machine boots. 
 * Initiate the script by running the `start wail2ban.bat` file. This is what the scheduled task starts. 

commandline execution
---------------------

There are a number of options to run wail2ban on the fly. 


 * `-debug`   : run the script with coloured standard out text
 * `-monitor` : run the script, where only the banned IP and unbanned IP messages are displayed in standard out. 
 * `-verbose` : run the script, with a heap of output going to a log file
 * `-quiet`   : run the script, with no output, either to file or standard out. 


There are also a number of options that can be run against the script to control it: 
 
 * `-config` : dumps a parsed output of the configuration file to standard out, including timing and whitelist configurations. 
 * `-jail`   : shows the current set of banned IPs on the machine
 * `-jailbreak`: unbans every IP currently banned by the script. 

technical overview 
------------------

Event logs for various software packages are configured to produce messages when failed connections occur. The contents of the events usually contain an IP, an a message something along the lines of "This IP failed to connect to your server."

Typical examples of this include: 

 * Security Event ID 4625, "Windows Security Auditing". 
  * `An account failed to log in. ... Source Network Address: 11.22.33.44`

Database products also include these kind of events, such as: 

 * Application Event ID 18456, "Microsoft SQL Server".
  *  `Login failed for user 'sa'. Reason: Password did not match that for the login provided. [CLIENT: 11.22.33.44]`

These events are produced any time someone mistypes a password, or similar. 

The issue occurs when automated brute-force entry systems attempt to access systems multiple times a second. 

what wail2ban does
------------------

wail2ban is a real-time event sink for these messages. As messages come in, wail2ban takes note of the time of the attempt and the IP used in the attempt. Given enough attempts in a specific period of time, wail2ban will generate a firewall rule to block all access to the client machine for a certain period of time. 

In a default setup, if an IP attempts 5 failed passwords in a 2 minute period, they get banned from attempting again for a period of time.

How long? Well, that depends on how many times they've been banned before!

There is a file called BannnedIPLog.ini that will keep a count of how many times an IP has been banned. 
 
 * First Offense: 5 minutes
 * Second Offense: 25 minutes
 * Third Offense: 2 hours
 * n Offense: 5 ^ n minutes

This allows for scaling of bans, but prevent permenant bans, which may cause issues in the future as IPs are reassigned around the blagosphere. 

failsafes 
---------

As with all automated systems, there can be some false-positives. 

**Whitelists** - this script can be configured with a whitelist of IPs that it will never ban, such as a company IP block. 

**Self-list** - the script automatically adds a set of IPs to the whitelist that it knows as not to ban, based on the configured static IPs on the host machine. That is, it will ignore attempts from itself (or event logs which list it's own IP in the message). 

**Timeouts** - IPs are only banned for specific period of time. After this time, they are removed from the firewall by the script. In addition, timed scheduled tasks are produced to force the removal of these rules, should the script fail to do so. 

**Jailbreak** - a configuration called `-jailbreak` can be run against the script at any time to immediately remove all banned IPs. 

ongoing work 
------------

This script has room for improvement. Presently, it only handles Windows 2008-style firewall usage. This can be expanded by changing the code near the `BLOCK_TYPE` variable, to overload it. 

There can also be work relating to the service-like execution of this script, so it's always running. This can be acheieved using something like [non-sucking service manager](http://nssm.cc/), but that is left as an exercise for the reader. 


