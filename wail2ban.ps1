################################################################################
#                        _ _ ____  _                 
#         __      ____ _(_) |___ \| |__   __ _ _ __  
#         \ \ /\ / / _` | | | __) | '_ \ / _` | '_ \ 
#          \ V  V / (_| | | |/ __/| |_) | (_| | | | |
#           \_/\_/ \__,_|_|_|_____|_.__/ \__,_|_| |_|
#   
################################################################################
# 
# BETA - Added functionality for staged banning levels. 
# BETA - Added exponential ban times, currently based on 5^x
#
# For help, read the below function. 
#
function help { 
	"`nwail2ban   `n"
	"wail2ban is an attempt to recreate fail2ban for windows, hence [w]indows f[ail2ban]."
	" "
	"wail2ban takes configured events known to be audit failures, or similar, checks for "+`
	"IPs in the event message, and given sufficient failures, bans them for a small amount"+`
	"of time."
	" "
	"Settings: "
	" -debug     : Debug the code, coloured messages to stdout"
	" -monitor   : Minimal coloured messages to std out, and file. "
	" -verbose   : Log a heap of messages to file"	
	" -quiet     : Run the code with no output anywhere, log, stdout or event log"
	" -config    : show the settings that are being used "
	" -jail      : show the currently banned IPs"
	" -jailbreak : bust out all the currently banned IPs"	
    " -help      : This message."
	" "
}

################################################################################
#  Constants

$CHECK_WINDOW = 120  # We check the most recent X seconds of log.         Default: 120
$CHECK_COUNT  = 5    # Ban after this many failures in search period.     Default: 5
	
################################################################################
#  Files

$wail2banInstall = ""+(Get-Location)+"\"
$wail2banScript  = $wail2banInstall+"wail2ban.ps1"
$logFile         = $wail2banInstall+"wail2ban_log.log"
$ConfigFile      = $wail2banInstall+"wail2ban_config.ini"
$BannedIPLog = $wail2banInstall+"bannedIPLog.ini"

################################################################################
# Constructs

$RecordEventLog     = "Application"     # Where we store our own event messages
$FirewallRulePrefix = "wail2ban block:" # What we name our Rules
$SchTaskName        = "wail2ban Unban"  # What we name our scheduled tasks

$EventTypes = "Application,Security,System"	  #Event logs we allow to be processed

$EventAddSuccess = 1001
$EventFailureModifier = 100
$EventAddFailure = $EventAddSuccess + $EventFailureModifier
$EventRemoveSuccess = 1010
$EventRemoveFailure = $EventRemoveSuccess + $EventFailureModifier

New-Variable -Name RegexIP -Force -Value ([regex]'(?<First>2[0-4]\d|25[0-5]|[01]?\d\d?)\.(?<Second>2[0-4]\d|25[0-5]|[01]?\d\d?)\.(?<Third>2[0-4]\d|25[0-5]|[01]?\d\d?)\.(?<Fourth>2[0-4]\d|25[0-5]|[01]?\d\d?)')

# Ban Count structure
$BannedIPs = @{}
# Incoming event structure
$CheckEvents = New-object system.data.datatable("CheckEvents")
$null = $CheckEvents.columns.add("EventLog")
$null = $CheckEvents.columns.add("EventID")
$null = $CheckEvents.columns.add("EventDescription")
	  
$WhiteList = @()
$host.UI.RawUI.BufferSize = new-object System.Management.Automation.Host.Size(100,50)

#You can overload the BlockType here for 2003, if you feel like having fun. 
$OSVersion = invoke-expression "wmic os get Caption /value"
if ($OSVersion -match "2008") { $BLOCK_TYPE = "NETSH" }

#Grep configuration file 
switch -regex -file $ConfigFile {
    "^\[(.+)\]$" {
		$Header = $matches[1].Trim()
    }
    "^\s*([^#].+?)\s*=\s*(.*)" {
		$Match1 = $matches[1]
		$Match2 = $matches[2]
		
		if ( $EventTypes -match $Header ) { 
			$row = $CheckEvents.NewRow()
			$row.EventLog = $Header
			$row.EventID = $Match1
			$row.EventDescription = $Match2
			$CheckEvents.Rows.Add($row)
		} else { 
			switch ($Header) { 
			"Whitelist" { $WhiteList += $Match1; }		
			}	
		}
    }
	
} 
#Also add the Remove Success Logger (from schtasks)
$row = $CheckEvents.NewRow()
$row.EventLog = $RecordEventLog
$row.EventID =  $EventRemoveSuccess
$row.EventDescription = "Event Remove Success"
$CheckEvents.Rows.Add($row)

#We also want to whitelist this machine's NICs.
$SelfList = @() 
foreach ($listing in ((ipconfig | findstr [0-9].\.))) {
	if ($listing -match "Address" ){ 	$SelfList += $listing.Split()[-1] }
} 

################################################################################
# Functions

# Log to event log, if allowed.
function log_event ($text,$task,$result) { 
	if 	   ($quiet) { <#do nothing#> } 
	else { 
		$event = new-object System.Diagnostics.EventLog($RecordEventLog)
		$event.Source="wail2ban"
		switch  ($task) { 
			"ADD"    { $logeventID = $EventAddSuccess }
			"REMOVE" { $logeventID = $EventRemoveSuccess }
		}
		switch ($result) { 
			"FAIL"   { $eventtype=[System.Diagnostics.EventLogEntryType]::Error; $logeventID += $EventFailureModifier }
			default  { $eventtype=[System.Diagnostics.EventLogEntryType]::Information}
		}
		#write the constructed entry
		$event.WriteEntry($text,$eventType,$logeventID)
	}
}

#Log output based on output type
function log ($text, $type, $colour) { 
	if     ($quiet)  {	}
	elseif ($verbose){ if ("ERROR,ACTION,WARNING,INFORMATION" -match $type) { $output = "File" } } 
	elseif ($debug)  { $output = "StdOut" } 
	elseif ($normal) { if ("ERROR,ACTION" -match $type) {  $output = "File";  } }
	elseif ($monitor){ 
		if ("ERROR,ACTION,WARNING,INFORMATION" -match $type) { $output = "File StdOut";} 
	}
	if ($output -match "File")   { (Get-Date -format G) +" - $text" | Out-File $logfile -Append} 
	if ($output -match "StdOut") { write-host ( ""+(Get-Date -format G) +" - $text") -foregroundcolor "$colour"}
} 

#Log type functions
function log_error       ($text) { log $text ERROR red }
function log_actioned    ($text) { log $text ACTION green }
function log_warning     ($text) { log $text WARNING yellow} 
function log_information ($text) { log $text INFORMATION cyan }
function log_debug       ($text) { log $text DEBUG white }

#Get the current list of wail2ban bans
function get_jail_list {
	$fw = New-Object -ComObject hnetcfg.fwpolicy2 
	return $fw.rules | Where-Object { $_.name -match $FirewallRulePrefix } | Select name, description
}

# Confirm if rule exists.
function rule_exists ($IP) { 
	switch($BLOCK_TYPE) {
		"NETSH" { $Rule = "netsh advfirewall firewall show rule name=`"$FirewallRulePrefix $IP`""}
		default { log_error "Don't have a known Block Type. $BLOCK_TYPE" }
	}
	if ($rule) { 
		$result = invoke-expression $rule
		if ($result -eq "No rules match the specified criteria." ) {
			return "No"
		}  else { 
			return "Yes"
		}
	}
}

#Convert subnet Slash (e.g. 26, for /26) to netmask (e.g. 255.255.255.192)
function netmask($MaskLength) { 
	$IPAddress =  [UInt32]([Convert]::ToUInt32($(("1" * $MaskLength).PadRight(32, "0")), 2))
	$DottedIP = $( For ($i = 3; $i -gt -1; $i--) {
	  $Remainder = $IPAddress % [Math]::Pow(256, $i)
	  ($IPAddress - $Remainder) / [Math]::Pow(256, $i)
	  $IPAddress = $Remainder
	 } )

	Return [String]::Join('.', $DottedIP)
}
  
#check if IP is whitelisted
function whitelisted($IP) { 
	foreach ($white in $Whitelist) {
		if ($IP -eq $white) { $Whitelisted = "Uniquely listed."; break} 
		if ($white.contains("/")) { 
			$Mask =  netmask($white.Split("/")[1])
			$subnet = $white.Split("/")[0]
			if ((([net.ipaddress]$IP).Address          -Band ([net.ipaddress]$Mask).Address ) 	-eq`
				(([net.ipaddress]$subnet).Address -Band ([net.ipaddress]$Mask).Address )) { 
				$Whitelisted = "Contained in subnet $white"; break;
			}
		}
	}
	return $Whitelisted
} 

#Read in the saved file of settings. Only called on script start, such as after reboot
function pickupBanDuration { 
#
	if (Test-Path $BannedIPLog) { 
		log_debug "Read in Banned IP Log from file $BannedIPLog"
		get-content $BannedIPLog | %{ 
			#log_debug "$($_.split(" ")[0]) is $($_.split(" ")[1])"	
			$BannedIPs.Add($_.split(" ")[0],$_.split(" ")[1])
		}			
	} else { log_debug "No IPs to collect from BannedIPLog" }
} 

#Get the ban time for an IP, in seconds
function getBanDuration ($IP) {	
	if ($BannedIPs.ContainsKey($IP)) { 
		[int]$Setting = $BannedIPs.Get_Item($IP)
	} else { 
		$Setting = 0
		$BannedIPs.Add($IP,$Setting)
	} 
	$Setting++
	#if ($Setting -lt $BanSetting.length-1) { $Setting++ }
	$BannedIPs.Set_Item($IP,$Setting)
	$BanDuration = [math]::pow(5,$Setting)*60 #$BanSetting[$setting]
	log_debug "IP has the new setting of $setting, being $BanDuration seconds"		
	if (Test-Path $BannedIPLog) { clear-content $BannedIPLog } else { New-Item $BannedIPLog -type file }
	$BannedIPs.keys  | %{ "$_ "+$BannedIPs.Get_Item($_) | Out-File $BannedIPLog -Append }
	return $BanDuration
}

# Ban the IP (with checking)
function jail_lockup ($IP, $ExpireDate) { 
	log_debug "Going to go about banning $IP"
	$result = whitelisted($IP)
	if ($result) { log_warning "$IP is whitelisted, except from banning. Why? $result " } 
	else {
		if (!$ExpireDate) { 
			$BanDuration = getBanDuration($IP)
			$ExpireDate = (Get-Date).AddSeconds($BanDuration)
		}
		log_debug "Going to ban $IP for $BanDuration seconds, expiry $ExpireDate"
	
		if ((rule_exists $IP) -eq "Yes") { log_warning ("IP $IP already blocked.")
		} else {
			if ($BanDuration -gt 0) {
				firewall_add $IP $ExpireDate; timed_release $IP $BanDuration}
			else {
				firewall_add $IP "None, permanent ban"
				log_information "Wowserz! $IP has been permabanned!"; log_event "IP $IP has been permabanned."
			}
		}
	}
}

# Unban the IP (with checking)
function jail_release ($IP) { 
	log_debug "Going to release IP $IP"
	if ((rule_exists $IP) -eq "No") { log_information "$IP firewall listing doesn't exist. Can't remove it. "
	} else {  
		firewall_remove $IP
	}
}

# Add the Firewall Rule
function firewall_add ($IP, $ExpireDate) { 
	if ($ExpireDate -match "permanent") { $FirewallRule = "wail2ban: Permenant ban"; $BanType = "Permenant" }
    else { $FirewallRule = $FirewallRulePrefix;  $BanType = "Temporary" }
	switch($BLOCK_TYPE) {
		"NETSH" {
		$Rule = "netsh advfirewall firewall add rule name=`"$FirewallRule $IP`" dir=in protocol=any action=block remoteip=$IP description=`"Expire: $ExpireDate`"" }
		default { log_error "Don't have a known Block Type. $BLOCK_TYPE" }
	}
	if ($rule) { 
		log_debug "Firewall rule: $rule"
		$result = invoke-expression $rule
		if ($result -contains "Ok.") {
			$BanMsg = "$BanType firewall rule added for $IP"
			log_actioned "$BanMsg"
			log_event "$BanMsg" ADD OK
		} else { 
			$Message = "Failure adding $($BanType.ToLower()) firewall rule for $IP Error: $result"
			log_error $Message 
			log_event $Message ADD FAIL
		}
	}
}

# Remore the Filewall Rule
function firewall_remove ($IP) { 
	switch($BLOCK_TYPE) {
		"NETSH" { $Rule = "netsh advfirewall firewall delete rule name=`"$FirewallRulePrefix $IP`""}
		default { log_error "Don't have a known Block Type. $BLOCK_TYPE" }
	}	 
	if ($rule) { 
		log_debug "Firewall rule: $Rule"
		$result = invoke-expression $rule
		if ($result -match "Ok.") {
			log_actioned "Firewall rule removed for $IP"
			log_event "Removed IP $IP from firewall rules"  REMOVE OK
		} else { 
			$Message = "Failure removing firewall rule for $IP : $result" 
			log_error $Message
			log_event $Message REMOVE FAIL
		}
	}
}

#Remove any expired bans
function unban_old_records {
	$jail = get_jail_list
	if ($jail) { 
		foreach ($inmate in $jail) { 		
			$IP = $inmate.Name.substring($FirewallRulePrefix.length+1)
			$ReleaseDate = $inmate.Description.substring("Expire: ".Length)
			
			if ($ReleaseDate -lt ((Get-Date))) { 
				jail_release $IP 
			} else { 					
				if ($ReleaseDate -match 'None') 
					{ log_debug "Current rule: $IP, permabanned." 
				} else { 
					#log_debug "Current Rule: $IP, til $ReleaseDate, $([int]([datetime]$ReleaseDate- (Get-Date)).TotalSeconds)s to go."
				} 
			}
		}
	}	
}

#Convert the TimeGenerated time into Epoch
function WMIDateStringToDateTime( [String] $iSt ) { 
	$iSt.Trim() > $null 
	$iYear   = [Int32]::Parse($iSt.SubString( 0, 4)) 
	$iMonth  = [Int32]::Parse($iSt.SubString( 4, 2)) 
	$iDay    = [Int32]::Parse($iSt.SubString( 6, 2)) 
	$iHour   = [Int32]::Parse($iSt.SubString( 8, 2)) 
	$iMinute = [Int32]::Parse($iSt.SubString(10, 2)) 
	$iSecond = [Int32]::Parse($iSt.SubString(12, 2)) 
	$iMilliseconds = 0 	
	$iUtcOffsetMinutes = [Int32]::Parse($iSt.Substring(21, 4)) 
	if ( $iUtcOffsetMinutes -ne 0 )  { $dtkind = [DateTimeKind]::Local } 
    else { $dtkind = [DateTimeKind]::Utc } 
	$ReturnDate =  New-Object -TypeName DateTime -ArgumentList $iYear, $iMonth, $iDay, $iHour, $iMinute, $iSecond, $iMilliseconds, $dtkind
	return (get-date $ReturnDate -UFormat "%s")
} 

# Set up a scheduled task to release the banned IP
function timed_release ($IP, $BanDuration) { 
    $date = (get-date).AddSeconds($BanDuration)
	if ($date -lt (get-date)) { log_debug "!!!!! You can't schedule events to execute in the past" }
	else {
		$time = (get-date $date -format HH:mm)
		$date =  (get-date $date -format dd/MM/yyyy)
		$invoke = "schtasks /create /tn `"$SchTaskName $IP`"  /TR `"powershell $wail2banScript -unban $IP`" /sc ONCE  /sd $date /st $time /f  /NP /RL HIGHEST"
		log_debug "Invoke remove task: $invoke"
		$output = invoke-expression $invoke

		if ($output -match "SUCCESS") { 
			log_debug "Task '$SchTaskName $IP' created successfully" 
		} else { 
			log_error "Task '$SchTaskName $IP' creation failed: $output" 
		}	
	}
} 

# Remove recorded access attempts, by IP, or expired records if no IP provided.
function clear_attempts ($IP = 0) {
	$Removes = @()
	foreach ($a in $Entry.GetEnumerator()) { 
		if ($IP -eq 0) { 
			if ([int]$a.Value[1]+$CHECK_WINDOW -lt (get-date ((get-date).ToUniversalTime()) -UFormat "%s")) { $Removes += $a.Key }
		} else { 
			foreach ($a in $Entry.GetEnumerator()) { if ($a.Value[0] -eq $IP) {	$Removes += $a.Key } } 		
		}
	} 
	foreach ($b in $Removes) { $Entry.Remove($b)} 
}

################################################################################
#Process input parameters

if ($args -match "-debug") { 
	$debug = "debug";  $setting = "Mode: debug"
} elseif ($args -match "-verbose") { 
	$verbose = "verbose"; $setting = "Mode: verbose"
} elseif ($args -match "-monitor") { 
	$monitor = "monitor"; $setting = "Mode: monitor"
} elseif ($args -match "-quiet") { 
	$quiet = "quiet"
} else {$normal = "normal" }

if ($setting) { log_information "wail2ban started. $setting" }

#Display current configuration.
if ($args -match "-config") { 
	write-host "`nwail2ban is currently configured to: `n ban IPs for " -nonewline
	write-host "various" -foregroundcolor "cyan" -nonewline
	write-host " minutes, `n if more than " -nonewline
	write-host $CHECK_COUNT -foregroundcolor "cyan" -nonewline
	write-host " failed attempts are found in a " -nonewline
	write-host $CHECK_WINDOW -foregroundcolor "cyan" -nonewline
	write-host " second window. `nThis process will loop every time a new record appears. "
	"`nIt's currently checking:"
	foreach ($event in $CheckEvents ) { 
		if ($Event.EventID -ne 1010) { "- "+$Event.EventLog+" event log for "+$Event.EventDescription+" (Event "+$Event.EventID+")"}
	}
	"`nAnd we're whitelisting: "
	foreach ($white in $whitelist) { 
		"- $($white)"
	} 
	exit 0
} 

# Release all current banned IPs
if ($args -match "-jailbreak") { 
	$EnrichmentCentre = get_jail_list
	if ($EnrichmentCentre){		
		"`nAre you trying to escape? [chuckle]"
		"Things have changed since the last time you left the building."
		"What's going on out there will make you wish you were back in here."
		" "
		foreach ($subject in $EnrichmentCentre) { 
		
			$IP = $subject.name.substring($FirewallRulePrefix.length+1)
			firewall_remove $IP
			"$IP restriction removed"
		}
	} else { "`nYou can't escape, you know. `n`n(No current firewall listings to remove.)" }
	exit 0
}


# Show the inmates in the jail.
if ($args -match "-jail") { 
	$inmates = get_jail_list 
	if ($inmates) { 	
		"wail2ban currently banned listings: `n" 
		foreach ($a in $inmates) { 
			$IP = $a.name.substring($FirewallRulePrefix.length+1)
			$Expire = $a.description.substring("Expire: ".length)
			""+$IP.PadLeft(14)+" expires at $Expire"
		}		
		"`nThis is a listing of the current Windows Firewall with Advanced Security rules, starting with `""+$FirewallRulePrefix+" *`""
	} else { "There are no currrently banned IPs"}
	
	exit 0
} 

#Unban specific IP. Remove associated schtask, if exists. 
if ($args -match "-unban") {     
    $IP = $args[ [array]::indexOf($args,"-unban")+1] 
	jail_release $IP
	$output = invoke-expression "schtasks /delete /tn `"$SchTaskName $IP`" /f"
	
	if ($output -match "SUCCESS") { 
		log_debug "Task $SchTaskName deleted successfully" 
	} else { 
		log_error "Task $SchTaskName deletion failed: $output" 
	}	
	exit 0
}

#Display Help Message
if ($args -match "-help") { 
	help
	exit 0
}

################################################################################
#Setup for the loop

$SinkName = "LoginAttempt"
$Entry = @{}
$eventlist ="("
foreach($a in $CheckEvents) { 
    $eventlist+="(TargetInstance.EventCode=$($a.EventID) and TargetInstance.LogFile='$($a.EventLog)') OR " 
}
$eventlist = $eventlist.substring(0,$eventlist.length-4)+")"
$query = "SELECT * FROM __instanceCreationEvent WHERE TargetInstance ISA 'Win32_NTLogEvent' AND $eventlist"

log_debug "The Query: $query"
log_information "The Whitelist: $whitelist"
log_debug "The Self-list: $Selflist"

pickupBanDuration

log_debug "  * start * `n "

#Hardcore logging

$ErrorActionPreference="SilentlyContinue"; Stop-Transcript | out-null
$ErrorActionPreference = "Continue"
$null = Start-Transcript -path $wail2banInstall\superlog.log -append

################################################################################
#Loop!

Register-WMIEvent -Query $query -sourceidentifier $SinkName
do { #bedobedo
	#log_debug "Waiting for new event.."
	$new_event = wait-event -sourceidentifier $SinkName  
	$TheEvent = $new_event.SourceeventArgs.NewEvent.TargetInstance
	
	select-string $RegexIP -input $TheEvent.message -AllMatches | foreach { foreach ($a in $_.matches) {
		$IP = $a.Value 		
		if ($SelfList -match $IP) { log_debug "Whitelist of self-listed IPs! Do nothing. ($IP)" }
		else {	
			$RecordID = $TheEvent.RecordNumber
			$EventDate = WMIDateStringToDateTime($TheEvent.TIMEGenerated)
		
			if ( ($EventRemoveSuccess,$EventRemoveSuccess+$EventFailureModifer) -match $TheEvent.EventCode) { 
                log_actioned "Firewall rule removed for $IP"}
			else {
				$Entry.Add($RecordID, @($IP,$EventDate))

				$IPCount = 0
				foreach ($a in $Entry.Values) { if ($IP -eq $a[0]) { $IPCount++} }		
				log_debug "Event Recorded: $($RecordID): IP: $IP, Event ID: $($TheEvent.EventCode). Count: $IPCount. "							
				
				if ($IPCount -ge $CHECK_COUNT) { 
					jail_lockup $IP		
					clear_attempts $IP
				} 	
			}
		}
	}}
	
	#Empty the sink, gurgle gurgle. 
	Remove-event  -sourceidentifier $SinkName  
	
    #Clear out old event records
	clear_attempts
	
    #Clear out old jail records, if they exist
	unban_old_records
	
} while ($true)

$null = Stop-transcript | out-null
