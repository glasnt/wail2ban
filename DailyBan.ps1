################################################################################
# Script that looks up log for failed rdp ssl logins and permaban if amount 
# exceeded. Added this due to a bunch of rate limited rdp-ssl bruteforce 
# attempts that can be detected only on a long run
#
# TODO: stats/logs/etc
################################################################################

$wail2banInstall = ""+(Get-Location)+"\"
$ConfigFile      = $wail2banInstall+"wail2ban_config.ini" # Using only whitelist from config
$Period          = 86400000                               # Depth of log to analyze in milliseconds
$Fails           = 20                                     # Number of fails per $Period for permanent ban


$WhiteList = @()
switch -regex -file $ConfigFile {
    "^\[(.+)\]$" {
		$Header = $matches[1].Trim()
    }
    "^\s*([^#].+?)\s*=\s*(.*)" {
		$Match1 = $matches[1]
		$Match2 = $matches[2]
		
		switch ($Header) { 
		"Whitelist" { $WhiteList += $Match1; }		
		}	
    }
} 

$WhiteList += (Get-NetIPAddress -AddressFamily IPv4).IPAddress

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


$Events = Get-WinEvent -FilterXPath "*[System[EventID=140 and TimeCreated[timediff(@SystemTime) <= $Period]]]" -LogName Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational
$Failed = $Events.Properties.Value | Group-Object | Sort-Object Count | Select-Object Count,Name
$Failed= $Failed | ?{$_.Count -gt $Fails}
$Failed = $Failed.Name
$Rule = Get-NetFirewallRule -DisplayName "Wail2ban persistent" -ErrorAction SilentlyContinue
if (!$Rule) {$Rule = New-NetFirewallRule -DisplayName "Wail2ban persistent" -Action Block -Direction Inbound -Enabled False -Profile Any}
$Exisitng = ($Rule | Get-NetFirewallAddressFilter).RemoteAddress
$TotalList = $Failed+$Exisitng | Sort -Unique
$ApplyList=@()
foreach ($ip in $TotalList){
	if ($ip -notmatch "Any") {
		$res=whitelisted($ip); if(!$res){$ApplyList+=$ip}
	}
}
if ($ApplyList.Count -gt 0){
	$Rule | Set-NetFirewallRule -RemoteAddress $ApplyList -Enabled true
}else{
	$Rule | Set-NetFirewallRule -RemoteAddress "Any" -Enabled false
}
