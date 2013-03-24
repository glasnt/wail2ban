#wail2ban  statistics
$wail2banInstall = ""+(Get-Location)+"\"
$BannedIPLog   = $wail2banInstall+"bannedIPLog.ini"
$logFile         = $wail2banInstall+"wail2ban_log.log"

$HTMLFile = $wail2banInstall+"public_html/index.html"
function html ($a) { $a | out-file $HTMLFile -append }
""|out-file $HTMLFile; clear-content $HTMLFile

$BannedIPs = @{}; if (Test-Path $BannedIPLog) { get-content $BannedIPLog | %{ 
	if (!$BannedIPs.ContainsKey($_.split(" ")[0])) { $BannedIPs.Add($_.split(" ")[0],$_.split(" ")[1]) }
} }

$BannedIPSum = 0; $BannedIPs.keys  | %{$BannedIPSum += [int]($BannedIPs.Get_Item($_))}
$TotalBans   = 0; $BannedIPs.GetEnumerator() | % { $TotalBans += [math]::pow(5,$_.value) }
$MaxBanCount = ($BannedIPs.GetEnumerator() | sort-object value -descending | select-object -first 1).Value

gc $logFile | %{	if($_ -match "Firewall ban for "){$BanCount--} 
	                if($_ -match "Firewall rule added for "){$BanCount++} }

$SinceLine = gc $logfile | select-object -first 1
gc $logfile | %{ if ($_ -match "jailbreak") {$SinceLine = $_ } }
$Since = $SinceLine.substring(0,$SinceLine.indexOf("  "))

$ExeTime =  $([int]((get-date) - [datetime]$Since).TotalMinutes)
$nbsp = "&nbsp; &nbsp;  "

html "<title>wail2ban statistics for  $((gc env:computername).ToLower())</title>"
html "<table><tr><td><img src=`"wail2ban.png`" alt=`"Saddest Whale`" /></p>"
html "</td><td>&nbsp;</td><td><H1>wail2ban statistics for $((gc env:computername).ToLower())</H1>"
html "<p>Bans: $BanCount current, $BannedIPSum total ($([math]::round($TotalBans/60,0)) hours)</p>"
html "An IP is banned once every $([math]::round($ExeTime/$BannedIPSum,0)) minutes, on average.<br/>"
html "This script has dealt $([math]::round($TotalBans / $ExeTime,0)) minutes of banhammer per minute of script execution.</p>"
html "These IPs have all been banned $MaxBanCount times, and are currently serving $([math]::round([math]::pow(5,$MaxBanCount)/60,0))  hours in jail.<br/><br/>"

html "<table>"
$TableColumns = 4; $out = 0; 
$BannedIPs.GetEnumerator() | sort-object name  |%{ if ($_.value -eq $MaxBanCount) {
	html "<td>$($_.Name)</td><td><a href=`"http://ip.robtex.com/$($_.name).html`#whois`" target=_blank><img src=`"http://api.hostip.info/flag.php?ip=$($_.Name)`" height=20 width=35> </a></td><td>$nbsp</td>" 
	$out++
	if ($out %$TableColumns -eq 0) { html "</tr><tr>" }
}}
html "</table>"

html "<br/><br/><small>click the flag for robtex information for the IP<br/>"
html "<i>Statistics started $(get-date $Since -format u), last updated $(get-date -format u)</i></small></table>"
