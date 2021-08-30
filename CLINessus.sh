#!/bin/bash
#
# CLINessus.sh is a program for managing Nessus scans with some extra features.
#
# Options: list all scans, show available templates, show existing policies, show existing scans, create a new scan, delete a scan, launch a scan, pause a scan, 
# resume a scan, stop a current scan, display scan results, export scan results, display export status, download reports (by host or by plugin)
#
#

ipNessus='localhost'
exportTokensFilePath=export.tokens
dbPassword=MySup3rPasSw0rd
listFormat=(pdf csv html nessus db)
checkNessusService=$(curl -s -k -m2 -H "Content-Type: application/json" -H "Cache-Control: no-cache" -X GET https://$ipNessus:8834/server/status | jq .status | tr -d '"')
#checkNessusService=$(service nessusd status | grep -Fio running)
#currentPID=$$

authenticate() {
	sed -i '/export X_NESSUS_TOKEN=.*/d' ~/.bashrc
	read -p "Login:" LOGIN
	read -p "Password:" -r -s PASS

	PASS=$(echo $PASS | sed 's/\\/\\\\/')
	X_COOKIE_TOKEN=$(curl -s -k -H "Content-Type: application/json" -H "Cache-Control: no-cache" -d '{"username":"'$LOGIN'","password":"'$PASS'"}' -X POST https://$ipNessus:8834/session| jq .token | tr -d '"')
	
	if [[ -n "$X_COOKIE_TOKEN" && "$X_COOKIE_TOKEN" != "null" ]]; then
		echo "export X_NESSUS_TOKEN=$X_COOKIE_TOKEN" >> ~/.bashrc
		mkdir -p ~/audit/Nessus
		echo -e "\e[32m\nAuthentication successful !\e[0m"
	else
		echo -e "\e[31m\nInvalid credentials !\e[0m"
	fi
}

checkExportTokens() {
	SCAN_ID=$1
	SCAN_NAME=$2
	EXPORT_TOKEN=$3
	FILE_FORMAT=${4^^}
	GROUP_BY=${5^^}
	if [[ -n "$EXPORT_TOKEN" && "$EXPORT_TOKEN" != "null" ]]; then
		if [[ -n "$GROUP_BY" ]]; then
			echo -e "Scan report generation in progress ! Please wait... \e[32m[SCANID:$SCAN_ID|NAME:$SCAN_NAME|TOKENID:$EXPORT_TOKEN|TYPE:$FILE_FORMAT|GROUPBY:$GROUP_BY]\e[0m"
		else
			echo -e "Scan report generation in progress ! Please wait... \e[32m[SCANID:$SCAN_ID|NAME:$SCAN_NAME|TOKENID:$EXPORT_TOKEN|TYPE:$FILE_FORMAT]\e[0m"
		fi
	else 
		echo -e "$scanId => \e[31mExport scan failed ! [TYPE:$FILE_FORMAT]\e[0m"
		exit 1
	fi
}

checkExistingScans() {
	listOfScanId=$(curl -s -k -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0" -H "Content-Type: application/json" -H "Cache-Control: no-cache" -H "X-API-Token: $X_API_TOKEN" -H "X-Cookie: token=$X_NESSUS_TOKEN" -X GET https://$ipNessus:8834/scans | jq '.scans | .[].id' 2> /dev/null)
	if [[ ! -n "$listOfScanId" ]]; then
		echo -e "\e[31mThere are no scans available ! Please create one first !\e[0m"
		exit 0
	fi
}

if [[ -z $checkNessusService ]]; then
	echo -e "\e[31mNessus service appears not to be running !\e[0m"
	exit 0
#if [[ $checkNessusService != "running" ]]; then
#	echo -e "\e[31mNessus service appears not to be running !\e[0m"
#	read -p "Would you like to start the Nessus service ? [Y/n]" REPLY
#	REPLY=${REPLY^^}
#	if [[ $REPLY = "Y" || $REPLY = "YES" ]]; then
#		service nessusd start
#	else
#		exit 0
#	fi
else
	checkNessusStatus=$(curl -s -k -H "Content-Type: application/json" -H "Cache-Control: no-cache" -X GET https://$ipNessus:8834/server/status | jq .status | tr -d '"')
	case "$checkNessusStatus" in
	locked)
		read -p "Please the master password to continue:" -r -s MASTER_PASS
		MASTER_PASS=$(echo $MASTER_PASS | sed 's/\\/\\\\/')
		error=$(curl -s -k -H "Content-Type: application/json" -H "Cache-Control: no-cache" -d '{"passwd":"'$MASTER_PASS'"}' -X POST https://$ipNessus:8834/server/unlock | jq .error | tr -d '"')
		echo -e "\e[31m\n$error\e[0m"
		$0
	;;
	loading)
		echo "Nessus is not ready ! Please wait..."
	;;
	ready)
		X_API_TOKEN=$(curl -s -k -H "User-Agent: Monilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0" -H "Cache-Control: no-cache" -X GET https://$ipNessus:8834/nessus6.js | grep -m1 -oE "[A-F0-9]+-[A-F0-9]+-[A-F0-9]+-[A-F0-9]+-[A-F0-9]+")
		X_NESSUS_TOKEN=$(grep -Fi X_NESSUS_TOKEN ~/.bashrc | awk -F "=" '{ print $2 }')
		checkAuth=$(curl -s -k -H "Content-Type: application/json" -H "Cache-Control: no-cache" -H "X-API-Token: $X_API_TOKEN" -H "X-Cookie: token=$X_NESSUS_TOKEN" -X GET https://$ipNessus:8834/session | jq .error | tr -d '"')
		if [[ $checkAuth != "null" ]]; then
			authenticate
		else
			case "$1" in
			  listscans)
				checkExistingScans
				curl -s -k -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0" -H "Content-Type: application/json" -H "Cache-Control: no-cache" -H "X-API-Token: $X_API_TOKEN" -H "X-Cookie: token=$X_NESSUS_TOKEN" -X GET https://$ipNessus:8834/scans | jq .scans
			  ;;
			  showtemplates)
				curl -s -k -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0" -H "Content-Type: application/json" -H "Cache-Control: no-cache" -H "X-API-Token: $X_API_TOKEN" -H "X-Cookie: token=$X_NESSUS_TOKEN" -X GET https://$ipNessus:8834/editor/scan/templates | jq .
			  ;;
			  showpolicies)
				curl -s -k -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0" -H "Content-Type: application/json" -H "Cache-Control: no-cache" -H "X-API-Token: $X_API_TOKEN" -H "X-Cookie: token=$X_NESSUS_TOKEN" -X GET https://$ipNessus:8834/policies | jq .
			  ;;
			  showscan)
				checkExistingScans
				if [[ -n "$2" ]]; then
					scanId=$2
					curl -s -k -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0" -H "Content-Type: application/json" -H "Cache-Control: no-cache" -H "X-API-Token: $X_API_TOKEN" -H "X-Cookie: token=$X_NESSUS_TOKEN" -X GET https://$ipNessus:8834/scans/$scanId | jq .
				else
					echo "Usage: $0 $1 <scan_id>"
				fi
			  ;;
			  createscan)
				if [[ -n "$2" && -n "$3" && -n "$4" && -n "$5" ]]; then
					templateUuid=$2
					scanName=$3
					scanDescription=$4
					filePath=$5
		  			targets=$(cat $filePath | sed -z "s/\n/,/g")
		  			curl -s -k -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0" -H "Content-Type: application/json" -H "Cache-Control: no-cache" -H "X-API-Token: $X_API_TOKEN" -H "X-Cookie: token=$X_NESSUS_TOKEN"  -d '{"uuid": "'$templateUuid'","settings": {"name": "'$scanName'","description": "'$scanDescription'","enabled": "false","launch": "ON_DEMAND","folder_id": 3,"text_targets": "'$targets'"}}' -X POST https://$ipNessus:8834/scans | jq .
				else
					echo "Usage: $0 $1 <template_uuid> <scan_name> <scan_description> <file_targets>"
				fi
			  ;;
			  deletescan)
				checkExistingScans
				if [[ -n "$2" && "$2" = "all" ]]; then
					for scanId in $listOfScanId; do
						$0 deletescan $scanId
					done
				elif [[ -n "$2" ]]; then
					scanId=$2
					echo -e "Delete Scan => \e[31m$scanId\e[0m"
					curl -s -k -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0" -H "Content-Type: application/json" -H "Cache-Control: no-cache" -H "X-API-Token: $X_API_TOKEN" -H "X-Cookie: token=$X_NESSUS_TOKEN" -d '{"ids":["'$scanId'"]}' -X DELETE https://$ipNessus:8834/scans | jq .
				else
					echo "Usage: $0 $1 <scan_id|all>"
				fi
			  ;;
			  launchscan)
				checkExistingScans
				if [[ -n "$2" && "$2" = "all" ]]; then
					for scanId in $listOfScanId; do
						$0 launchscan $scanId
					done
				elif [[ -n "$2" ]]; then
					scanId=$2
					echo -e "Start Scan => \e[32m$scanId\e[0m" 
					curl -s -k -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0" -H "Content-Type: application/json" -H "Cache-Control: no-cache" -H "X-API-Token: $X_API_TOKEN" -H "X-Cookie: token=$X_NESSUS_TOKEN" -X POST https://$ipNessus:8834/scans/$scanId/launch | jq .
				else
					echo "Usage: $0 $1 <scan_id|all>"
				fi
			  ;;
			  pausescan)
				checkExistingScans
				if [[ -n "$2" && "$2" = "all" ]]; then
					for scanId in $listOfScanId; do
						$0 pausescan $scanId
					done
				elif [[ -n "$2" ]]; then
					scanId=$2
					echo -e "Pause Scan => \e[32m$scanId\e[0m"
					curl -s -k -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0" -H "Content-Type: application/json" -H "Cache-Control: no-cache" -H "X-API-Token: $X_API_TOKEN" -H "X-Cookie: token=$X_NESSUS_TOKEN" -X POST https://$ipNessus:8834/scans/$scanId/pause | jq .
				else
					echo "Usage: $0 $1 <scan_id|all>"
				fi
			  ;;
			  resumescan)
				checkExistingScans
				if [[ -n "$2" && "$2" = "all" ]]; then
					for scanId in $listOfScanId; do
						$0 resumescan $scanId
					done
				elif [[ -n "$2" ]]; then
					scanId=$2
					echo -e "Resume Scan => \e[32m$scanId\e[0m"
					curl -s -k -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0" -H "Content-Type: application/json" -H "Cache-Control: no-cache" -H "X-API-Token: $X_API_TOKEN" -H "X-Cookie: token=$X_NESSUS_TOKEN" -X POST https://$ipNessus:8834/scans/$scanId/resume | jq .
				else
					echo "Usage: $0 $1 <scan_id|all>"
				fi
			  ;;
			  stopscan)
				checkExistingScans
				if [[ -n "$2" && "$2" = "all" ]]; then
					for scanId in $listOfScanId; do
						$0 stopscan $scanId
					done
				elif [[ -n "$2" ]]; then
					scanId=$2
					echo -e "Stop Scan => \e[32m$scanId\e[0m"
					curl -s -k -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0" -H "Content-Type: application/json" -H "Cache-Control: no-cache" -H "X-API-Token: $X_API_TOKEN" -H "X-Cookie: token=$X_NESSUS_TOKEN" -X POST https://$ipNessus:8834/scans/$scanId/stop | jq .
				else
					echo "Usage: $0 $1 <scan_id|all>"
				fi
			  ;;
			  resultscan)
				checkExistingScans
				if [[ -n "$2" ]]; then
					scanId=$2
					curl -s -k -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0" -H "Content-Type: application/json" -H "Cache-Control: no-cache" -H "X-API-Token: $X_API_TOKEN" -H "X-Cookie: token=$X_NESSUS_TOKEN" -X GET https://$ipNessus:8834/scans/$scanId | jq '.vulnerabilities | sort_by(.severity)'
				else
					echo "Usage: $0 $1 <scan_id>"
				fi
			  ;;
			  exportscan)
				checkExistingScans
				if [[ -n "$4" && "$4" = "host" ]]; then
					groupBy=vuln_by_host
				elif [[ -n "$4" && "$4" = "plugin" ]]; then
					groupBy=vuln_by_plugin
				else
					groupBy=vuln_by_host
				fi
				if [[ "$2" = "all" && -n "$3" ]]; then
					fileFormat=$3
					if [[ ! " ${listFormat[@]} " =~ " ${fileFormat} " ]]; then
    					$0 exportscan
    				else
    					for scanId in $listOfScanId; do
							$0 exportscan $scanId $fileFormat $4
						done
					fi
				elif [[ -n "$2" && -n "$3" ]]; then
					scanId=$2
					scanName=$(curl -s -k -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0" -H "Content-Type: application/json" -H "Cache-Control: no-cache" -H "X-API-Token: $X_API_TOKEN" -H "X-Cookie: token=$X_NESSUS_TOKEN" -X GET https://$ipNessus:8834/scans/$scanId | jq .info.name | sed "s/ /_/g" | tr -d '"')
					fileFormat=$3
					case "$fileFormat" in
					  pdf)
						EXPORT_TOKEN=$(curl -s -k -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0" -H "Content-Type: application/json" -H "Cache-Control: no-cache" -H "X-API-Token: $X_API_TOKEN" -H "X-Cookie: token=$X_NESSUS_TOKEN" -d '{"format":"pdf","chapters":"'$groupBy'"}' -X POST https://$ipNessus:8834/scans/$scanId/export | jq .token | tr -d '"')
						checkExportTokens $scanId $scanName $EXPORT_TOKEN pdf $groupBy
						echo $scanId:$scanName:$EXPORT_TOKEN:PDF:$groupBy | tee -a $exportTokensFilePath >& /dev/null
					  ;;
					  csv)
						EXPORT_TOKEN=$(curl -s -k -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0" -H "Content-Type: application/json" -H "Cache-Control: no-cache" -H "X-API-Token: $X_API_TOKEN" -H "X-Cookie: token=$X_NESSUS_TOKEN" -d '{"format":"csv"}' -X POST https://$ipNessus:8834/scans/$scanId/export | jq .token | tr -d '"')
						checkExportTokens $scanId $scanName $EXPORT_TOKEN csv
						echo $scanId:$scanName:$EXPORT_TOKEN:CSV | tee -a $exportTokensFilePath >& /dev/null
					  ;;
					  html)
						EXPORT_TOKEN=$(curl -s -k -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0" -H "Content-Type: application/json" -H "Cache-Control: no-cache" -H "X-API-Token: $X_API_TOKEN" -H "X-Cookie: token=$X_NESSUS_TOKEN" -d '{"format":"html","chapters":"'$groupBy'"}' -X POST https://$ipNessus:8834/scans/$scanId/export | jq .token | tr -d '"')
						checkExportTokens $scanId $scanName $EXPORT_TOKEN html $groupBy
						echo $scanId:$scanName:$EXPORT_TOKEN:HTML:$groupBy | tee -a $exportTokensFilePath >& /dev/null
					  ;;
					  nessus)
						EXPORT_TOKEN=$(curl -s -k -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0" -H "Content-Type: application/json" -H "Cache-Control: no-cache" -H "X-API-Token: $X_API_TOKEN" -H "X-Cookie: token=$X_NESSUS_TOKEN" -d '{"format":"nessus"}' -X POST https://$ipNessus:8834/scans/$scanId/export | jq .token | tr -d '"')
						checkExportTokens $scanId $scanName $EXPORT_TOKEN nessus
						echo $scanId:$scanName:$EXPORT_TOKEN:NESSUS | tee -a $exportTokensFilePath >& /dev/null
					  ;;
					  db)
						EXPORT_TOKEN=$(curl -s -k -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0" -H "Content-Type: application/json" -H "Cache-Control: no-cache" -H "X-API-Token: $X_API_TOKEN" -H "X-Cookie: token=$X_NESSUS_TOKEN" -d '{"format":"db","password":"'$dbPassword'"}' -X POST https://$ipNessus:8834/scans/$scanId/export | jq .token | tr -d '"')
						checkExportTokens $scanId $scanName $EXPORT_TOKEN db
						echo $scanId:$scanName:$EXPORT_TOKEN:DB | tee -a $exportTokensFilePath >& /dev/null
					  ;;
					  *)
						$0 exportscan
					esac
				else
					echo "Usage: $0 $1 <scan_id|all> <pdf|csv|html|nessus|db> [GroupBy:host|plugin]"
				fi
			  ;;
			  exportstatus)
				if [[ ! -f $exportTokensFilePath || ! -s $exportTokensFilePath ]]; then
				    echo "No export scan has been requested !"
				else
					listOfExportTokens=$(cat $exportTokensFilePath)
					for token in ${listOfExportTokens[@]}; do
						tokenId=$(echo -n "$token" | awk -F ':' '{ print $3 }')
						echo -e "Export Scan => \e[32m$token\e[0m" 
						curl -s -k -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0" -H "Content-Type: application/json" -H "Cache-Control: no-cache" -H "X-API-Token: $X_API_TOKEN" -H "X-Cookie: token=$X_NESSUS_TOKEN" -X GET https://$ipNessus:8834/tokens/$tokenId/status| jq .
					done
				fi
			  ;;
			  exportdownload)
				if [[ ! -f $exportTokensFilePath || ! -s $exportTokensFilePath ]]; then
				    echo "No export scan has been requested !"
				else
					if [[ "$2" = "all" ]]; then
						listOfExportTokens=$(cat $exportTokensFilePath)
						for token in ${listOfExportTokens[@]}; do
							tokenId=$(echo -n "$token" | awk -F ':' '{ print $3 }')
							$0 exportdownload $tokenId
						done
					elif [[ -n "$2" ]]; then
						tokenId=$2
						exportStatus=$(curl -s -k -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0" -H "Content-Type: application/json" -H "Cache-Control: no-cache" -H "X-API-Token: $X_API_TOKEN" -H "X-Cookie: token=$X_NESSUS_TOKEN" -X GET https://$ipNessus:8834/tokens/$tokenId/status| jq .status | tr -d '"')
						scanName=$(grep $tokenId $exportTokensFilePath | awk -F ':' '{ print $2 }' | sed -e 's/\\/_/g; s/\//\_/g')
						fileExt=$(grep $tokenId $exportTokensFilePath | awk -F ':' '{ print $4 }')
						groupBy=$(grep $tokenId $exportTokensFilePath | awk -F ':' '{ print $5 }')
						fileExtLowerCase=${fileExt,,}
						fileName=${scanName}_$(date '+%Y-%m-%d_%H-%M-%S')_$(cat /dev/urandom | tr -cd 'a-f0-9' | head -c 10).$fileExtLowerCase
				    	if [[ "$groupBy" = "vuln_by_host" ]]; then
				    		folderPath=~/audit/Nessus/$fileExt-HOST
				    	elif [[ "$groupBy" = "vuln_by_plugin" ]]; then
				    		folderPath=~/audit/Nessus/$fileExt-PLUGIN
				    	else
				    		folderPath=~/audit/Nessus/$fileExt
				    	fi
				    	mkdir -p $folderPath
				    	filePath=$folderPath/$fileName
				    	if [[ $exportStatus = "loading" ]]; then
							echo -e "$scanName:$tokenId:$fileExt:${groupBy^^} => \e[31mThe download is not ready yet.\e[0m"
						elif [[ $exportStatus = "ready" ]]; then
							curl -s -k -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0" -H "Content-Type: application/json" -H "Cache-Control: no-cache" -H "X-API-Token: $X_API_TOKEN" -H "X-Cookie: token=$X_NESSUS_TOKEN" -X GET https://$ipNessus:8834/tokens/$tokenId/download -o $filePath
							checkdownload=$(file $filePath | grep -io ASCII)
							if [[ "$checkdownload" = "ASCII" && ! -s $filePath ]]; then
								echo -e "$filePath => \e[31mDownload failed !\e[0m"
								sed -i "{/.*$tokenId.*/d}" $exportTokensFilePath
								rm $filePath
							else
								sed -i "{/.*$tokenId.*/d}" $exportTokensFilePath
								echo -e "$filePath => \e[32mFile downloaded successfully !\e[0m"
							fi
						else
							echo -e "$scanName:$tokenId:$fileExt:${groupBy^^} => \e[31mExport failed ! status: $exportStatus\e[0m"
						fi
					else
						echo "Usage: $0 $1 <token_id|all>"
					fi
				fi
			  ;;
			  *)
				echo "Usage: $0 <listscans|showtemplates|showpolicies|showscan|createscan|deletescan|launchscan|pausescan|resumescan|stopscan|resultscan|exportscan|exportstatus|exportdownload>"
			esac
		fi
	;;
	esac
fi
