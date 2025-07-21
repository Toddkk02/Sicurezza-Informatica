#!/bin/bash
GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[0;33m"
RESET="\033[0m"
echo -e "${GREEN}Starting backdoor detection${RESET}"
FLAG1="false"
FLAG2="false"
FLAG3="false"

level_one()
{
if [[ $(id -u) != 0 ]]; then
echo -e "${RED}This script must be run as root!${RESET}"
exit 1
else
echo -e "${GREEN}Root checked.${RESET}"
fi
echo -e "${YELLOW}Checking for suspicious files...${RESET}"
MATCHES=$(find /proc/*/exe -type l -print0 2>/dev/null | xargs -0 ls -al 2>/dev/null | grep -E '/tmp|/dev|/var/tmp')
if [[ -z "$MATCHES" ]]; then
echo -e "${GREEN}No suspicious files found.${RESET}"
FLAG1="true"
else
echo -e "${RED}Suspicious files detected!${RESET}"
echo "$MATCHES"
fi
}

level_two(){
echo -e "${YELLOW}Checking for unusual network connections...${RESET}"
# Check for listening or established connections that are not standard
if netstat -tulnp | grep -E 'LISTEN|ESTABLISHED' | grep -v -E '127.0.0.1|::1|ssh|127.0.0.53|spotify' | grep . ; then
echo "Suspicious connections found"
netstat -tulnp | grep -E 'LISTEN|ESTABLISHED' | grep -v -E '127.0.0.1|::1|ssh|127.0.0.53|spotify'
else
echo "No suspicious connections"
FLAG2="true"
fi
}

level_three(){
echo -e "${YELLOW}Checking for unusual processes...${RESET}"
# Check for processes running from unusual locations
SUSPICIOUS_PROCS=$(ps aux | awk '$11 ~ /^(\/tmp\/|\/var\/tmp\/|\/dev\/shm\/)/ {print}')
if [[ -n "$SUSPICIOUS_PROCS" ]]; then
echo "Suspicious processes found"
echo "$SUSPICIOUS_PROCS"
else
echo "No suspicious processes"
FLAG3="true"
fi
}

main() {
level_one
if [[ "$FLAG1" == "true" ]]; then
echo -e "${GREEN}No suspicious files found, proceeding to network checks.${RESET}"
else
echo -e "${RED}Suspicious files detected, please investigate further.${RESET}"
exit 1
fi

level_two
if [[ "$FLAG2" == "true" ]]; then
echo -e "${GREEN}No unusual network connections found, proceeding to process checks.${RESET}"
else
echo -e "${RED}Unusual network connections detected, please investigate further.${RESET}"
exit 1
fi

level_three
if [[ "$FLAG3" == "true" ]]; then
echo -e "${GREEN}No unusual processes found, system appears clean.${RESET}"
else
echo -e "${RED}Unusual processes detected, please investigate further.${RESET}"
exit 1
fi

echo -e "${GREEN}Backdoor detection completed.${RESET}"
}

main
