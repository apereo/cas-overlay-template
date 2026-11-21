#!/bin/bash

CAS_ARGS="${CAS_ARGS:-}"

RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
ENDCOLOR="\e[0m"

function printgreen() {
  printf "${GREEN}$1${ENDCOLOR}\n"
}
function printyellow() {
  printf "${YELLOW}$1${ENDCOLOR}\n"
}
function printred() {
  printf "${RED}$1${ENDCOLOR}\n"
}

casWebApplicationFile="${PWD}/build/libs/cas.war"
if [[ ! -f "$casWebApplicationFile" ]]; then
    echo "Building CAS"
    ./gradlew clean build -x test -x javadoc --no-configuration-cache --offline
    if [ $? -ne 0 ]; then
        printred "Failed to build CAS"
        exit 1
    fi
fi

if [[ ! -d "${PWD}/puppeteer/node_modules/puppeteer" ]]; then
    echo "Installing Puppeteer"
    (cd "${PWD}/puppeteer" && npm install puppeteer)
else
    echo "Using existing Puppeteer modules..."
fi

echo -n "NPM version: " && npm --version
echo -n "Node version: " && node --version

echo "Launching CAS at $casWebApplicationFile with options $CAS_ARGS"
java -jar "$casWebApplicationFile" $CAS_ARGS &
pid=$!
echo "Waiting for CAS under process id ${pid}"
sleep 45
casLogin="${PUPPETEER_CAS_HOST:-https://localhost:8443}/cas/login"
echo "Checking CAS status at ${casLogin}"
curl -k -L --output /dev/null --silent --fail "$casLogin"
if [[ $? -ne 0 ]]; then
    printred "Unable to launch CAS instance under process id ${pid}."
    printred "Killing process id $pid and exiting"
    kill -9 "$pid"
    exit 1
fi

export NODE_TLS_REJECT_UNAUTHORIZED=0
echo "Executing puppeteer scenarios..."
for scenario in "${PWD}"/puppeteer/scenarios/*; do
    scenarioName=$(basename "$scenario")
    echo "=========================="
    echo "- Scenario $scenarioName "
    echo -e "==========================\n"
    node "$scenario"
    rc=$?
    echo -e "\n"
    if [[ $rc -ne 0 ]]; then
        printred "🔥 Scenario $scenarioName FAILED"
    else 
        printgreen "✅ Scenario $scenarioName PASSED"
    fi
    echo -e "\n"
    sleep 1
done;

kill -9 "$pid"
exit 0
