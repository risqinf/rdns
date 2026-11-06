#!/usr/bin/env bash
#
# rdns Split-Routing & Media Regional Unlock Checker
# https://github.com/risqinf/rdns
#

# Clear screen right away
clear

set -o pipefail

# ANSI color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
PLAIN='\033[0m'

if [ ! -t 1 ]; then
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    PURPLE=''
    CYAN=''
    BOLD=''
    PLAIN=''
fi

UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"

print_item() {
    local name="$1"
    local value="$2"
    local status="${3:-normal}"

    case "$status" in
        yes)  printf " %-24s : ${GREEN}%s${PLAIN}\n" "$name" "$value" ;;
        no)   printf " %-24s : ${RED}%s${PLAIN}\n" "$name" "$value" ;;
        warn) printf " %-24s : ${YELLOW}%s${PLAIN}\n" "$name" "$value" ;;
        *)    printf " %-24s : %s\n" "$name" "$value" ;;
    esac
}

print_header() {
    echo ""
    echo -e "${BOLD}${CYAN} -- $1 --${PLAIN}"
}

echo -e "${CYAN}"
echo " ========================================================="
echo " \\         rdns Split-Routing & Unlock Checker           /"
echo " \\                    Version v0.1.5                     /"
echo " \\           https://github.com/risqinf/rdns            /"
echo " ========================================================="
echo -e "${PLAIN}"

# --- IP & Network Information ---
echo -e "${BOLD} [ IP & Network Detection ]${PLAIN}"

HOST_IP=""
if command -v hostname >/dev/null 2>&1; then
    for cand in $(hostname -I 2>/dev/null) $(hostname -i 2>/dev/null); do
        if [[ "$cand" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && [[ "$cand" != 127.* ]]; then
            HOST_IP="$cand"
            break
        fi
    done
fi

if [ -n "$HOST_IP" ]; then
    # Query ipinfo for this specific host IP
    host_raw=$(curl -sL --connect-timeout 4 --max-time 6 "https://ipinfo.io/${HOST_IP}/json" 2>/dev/null)
    h_org=$(echo "$host_raw" | grep -o '"org": *"[^"]*"' | head -n1 | cut -d'"' -f4)
    h_city=$(echo "$host_raw" | grep -o '"city": *"[^"]*"' | head -n1 | cut -d'"' -f4)
    h_country=$(echo "$host_raw" | grep -o '"country": *"[^"]*"' | head -n1 | cut -d'"' -f4)
    printf " %-24s : %s (%s, %s - %s)\n" "Node IP (hostname -i)" "$HOST_IP" "${h_city:-Unknown}" "${h_country:-Unknown}" "${h_org:-Unknown}"
else
    printf " %-24s : %s\n" "Node IP (hostname -i)" "Not detected"
fi

egress_raw=$(curl -sL --connect-timeout 4 --max-time 6 "https://ipinfo.io/json" 2>/dev/null)
e_ip=$(echo "$egress_raw" | grep -o '"ip": *"[^"]*"' | head -n1 | cut -d'"' -f4)
e_org=$(echo "$egress_raw" | grep -o '"org": *"[^"]*"' | head -n1 | cut -d'"' -f4)
e_city=$(echo "$egress_raw" | grep -o '"city": *"[^"]*"' | head -n1 | cut -d'"' -f4)
e_country=$(echo "$egress_raw" | grep -o '"country": *"[^"]*"' | head -n1 | cut -d'"' -f4)
if [ -n "$e_ip" ]; then
    printf " %-24s : %s (%s, %s - %s)\n" "Egress IP (Tunnel)" "$e_ip" "${e_city:-Unknown}" "${e_country:-Unknown}" "${e_org:-Unknown}"
fi
echo "------------------------------------------------------------"

# --- Section 1: Global Media & Streaming ---
print_header "Global Media & Streaming"

# Netflix
check_netflix() {
    local res1 res2 net_country
    res1=$(curl -sL --connect-timeout 4 --max-time 8 -H "User-Agent: $UA" "https://www.netflix.com/title/80018499" 2>/dev/null)
    res2=$(curl -sL --connect-timeout 4 --max-time 8 -H "User-Agent: $UA" "https://www.netflix.com/title/70143836" 2>/dev/null)

    net_country=$(curl -sL --connect-timeout 4 --max-time 5 -H "User-Agent: $UA" "https://www.netflix.com" 2>/dev/null | grep -o '"country":"[A-Z]*"' | head -n1 | cut -d'"' -f4)
    [ -z "$net_country" ] && net_country=$(curl -sI --connect-timeout 4 --max-time 5 -H "User-Agent: $UA" "https://www.netflix.com" 2>/dev/null | grep -i '^Location:' | grep -o '/[a-z]\{2\}/' | tr -d '/' | tr 'a-z' 'A-Z')
    [ -z "$net_country" ] && net_country="ID"

    if echo "$res2" | grep -qiE 'title/70143836|"titleId":70143836|Breaking Bad'; then
        print_item "Netflix" "Yes (Region: ${net_country})" "yes"
    elif echo "$res1" | grep -qiE 'title/80018499|"titleId":80018499|The Square'; then
        print_item "Netflix" "Originals Only (Region: ${net_country})" "warn"
    else
        print_item "Netflix" "No" "no"
    fi
}

# YouTube Premium
check_youtube() {
    local res reg
    res=$(curl -sL --connect-timeout 4 --max-time 6 -H "User-Agent: $UA" "https://www.youtube.com/premium" 2>/dev/null)
    reg=$(echo "$res" | grep -o '"countryCode":"[A-Z]*"' | head -n1 | cut -d'"' -f4)
    [ -z "$reg" ] && reg=$(echo "$res" | grep -o '"INNERTUBE_CONTEXT_GL":"[A-Z]*"' | head -n1 | cut -d'"' -f4)

    if [ -n "$reg" ]; then
        print_item "YouTube Premium" "Yes (Region: ${reg})" "yes"
    else
        print_item "YouTube Premium" "No" "no"
    fi
}

# YouTube CDN
check_youtube_cdn() {
    local cdn_info isp
    cdn_info=$(curl -sL --connect-timeout 4 --max-time 6 "https://redirector.googlevideo.com/report_mapping" 2>/dev/null)
    isp=$(echo "$cdn_info" | head -n1 | cut -d'=' -f2 | tr -d ' ')
    if [ -n "$isp" ]; then
        print_item "YouTube CDN" "Yes ($isp)" "yes"
    else
        print_item "YouTube CDN" "No" "no"
    fi
}

# Disney+ Hotstar
check_hotstar() {
    local res code reg
    res=$(curl -sI --connect-timeout 4 --max-time 6 -H "User-Agent: $UA" "https://www.hotstar.com/id" 2>/dev/null)
    code=$(echo "$res" | head -n1 | grep -o '[0-9]\{3\}')
    reg=$(echo "$res" | grep -i '^Set-Cookie:' | grep -o 'geo=[A-Z]*' | head -n1 | cut -d'=' -f2)
    [ -z "$reg" ] && reg="ID"

    if echo "$code" | grep -qE '200|301|302'; then
        print_item "Disney+ HotStar" "Yes (Region: ${reg})" "yes"
    else
        print_item "Disney+ HotStar" "No" "no"
    fi
}

# Amazon Prime Video
check_primevideo() {
    local res reg
    res=$(curl -sL --connect-timeout 4 --max-time 6 -H "User-Agent: $UA" "https://www.primevideo.com" 2>/dev/null)
    reg=$(echo "$res" | grep -o '"currentTerritory":"[A-Z]*"' | head -n1 | cut -d'"' -f4)
    [ -z "$reg" ] && reg=$(echo "$res" | grep -o 'countryCode=[A-Z]*' | head -n1 | cut -d'=' -f2)

    if [ -n "$reg" ]; then
        print_item "Amazon Prime Video" "Yes (Region: ${reg})" "yes"
    elif echo "$res" | grep -qiE 'Prime Video|Amazon Digital'; then
        print_item "Amazon Prime Video" "Yes" "yes"
    else
        print_item "Amazon Prime Video" "No" "no"
    fi
}

# TikTok
check_tiktok() {
    local res reg
    res=$(curl -sL --connect-timeout 4 --max-time 6 -H "User-Agent: $UA" "https://www.tiktok.com" 2>/dev/null)
    reg=$(echo "$res" | grep -o '"vregion":"[^"]*"' | head -n1 | cut -d'"' -f4)
    if [ -n "$reg" ] && [ "$reg" != "-" ]; then
        print_item "TikTok" "Yes (Region: ${reg})" "yes"
    else
        print_item "TikTok" "No" "no"
    fi
}

# iQIYI International
check_iqiyi() {
    local res reg
    res=$(curl -sI --connect-timeout 4 --max-time 6 -H "User-Agent: $UA" "https://www.iq.com" 2>/dev/null)
    reg=$(echo "$res" | grep -i '^Set-Cookie:' | grep -o 'mod=[a-z]*' | head -n1 | cut -d'=' -f2 | tr 'a-z' 'A-Z')
    [ -z "$reg" ] && reg=$(echo "$res" | grep -i '^x-custom-client-ip:' | grep -o ':[a-z]*' | head -n1 | tr -d ':' | tr 'a-z' 'A-Z')

    if [ -n "$reg" ]; then
        print_item "iQIYI International" "Yes (Region: ${reg})" "yes"
    else
        print_item "iQIYI International" "No" "no"
    fi
}

# Viu.com
check_viu() {
    local res reg
    res=$(curl -sI --connect-timeout 4 --max-time 6 -H "User-Agent: $UA" "https://www.viu.com" 2>/dev/null)
    reg=$(echo "$res" | grep -i '^Location:' | grep -o '/ott/[a-z]*' | head -n1 | cut -d'/' -f3 | tr 'a-z' 'A-Z')
    [ -z "$reg" ] && reg=$(echo "$res" | grep -i '^x-middleware-rewrite:' | grep -o '/ott/[a-z]*' | head -n1 | cut -d'/' -f3 | tr 'a-z' 'A-Z')

    if [ -n "$reg" ]; then
        print_item "Viu.com" "Yes (Region: ${reg})" "yes"
    else
        print_item "Viu.com" "No" "no"
    fi
}

# Bilibili China
check_bilibili_cn() {
    local res
    res=$(curl -sL --connect-timeout 4 --max-time 6 "https://api.bilibili.com/pgc/player/web/playurl?avid=18281381&cid=29892777&qn=0&type=&otype=json&ep_id=183799&fnver=0&fnval=16" 2>/dev/null)
    if echo "$res" | grep -q '"code":0'; then
        print_item "BiliBili China" "Yes" "yes"
    else
        print_item "BiliBili China" "No" "no"
    fi
}

# Bstation (Bilibili Global)
check_bstation() {
    local code
    code=$(curl -s -o /dev/null -w "%{http_code}" -L --connect-timeout 4 --max-time 6 -H "User-Agent: $UA" "https://www.bilibili.tv" 2>/dev/null)
    if echo "$code" | grep -qE '200|301|302'; then
        print_item "Bstation (Global)" "Yes (Region: ID)" "yes"
    else
        print_item "Bstation (Global)" "No" "no"
    fi
}

# Steam Store
check_steam() {
    local res
    res=$(curl -sL --connect-timeout 4 --max-time 6 -H "Accept-Language: en-US,en" "https://store.steampowered.com/app/10/" 2>/dev/null)
    if echo "$res" | grep -qiE 'Rp\s*[0-9]|IDR'; then
        print_item "Steam" "Yes (Currency: IDR)" "yes"
    elif echo "$res" | grep -qiE 'S\$|SGD'; then
        print_item "Steam" "Yes (Currency: SGD)" "yes"
    elif echo "$res" | grep -qiE 'RM|MYR'; then
        print_item "Steam" "Yes (Currency: MYR)" "yes"
    else
        print_item "Steam" "Yes" "yes"
    fi
}

# Spotify
check_spotify() {
    local code
    code=$(curl -s -o /dev/null -w "%{http_code}" -L --connect-timeout 4 --max-time 6 -H "User-Agent: $UA" "https://www.spotify.com/id/" 2>/dev/null)
    if echo "$code" | grep -qE '200|301|302'; then
        print_item "Spotify" "Yes (Region: ID)" "yes"
    else
        print_item "Spotify" "No" "no"
    fi
}

check_netflix
check_youtube
check_youtube_cdn
check_hotstar
check_primevideo
check_tiktok
check_iqiyi
check_viu
check_bilibili_cn
check_bstation
check_steam
check_spotify

# --- Section 2: AI Services ---
print_header "AI Services"

check_chatgpt() {
    local res reg
    res=$(curl -sL --connect-timeout 4 --max-time 6 -H "User-Agent: $UA" "https://chatgpt.com/cdn-cgi/trace" 2>/dev/null)
    reg=$(echo "$res" | grep '^loc=' | cut -d'=' -f2)
    if [ -n "$reg" ]; then
        print_item "ChatGPT (Web)" "Yes (Region: ${reg})" "yes"
    else
        print_item "ChatGPT (Web)" "No" "no"
    fi
}

check_openai_api() {
    local code
    code=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 4 --max-time 6 "https://api.openai.com/v1/models" 2>/dev/null)
    if [ "$code" = "401" ] || [ "$code" = "200" ]; then
        print_item "OpenAI API" "Yes" "yes"
    else
        print_item "OpenAI API" "No" "no"
    fi
}

check_claude() {
    local res reg
    res=$(curl -sL --connect-timeout 4 --max-time 6 -H "User-Agent: $UA" "https://claude.ai/cdn-cgi/trace" 2>/dev/null)
    reg=$(echo "$res" | grep '^loc=' | cut -d'=' -f2)
    if [ -n "$reg" ]; then
        print_item "Claude (Anthropic)" "Yes (Region: ${reg})" "yes"
    else
        print_item "Claude (Anthropic)" "No" "no"
    fi
}

check_gemini() {
    local code
    code=$(curl -s -o /dev/null -w "%{http_code}" -L --connect-timeout 4 --max-time 6 -H "User-Agent: $UA" "https://gemini.google.com" 2>/dev/null)
    if echo "$code" | grep -qE '200|301|302'; then
        print_item "Google Gemini" "Yes" "yes"
    else
        print_item "Google Gemini" "No" "no"
    fi
}

check_copilot() {
    local code
    code=$(curl -s -o /dev/null -w "%{http_code}" -L --connect-timeout 4 --max-time 6 -H "User-Agent: $UA" "https://copilot.microsoft.com" 2>/dev/null)
    if echo "$code" | grep -qE '200|301|302'; then
        print_item "Microsoft Copilot" "Yes" "yes"
    else
        print_item "Microsoft Copilot" "No" "no"
    fi
}

check_chatgpt
check_openai_api
check_claude
check_gemini
check_copilot

# --- Section 3: Indonesian Regional Media ---
print_header "Indonesian Regional Media"

check_generic_service() {
    local name="$1"
    local url="$2"
    local code
    code=$(curl -s -o /dev/null -w "%{http_code}" -L --connect-timeout 4 --max-time 6 -H "User-Agent: $UA" "$url" 2>/dev/null)
    if echo "$code" | grep -qE '200|301|302|403'; then
        if [ "$code" = "403" ]; then
            print_item "$name" "Blocked (403)" "no"
        else
            print_item "$name" "Yes (Region: ID)" "yes"
        fi
    else
        print_item "$name" "No" "no"
    fi
}

check_generic_service "Vidio Premier" "https://www.vidio.com"
check_generic_service "Vision+ / RCTI+" "https://www.visionplus.id"
check_generic_service "WeTV Indonesia" "https://wetv.vip"
check_generic_service "MAXstream" "https://maxstream.tv"
check_generic_service "Catchplay+" "https://www.catchplay.com/id"

# --- Section 4: Indonesian Banking & Finance ---
print_header "Indonesian Banking & E-Wallets"

check_bank() {
    local name="$1"
    local url="$2"
    local code
    code=$(curl -s -o /dev/null -w "%{http_code}" -L --connect-timeout 4 --max-time 6 -H "User-Agent: $UA" "$url" 2>/dev/null)
    if echo "$code" | grep -qE '200|301|302'; then
        print_item "$name" "Yes (Accessible)" "yes"
    elif [ "$code" = "403" ]; then
        print_item "$name" "Blocked (403 Geoblock)" "no"
    else
        print_item "$name" "No / Timeout" "no"
    fi
}

check_bank "BCA (KlikBCA)" "https://www.klikbca.com"
check_bank "Bank Mandiri (Livin)" "https://bankmandiri.co.id"
check_bank "BRI (BRImo)" "https://bri.co.id"
check_bank "BNI Mobile" "https://bni.co.id"
check_bank "CIMB Niaga" "https://www.cimbniaga.co.id"
check_bank "DANA Indonesia" "https://www.dana.id"
check_bank "OVO" "https://www.ovo.id"
check_bank "GoPay" "https://gopay.co.id"

# --- Section 5: Indonesian Marketplaces & Public Services ---
print_header "Indonesian Marketplaces & Public Services"

check_bank "Tokopedia" "https://www.tokopedia.com"
check_bank "Shopee Indonesia" "https://shopee.co.id"
check_bank "Bukalapak" "https://www.bukalapak.com"
check_bank "DJP Online (Pajak)" "https://djponline.pajak.go.id"
check_bank "BPJS Kesehatan" "https://bpjs-kesehatan.go.id"

echo "------------------------------------------------------------"
