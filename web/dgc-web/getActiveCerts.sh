TOKEN=<INSERT_TOKEN>
keyIds=$(curl -v -H "Authorization: Bearer $TOKEN"  "https://www.cc.bit.admin.ch/trust/v2/keys/list?certFormat=ANDROID&since=0&upTo=100000&country=CH" | jq -r '.activeKeyIds | .[]')
certs=$(curl -v -H "Authorization: Bearer $TOKEN"  "https://www.cc.bit.admin.ch/trust/v2/keys/updates?certFormat=ANDROID&since=0&upTo=100000" | jq -r -c ".certs | .[]")

for cert in $certs
do
    keyId=$(echo $cert | jq -r '.keyId' )
    for id in $keyIds
    do
        if [[ $id == $keyId ]]
        then
            n=$(echo $cert | jq -r '.n')
            e=$(echo $cert | jq -r '.e')
            echo "$keyId,$n,$e"
        fi
    done
done
