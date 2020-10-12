#!/bin/bash

find build -type f -print0 | xargs -0 -I{} sed -i "s/localhost/${EXTERNAL_IP}/g" "{}"

node react-server &
node api-server &
node flag-server &

while :;do
   sleep 300
   node admin.js
done
