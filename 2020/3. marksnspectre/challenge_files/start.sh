#!/bin/bash

cd "$WORKING_DIR"

user_file=$(mktemp /tmp/user.XXXXXXXXX.c)
main_file=$(mktemp /tmp/main.XXXXXXXXX)

echo 'ENter the file contents, last line should be "$" (ignored):'
while [[ "$input" != '$' ]]; do
    read -r input
    echo "$input"
done | head -n -1 > "$user_file"

gcc -L. -Wall -o "${main_file}" main.c "${user_file}" -lmns -Wl,-rpath=.

./parent "${main_file}"

rm "${user_file}"
rm "${main_file}"
