#!/bin/bash

export WORKING_DIR=$(pwd)

./socat -T 15 tcp-l:1337,reuseaddr,fork exec:'/marksnspectre/start.sh'

