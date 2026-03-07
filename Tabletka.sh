#!/bin/bash

ROWS=$(tput lines)
COLS=$(tput cols)

clear
tput civis
trap 'tput cnorm; clear; exit' INT TERM EXIT

while true; do
    tput cup 0 0
    line=$(printf "хуй %.0s" $(seq 1 $((COLS / 4 + 1))))
    line=${line:0:$COLS}

    for ((i=0; i<ROWS; i++)); do
        echo -n "$line"
        [ $i -lt $((ROWS-1)) ] && echo
    done

    sleep 0.05
done
