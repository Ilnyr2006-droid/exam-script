#!/bin/bash

# Получаем размеры терминала
ROWS=$(tput lines)
COLS=$(tput cols)

# Очищаем экран и прячем курсор
clear
tput civis

# Функция для восстановления курсора при выходе
trap 'tput cnorm; clear; exit' INT TERM EXIT

while true; do
    # Перемещаем курсор в начало
    tput cup 0 0
    
    # Создаем строку, заполняющую всю ширину
    line=$(printf "хуй %.0s" $(seq 1 $((COLS / 4 + 1))))
    line=${line:0:$COLS}
    
    # Выводим строку на весь экран
    for ((i=0; i<ROWS; i++)); do
        echo -n "$line"
        if [ $i -lt $((ROWS-1)) ]; then
            echo
        fi
    done
    
    # Небольшая задержка, чтобы не перегружать процессор
    sleep 0.05
done
