#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/common.sh"
require_root

if [[ "$(cat /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages)" -gt "$HUGEPAGES_2M" ]]; then
    echo "More hugepages are already reserved; leaving the larger allocation unchanged."
else
    echo "$HUGEPAGES_2M" > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
fi
install -d -m 0755 "$HUGEPAGE_MOUNT"
mountpoint -q "$HUGEPAGE_MOUNT" || mount -t hugetlbfs -o pagesize=2M nodev "$HUGEPAGE_MOUNT"
cat > /etc/sysctl.d/90-tls-loadgen-hugepages.conf <<EOF
vm.nr_hugepages = $HUGEPAGES_2M
EOF
if ! grep -Eq "^[^#]*[[:space:]]${HUGEPAGE_MOUNT//\//\\/}[[:space:]]+hugetlbfs" /etc/fstab; then
    echo "nodev $HUGEPAGE_MOUNT hugetlbfs pagesize=2M 0 0" >> /etc/fstab
fi

grep -i huge /proc/meminfo
mount | grep " $HUGEPAGE_MOUNT "
