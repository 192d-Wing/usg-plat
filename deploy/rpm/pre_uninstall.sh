# Stop and disable platd and the forward-policy guard on removal only
# ($1 = 0), not on upgrade.
if [ "$1" -eq 0 ]; then
    systemctl --no-reload disable --now platd.service plat-fwguard.timer \
        plat-fwguard.service >/dev/null 2>&1 || :
fi
