#!/bin/sh
rmmod bmath
echo clear >/sys/kernel/debug/kmemleak
insmod bmath.ko bmath.dyndbg=+p
pytest --tb=short -s -v tests
rmmod bmath
# TODO: Implement the following patch:
# An API should be added to kernel to wait for a scan to complete to then
# do a read. Would help with automated test workflows. This API must
# report back on success or failure to avoid a hang
echo scan >/sys/kernel/debug/kmemleak
cat /sys/kernel/debug/kmemleak
