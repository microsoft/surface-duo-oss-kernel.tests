#!/bin/bash
# This defaults to 60 which is needlessly long during boot
# (we will reset it back to the default later)
echo 0 > /proc/sys/kernel/random/urandom_min_reseed_secs

if [[ -n "${entropy}" ]]; then
  echo "adding entropy from hex string [${entropy}]" 1>&2

  # In kernel/include/uapi/linux/random.h RNDADDENTROPY is defined as
  # _IOW('R', 0x03, int[2]) =(R is 0x52)= 0x40085203 = 1074287107
  /usr/bin/python 3>/dev/random <<EOF
import fcntl, struct
rnd = '${entropy}'.decode('base64')
fcntl.ioctl(3, 0x40085203, struct.pack('ii', len(rnd) * 8, len(rnd)) + rnd)
EOF

fi

# Make sure the urandom pool has a chance to initialize before we reset
# the reseed timer back to 60 seconds.  One timer tick should be enough.
sleep 1.1

# By this point either 'random: crng init done' (newer kernels)
# or 'random: nonblocking pool is initialized' (older kernels)
# should have been printed out to dmesg/console.

# Reset it back to boot time default
echo 60 > /proc/sys/kernel/random/urandom_min_reseed_secs


# In case IPv6 is compiled as a module.
[ -f /proc/net/if_inet6 ] || insmod $DIR/kernel/net-next/net/ipv6/ipv6.ko

# Minimal network setup.
ip link set lo up
ip link set lo mtu 16436
ip link set eth0 up

# Allow people to run ping.
echo "0 65536" > /proc/sys/net/ipv4/ping_group_range

# Read environment variables passed to the kernel to determine if script is
# running on builder and to find which test to run.

if [ "$net_test_mode" != "builder" ]; then
  # Fall out to a shell once the test completes or if there's an error.
  trap "exec /bin/bash" ERR EXIT
fi

echo -e "Running $net_test $net_test_args\n"
$net_test $net_test_args

# Write exit code of net_test to a file so that the builder can use it
# to signal failure if any tests fail.
echo $? >$net_test_exitcode
