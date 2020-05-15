#!/usr/bin/python
#
# Copyright 2020 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Namespace related support code."""

import ctypes
import ctypes.util
import os

import net_test

# //include/uapi/linux/fs.h
MS_RDONLY       = 1         # Mount read-only
MS_NOSUID       = 2         # Ignore suid and sgid bits
MS_NODEV        = 4         # Disallow access to device special files
MS_NOEXEC       = 8         # Disallow program execution
MS_SYNCHRONOUS  = 16        # Writes are synced at once
MS_REMOUNT      = 32        # Alter flags of a mounted FS
MS_MANDLOCK     = 64        # Allow mandatory locks on an FS
MS_DIRSYNC      = 128       # Directory modifications are synchronous
MS_NOATIME      = 1024      # Do not update access times.
MS_NODIRATIME   = 2048      # Do not update directory access times
MS_BIND         = 4096      #
MS_MOVE         = 8192      #
MS_REC          = 16384     #
MS_SILENT       = 32768     #
MS_POSIXACL     = (1<<16)   # VFS does not apply the umask
MS_UNBINDABLE   = (1<<17)   # change to unbindable
MS_PRIVATE      = (1<<18)   # change to private
MS_SLAVE        = (1<<19)   # change to slave
MS_SHARED       = (1<<20)   # change to shared
MS_RELATIME     = (1<<21)   # Update atime relative to mtime/ctime.
MS_STRICTATIME  = (1<<24)   # Always perform atime updates
MS_LAZYTIME     = (1<<25)   # Update the on-disk [acm]times lazily

# //include/uapi/linux/sched.h
CLONE_NEWNS     = 0x00020000   # New mount namespace group
CLONE_NEWCGROUP = 0x02000000   # New cgroup namespace
CLONE_NEWUTS    = 0x04000000   # New utsname namespace
CLONE_NEWIPC    = 0x08000000   # New ipc namespace
CLONE_NEWUSER   = 0x10000000   # New user namespace
CLONE_NEWPID    = 0x20000000   # New pid namespace
CLONE_NEWNET    = 0x40000000   # New network namespace

libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)

# See the relevant system call's man pages and:
#   https://docs.python.org/3/library/ctypes.html#fundamental-data-types
libc.mount.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
                       ctypes.c_ulong, ctypes.c_void_p)
libc.sethostname.argtype = (ctypes.c_char_p, ctypes.c_size_t)
libc.umount.argtypes = (ctypes.c_char_p,)
libc.unshare.argtypes = (ctypes.c_int,)


def Mount(src, tgt, fs, flags=MS_NODEV|MS_NOEXEC|MS_NOSUID|MS_RELATIME):
  ret = libc.mount(src, tgt, fs, flags, None)
  if ret < 0:
    errno = ctypes.get_errno()
    raise OSError(errno, '%s mounting %s on %s (fs=%s flags=%x)'
                  % (os.strerror(errno), src, tgt, fs, flags))


def ReMountProc():
  libc.umount('/proc')  # Ignore failure: might not be mounted
  Mount('proc', '/proc', 'proc')


def ReMountSys():
  libc.umount('/sys')  # Ignore failure: might not be mounted
  Mount('sysfs', '/sys', 'sysfs')


def SetFileContents(f, s):
  open(f, 'w').write(s)


def SetHostName(s):
  ret = libc.sethostname(s, len(s))
  if ret < 0:
    errno = ctypes.get_errno()
    raise OSError(errno, '%s while sethostname(%s)' % (os.strerror(errno), s))


def UnShare(flags):
  ret = libc.unshare(flags)
  if ret < 0:
    errno = ctypes.get_errno()
    raise OSError(errno, '%s while unshare(%x)' % (os.strerror(errno), flags))


def DumpMounts(hdr):
  print
  print hdr
  print open('/proc/mounts', 'r').read(),
  print '---'


# Requires at least kernel configuration options:
#   CONFIG_NAMESPACES=y
#   CONFIG_NET_NS=y
#   CONFIG_UTS_NS=y
def IfPossibleEnterNewNetworkNamespace():
  """Instantiate and transition into a fresh new network namespace if possible."""

  print 'Creating clean namespace...',

  try:
    UnShare(CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWNET)
  except OSError as err:
    print 'failed: %s (likely: no privs or lack of kernel support).' % err
    return False

  try:
    # DumpMounts('Before:')
    ReMountProc()
    ReMountSys()
    # DumpMounts('After:')
    SetHostName('netns')
    SetFileContents('/proc/sys/net/ipv4/ping_group_range', '0 2147483647')
    net_test.SetInterfaceUp('lo')
  except:
    print 'failed.'
    # We've already transitioned into the new netns -- it's too late to recover.
    raise

  print 'succeeded.'
  return True
