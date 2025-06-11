Takes an inode lock and keeps it until module is removed.

## Observations

`CONFIG_LOCKDEP` is needed for the sysrq `d` trigger.

Affects of a locked inode can be observed indirectly via `lsof`:

```sh
$ cat /home/fred/Projects/lock-inode/lockable &
[1] 1969

$ lsof /home/fred/Projects/lock-inode/lockable
root@virtme-ng:/home/fred/Projects/lock-inode# lsof /home/fred/Projects/lock-inode/lockable
COMMAND  PID USER   FD   TYPE DEVICE SIZE/OFF   NODE NAME
cat     1969 root    3r   REG   0,60        5 389987 /home/fred/Projects/lock-inode/lockable
```

`lslocks` doesn't seem useful here.

`perf lock` also apparently needs `CONFIG_LOCKDEP`` too.

`klockstat` libbpf-tool could be used to detect what is waiting on the lock
from the kernel perspective. Similar to `lsof`.

## Build

```sh
$ make src/lockinode.c
$ make run
```

Inside the virtual machine:

```sh
make probe
```

Perform any testing needed.

