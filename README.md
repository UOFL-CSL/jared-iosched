# Jared I/O Scheduler

A minimalistic I/O scheduler for [blk-mq](https://www.thomas-krenn.com/en/wiki/Linux_Multi-Queue_Block_IO_Queueing_Mechanism_(blk-mq)).

## Installation

The following steps are recommended in retrieving the package:
 1. Use `wget` to pull the latest [tarball](https://github.com/uofl-csl/jared-iosched/releases) onto the machine. 
 2. Run `tar xvzf <file-name>.tar.gz` on the tarball to extract it.
 3. `cd` into the directory.
 4. Run `make` to install the I/O scheduler.
 5. (Optional) If failure to find modules when running make...
   * Obtain source code from current kernel: `apt-get source linux-image-$(uname -r)`
   * Obtain build dependencies `sudo apt-get build-dep linux-image-$(uname -r)`
   * Place `jared-iosched.c` and `Makefile` in kernel source directory/block.
   * Run `make` to install the I/O scheduler.
 6. Run `sudo insmod jared-iosched.ko` to install the module.
 7. Validate it is installed by running `sudo lsmod`.
 
## Changelog

All changes and versioning information can be found in the [CHANGELOG](https://github.com/UOFL-CSL/jared-iosched/tree/master/CHANGELOG.md).

## License

Copyright (c) 2019 UofL Computer Systems Lab. See [LICENSE](https://github.com/UOFL-CSL/iobs/tree/master/LICENSE) for details.
