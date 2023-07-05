# Fridump-kai
Fridump-kai is an open source memory dumping tool based on [fridump](https://github.com/Nightbringer21/fridump), and is primarily for Android revesing. Fridump-kai uses the Frida framework, so it can be used on Windows, Linux or Mac OS X system to dump the memory of an iOS, Android or Windows application theoretically.

However, it is found that on many Android devices, fridump's target selection does not work. Hence, fridump-kai only supports choosing target process precisely by pid. You may also view other important features below.

Note: 'kai' means 'improved' here.

Features
---
- Choosing target process by pid.
- Device selection.
- [XOM](https://source.android.google.cn/docs/security/test/execute-only-memory?hl=zh-cn) dumping.
- Dump all readable memory by default, and executable memory if required.

Usage
---

How to:

      fridump [-h] [-o dir] [-U/-D] [-v] [-x] [-s] [--max-size bytes] <pid>

The following are the main flags that can be used with fridump-kai:

      positional arguments:
      pid            pid of the process that you will be injecting to

      optional arguments:
      -h, --help         show this help message and exit
      -o dir, --out dir  provide full output directory path. (default: 'dump')
      -U, --usb          device connected over usb
      -D, --device       specify a device by device ID, you can enumrate all devices by running frida-ls-devices
      -v, --verbose      verbose
      -x, --executable   dump executable memory.
      -s, --strings      run strings on all dump files. Saved in output dir.
      --max-size bytes   maximum size of dump file in bytes (default: 2GB)

To find the name of a local process, you can use:

      frida-ps
For a process that is running on a USB connected device, you can use:

      frida-ps -U
or

      frida-ps -D <device ID>

Example:

      python fridump.py -D abcd1234 -x 8848         # Dump all readable and executable memory of pid 8848, from device abcd1234


Installation
---
To install fridump-kai you just need to clone it from git and run fridump.py.

            
Pre-requisites
---
To use fridump-kai you need to have frida installed on your python environment and frida-server on the device you are trying to dump the memory from.
The easiest way to install frida on your python is using pip:

    pip install frida
    pip install frida-tools
    
More information on how to install Frida can be found [here](http://www.frida.re/docs/installation/)

For iOS, installation instructions can be found [here](http://www.frida.re/docs/ios/).

For Android, installation instructions can be found [here](http://www.frida.re/docs/android/).

Note: On Android devices, make sure that the frida-server binary is running as root!

Original work by Nightbringer21
---
Thanks to [fridump](https://github.com/Nightbringer21/fridump)!
