import textwrap
import frida
import os
import sys
import frida.core
import dumper
import utils
import argparse
import logging

logo = """

   __        _      _                                  _           _ 
  / _|      (_)    | |                                | |         (_)
 | |_  _ __  _   __| | _   _  _ __ ___   _ __  ______ | | __ __ _  _ 
 |  _|| '__|| | / _` || | | || '_ ` _ \ | '_ \|______|| |/ // _` || |
 | |  | |   | || (_| || |_| || | | | | || |_) |       |   <| (_| || |
 |_|  |_|   |_| \__,_| \__,_||_| |_| |_|| .__/        |_|\_\\__,_||_|
                                        | |                          
                                        |_|                          
"""


# Main Menu
def MENU():
    parser = argparse.ArgumentParser(
        prog='fridump',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent(""))

    parser.add_argument('pid',
                        help='pid of the process that you will be injecting to')
    parser.add_argument('-o', '--out', type=str, metavar="dir",
                        help='provide full output directory path. (def: \'dump\')')
    parser.add_argument('-U', '--usb', action='store_true',
                        help='device connected over usb')
    parser.add_argument('-D', '--device', action='store',
                    help='specify a device by device id')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='verbose')
    # parser.add_argument('-r', '--read-only', action='store_true',
    #                     help="dump read-only parts of memory. More data, more errors")
    parser.add_argument('-x', '--executable', action='store_true',
                        help="dump executable parts of memory.")
    parser.add_argument('-s', '--strings', action='store_true',
                        help='run strings on all dump files. Saved in output dir.')
    parser.add_argument('--max-size', type=int, metavar="bytes",
                        help='maximum size of dump file in bytes (def: 20971520)')
    args = parser.parse_args()
    return args


print(logo)

arguments = MENU()

# Define Configurations
APP_PID = arguments.pid
DIRECTORY = ""
USB = arguments.usb
DEBUG_LEVEL = logging.INFO
STRINGS = arguments.strings
MAX_SIZE = 2*1024*1024*1024 # 2GB
PERMS = ['rw-', 'r--']
PERMS = []
DEVICE = arguments.device

if arguments.executable:
    PERMS.append('r-x')
    PERMS.append('rwx')
    PERMS.append('--x') # For XOM

# if arguments.read_only:
#     PERMS = 'r--'

if arguments.verbose:
    DEBUG_LEVEL = logging.DEBUG
logging.basicConfig(format='%(levelname)s:%(message)s', level=DEBUG_LEVEL)


# Start a new Session
session = None
try:
    if USB:
        session = frida.get_usb_device().attach(int(APP_PID))
    elif DEVICE is not None:
        session = frida.get_device(DEVICE).attach(int(APP_PID))
    else:
        session = frida.attach(int(APP_PID))
except Exception as e:
    print("Can't connect to App. Have you connected the device?")
    logging.debug(str(e))
    sys.exit()


# Selecting Output directory
if arguments.out is not None:
    DIRECTORY = arguments.out
    if os.path.isdir(DIRECTORY):
        print("Output directory is set to: " + DIRECTORY)
    else:
        print("The selected output directory does not exist!")
        sys.exit(1)

else:
    print("Current Directory: " + str(os.getcwd()))
    DIRECTORY = os.path.join(os.getcwd(), "dump")
    print("Output directory is set to: " + DIRECTORY)
    if not os.path.exists(DIRECTORY):
        print("Creating directory...")
        os.makedirs(DIRECTORY)

mem_access_viol = ""

print("Starting Memory dump...")

# makexomreadable: To make XOM readable
script = session.create_script(
    """'use strict';

    rpc.exports = {
      enumerateRanges: function (prot) {
        return Process.enumerateRangesSync(prot);
      },
      readMemory: function (address, size) {
        return Memory.readByteArray(ptr(address), size);
      },
      makexomreadable: function (addr, size) {
        return Memory.protect(ptr(addr), size, 'r-x');
      }
    };

    """)
script.on("message", utils.on_message)
script.load()

agent = script.exports
ranges = []
for perm in PERMS:
    ranges += agent.enumerate_ranges(perm)

if arguments.max_size is not None:
    MAX_SIZE = arguments.max_size

i = 0
l = len(ranges)

# Performing the memory dump
for range in ranges:
    base = range["base"]
    size = range["size"]

    logging.debug("Base Address: " + str(base))
    logging.debug("")
    logging.debug("Size: " + str(size))

    if range["protection"] == '--x':
        # start = int(base, 16) & ~(4096-1)
        # end = (int(base, 16) + int(size) - 1 + 4096-1) & ~(4096-1)
        # mp_len = end - start + 1
        # ret = agent.makexomreadable(start, mp_len)
        ret = agent.makexomreadable(int(base, 16), int(size))
        if ret:
            logging.info("XOM memory " + str(base) + " is now readable.")
        else:
            logging.info("Making XOM memory " + str(base) + " readable failed.")


    if size > MAX_SIZE:
        logging.debug("Too big, splitting the dump into chunks")
        mem_access_viol = dumper.splitter(
            agent, base, size, MAX_SIZE, mem_access_viol, DIRECTORY)
        continue
    mem_access_viol = dumper.dump_to_file(
        agent, base, size, mem_access_viol, DIRECTORY)
    i += 1
    utils.printProgress(i, l, prefix='Progress:', suffix='Complete', bar=50)
print("")

# Run Strings if selected

if STRINGS:
    files = os.listdir(DIRECTORY)
    i = 0
    l = len(files)
    print("Running strings on all files:")
    for f1 in files:
        utils.strings(f1, DIRECTORY)
        i += 1
        utils.printProgress(i, l, prefix='Progress:', suffix='Complete', bar=50)
print("Finished!")