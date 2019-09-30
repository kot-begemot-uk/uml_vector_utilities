#!/usr/bin/python
#
'''
Wrapper around tcpdump to write out a pcap filter expression as a binary bpf
filter
'''

from argparse import ArgumentParser, REMAINDER
from subprocess import Popen, PIPE
import struct

FRSIZE = 8 # filter record size - short, byte, byte, word

def debug(bpf):
    '''print the filter in a human readable form'''
    for rno in range(0, len(bpf) / FRSIZE):
        (opcode, bpf_jt, bpf_jf, data) = struct.unpack("HBBI", bpf[rno * FRSIZE:(rno + 1) * FRSIZE])
        print "0x{:04x}, 0x{:02x}, 0x{:02x}, 0x{:08x}".format(opcode, bpf_jt, bpf_jf, data)

def compile_bpf(pcap_filter):
    '''Uses tcpdump to compile the filter into machine readable
       form, then builds the binary string out of it'''
    bpfprog = ""
    tcpdump = Popen(["/usr/sbin/tcpdump", "-ddd", "-i", "lo", pcap_filter], stdout=PIPE)
    while True:
        data = tcpdump.stdout.readline()
        print data
        if data == "":
            break
        fields = data.split(" ")
        if len(fields) == 4:
            bpfprog = bpfprog + struct.pack(
                "HBBI", int(fields[0]), int(fields[1]), int(fields[2]), int(fields[3]))
    return bpfprog

def main():
    '''Compile a pcap filter'''
    aparser = ArgumentParser(description=main.__doc__)
    aparser.add_argument(
        '--file',
        help='output file for the filter',
        type=str)

    aparser.add_argument('--verbose', help='verbosity level', type=int)
    aparser.add_argument('filter', nargs=REMAINDER)

    args = vars(aparser.parse_args())

    bpf = compile_bpf(" ".join(args.get('filter')))

    if args.get('verbose'):
        debug(bpf)

    if args.get('file'):
        result = open(args.get('file'), "w")
        result.write(bpf)
        result.close()

if __name__ == '__main__':
    main()
