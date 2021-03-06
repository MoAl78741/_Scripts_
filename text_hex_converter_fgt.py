#!/usr/bin/env python3
# To run:  python3 text_hex_converter_fgt.py -fgt input.txt > input.txt.converted && text2pcap -t "%d/%m/%Y %H:%M:%S." input.txt.converted output.pcap
# Quick script to convert sniffer output from FortiGate and TCPDump to hex in order to run through text2pcap for final PCAP format. 
# Similar to fgt2eth.pl which also converts to hex then pipes to text2pcap.

from re import compile
import sys

class ParsePacket(object):
    '''Parses sniffer output for FortiGate devices'''

    text_input_file_as_hex = ""

    def __init__(self):
        # identifying lines
        self.re_identify_hex_data = r'^\t|^(0x\w{4}\:?\s+([0-9a-f]{2,4}\s){2,10})'
        self.re_identify_timestamp = r'^(\d+\.\d+)\s|^(\d+\-\d+\-\d+)\s(\d+\:\d+:\d+\.\d+)\s'

        # header time parsing
        self.headerLineTimeAbsolute = r'(^([0-9]{4})-(\d\d)-(\d\d) (\d\d):(\d\d):(\d\d)\.([0-9]*) )' # 2015-06-23 17:00:16.633104 
        self.headerLineTimeRelative = r'(^([0-9]*)\.([0-9]*)[ \t])'    # 0.951333        

    def identify_line(self, line : str) -> int:
        '''
        :param $line
        :return int 1|2 (1=header|2=body)
        '''
        idhexc = compile(self.re_identify_hex_data)
        idtsc = compile(self.re_identify_timestamp)
        idhexs = idhexc.search(line)
        idtss = idtsc.search(line)
        if idhexs:
            return 0
        elif idtss:
            return 1

    def identify_timestamp(self, line : str):
        absolutec = compile(self.headerLineTimeAbsolute)
        relativec = compile(self.headerLineTimeRelative)
        absolutes = absolutec.search(line)
        relatives = relativec.search(line)
        if absolutes:
            return 0
        if relatives:
            return 1
        raise Exception('Unable to identify timestamp in packet header')

    def parsepacket_header_absolute_time(self, line : list) -> tuple:
        '''
        absolute time format
        :param      2015-06-23 17:00:16.633104 wan1 in arp who-has 10.108.17.254 tell 10.108.16.125
        :returns    23/06/2015, 17:00:16.633104, wan1, in
        '''
        year, month, day = [ int(i) for i in line.pop(0).split('-') ]
        hours, minutes, seconds = [ i if '.' in i else int(i) for i in line.pop(0).split(':') ]
        seconds, msecs = [ int(i) for i in seconds.split('.') ]
        iface = line.pop(0)
        direction = line.pop(0)
        ts = f'{hours}:{minutes}:{seconds}.{msecs}'
        us = f'{day}/{month}/{year}'
        return us, ts, iface, direction      

    def parsepacket_header_relative_time(self, line : list) -> tuple:
        '''
        relative time format
        :param      0.806164 wan1 in arp who-has 10.108.18.77 tell 10.108.17.106
        :returns    0, 806164, wan1, in
        '''
        time_param = line.pop(0).split('.')
        ts = time_param[0]
        us = time_param[1]
        iface = line.pop(0)
        direction = line.pop(0)
        return ts, us, iface, direction

    def parsepacket_body_prefix_remove_x(self, line : list) -> list:
        ''' 1
        converts 0x to 00
        :param line:    0x0000\t ffff ffff ffff 94de 8061 a404 0806 0001
        :return:        000000\t ffff ffff ffff 94de 8061 a404 0806 0001
        '''
        line[0] = line[0].replace('x', '0')
        return line


    def parsepacket_body_ascii(self, line : list) -> list:
        ''' 2
        removes ascii
        :param  000000	 ffff ffff ffff 94de 8061 a404 0806 0001	.........a......
        :return 000000	 ffff ffff ffff 94de 8061 a404 0806 0001
        '''
        line.pop(-1)
        return line

    def parsepacket_body_split_in_two(self, line : list) -> str:
        ''' 3
        converts 0000 to 00 00
        :param line:    000000\t ffff ffff ffff 94de 8061 a404 0806 0001
        :return:        000000\t ff ff ff ff ff ff 94 de 80 61 a4 04 08 06 00 01
        final hex conversion step
        '''
        prefix = line.pop(0)
        line = ''.join(line)
        two_list = [line[i:i+2] for i in range(0, len(line), 2)]
        line = ' '.join(two_list)
        return f'{prefix}  {line}'

    def parsepacket_body_final(self, line : list) -> str:
        newline = self.parsepacket_body_prefix_remove_x(line)  #000000   ffff ffff ffff 94de 8061 a404 0806 0001        .........a......
        newline = self.parsepacket_body_ascii(newline)               #000000   ffff ffff ffff 94de 8061 a404 0806 0001
        return self.parsepacket_body_split_in_two(newline)   #000000   ff ff ff ff ff ff 94 de 80 61 a4 04 08 06 00 01

    def header_line_operations(self, line : str):
        timestamp_code = self.identify_timestamp(line)
        if timestamp_code == 0:         #absolute timestamp
            us_date, ts_time, iface, direction = self.parsepacket_header_absolute_time(line.split())    #(23/06/2015, 17:00:16.633104, 'wan1', 'in')
            return f'\n{us_date} {ts_time}' + '\n'
        if timestamp_code == 1:         #relative timestamp
            ts, us, iface, direction = self.parsepacket_header_relative_time(line.split())              #(0, 806164, 'wan1', 'in')
            return f'\n01/01/2005 0:0:{ts}.{us}' + '\n'

    def body_line_operations(self, line: str):
        return self.parsepacket_body_final(line.split()) + '\n'

    def header_line_operations_run(self, line : str):
        header = self.header_line_operations(line)
        self.append_to_class_var(header)
    
    def body_line_operations_run(self, line : str):
        body = self.body_line_operations(line)
        self.append_to_class_var(body)

    def run_operations(self, file : str):
        with open(file, 'r') as infile:
            rfile = infile.read()       
        for line in rfile.splitlines():
            line_code = self.identify_line(line)  #identify line 1=header 2=body
            if line_code == 1:                  #header lines
                self.header_line_operations_run(line)
            elif line_code == 0: #body lines
                self.body_line_operations_run(line)

    @classmethod
    def run_text_to_hex_conversion(cls, file):
        cls().run_operations(file)
        return cls().text_input_file_as_hex

    @staticmethod
    def append_to_class_var(line):
        ParsePacket.text_input_file_as_hex += line


class ParsePacketTcpDump(ParsePacket):
    '''Parses sniffer output for TCPDump devices'''
   
    def convert_data_to_fgt_compatible(self, line : str) -> str:
        '''
        tcpdump: 0x0000:  0001 0800 0604 0001 94de 8061 a404 0a6c  ...........a...l
        fgt: 0x0000	 ffff ffff ffff 000c 2913 c0cf 0806 0001	........).......
        returns: 0x0000  0001 0800 0604 0001 94de 8061 a404 0a6c  ...........a...l
        '''
        line = line.split()
        line[0] = line[0].split(':')[:-1][0]
        return ' '.join(line)

    def body_line_operations_run(self, line : str):
        line = self.convert_data_to_fgt_compatible(line)
        super().body_line_operations_run(line)


def main():
    if sys.argv[1] == '-fgt':
        results = ParsePacket.run_text_to_hex_conversion(sys.argv[2])
        print(results) 
    if sys.argv[1] == '-tcpdump':
        results = ParsePacketTcpDump.run_text_to_hex_conversion(sys.argv[2])
        print(results)

if __name__ == '__main__':
     main()
