import os
import argparse
import pyshark
import time
import asyncio

from aiopacketstrider import streams

__author__ = 'Ben Reardon'
__contact__ = 'benjeems@gmail.com @benreardon'
__version__ = '0.1'
__license__ = 'GNU General Public License v3.0'

PACKETS = []


def parse_command_args():
    """Parse command line arguments"""
    desc = """packetSrider-ssh is a packet forensics tool for SSH.
   It creates a rich feature set from packet metadata such SSH Protocol message content, direction, size, latency and sequencing.
   It performs pattern matching on these features, using statistical analysis, and sliding windows to predict session initiation, 
   keystrokes, human/script behaviour, password length, use of client certificates, 
   context into the historic nature of client/server contact and exfil/infil data movement characteristics 
   in both Forward and Reverse sessions"""
    parser = argparse.ArgumentParser(description=desc)
    helptxt = 'pcap file to analyze'
    parser.add_argument('-f', '--file', type=str, help=helptxt)
    helptxt = 'Perform analysis only on stream n'
    parser.add_argument('-n', '--nstream', default=-1, type=int, help=helptxt)
    helptxt = 'Display stream metadata only'
    parser.add_argument('-m', '--metaonly', help=helptxt, action='store_true')
    helptxt = 'Perform keystroke prediction'
    parser.add_argument('-k', '--keystrokes', help=helptxt, action='store_true')
    helptxt = 'Plot data movement and keystrokes'
    parser.add_argument('-p', '--predict_plot', help=helptxt, action='store_true')
    helptxt = 'Narrow down/zoom the analysis and plotting to only packets "x-y"'
    parser.add_argument('-z', '--zoom', help=helptxt, default='0', type=str)
    helptxt = 'Perform analysis on SSH direction : "forward", "reverse" OR "both"'
    parser.add_argument('-d', '--direction', help=helptxt, default='both', type=str)
    helptxt = 'Directory to output plots'
    parser.add_argument('-o', '--output_dir', type=str, help=helptxt)
    helptxt = 'Sliding window size, # of packets to side of window center packet, default is 2'
    parser.add_argument('-w', '--window', default=2, type=int, help=helptxt)
    helptxt = 'Stride between sliding windows, default is 1'
    parser.add_argument('-s', '--stride', default=1, type=int, help=helptxt)

    return parser.parse_args()

def process_packet(packet):
    PACKETS.append(packet)

def get_streams(packets):
    """ Walks through fullpcap and makes a list (streams) of streams within
    """
    streams = []
    for packet in packets:
        stream = int(packet.tcp.stream)
        if stream not in streams:
            print('    ...found stream {}'.format(stream))
            streams.append(stream)
    return streams


async def main(eventloop):
    """aiopacketstrider-ssh is a packet forensics tool for SSH.
   It creates a rich feature set from packet metadata such SSH Protocol message content, direction, size, latency and sequencing.
   It performs pattern matching on these features, using statistical analysis, and sliding windows to predict session initiation,
   keystrokes, human/script behaviour, password length, use of client certificates,
   context into the historic nature of client/server contact and exfil/infil data movement characteristics
   in both Forward and Reverse sessions"""

    command_args = parse_command_args()

    if command_args.file:
        file = command_args.file
        base_file = os.path.basename(file)
        output_dir = command_args.output_dir
        only_stream = command_args.nstream
        window = int(command_args.window)
        stride = int(command_args.stride)
        keystrokes = command_args.keystrokes
        do_direction = command_args.direction
        meta_only = command_args.metaonly
        do_windowing_and_plots = command_args.predict_plot
        zoom = command_args.zoom
        if output_dir != None:
            # print('output_dir=_{}_'.format(output_dir))
            # TODO Can remove this later, is just to clean dir for debugging
            # shutil.rmtree(output_dir)
            if output_dir and not os.path.exists(output_dir):
                os.makedirs(output_dir)
        else:
            print('no output directory')
        print('\n... Loading full pcap : {}'.format(file))
        if only_stream >= 0:
            string = 'ssh && !tcp.analysis.spurious_retransmission && !tcp.analysis.retransmission && !tcp.analysis.fast_retransmission && tcp.stream==' + str(
                only_stream)
            try:
                fullpcap = pyshark.FileCapture(file, display_filter=string, eventloop=eventloop)
                # TODO is this needed at all ? This was a test access to the data, to ensure that an exception occurs if the data is empty
                # fullpcap[0]
                stream_list = [only_stream]
            except:
                print('There is no stream {} in {}, try another'.format(only_stream, file))
                stream_list = []
                await fullpcap.close_async()
        else:
            fullpcap = pyshark.FileCapture(file, display_filter='ssh && !tcp.analysis.spurious_retransmission && \
                                                                !tcp.analysis.retransmission && \
                                                                !tcp.analysis.fast_retransmission', eventloop=eventloop)
            print('... Getting streams from pcap:')
            await fullpcap.packets_from_tshark(process_packet)
            stream_list = get_streams(PACKETS)

        stream_tasks = []
        for stream in stream_list:
            stream_tasks.append(streams.stream_processor(stream, file, loop, meta_only, window, stride,
                                                                   do_direction,
                                                       do_windowing_and_plots,
                           keystrokes, output_dir, zoom))

        await asyncio.wait(stream_tasks)

    print("\n... packet-strider-ssh complete\n")


if __name__ == '__main__':
    start_time = time.time()
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main(loop))
    end_time = time.time()
    print(f"Total Time: {end_time-start_time}")
