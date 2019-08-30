import pyshark
import pandas
import time
import traceback


from aiopacketstrider import metadata, matrix_builder, analyzer, report


async def stream_processor(stream, file, eventloop, meta_only, window, stride, do_direction, do_windowing_and_plots,
                           keystrokes, output_dir, zoom):
    string = f'ssh && !tcp.analysis.spurious_retransmission && !tcp.analysis.retransmission && ' \
             f'!tcp.analysis.fast_retransmission && tcp.stream=={stream}'
    try:
        stream_packets = []

        def process_stream_packets(packet):
            stream_packets.append(packet)

        print('... Loading stream {}'.format(stream))
        pcap = pyshark.FileCapture(file, display_filter=string, eventloop=eventloop)
        await pcap.packets_from_tshark(process_stream_packets)
        num_packets = len(stream_packets)
        if num_packets > 10:

            print('... Finding meta')
            meta_size = await metadata.find_meta_size(stream_packets, num_packets, stream)
            df_meta_size = pandas.DataFrame([meta_size], columns=[
                'stream', 'Reverse keystoke size', 'size_newkeys_next', 'size_newkeys_next2',
                'size_newkeys_next3', 'size_login_prompt'])

            print('... Finding hassh elements')
            meta_hassh = await metadata.find_meta_hassh(stream_packets, num_packets, stream)
            df_meta_hassh = pandas.DataFrame([meta_hassh], columns=[
                'stream', 'Client Proto', 'hassh', 'Server Proto', 'hassh_server',
                'sip', 'sport', 'dip', 'dport'])

            if len(df_meta_hassh) > 0 and len(df_meta_size) > 0:
                df_stream_meta = df_meta_size.merge(df_meta_hassh, left_on='stream', right_on='stream')
            else:
                df_stream_meta = []

            if meta_only:
                matrix = []
                window_matrix = []
                results = []
            else:
                print('... Building size matrix')
                # Note this returns the raw, unordered matrix
                matrix = await matrix_builder.construct_matrix(stream_packets)
                # Note the matrix is reordered inside the anaylze function to account for any of order
                # keystroke packets Hence appearing on both side of the function call
                results, window_matrix, matrix = await analyzer.analyze(matrix, meta_size, stream_packets, window,
                                                                       stride, do_direction, do_windowing_and_plots, keystrokes)
            time_first_packet = float(stream_packets[0].sniff_timestamp)
            time_first_packet_gmt = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(time_first_packet))
            await pcap.close_async()
            await report.report(results, file, matrix, window_matrix, window, stride, output_dir, df_stream_meta,
                   do_direction, meta_only, do_windowing_and_plots, time_first_packet_gmt, num_packets, zoom)
        else:
            print('    ... < 10 packets in stream {}, quiting this stream'.format(stream))
    except Exception as error:
        print('Error: ({})'.format(error))
        traceback.print_exc()