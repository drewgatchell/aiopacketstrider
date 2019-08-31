import sys
import asyncio

from typing import List

from pyshark.packet.packet import Packet


async def construct_matrix(pcap: List[Packet]) -> List[int]:
    """Returns a matrix containing packet of index, stream and size
       Each packet has a row in the matrix"""
    matrix: List[int] = []
    index = 0
    for packet in pcap:
        # TODO: Async this
        status = f"\r... Carving basic features, packet {index}"
        sys.stdout.write(status)
        sys.stdout.flush()
        # get the packet length
        length = int(packet.tcp.len)
        # To save memory, let server packets have a negative size
        # This best effort port check is required if the session init for this stream is not in the pcap
        if int(packet.tcp.dstport) > int(packet.tcp.srcport):
            length = -length
        # Update the matrix with details
        matrix = matrix + [length]
        index = index + 1

    return matrix


async def construct_window_matrix(
    pcap, matrix, stream, window, stride, meta_size, reverse_init_start, results
):
    """Returns window_matrix containing features of window analysis
       Each packet has a row of features in window_matrix"""

    loop = asyncio.get_event_loop()
    # Splay defined as amount of packets to the left (and right)
    # of the midpoint of the window
    splay = int((window - int(window % 2))) / 2
    # Set the initial mid point (datum) of the first window
    max_client_packet_size = max_server_packet_size = 0

    datum = int(splay)
    window_matrix = []

    # calculate time ranges in order to use in min-max feature normalization of timestamps
    print(
        "   ... Building features with window size = {}, stride = {}".format(
            window, stride
        )
    )
    print("       ... Calculating first packet timestamp")
    time_first_packet = float(pcap[0].sniff_timestamp)
    print("       ... Calculating last packet timestamp")
    time_last_packet = pcap[len(matrix) - 1].sniff_timestamp
    time_last_packet = float(time_last_packet)
    time_range = time_last_packet - time_first_packet
    sniff_timestamp_last = time_first_packet
    # calculate time Delta range in order to use in min-max feature normalization of time deltas
    delta_max = 0
    print("       ... Calculating Max Packet delta")
    for i in range(0, len(matrix)):
        sniff_timestamp = float(pcap[i].sniff_timestamp)
        delta = round(sniff_timestamp - sniff_timestamp_last, 3)
        if delta > delta_max:
            delta_max = delta
        sniff_timestamp_last = sniff_timestamp
    # Reset the initial sniff_timestamp_last after calculating feature scaling params
    sniff_timestamp_last = time_first_packet
    # The "datum" is the center packet of the window
    print("       ... Striding through windows of size {}".format(window))
    while datum < (len(matrix) - splay) and window < (len(matrix) - 1):
        datum_packet_size = matrix[datum]
        server_packets = 0
        server_packets_size = 0
        client_packets = 0
        client_packets_size = 0
        client_packets_list = []
        server_packets_list = []
        packet_size = 0

        for i in range(int(datum - splay), int(datum + splay + 1)):
            packet_size = matrix[i]
            if packet_size < 0:
                if abs(packet_size) > max_server_packet_size:
                    max_server_packet_size = abs(packet_size)
                server_packets = server_packets + 1
                server_packets_size = server_packets_size + packet_size
                server_packets_list.append(int(packet_size))
            else:
                if packet_size > max_client_packet_size:
                    max_client_packet_size = abs(packet_size)
                client_packets = client_packets + 1
                client_packets_size = client_packets_size + packet_size
                client_packets_list.append(int(packet_size))

        # If there were client packets in the window, calculate the stats
        if client_packets_list:
            client_packet_variability = round(
                (len(set(client_packets_list))) / len(client_packets_list), 3
            )
            normalized_client_datum_packet_size = round(
                abs(datum_packet_size / max_client_packet_size), 3
            )
        else:
            client_packet_variability = 0
            normalized_client_datum_packet_size = 0
        # If there were server packets in the window, calculate the stats
        if server_packets_list:
            server_packet_variability = round(
                (len(set(server_packets_list))) / len(server_packets_list), 3
            )
            normalized_server_datum_packet_size = round(
                abs(datum_packet_size / max_server_packet_size), 3
            )
        else:
            server_packet_variability = 0
            normalized_server_datum_packet_size = 0

        ratio_packets = round((client_packets / (client_packets + server_packets)), 3)
        ratio_size = round(
            client_packets_size / (client_packets_size + abs(server_packets_size)), 3
        )

        new_window_row = [
            datum,
            stream,
            window,
            stride,
            normalized_client_datum_packet_size,
            client_packets,
            client_packets_size,
            client_packet_variability,
            normalized_server_datum_packet_size,
            server_packets,
            abs(server_packets_size),
            server_packet_variability,
            ratio_packets,
            ratio_size,
            packet_size,
            datum_packet_size,
        ]
        # Determine if the window size charactericts indicate exfil
        predict_exfiltration = await loop.run_in_executor(
            None, predict_exfil, new_window_row, meta_size, reverse_init_start
        )
        predict_infiltration = await loop.run_in_executor(
            None, predict_infil, new_window_row, meta_size, reverse_init_start
        )
        # Also we want to populate the matrix with atomic Enter key exfils/infils
        enter_child_forward, enter_child_reverse = tag_enter_child_packets(
            new_window_row, results
        )

        sniff_timestamp = round(float(pcap[datum].sniff_timestamp), 3)
        delta_normal = round((sniff_timestamp - sniff_timestamp_last) / delta_max, 3)
        this_time_elapsed_normal = round(
            (sniff_timestamp - time_first_packet) / time_range, 3
        )

        sniff_timestamp_last = sniff_timestamp

        if predict_infiltration or enter_child_forward:
            predict_infiltration_aggregate = 1
        else:
            predict_infiltration_aggregate = 0

        if predict_exfiltration or enter_child_reverse:
            predict_exfiltration_aggregate = 1
        else:
            predict_exfiltration_aggregate = 0

        # Add these predictions and time deltas to the end of new_window_row
        new_window_row = [
            datum,
            stream,
            window,
            stride,
            normalized_client_datum_packet_size,
            client_packets,
            client_packets_size,
            client_packet_variability,
            normalized_server_datum_packet_size,
            server_packets,
            abs(server_packets_size),
            server_packet_variability,
            ratio_packets,
            ratio_size,
            predict_exfiltration,
            predict_infiltration,
            this_time_elapsed_normal,
            delta_normal,
            datum_packet_size,
            enter_child_forward,
            enter_child_reverse,
            predict_infiltration_aggregate,
            predict_exfiltration_aggregate,
        ]
        window_matrix.append(new_window_row)
        # Advance to the next datum by "stride" packets
        datum = datum + stride
    return window_matrix


def tag_enter_child_packets(new_window_row, results):
    """tags packets that occur in contiguous blocks after an enter key has been pressed.
       This is useful to augment exfil/infil predictions based on separate window analysis"""
    enter_child_forward = 0
    enter_child_reverse = 0
    i = new_window_row[0]
    for result in results:
        if "ENTER" in result[1]:
            start = result[2]
            finish = result[3]
            if start < i < finish:
                if "forward" in result[0]:
                    enter_child_forward = 1
                elif "reverse" in result[0]:
                    enter_child_reverse = 1

    return enter_child_forward, enter_child_reverse


def predict_exfil(new_window_row, meta_size, reverse_init_start):
    ratio_packets = new_window_row[12]
    ratio_size = new_window_row[13]
    datum_packet_size = new_window_row[15]
    max_keystroke_size = abs(meta_size[1])

    predict_exfil = 0

    # to prevent FPs, Skip the first 35 packets, as these can contain legit contiguous session init packets from client
    # Also skip the 35 packets after/before reverse_init_start as these also contain legit contiguous client packets
    if new_window_row[0] > 35 and not (
        (reverse_init_start - 35) < new_window_row[0] < (reverse_init_start + 35)
    ):
        # new_window_row[0] > reverse_init_start and new_window_row[0] < (reverse_init_start + 35)):
        # This stems from reverse interactive command line driven exfil
        if (ratio_packets == 1 and ratio_size == 1) and abs(datum_packet_size) > (
            1.2 * abs(max_keystroke_size)
        ):  # and
            # (client_packet_variability >= round((2 / window), 3)) and
            # client_packet_normalized_size > 0.3 and client_packet_normalized_size < 1.0):
            predict_exfil = 1
    return predict_exfil


def predict_infil(new_window_row, meta_size, reverse_init_start):
    """Returns prediction on forward inbound file transfers"""
    ratio_packets = new_window_row[12]
    ratio_size = new_window_row[13]
    predict_infil = 0
    datum_packet_size = new_window_row[15]
    max_keystroke_size = abs(meta_size[1])

    # to prevent FPs Skip the first 35 packets, as these can contain many contiguous session init packets from server
    # Also skip the 30 packets prior to the reverse_init_start as these also contain server packets

    if new_window_row[0] > 35 and not (
        (reverse_init_start - 30) < new_window_row[0] < reverse_init_start
        and new_window_row[0]
    ):
        if (ratio_packets == 0 and ratio_size == 0) and abs(datum_packet_size) > (
            1.2 * abs(max_keystroke_size)
        ):
            predict_infil = 1
    return predict_infil
