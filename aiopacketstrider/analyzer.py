import asyncio

from aiopacketstrider import enrich, matrix_builder


async def analyze(matrix, meta_size, pcap, window, stride, do_direction, do_windowing_and_plots, keystrokes):
    loop = asyncio.get_event_loop()

    # Initialialize with the first packet of the pcap
    # TODO this assumes that the pcap contains the entire init.
    results = [['packet0', 'packet0      ', 0, 0, int(pcap[0].tcp.len), 1, 0]]
    results_f_keystroke = []

    window_matrix = []
    stream = meta_size[0]
    reverse_init_start = results_r_logins = []

    # Order the keystroke packets in this stream so they appear in realtime order
    print('\n   ... Ordering the keystroke packets')
    matrix = await loop.run_in_executor(None, order_keystrokes, matrix, meta_size)

    # only do the rest of the analysis if we have metadata.
    if meta_size[1] != 0:
        if do_direction == 'forward':
            print('   ... Scanning for Forward login attempts')
            results_f_logins, fwd_logged_in_at_packet = await loop.run_in_executor(None,
                                                                                   scan_for_forward_login_attempts,
                                                                                   matrix, meta_size, pcap)
            print('   ... Scanning for Forward key accepts')
            results_f_key_accepts = await loop.run_in_executor(None, scan_for_forward_host_key_accepts, pcap,
                                                                                                 fwd_logged_in_at_packet)
            print('   ... Scanning for Forward login prompts')
            results_f_login_prompts = await loop.run_in_executor(None, scan_for_forward_login_prompts, matrix,
                                                                                                     meta_size, pcap,
                                                                        fwd_logged_in_at_packet)
            # print('fwd_logged_in_at_packet={}'.format(fwd_logged_in_at_packet))
            if keystrokes and fwd_logged_in_at_packet > 0:
                print('   ... Scanning for Forward keystrokes and enters')
                results_f_keystroke = await loop.run_in_executor(None, scan_for_forward_keystrokes, matrix, meta_size,
                                                                                                  pcap,
                                                                        fwd_logged_in_at_packet)

                results = (results + results_f_key_accepts + results_f_login_prompts +
                           results_f_logins + results_f_keystroke)
            else:
                results = results + results_f_key_accepts + results_f_login_prompts + results_f_logins

        elif do_direction == 'reverse':
            print('   ... Scanning for Reverse Session initiation')
            results_r_init, reverse_init_start = await loop.run_in_executor(None, scan_for_reverse_session_initiation,
                matrix, meta_size, pcap)
            if reverse_init_start != 0:
                print('   ... Scanning for Reverse Session logins')
                results_r_logins = await loop.run_in_executor(None, scan_for_reverse_login_attempts, matrix, meta_size,
                                                                                                   pcap,
                                                                             reverse_init_start)

                # TODO only look for keystrokes after reverse_init_start, or do we support multi reverse sessions?
                if keystrokes:
                    print('   ... Scanning for Reverse keystrokes and enters')
                    results_r_keystroke = await loop.run_in_executor(None, scan_for_reverse_keystrokes, matrix,
                                                                                                      meta_size, pcap,
                                                                             reverse_init_start)
                    results = results + results_r_keystroke + results_r_init + results_r_logins
                else:
                    results = results + results_r_init + results_r_logins
        elif do_direction == 'both':
            print('   ... Scanning for Forward login attempts')
            results_f_logins, fwd_logged_in_at_packet = await loop.run_in_executor(None,
                                                                                   scan_for_forward_login_attempts, matrix, meta_size,
                                                                                                 pcap)
            print('   ... Scanning for Forward key accepts')
            results_f_key_accepts = await loop.run_in_executor(None, scan_for_forward_host_key_accepts, pcap,
                                                                                                 fwd_logged_in_at_packet)
            print('   ... Scanning for Forward login prompts')
            results_f_login_prompts = await loop.run_in_executor(None, scan_for_forward_login_prompts, matrix,
                                                                                                     meta_size, pcap,
                                                                        fwd_logged_in_at_packet)
            if keystrokes and fwd_logged_in_at_packet > 0:
                print('   ... Scanning for Forward keystrokes and enters')
                results_f_keystroke = await loop.run_in_executor(None, scan_for_forward_keystrokes, matrix, meta_size,
                                                                                                  pcap,
                                                                        fwd_logged_in_at_packet)
            print('   ... Scanning for Reverse Session initiation')
            results_r_init, reverse_init_start = await loop.run_in_executor(None, scan_for_reverse_session_initiation,
                    matrix, meta_size, pcap)
            if reverse_init_start != 0:
                print('   ... Scanning for Reverse Session logins')
                results_r_logins = await loop.run_in_executor(None, scan_for_reverse_login_attempts, matrix, meta_size,
                                                                                                   pcap,
                                                                             reverse_init_start)
            if keystrokes and fwd_logged_in_at_packet > 0:
                print('   ... Scanning for Reverse keystrokes and enters')
                results_r_keystroke = await loop.run_in_executor(None, scan_for_reverse_keystrokes, matrix, meta_size,
                                                                                                  pcap,
                                                                             reverse_init_start)
                results = results + (results_f_key_accepts + results_f_login_prompts + results_f_logins
                                     + results_f_keystroke + results_r_init + results_r_logins + results_r_keystroke)
            else:
                results = results + (results_f_key_accepts + results_f_login_prompts + results_f_logins +
                                     results_r_init + results_r_logins)
    if do_windowing_and_plots:
        window_matrix = await matrix_builder.construct_window_matrix(pcap, matrix, stream, window, stride, meta_size,
                                                               reverse_init_start,
                                                results)

    results = sorted(results, key=lambda x: x[2])
    # window_matrix = sorted(window_matrix, key=lambda x: x[1])
    results = enrich.enrich_results_time_delta(results)
    results = enrich.enrich_results_notes_field(results)
    return results, window_matrix, matrix


def order_keystrokes(matrix_unordered, meta_size):
    """ Attempts to put forward keystroke packets in order of occurrence in real world"""
    forward_keystroke_size = meta_size[2] - 8
    ordered = []
    keystone = 0
    looking_for_match = 1
    while len(matrix_unordered) > 1:
        size_keystone = matrix_unordered[keystone]
        # If non keystroke packet, then just add to ordered matrix
        if size_keystone != forward_keystroke_size:
            ordered = ordered + [matrix_unordered[keystone]]
            matrix_unordered.remove(matrix_unordered[keystone])
            looking_for_match = 0

        # Must be the start of a keystroke block
        else:
            # Add the keystone to the ordered list
            ordered = ordered + [matrix_unordered[keystone]]
            matrix_unordered.remove(matrix_unordered[keystone])
            looking_for_match = 1

            if looking_for_match == 0:
                ordered = ordered + [matrix_unordered[keystone]]
            # Then look ahead for matches
            else:
                mark = keystone
                count = 0
                while looking_for_match == 1 and mark < len(matrix_unordered):
                    size_mark = matrix_unordered[mark]
                    # Check if this packet is the servers return packet, but only look ahead 10 packets
                    if count == 10:
                        ordered = ordered + [matrix_unordered[mark]]
                        matrix_unordered.remove(matrix_unordered[mark])
                        looking_for_match = 0
                        break

                    if size_mark == -forward_keystroke_size:
                        ordered = ordered + [matrix_unordered[mark]]
                        matrix_unordered.remove(matrix_unordered[mark])
                        looking_for_match = 0
                    elif size_mark <= -(forward_keystroke_size + 8):
                        ordered = ordered + [matrix_unordered[mark]]
                        matrix_unordered.remove(matrix_unordered[mark])
                        looking_for_match = 0
                    else:
                        mark = mark + 1
                    count = count + 1

    # Add any leftover packets onto the end of the ordered list
    ordered = ordered + matrix_unordered

    return ordered


def scan_for_forward_host_key_accepts(pcap, fwd_logged_in_at_packet):
    """Looks for the client's acceptance of the servers SSH host key
       which is when the public key is in known_hosts"""

    results_f_key_accepts = []
    if fwd_logged_in_at_packet == 0:
        stop_at = 100
    else:
        stop_at = fwd_logged_in_at_packet

    timestamp_first = float(pcap[0].sniff_timestamp)
    for i in range(0, len(pcap) - 4):
        if i == stop_at:
            break
        if 'message_code' in dir(pcap[i].ssh):
            # look for 'New Keys' code packet 21, this indicates acceptance of servers key
            if int(pcap[i].ssh.message_code) == 21 and 'message_code' not in dir(pcap[i + 1].ssh):
                # The packet prior to this is the server sending it's key fingerprint
                relative_timestamp = float(pcap[i - 1].sniff_timestamp) - timestamp_first
                results_f_key_accepts = [['forward', 'key offered  ',
                                          i-1, i-1,
                                          int(pcap[i - 1].tcp.len), 1, relative_timestamp]]

                # This packet occurs only once the client has accepted entry of key into known_hosts
                relative_timestamp = float(pcap[i].sniff_timestamp) - timestamp_first
                results_f_key_accepts = results_f_key_accepts + [['forward', 'key accepted ',
                                                                  i, i, int(pcap[i].tcp.len),
                                                                  1, relative_timestamp]]
                break
    return results_f_key_accepts


def scan_for_forward_login_prompts(matrix, meta_size, pcap, fwd_logged_in_at_packet):
    """Looks for the server's login prompt"""

    results_f_login_prompts = []
    size_login_prompt = meta_size[5]
    timestamp_first = float(pcap[0].sniff_timestamp)
    if fwd_logged_in_at_packet == 0:
        stop_at = 300

    else:
        stop_at = fwd_logged_in_at_packet + 2
    for i in range(0, min(len(matrix), stop_at)):
        if matrix[i] == size_login_prompt:
            relative_timestamp = (float(pcap[i].sniff_timestamp) - timestamp_first)
            results_f_login_prompts = results_f_login_prompts + [['forward', 'login prompt ',
                                                                  i, i, int(pcap[i].tcp.len),
                                                                  1, relative_timestamp]]

    return results_f_login_prompts


def scan_for_forward_login_attempts(matrix, meta_size, pcap):
    """Looks for successful and unsuccessful forward SSH logins"""
    fwd_logged_in_at_packet = 0
    results_f_logins = []
    size_login_prompt = meta_size[5]
    timestamp_first = float(pcap[0].sniff_timestamp)
    # Start at packet 8 , to make sure we are out of negotiation phase
    # Only check the first 300 packets for login attempts

    for i in range(8, (min(len(matrix) - 2, 300))):

        if matrix[i] == size_login_prompt and \
                matrix[i + 1] > 0 and \
                matrix[i + 2] == size_login_prompt:
            relative_timestamp = float(pcap[i + 1].sniff_timestamp) - timestamp_first
            results_f_logins = results_f_logins + [['forward', 'login failure',
                                                    i, i + 1,
                                                    abs(matrix[i + 1]), 2, relative_timestamp]]

        if matrix[i] == size_login_prompt and \
                matrix[i + 1] > 0 and \
                matrix[i + 2] < 0 and \
                matrix[i + 2] != size_login_prompt:
            relative_timestamp = float(pcap[i + 1].sniff_timestamp) - timestamp_first
            results_f_logins = results_f_logins + [['forward', 'login success',
                                                    i, i + 1,
                                                    abs(matrix[i + 1]), 2, relative_timestamp]]
            # This is used later as a stop point on scans for password prompts and key accepts
            fwd_logged_in_at_packet = i
            # Stop looking when the log in has been seen
            break
    return results_f_logins, fwd_logged_in_at_packet


def scan_for_reverse_login_attempts(matrix, meta_size, pcap, reverse_init_start):
    """Looks for successful and unsuccessful forward SSH logins"""

    results_r_logins = []
    size_reverse_login_prompt = -meta_size[5] + 40 + 8
    timestamp_first = float(pcap[0].sniff_timestamp)
    # only look at the 300 packets after the first reverse session initiation
    # TODO what if there are mutiple reverse sessions within the single fwd ?
    for i in range(reverse_init_start, min((len(matrix) - 4), 300)):
        if matrix[i] == size_reverse_login_prompt and \
                matrix[i + 1] < -size_reverse_login_prompt and \
                matrix[i + 2] > size_reverse_login_prompt and \
                matrix[i + 3] < -size_reverse_login_prompt and \
                matrix[i + 4] == size_reverse_login_prompt:
            relative_timestamp = float(pcap[i].sniff_timestamp) - timestamp_first
            results_r_logins = results_r_logins + [['reverse', 'login prompt ',
                                                    i, i + 4,
                                                    abs(matrix[i]), 4, relative_timestamp]]
            # The packet directly after the login prompt is when the password is entered
            relative_timestamp = float(pcap[i + 1].sniff_timestamp) - timestamp_first
            results_r_logins = results_r_logins + [['reverse', 'login failure',
                                                    i, i + 4,
                                                    abs(matrix[i + 1]), 4, relative_timestamp]]
        if matrix[i] == size_reverse_login_prompt and \
                matrix[i + 1] < -size_reverse_login_prompt and \
                0 < matrix[i + 2] < size_reverse_login_prompt and \
                matrix[i + 3] < -size_reverse_login_prompt and \
                0 < matrix[i + 4] < size_reverse_login_prompt:

            relative_timestamp = float(pcap[i].sniff_timestamp) - timestamp_first
            results_r_logins = results_r_logins + [['reverse', 'login prompt ',
                                                    i, i + 4,
                                                    abs(matrix[i]), 4, relative_timestamp]]
            # The packet directly after the login prompt is when the password is entered
            relative_timestamp = float(pcap[i + 1].sniff_timestamp) - timestamp_first
            results_r_logins = results_r_logins + [['reverse', 'login success',
                                                    i, i + 4,
                                                    abs(matrix[i + 1]), 4, relative_timestamp]]
            # Stop looking once reverse is logged in
            break
    return results_r_logins


def scan_for_forward_keystrokes(matrix, meta_size, pcap, fwd_logged_in_at_packet):
    """ Looks for forward key strokes """
    results_f_keystroke = []
    forward_keystroke_size = meta_size[2] - 8
    packets_infiltrated = 0
    bytes_infiltated = 0
    keystrokes = 0

    timestamp_first = float(pcap[0].sniff_timestamp)
    # Skip over packets prior to successful login as there are no keylogs there
    i = fwd_logged_in_at_packet

    while i < len(matrix) - 2:
        size_this = matrix[i]
        size_next = matrix[i + 1]
        size_next_next = matrix[i + 2]
        if size_this == forward_keystroke_size:

            if size_next == -forward_keystroke_size and size_next_next == forward_keystroke_size:
                relative_timestamp = float(pcap[i].sniff_timestamp) - timestamp_first
                keystrokes = keystrokes + 1
                results_f_keystroke = results_f_keystroke + [['forward', 'keystroke    ',
                                                              i, i + 1,
                                                              abs(size_this), 2, relative_timestamp]]
                i = i + 2
            elif size_next == -(forward_keystroke_size + 8) and size_next_next == forward_keystroke_size:
                relative_timestamp = float(pcap[i].sniff_timestamp) - timestamp_first
                keystrokes = keystrokes + 1
                results_f_keystroke = results_f_keystroke + [['forward', '< delete/ac  ',
                                                              i, i + 1,
                                                              abs(size_this), 2, relative_timestamp]]
                i = i + 2
            # If packet is server packet, and bigger than forward size (i.e not a keepalive), lets report the enter key
            elif size_next < -(forward_keystroke_size + 8) and size_next_next == forward_keystroke_size:
                relative_timestamp = float(pcap[i].sniff_timestamp) - timestamp_first
                keystrokes = keystrokes + 1
                results_f_keystroke = results_f_keystroke + [['forward', 'tab complete ',
                                                              i, i + 1,
                                                              abs(size_this), 2, relative_timestamp]]
                i = i + 1

            elif size_next <= -forward_keystroke_size and size_next_next <= -forward_keystroke_size and keystrokes > 0:
                i_enterkey_pressed = i
                finish = i + 2
                # Look forward past the return and calculate the number of bytes in subsequent Server packets
                relative_timestamp = float(pcap[i].sniff_timestamp) - timestamp_first
                while finish < len(matrix):
                    # A client packet signifies the end of a contiguous server block of packets
                    if matrix[finish] > 0:
                        i = finish
                        break
                    packets_infiltrated = packets_infiltrated + 1
                    bytes_infiltated = bytes_infiltated + abs(matrix[finish])
                    finish = finish + 1
                    i = i + 1
                results_f_keystroke = results_f_keystroke + [['forward', '_\u2503 ENTER     ',
                                                              i_enterkey_pressed, i,
                                                              bytes_infiltated, packets_infiltrated,
                                                              relative_timestamp]]
                packets_infiltrated = 0
                bytes_infiltated = 0
                keystrokes = 0
            else:
                i = i + 1

        # This component seems to FP on some file transfers. uncomment this if you like though. YMMV
        # elif (size_this == (forward_keystroke_size + 8) and size_next <= -(forward_keystroke_size + 8)) or \
        #         ((forward_keystroke_size + 40) > size_this > forward_keystroke_size and
        #          size_next == -size_this):
        #     relative_timestamp = float(pcap[i].sniff_timestamp) - timestamp_first
        #     results_f_keystroke = results_f_keystroke + [['forward', 'UP/DOWN/Paste',
        #                                                   i, i + 1,
        #                                                   abs(size_this), 2, relative_timestamp]]
        #     keystrokes = keystrokes + 1
        #     i = i + 2

        else:
            i = i + 1

    return results_f_keystroke


def scan_for_reverse_session_initiation(matrix, meta_size, pcap):
    """Looks for when a Reverse sesssion is initiated by watching for reverse meta"""
    reverse_init_start = 0
    results_r_init = []
    size_newkeys_next = meta_size[2]
    size_newkeys_next2 = meta_size[3]
    timestamp_first = float(pcap[0].sniff_timestamp)

    for i in range(0, len(matrix) - 3):
        if matrix[i + 1] == -(size_newkeys_next + 40) and \
                matrix[i + 2] == -(size_newkeys_next2 - 40) and \
                matrix[i + 3] < 0 and \
                abs(matrix[i + 3]) >= (matrix[i + 2]):
            relative_timestamp = float(pcap[i + 1].sniff_timestamp) - timestamp_first
            reverse_init_start = i
            finish = i + 3
            results_r_init = (results_r_init + [['reverse', 'session init ',
                                                 reverse_init_start, finish,
                                                 abs(matrix[i + 1]), 3, relative_timestamp]])
    return results_r_init, reverse_init_start


def scan_for_reverse_keystrokes(matrix, meta_size, pcap, reverse_init_start):
    """ Looks for reverse key strokes """
    results_r_keystroke = []
    reverse_keystroke_size = meta_size[1]
    packets_exfiltrated = 0
    bytes_exfiltated = 0
    keystrokes = 0
    timestamp_first = float(pcap[0].sniff_timestamp)
    # Skip over all packets prior to reverse_init_start as there are no reverse keystrokes here
    i = reverse_init_start - 1

    while i < len(matrix) - 2:
        size_this = matrix[i]
        size_next = matrix[i + 1]
        size_next_next = matrix[i + 2]
        if size_this == reverse_keystroke_size:

            if size_next == -reverse_keystroke_size and size_next_next == reverse_keystroke_size:
                keystrokes = keystrokes + 1
                relative_timestamp = float(pcap[i].sniff_timestamp) - timestamp_first
                results_r_keystroke = results_r_keystroke + [['reverse', 'keystroke    ',
                                                              i, i + 1,
                                                              abs(size_this), 2, relative_timestamp]]
                i = i + 2
            # debug changed +8 to -8
            elif size_next == -(reverse_keystroke_size - 8) and size_next_next == reverse_keystroke_size:

                keystrokes = keystrokes + 1
                relative_timestamp = float(pcap[i].sniff_timestamp) - timestamp_first
                results_r_keystroke = results_r_keystroke + [['reverse', '< delete     ',
                                                              i, i + 1,
                                                              abs(size_this), 2, relative_timestamp]]
                i = i + 2

            # If packet is client packet, but is not the delete key size, lets report the enter key
            # debug changed +8 to -8
            elif size_next == -reverse_keystroke_size and \
                    size_next_next > -(reverse_keystroke_size - 8) and keystrokes > 0:
                relative_timestamp = float(pcap[i].sniff_timestamp) - timestamp_first
                i_enterkey_pressed = i
                finish = i + 2
                # Look forward past the return and calculate the number of bytes in subsequent Client packets
                while finish < len(matrix):
                    # A server packet signifies the end of a contiguous server block of packets
                    if matrix[finish] < 0:
                        i = finish
                        break
                    packets_exfiltrated = packets_exfiltrated + 1
                    bytes_exfiltated = bytes_exfiltated + abs(matrix[finish])
                    finish = finish + 1
                    i = i + 1

                results_r_keystroke = results_r_keystroke + [['reverse', '_\u2503 ENTER     ',
                                                              i_enterkey_pressed, i,
                                                              bytes_exfiltated, packets_exfiltrated,
                                                              relative_timestamp]]
                packets_exfiltrated = 0
                bytes_exfiltated = 0
                keystrokes = 0
            else:
                i = i + 1

        else:
            i = i + 1
    return results_r_keystroke
