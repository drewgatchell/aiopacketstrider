import os
import asyncio
import concurrent.futures

import pandas
import matplotlib.pyplot as plt


async def report(results, file, matrix, window_matrix, window, stride, output_dir, df_stream_meta, do_direction,
           meta_only, do_plots, time_first_packet_gmt, num_packets, zoom):

    loop = asyncio.get_event_loop()
    row = 0
    stream = df_stream_meta.loc[row, 'stream']
    client_protocol = df_stream_meta.loc[row, 'Client Proto']
    server_protocol = df_stream_meta.loc[row, 'Server Proto']
    hassh = df_stream_meta.loc[row, 'hassh']
    hassh_server = df_stream_meta.loc[row, 'hassh_server']
    sip = df_stream_meta.loc[row, 'sip']
    sport = df_stream_meta.loc[row, 'sport']
    dip = df_stream_meta.loc[row, 'dip']
    dport = df_stream_meta.loc[row, 'dport']
    # Prepare filenames for results
    if output_dir != None:
        base_file = os.path.basename(file)
        output_dir = output_dir  # +'/'+base_file
        string_file = str('./' + output_dir + '/' + 'packet-strider-ssh ' + base_file +
                          ' stream ' + str(stream) + ' - Summary.txt')
        out_plot_predictions = str('./' + output_dir + '/' + 'packet-strider-ssh ' + base_file +
                                   ' stream ' + str(stream) + ' - Data Movement.png')
        out_plot_keystroke_timeline = str('./' + output_dir + '/' + 'packet-strider-ssh ' + base_file +
                                          ' stream ' + str(stream) + ' - Keystrokes.png')

    print('\n\u250F\u2501\u2501\u2501\u2501 Reporting results for stream {}'.format(stream))

    num_f_init_events = num_f_keystroke_events = 0
    num_r_init_events = num_r_keystroke_events = 0
    bytes_f_infiled = bytes_r_exfiled = 0
    num_predict_exfiltrations = 0
    predict_exfiltrations_bytes = 0
    num_predict_infiltrations = 0
    predict_infiltrations_bytes = 0

    for row in window_matrix:
        if row[21] == 1:
            num_predict_exfiltrations += 1
            predict_exfiltrations_bytes = predict_exfiltrations_bytes + matrix[row[0]]

        if row[22] == 1:
            num_predict_infiltrations += 1
            predict_infiltrations_bytes = predict_infiltrations_bytes + matrix[row[0]]

    # Aggregate the Indicator numbers
    for result in results:
        # First do Forward indicators
        if 'forward' in result[0]:
            if 'login' in result[1] or 'key ' in result[1]:
                num_f_init_events += 1
            elif 'ENTER' in result[1]:
                num_f_keystroke_events += 1
                bytes_f_infiled = bytes_f_infiled + int(result[4])
            else:
                num_f_keystroke_events += 1
        # Then do Reverse indicators
        elif 'reverse' in result[0]:
            if 'init' in result[1] or 'login' in result[1]:
                num_r_init_events += 1
            elif 'ENTER' in result[1]:
                num_r_keystroke_events += 1
                bytes_r_exfiled = bytes_r_exfiled + int(result[4])
            else:
                num_r_keystroke_events += 1
    # TODO simplify this block of reporting code
    print('\u2503')
    print('\u2503 Stream \033[0;33;40m{}\033[0m of pcap \'{}\''.format(stream, file))
    print('\u2503 {} packets in total, first at {}'.format(num_packets, time_first_packet_gmt))
    print('\u2503 \033[0;36;40m{}:{}\033[0m -> \033[0;31;40m {}:{}\033[0m'.format(sip, sport, dip, dport))
    print('\u2503 Client Proto : \033[0;33;40m{}\033[0m'.format(client_protocol))
    print('\u2503 hassh        : \033[0;33;40m{}\033[0m'.format(hassh))
    print('\u2503 Server Proto : \033[0;33;40m{}\033[0m'.format(server_protocol))
    print('\u2503 hasshServer  : \033[0;33;40m{}\033[0m'.format(hassh_server))
    print('\u2503 Summary of findings:')
    if (do_direction == 'forward' or do_direction == 'both') and not meta_only:
        if num_f_init_events > 0:
            print('\u2503       \033[0;36;40m {} Forward SSH login/init events\033[0m'.format(num_f_init_events))
        if num_f_keystroke_events > 0:
            print('\u2503       \033[0;36;40m {} Forward keystroke related events\033[0m'.
                  format(num_f_keystroke_events))
        # TODO fix this, calculate aggregate and report on this rather than separate techniques.
        # if bytes_f_infiled > 0:
        #    print('\u2503       \033[0;36;40m Estimated {} Bytes infiled\033[0m'.format(bytes_f_infiled))

    if (do_direction == 'reverse' or do_direction == 'both') and not meta_only:
        if num_r_init_events > 0:
            print('\u2503       \033[1;31;40m {} Reverse SSH login/init events\033[0m'.format(num_r_init_events))
        if num_r_keystroke_events > 0:
            print('\u2503       \033[1;31;40m {} Reverse keystroke related events\033[0m'.
                  format(num_r_keystroke_events))
        # TODO fix this, calculate aggregate and report on this rather than separate techniques.
        # if bytes_r_exfiled > 0:
        #    print('\u2503       \033[1;31;40m Estimated {} Bytes exfiled\033[0m'.format(bytes_r_exfiled))

    # if num_predict_exfiltrations > 0 and not meta_only:
    #     print('\u2503\033[0;2;40m {} POSITIVE outbound exfiltation predictions from Window modeling ({} MB - lower bound)\033[0m'.
    #           format(num_predict_exfiltrations, round((abs(predict_exfiltrations_bytes) / 1024 / 1024), 3)))
    # if num_predict_infiltrations > 0 and not meta_only:
    #     print('\u2503\033[0;2;40m {} POSITIVE inbound transfer predictions from Window modeling ({} MB - lower bound)\033[0m'
    #           .format(num_predict_infiltrations, round((abs(predict_infiltrations_bytes) / 1024 / 1024), 3)))
    if results:
        pretty_print(results)
    if window_matrix and not meta_only and do_plots:
        with concurrent.futures.ProcessPoolExecutor() as pool:
            zleft, zright = zooms(zoom, num_packets)
            if len(matrix) > 10:
                print('\u2503 Plotting packets {}-{} size histogram to \'{}\''.format(zleft, zright,
                                                                                  out_plot_predictions))

                await loop.run_in_executor(pool, plot_packet_size_histogram, stream, matrix, output_dir, base_file,
                                           zleft,
                                  zright)

            print('\u2503 Plotting packets {}-{} Data Movement predictions to \'{}\''.format(zleft, zright,
                                                                                         out_plot_predictions))

            await loop.run_in_executor(pool, plot_window_stat_predictions, stream, window_matrix, window, stride, file,
                                                                 out_plot_predictions,
                                               zleft, zright)
            if results:
                print('\u2503 Plotting packets {}-{} keystroke timeline to \'{}\''.format(zleft, zright,
                                                                                      out_plot_keystroke_timeline))

            # Now plot the keystroke timeline
                await loop.run_in_executor(pool, plot_keystroke_timeline, stream, results, window_matrix, file,
                                                                out_plot_keystroke_timeline,
                                    df_stream_meta, zleft, zright)
            else:
                print('\u2503 No keystrokes found')

    print('\u2503')
    print('\u2517\u2501\u2501\u2501\u2501 End of Analysis for stream {}'.format(stream))


def pretty_print(results):
    """Prints colorized table of results to terminal"""

    print('\u2503 Detailed Events:')
    print('\u2503     packet     time(s)   delta(s)   Direction Indicator      Bytes   Notes')
    print('\u2503   -----------------------------------------------------------------------')
    for result in results:
        # print(result)
        if result[0] == 'forward':
            print('\u2503       \033[1;36;40m{:<10}{:<10}{:<10}{:<10}{:^10}{:^10}{:^10}\033[0m'.
                  format(result[3], round(result[6], 3), round(result[7], 3), result[0], result[1], result[4], result[8]))
        elif result[0] == 'reverse':
            print('\u2503       \033[1;31;40m{:<10}{:<10}{:<10}{:<10}{:^10}{:^10}{:^10}\033[0m'.
                  format(result[3], round(result[6], 3), round(result[7], 3), result[0], result[1], result[4], result[8]))
        else:
            print('\u2503       {:<10}{:<10}{:<10}{:<10}{:^10}{:^10}{:^10}'.
                  format(result[3], round(result[6], 3), round(result[7], 3), result[0], result[1], result[4], result[8]))
    print('\u2503')



def plot_window_stat_predictions(stream, window_matrix, window, stride, file, out_plot_predictions, zleft, zright):
    """Plots the window analysis including the exfil prediction
       which does not rely of stream meta being known"""
    df_stream = pandas.DataFrame(window_matrix,
                             columns=['Packet number (datum)',
                                      'stream', 'window', 'stride', 'Client packet size (normalized)',
                                      'client_packets', 'client_packets_size', 'Client size variance',
                                      'Server packet size (normalized)', 'server_packets',
                                      'server_packets_size', 'Server Size variance',
                                      'Client:Server packet ratio', 'Client:Server size ratio',
                                      'Window Exfiltration prediction',
                                      'Window Infiltration prediction',
                                      'Time elapsed normalized', 'Packet Time delta normalized',
                                      'Datum packet size', 'Is forward enter child', 'Is reverse enter child',
                                      'Infiltration prediction aggregate', 'Exfiltration prediction aggregate'])
    # Slice the dataframe so as to only get the zoomed selection
    df_stream = df_stream.loc[zleft:zright]

    title = ("Strider - protocol:SSH" + '\n' + "Data Movement Predictions for pcap '" + file + "'\n" + 'Stream' +
             str(stream) + ' - showing packets ' + str(zleft) + ' to ' + str(zright) + '\n' + 'windowsize ' + str(
                window) + ' stride:' + str(stride))
    df_stream.plot(kind='bar', y=[16, 17, 12, 13, 7, 4, 11, 8, 14, 15], grid=True, ylim=[0, 1.05],
                   yticks=[.2, .4, .6, .8, 1.0], subplots=True,
                   title=[title, '', '', '', '', '', '', '', '', ''], figsize=[15, 20],
                   color=['#FFA500', '#FFA500', 'b', 'b', '#13ee00', '#13ee00', 'm', 'm', 'r', 'c', 'c'])

    plt.xlabel('Packet number in Stream {}'.format(stream))
    plt.ylabel('Normalized value')
    plt.legend(loc='upper left')

    packets_to_plot = zright - zleft

    plt.xticks([i for i in range(0, packets_to_plot, int(packets_to_plot / 10))],
               [i for i in range(0, packets_to_plot, int(packets_to_plot / 10))])
    plt.xlim(zleft, zright)
    # print('time debug - plt.savefig(out_plot_predictions)')
    plt.savefig(out_plot_predictions)
    # print('time debug - closing plot after saving')
    plt.close(out_plot_predictions)
    plt.close('all')


def plot_packet_size_histogram(stream, matrix, output_dir, base_file, zleft, zright):
    """Plots the packet size histogram
       which does not rely of stream meta being known"""
    out_plot_packet_size_histogram = str('./' + output_dir + '/' + 'packet-strider-ssh ' + base_file +
                                         ' stream ' + str(stream) + ' - Packet Size Histogram.png')
    m = []
    # Construct size matrix m and then dataframe df_m
    for size in matrix:
        if size > 0:
            m = m + [[size, 0]]
        else:
            m = m + [[0, size]]

    df_m = pandas.DataFrame(m, columns=['Client bytes sent', 'Server bytes sent'])
    # Slice the dataframe so as to only get the zoomed selection, this makes plotting much faster
    df_m = df_m.loc[zleft:zright]

    title = ("Strider - protocol:SSH" + '\n' + "Packet size histogram for '" + str(base_file) + "'\n" + 'Stream' + str(
        stream) + ' - showing packets ' + str(zleft) + ' to ' + str(zright))
    df_m.plot(kind='bar', y=[0, 1], grid=False, title=title, figsize=[12, 6.5],
              color=['b', 'r'])
    plt.xlabel('Packet numbers in Stream {}'.format(stream))
    plt.ylabel('Bytes sent')
    plt.legend(loc='best')
    packets_to_plot = zright - zleft
    plt.xticks([i for i in range(0, packets_to_plot, int(packets_to_plot / 10))],
               [i for i in range(0, packets_to_plot, int(packets_to_plot / 10))])
    plt.xlim(zleft, zright)
    plt.savefig(out_plot_packet_size_histogram)
    plt.close(out_plot_packet_size_histogram)
    plt.close('all')


def plot_keystroke_timeline(stream, results, window_matrix, file, out_plot_keystroke_timeline, df_stream_meta, zleft,
                            zright):
    """Plots the keystroke data, mapping them to time elapsed
       from the first packet in the stream"""
    indicators = []
    client_protocol = str(df_stream_meta.loc[0, 'Client Proto'])
    server_protocol = str(df_stream_meta.loc[0, 'Server Proto'])
    sip = str(df_stream_meta.loc[0, 'sip'])
    sport = str(df_stream_meta.loc[0, 'sport'])
    dip = str(df_stream_meta.loc[0, 'dip'])
    dport = str(df_stream_meta.loc[0, 'dport'])

    for result in results:
        index = result[2]
        r_initiation = r_login_prompt = 0
        r_login_success = r_login_failure = 0
        r_keystroke = r_delete = r_exfil = r_up_down_paste = 0
        bytes_r_exfiled = 0

        f_key_offer = f_key_accept = f_login_prompt = 0
        f_login_success = f_login_failure = f_keystroke = f_delete = f_exfil = f_up_down_paste = 0
        # First do Reverse indicators
        if 'reverse' in result[0]:
            if ' init' in result[1]:
                r_initiation = 1
            elif 'prompt' in result[1]:
                r_login_prompt = 0
            elif 'login success' in result[1]:
                r_login_success = 1
            elif 'login failure' in result[1]:
                r_login_failure = 1
            elif 'keystroke' in result[1]:
                r_keystroke = 1
            elif 'delete' in result[1]:
                r_delete = 1
            elif 'ENTER' in result[1]:
                r_exfil = 1
                bytes_r_exfiled = bytes_r_exfiled + int(result[5])
            elif 'UP/DOWN/Paste' in result[1]:
                r_up_down_paste = 1
        # Then do Forward indicators
        else:
            if 'key offered' in result[1]:
                f_key_offer = 1
            elif 'key accepted' in result[1]:
                f_key_accept = 1
            elif 'login prompt' in result[1]:
                f_login_prompt = 1
            elif 'login success' in result[1]:
                f_login_success = 1
            elif 'login failure' in result[1]:
                f_login_failure = 1
            elif 'keystroke' in result[1]:
                f_keystroke = 1
            elif 'delete' in result[1]:
                f_delete = 1
            elif 'ENTER' in result[1]:
                f_exfil = 1
            elif 'UP/DOWN/Paste' in result[1]:
                f_up_down_paste = 1

        indicators = indicators + [
            [index, r_initiation, r_login_prompt, r_login_success, r_login_failure, r_keystroke, r_delete,
             r_exfil, r_up_down_paste, bytes_r_exfiled, f_key_offer, f_key_accept, f_login_prompt,
             f_login_success, f_login_failure, f_keystroke, f_delete, f_exfil, f_up_down_paste]]
    df_indicators = pandas.DataFrame(indicators, columns=['index', 'REVERSE session initiation', 'REVERSE login prompt',
                                                      'REVERSE login success', 'REVERSE login failure',
                                                      'REVERSE keystroke', 'REVERSE delete',
                                                      'REVERSE Enter', 'Reverse UP/DOWN/Paste',
                                                      'Bytes exfiled when Reverse Enter key pressed',
                                                      'Forward key offer', 'Forward key accept', 'Forward login prompt',
                                                      'Forward login success', 'Forward login failure',
                                                      'Forward keystroke', 'Forward delete', 'Forward Enter key',
                                                      'Forward UP/DOWN/Paste'
                                                      ])
    df_indicators = df_indicators.loc[zleft:zright]

    df_stream = pandas.DataFrame(window_matrix,
                             columns=['Packet number (datum)',
                                      'stream', 'window', 'stride', 'Client packet size (normalized)',
                                      'client_packets', 'client_packets_size', 'Client size variance',
                                      'Server packet size (normalized)', 'server_packets',
                                      'server_packets_size', 'Server Size variance',
                                      'Client:Server packet ratio', 'Client:Server size ratio',
                                      'Exfil prediction',
                                      'Infil prediction', 'Time elapsed normalized', 'Time delta normalized',
                                      'Datum packet size', 'Is forward Enter child', 'Is reverse Enter child',
                                      'Infiltration prediction aggregate', 'Exfiltration prediction aggregate'
                                      ])
    df_stream = df_stream.loc[zleft:zright]

    df_stream_merged_results = df_stream.merge(df_indicators, how='outer', left_on='Packet number (datum)',
                                               right_on='index').fillna(0)

    df_stream_merged_results = df_stream_merged_results.loc[zleft:zright]

    title = ("Strider - protocol:SSH Keystroke predictions timeline" + "\n" +
             file + '    Stream ' + str(stream) + ' - showing packets ' + str(zleft) + ' to ' + str(zright) +
             "\nClient:" + client_protocol +
             "'\nServer:" + server_protocol +
             "\n" + sip + ":" + sport + " -> " + dip + ":" + dport)
    resolution = 2000
    width = max(1, (zright-zleft)/resolution)

    df_stream_merged_results.plot(kind='bar', width=width, sharex='True', grid=True, subplots=True,
                                  y=[36, 38, 39, 40, 21, 24, 26, 28, 29, 30, 22],
                                  fontsize=16,
                                  title=[title, '', '', '', '', '', '', '', '', '', ''],
                                  color=['c', 'c', 'c', 'b', 'k', 'm', 'm', 'm', 'm',
                                         'r', 'k'],
                                  figsize=[20, 20], ylim=[0, 1], yticks=[0, 1]
                                  )

    plt.xlabel('Packet number in Stream {}'.format(stream))
    plt.ylabel('Indicator')

    packets_to_plot = zright - zleft

    plt.xticks([i for i in range(0, packets_to_plot, int(packets_to_plot / 10))],
               [i for i in range(0, packets_to_plot, int(packets_to_plot / 10))])
    plt.xlim(zleft, zright)

    plt.savefig(out_plot_keystroke_timeline)
    plt.close(out_plot_keystroke_timeline)
    plt.close('all')


def zooms(zoom, num_packets):
    if zoom == '0':
        zleft = 0
        zright = num_packets
        return zleft, zright

    if '-' in zoom:
        zleft = int(zoom.split("-")[0])
        zright = int(zoom.split("-")[1])
        if zright < zleft or zleft < 0 or zright < 0 or zleft > num_packets or zright > num_packets:
            print('... ignoring out of bounds packet zooms, max zoom out is -z 0-{}'.format(num_packets))
            zleft = 0
            zright = num_packets
        return zleft, zright
    else:
        print('... ignoring invalid packet zooms, the max zoom out is -z 0-{}'.format(num_packets))
        zleft = 0
        zright = num_packets
        return zleft, zright