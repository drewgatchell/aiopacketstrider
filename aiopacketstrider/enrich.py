def enrich_results_notes_field(results):
    """ Enriches the results with notes field"""
    result_enriched = []

    for result in results:
        note_field = ""
        delta = result[7]
        direction = result[0]
        indicator = result[1]
        packet_size = result[4]
        # If the size of the login failure or login success is > 350 (372 in testing) then likely it is certificate auth
        if "forward" in direction and (
            "login success" in indicator or "login failure" in indicator
        ):
            if packet_size > 350:
                if delta < 0.100:
                    note_field = "Delta suggests Certificate Auth, pwd to cert null or non interactive"
                else:
                    note_field = "Delta suggests Certificate Auth, pwd to cert entered interactively"

            else:
                if delta < 0.100:
                    if 0 < packet_size <= 84:
                        note_field = (
                            "< 8 char Password, NOT entered interactively by human"
                        )
                    elif 84 < packet_size <= 148:
                        note_field = (
                            "8+ char Password, NOT entered interactively by human"
                        )

                else:
                    if 0 < packet_size <= 84:
                        note_field = "< 8 char Password, entered interactively by human"
                    elif 84 < packet_size <= 148:
                        note_field = "8+char Password, entered interactively by human"

        # If the time delta between key offered and key accepted in small (say 50ms) likely the server is
        # in the known_hosts already, and the user was not prompted interactively to accept the server's key.
        # another explanation is that host checking is being ignored.
        if "forward" in direction and "key accepted" in indicator:
            if delta < 0.050:
                note_field = (
                    "Delta suggests hostkey was already in known_hosts or ignored"
                )
            else:
                note_field = "Delta suggests hostkey was NOT in known_hosts, user manually accepted it"

        if "reverse" in direction and (
            "login success" in indicator or "login failure" in indicator
        ):
            if delta < 1:
                note_field = "Delta suggests creds NOT entered interactively by human"
            else:
                note_field = "Delta suggests creds were entered interactively by human"

        enriched_row = [
            result[0],
            result[1],
            result[2],
            result[3],
            result[4],
            result[5],
            result[6],
            result[7],
            note_field,
        ]
        result_enriched.append(enriched_row)

    return result_enriched


def enrich_results_time_delta(results):
    """ Calculates and enriches time deltas between events"""
    result_enriched = []

    result_count = 0
    for result in results:
        if result_count == 0:
            delta_this_event = 0
        else:
            time_this_event = result[6]
            time_last_event = results[result_count - 1][6]
            delta_this_event = time_this_event - time_last_event
        enriched_row = [
            result[0],
            result[1],
            result[2],
            result[3],
            result[4],
            result[5],
            result[6],
            delta_this_event,
        ]
        result_enriched.append(enriched_row)
        result_count = result_count + 1

    return result_enriched
