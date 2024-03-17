
from datetime import datetime



def clean_multiline_string(input_string: str) -> str:
    """
    General text helper for universal use.
    Clean up newline-separated multi-line raw strings and put them
    back together without any blank lines.

    Edit the "formatted" variable to either concat lines with a space or
    newline, depending on your needs.
    """
    raw_text = []

    for line in input_string.split('\n'):
        if line.strip() == '':
            continue
        raw_text.append(line.strip())

    # formatted = ('\n'.join(str(x) for x in raw_text))
    formatted_text = (' '.join(str(x) for x in raw_text))
    if not formatted_text:
        # print("[DBG] Fallback cleaning method due to line being only a single line")
        formatted_text = input_string.strip()

    return formatted_text


def convert_string_to_datetime(raw_string):
    """
    Convert a raw timestamp string to a date & time string.
    """
    # input_date_format = "%Y-%m-%d %I:%M:%S %p"  # 12-hr time with AM/PM
    # output_date_format = "%Y-%m-%d %H:%M:%S"    # 24-hr time
    date_obj = None
    found = False
    input_date_formats = [
        # "%Y-%m-%d %I:%M:%S %p",
        # "%d/%m/%Y %I:%M %p",
        # "%b %d, %Y",
        # "%b. %d, %Y",
        # "%d-%b-%y",
        # "%Y-%m-%d",
        "%Y-%m-%dT%H:%M:%S+00:00",
        "%Y-%m-%dT%I:%M:%S+00:00",
        "%Y-%m-%dT%I:%M:%S.%f",
        "%Y-%m-%dT%I:%M:%SZ",
        # "%m/%d/%Y",
    ]

    while 1:
        for format in input_date_formats:
            try:
                # log.debug(f"Checking date pattern: {format=}")
                date_obj = datetime.strptime(raw_string, format)
                found = True
            except ValueError as e:
                # log.debug(f"ValueError exception: {e}")
                continue
            # If we manage to create a datetime object without exception, we found
            # the right pattern
            # log.debug(f"Found correct datetime pattern: {format=}")
            break

        if not found:
            # log.warn(f"Did not find correct datetime pattern from this string: {raw_string=}")
            # Try this method as fallback
            # date_obj = datetime.fromisoformat(raw_string)
            pass
        break

    # date_obj = datetime.strptime(raw_string, input_date_format)
    # Output format: YYYY-MM-DD HH:MM:SS
    # return f"{date_obj:%Y-%m-%d %H:%M:%S}"
    return date_obj