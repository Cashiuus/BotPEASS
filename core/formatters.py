


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
