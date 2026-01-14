import re
from aprslib import base91
from aprslib.exceptions import ParseError
from aprslib.parsing import logger

__all__ = [
        'parse_comment_telemetry',
        'parse_telemetry_config',
        'parse_telemetry_report',
        ]


def parse_comment_telemetry(text):
    """
    Looks for base91 telemetry found in comment field
    Returns [remaining_text, telemetry]
    """
    parsed = {}
    match = re.findall(r"^(.*?)\|([!-{]{4,14})\|(.*)$", text)

    if match and len(match[0][1]) % 2 == 0:
        text, telemetry, post = match[0]
        text += post

        temp = [0] * 7
        for i in range(7):
            temp[i] = base91.to_decimal(telemetry[i*2:i*2+2])

        parsed.update({
            'telemetry': {
                'seq': temp[0],
                'vals': temp[1:6]
                }
            })

        if temp[6] != '':
            parsed['telemetry'].update({
                'bits': "{0:08b}".format(temp[6] & 0xFF)[::-1]
                })

    return (text, parsed)


def parse_telemetry_config(body):
    parsed = {}

    match = re.findall(r"^(PARM|UNIT|EQNS|BITS)\.(.*)$", body)
    if match:
        logger.debug("Attempting to parse telemetry-message packet")
        form, body = match[0]

        parsed.update({'format': 'telemetry-message'})

        if form in ["PARM", "UNIT"]:
            vals = body.rstrip().split(',')[:13]

            for val in vals:
                if not re.match(r"^(.{1,20}|)$", val):
                    raise ParseError("incorrect format of %s (name too long?)" % form)

            defvals = [''] * 13
            defvals[:len(vals)] = vals

            parsed.update({
                't%s' % form: defvals
                })
        elif form == "EQNS":
            eqns = body.rstrip().split(',')[:15]
            teqns = [0, 1, 0] * 5

            for idx, val in enumerate(eqns):
                if not re.match(r"^([-]?\d*\.?\d+|)$", val):
                    raise ParseError("value at %d is not a number in %s" % (idx+1, form))
                else:
                    try:
                        val = int(val)
                    except:
                        val = float(val) if val != "" else 0

                    teqns[idx] = val

            # group values in 5 list of 3
            teqns = [teqns[i*3:(i+1)*3] for i in range(5)]

            parsed.update({
                't%s' % form: teqns
                })
        elif form == "BITS":
            # APRS spec says 23 chars, but real-world packets may be longer
            # Accept any reasonable length (up to 100 chars to be safe)
            match = re.findall(r"^([01]{8}),(.{0,100})$", body.rstrip())
            if not match:
                raise ParseError("incorrect format of %s" % form)

            bits, title = match[0]

            parsed.update({
                't%s' % form: bits,
                'title': title.strip(' ')
                })

    return (body, parsed)


def parse_telemetry_report(body):
    """
    Parses APRS 1.2 telemetry report format: T#sss,aaa,bbb,ccc,ddd,eee,bbbbbbbb,comment

    Format:
    - T# indicates telemetry report
    - sss is sequence number (000-999)
    - aaa to eee are 5 analog values (000-999)
    - bbbbbbbb is 8 binary digits (digital I/O)
    - comment is optional text

    Returns (remaining_body, parsed_dict)
    """
    parsed = {}

    # Check if body starts with '#'
    if not body.startswith('#'):
        raise ParseError("telemetry report must start with '#'")

    # Remove the '#' prefix
    body = body[1:]

    # Split by comma - need at least sequence number
    # Some real-world packets are incomplete (missing analog values or digital I/O)
    parts = body.split(',', 7)

    if len(parts) < 1:
        raise ParseError("telemetry report must have at least a sequence number")

    seq_str = parts[0]
    # Extract analog values (up to 5, pad with empty strings if missing)
    analog_strs = parts[1:6] if len(parts) > 1 else []
    # Pad to 5 analog values if we have fewer
    while len(analog_strs) < 5:
        analog_strs.append('')
    
    # Digital I/O field (may be missing)
    digital_field = parts[6] if len(parts) > 6 else '00000000'
    comment = parts[7] if len(parts) > 7 else ''

    # Validate and parse sequence number (allow any positive integer)
    # APRS spec says 000-999, but real-world packets use larger numbers
    if not re.match(r'^\d+$', seq_str):
        raise ParseError("telemetry sequence number must be numeric")
    seq = int(seq_str)

    # Parse analog values (can be 000-999, allow decimals and negatives per APRS 1.2)
    # Empty values are allowed and treated as 0
    analog_vals = []
    for i, val_str in enumerate(analog_strs):
        # Allow empty values (treated as 0)
        if not val_str or val_str.strip() == '':
            analog_vals.append(0.0)
            continue
        
        # Allow integers, decimals, and negative numbers
        if not re.match(r'^-?\d+\.?\d*$', val_str):
            raise ParseError("telemetry analog value %d has invalid format" % (i+1))
        try:
            val = float(val_str)
        except ValueError:
            raise ParseError("telemetry analog value %d is not a valid number" % (i+1))
        analog_vals.append(val)

    # Validate digital I/O (must be binary digits, pad to 8 if shorter)
    # Some packets have comment concatenated without comma separator
    # Some packets have shorter binary strings (pad with leading zeros)
    # Check if field is entirely binary digits
    if re.match(r'^[01]+$', digital_field):
        # Pure binary string (all 0s and 1s)
        if len(digital_field) < 8:
            # Pad shorter binary strings to 8 digits
            digital_str = digital_field.zfill(8)
        elif len(digital_field) == 8:
            digital_str = digital_field
        else:
            # Longer than 8, use first 8
            digital_str = digital_field[:8]
    elif re.match(r'^[01]{8,}[^01]', digital_field):
        # Starts with 8+ binary digits followed by non-binary (concatenated comment)
        digital_str = digital_field[:8]
        if not comment:
            comment = digital_field[8:]
    elif re.match(r'^[01]{1,7}[^01]', digital_field):
        # Starts with 1-7 binary digits followed by non-binary
        # This is invalid - need at least 8 binary digits before comment
        raise ParseError("telemetry digital I/O must be binary digits")
    else:
        # No valid binary digits found or invalid format
        raise ParseError("telemetry digital I/O must be binary digits")

    parsed.update({
        'format': 'telemetry',
        'telemetry': {
            'seq': seq,
            'vals': analog_vals,
            'bits': digital_str
        }
    })

    # Add comment if present
    if comment:
        parsed['comment'] = comment.strip(' ')

    # Return empty remaining body since we consumed everything
    return ('', parsed)

