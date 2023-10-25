# import datetime
import os
from datetime import datetime

import requests
#from discord import Webhook, RequestsWebhookAdapter
from discord import SyncWebhook

from core.epss import EPSSGopher

# Example URL: https://www.cvedetails.com/cve/CVE-2023-41892/
CVE_URL = "https://www.cvedetails.com/cve"


def trim_datetime(dt):
    TIME_FORMAT = "%Y-%m-%dT%H:%M:%S"
    DATE_FORMAT = "%Y-%m-%d"
    date_only = datetime.strptime(dt, TIME_FORMAT)
    date_only = date_only.strftime(DATE_FORMAT)
    return date_only


def convert_string_to_datetime(raw_string):
    """ Convert a raw timestamp string to a YYYY-MM-DD HH:MM:SS date & time string. """
    # input_date_format = "%Y-%m-%d %I:%M:%S %p"  # 12-hr time with AM/PM
    # output_date_format = "%Y-%m-%d %H:%M:%S"    # 24-hr time
    date_obj = None
    found = False
    input_date_formats = [
        # "%Y-%m-%d %I:%M:%S %p",
        # "%d/%m/%Y %I:%M %p",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%I:%M:%S+00:00",
        "%Y-%m-%dT%I:%M:%S+00:00",
        "%b %d, %Y",                    # Commonly seen in Qualys Vuln exports
    ]

    while 1:
        for format in input_date_formats:
            try:
                # log.debug(f"Checking date pattern: {format=}")
                date_obj = datetime.strptime(raw_string, format)
                found = True
            except ValueError as e:
                # log.debug(f"ValueError exception: {e}")
                # print(e)
                continue
            # If we manage to create a datetime object without exception, we found
            # the right pattern
            # log.debug(f"Found correct datetime pattern: {format=}")
            break

        if not found:
            print(f"Did not find correct datetime pattern from this string: {raw_string=}")
            date_obj = datetime.fromisoformat(raw_string)
            print("Stored instead using fromisoformat()")
        break

    # date_obj = datetime.strptime(raw_string, input_date_format)
    # return f"{date_obj:%Y-%m-%d %H:%M:%S}"
    return date_obj


#################### GENERATE MESSAGES #########################
def generate_new_cve_message(cve_data: dict, github_addendum=None) -> str:
    """
    Generate new CVE message for sending to slack
    """
    # friendly_time = "%Y-%m-%d"

    # Set this to True to put CVE - CVSS - EPSS all on first line of message
    condense_message = True

    # TODO: If config has this integration enabled do it, else skip
    # Knowing if config has this requires this to be in the provider class
    # where the config is parsed.
    # Refactor all this once I move code around in this project
    gopher_epss = EPSSGopher()
    epss_string = ""
    epss_score = None
    epss_score, epss_percentile = gopher_epss.get_score_tuple_for_cve(cve_data["CVE_ID"])
    if epss_score:
        # log.debug(f"{row_data['CVE']} has EPSS: {float(epss):.2f}")
        # log.debug(f"{row_data['CVE']} has EPSS: {epss}")
        epss_score = round(float(epss_score), 2)
        epss_percentile = round(float(epss_percentile) * 100, 0)
        print(f"[*] {cve_data['CVE_ID']} has EPSS: {float(epss_score):.2f} - Percentile: {epss_percentile:.2f}ᵀᴴ)")
        # if round(epss_score) == 0:
        #     print("[DBG] EPSS for this CVE is rounded to 0%")
        # cve_data["EPSS"] = f"{epss_score:.0f}%"
        # -- Format the EPSS String for the message --
        epss_string = f"*EPSS:* {epss_score} / {epss_percentile}ᵀᴴ"
        cve_data["EPSS"] = epss_string
    else:
        # EPSS doesn't exist for this CVE yet, setting to NA or blank for messages
        # epss_string = "NA"
        cve_data["EPSS"] = epss_string

    # Emoji's we can use: https://www.freecodecamp.org/news/all-emojis-emoji-list-for-copy-and-paste/
    # 💥 📅

    message = ""
    if condense_message:
        # All of this is on one line, but broken up for readability here
        message = f"🚨  *<{CVE_URL}/{cve_data['CVE_ID']}/|{cve_data['CVE_ID']}>*"
        message += f"  CVSS: {cve_data['CVSSv3_Score']}"
        if cve_data.get("EPSS"):
            message += f"  {cve_data['EPSS']}\n"
        else:
            message += "\n"
    else:
        # -- Original message breakdown --
        message = f"🚨  *{cve_data['CVE_ID']}*  🚨\n"
        message += f"*CVSSv3.1*: {cve_data['CVSSv3_Score']}\n"
        if cve_data.get("EPSS") is not None:
            message += f"  {cve_data['EPSS']}\n"

    if cve_data.get('ExploitDB_ID') is not None:
        #message = "😈  *Public Exploits* (_limit 10_):\n" + "\n".join(public_expls[:20])
        message += f"😈  *Exploit-DB*: <https://www.exploit-db.com/exploits/{cve_data['ExploitDB_ID']}|EDB {cve_data['ExploitDB_ID']} Link>\n"

    # -- Rest of Message, regardless --
    # message += f"  *Published*: {datetime.datetime.strptime(cve_data['Published'], friendly_time)}"
    message += f"📅  *Published*: {convert_string_to_datetime(cve_data['Published']):%Y-%m-%d}"
    # message += f" - *Modified*: {datetime.datetime.strptime(cve_data['Last_Modified'], friendly_time)}\n"
    message += f" - *Modified*: {convert_string_to_datetime(cve_data['Last_Modified']):%Y-%m-%d}\n"

    message += "📓  *Description*: "
    message += cve_data["Description"] if len(cve_data["Description"]) < 500 else cve_data["Description"][:500] + "..."
    message += "\n"

    if cve_data.get("Exploit_References"):
        message += f"🔓  *Exploit References* (_limit 5_):\n" + "\n".join(cve_data["Exploit_References"][:5])

    if github_addendum:
        message += f"🔗  *GitHub Dork:* <https://github.com/search?q={cve_data['CVE_ID']} {github_addendum}|GitHub Dork Link>\n"
    else:
        message += f"🔗  *GitHub Dork:* <https://github.com/search?q={cve_data['CVE_ID']}|GitHub CVE Search Link>\n"

    message += "ℹ️   *More information* (_limit 5_):\n" + "\n".join(cve_data["Normal_References"][:5])

    # Don't need a newline at the end of the message string
    message = message.rstrip()
    # message += "\n"

    return message


# def generate_modified_cve_message(cve_data: dict) -> str:
#     ''' Generate modified CVE message for sending to slack '''

#     message = f"📣 *{cve_data['CVE_ID']}*(_{cve_data['CVSSv3_Score']}_) was modified the {cve_data['Last_Modified'].split('T')[0]} (_originally published the {cve_data['Published'].split('T')[0]}_)\n"
#     return message


# def generate_exploits_message(cve_data: dict) -> str:
#     ''' Given the list of public exploits, generate the message '''

#     message = ""
#     if cve_data.get('ExploitDB_ID') is not None:
#         #message = "😈  *Public Exploits* (_limit 10_):\n" + "\n".join(public_expls[:20])
#         message = f"😈  *Exploit-DB IDs*: {cve_data['ExploitDB_ID']}\n"
#     return message


#################### SEND MESSAGES - SLACK #########################

def send_slack_mesage(message: str):
    ''' Send a message to the slack group '''

    slack_url = os.getenv('SLACK_WEBHOOK')

    if not slack_url:
        #print("SLACK_WEBHOOK wasn't configured in the secrets!")
        return

    json_params = {
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": message
                }
            },
            {
                "type": "divider"
            }
        ]
    }

    # if public_expls_msg:
    #     json_params["blocks"].append({
    #             "type": "section",
    #             "text": {
    #                 "type": "mrkdwn",
    #                 "text": public_expls_msg
    #             }
    #     })
    requests.post(slack_url, json=json_params)
    return


#################### SEND MESSAGES - TELEGRAM #########################

def send_telegram_message(message: str, public_expls_msg: str):
    ''' Send a message to the telegram group '''

    telegram_bot_token = os.getenv('TELEGRAM_BOT_TOKEN')
    telegram_chat_id = os.getenv('TELEGRAM_CHAT_ID')

    if not telegram_bot_token:
        print("TELEGRAM_BOT_TOKEN wasn't configured in the secrets!")
        return

    if not telegram_chat_id:
        print("TELEGRAM_CHAT_ID wasn't configured in the secrets!")
        return

    if public_expls_msg:
        message = message + "\n" + public_expls_msg

    message = message.replace(".", "\.").replace("-", "\-").replace("(", "\(").replace(")", "\)").replace("_", "").replace("[","\[").replace("]","\]").replace("{","\{").replace("}","\}").replace("=","\=")
    r = requests.get(f'https://api.telegram.org/bot{telegram_bot_token}/sendMessage?parse_mode=MarkdownV2&text={message}&chat_id={telegram_chat_id}')

    resp = r.json()
    if not resp['ok']:
        r = requests.get(f'https://api.telegram.org/bot{telegram_bot_token}/sendMessage?parse_mode=MarkdownV2&text=Error with' + message.split("\n")[0] + f'{resp["description"]}&chat_id={telegram_chat_id}')
        resp = r.json()
        if not resp['ok']:
            print("ERROR SENDING TO TELEGRAM: " + message.split("\n")[0] + resp["description"])
    return


#################### SEND MESSAGES - DISCORD #########################

def send_discord_message(message: str, public_expls_msg: str):
    ''' Send a message to the discord channel webhook '''

    discord_webhook_url = os.getenv('DISCORD_WEBHOOK_URL')

    if not discord_webhook_url:
        print("DISCORD_WEBHOOK_URL wasn't configured in the secrets!")
        return

    if public_expls_msg:
        message = message + "\n" + public_expls_msg

    message = message.replace("(", "\(").replace(")", "\)").replace("_", "").replace("[","\[").replace("]","\]").replace("{","\{").replace("}","\}").replace("=","\=")
    #webhook = Webhook.from_url(discord_webhook_url, adapter=RequestsWebhookAdapter())
    webhook = SyncWebhook.from_url(discord_webhook_url)
    if public_expls_msg:
        message = message + "\n" + public_expls_msg

    #webhook.send(message)
    webhook.send(content=message)
    return
