import re
import requests
import socket
ADVICE = {
    "only_clicked": {
        "title": "You only opened the link but did not enter anything",
        "steps": [
            "Close the page immediately and do not click anything else on it.",
            "Cancel any downloads in progress; if a file has already been downloaded, do not open it and delete it directly.",
            "Remove any browser notification permissions or site permissions you just granted.",
            "Run a full antivirus scan.",
            "Monitor for abnormal login alerts or unfamiliar activity in the next few days."
        ],
        "source": "PSafe, Internet Society Online Trust & Safety Hub"
    },
    "entered_password": {
        "title": "You entered your password",
        "steps": [
            "Immediately change that account's password from another trusted device.",
            "Do not reuse the old password or a similar variant.",
            "Change the same password on any other websites where it was used, especially email, banking, and cloud storage.",
            "Log out of all other sessions/devices on that account.",
            "Enable two-factor authentication (prefer an authenticator app over SMS).",
            "Check the account's recovery email/phone number to confirm it has not been tampered with."
        ],
        "source": "PSafe, Internet Society Online Trust & Safety Hub"
    },
    "shared_otp": {
        "title": "You shared a one-time code / OTP",
        "steps": [
            "Assume the account has been compromised, contact the platform's official customer service immediately to report the anomaly and request a freeze.",
            "If it is a bank OTP, call the phone number on the back of your card immediately (do not call any number provided by the other party).",
            "Change the account password and log out of all sessions.",
            "Enable two-factor authentication (if not already enabled).",
            "Review recent transactions and login records."
        ],
        "source": "PSafe"
    },
    "downloaded_file": {
        "title": "You downloaded or opened a file / installed software",
        "steps": [
            "If you suspect malicious software is running, disconnect from the network (unplug ethernet, turn off Wi-Fi) to prevent data from being sent back.",
            "Use a trusted antivirus for a full scan (such as Windows Defender offline scan).",
            "Remove any recently installed unknown programs, browser extensions, or configuration profiles.",
            "Reset browser settings to remove unknown extensions and notification permissions.",
            "If the scan cannot remove the threat or the system still behaves abnormally, consider backing up data and reinstalling the operating system."
        ],
        "source": "PSafe"
    },
    "financial_info": {
        "title": "You entered bank card / financial information",
        "steps": [
            "Call the phone number on the back of your card or on your statement to contact the bank, explain the situation, and request to freeze the card.",
            "Review recent transactions and dispute any unauthorized charges.",
            "Consider requesting a new card number.",
            "Enable transaction alerts."
        ],
        "source": "PSafe"
    }
}

def get_advice(scenario: str) -> dict:
    return ADVICE.get(scenario, ADVICE["only_clicked"])
