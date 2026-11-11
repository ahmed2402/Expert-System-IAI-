"""CyberTriage knowledge base: questions, rules, attack profiles, demo scenarios.

Everything here is data. The engine (engine.py) never needs to change when a
rule is added; you just append a line to RULES.
"""
from engine import Rule as R

# ---------------------------------------------------------------- questions
# fact_id -> what the user is asked. Grouped the way people notice problems.
QUESTIONS = {
    "Email & messages": [
        ("email_urgent", "An email or message pushed you to act fast: account locked, payment overdue, you won a prize"),
        ("email_sender_odd", "The sender's address looked slightly off, like paypa1.com or a free Gmail for a 'bank'"),
        ("clicked_link", "You clicked a link or opened an attachment from it"),
        ("entered_password", "You typed a password or one-time code into the page that opened"),
        ("attachment_macro", "A document asked you to click 'Enable content' or 'Enable macros'"),
        ("boss_payment_request", "Your 'boss' or a supplier asked for an urgent transfer or sent new bank details"),
        ("contacts_got_spam", "Friends say they got weird messages or links from you"),
    ],
    "Files": [
        ("files_unreadable", "Files won't open, or open as gibberish"),
        ("odd_extensions", "File names have a new ending, like .locked, .crypt or random letters"),
        ("ransom_note", "There's a note asking for payment (usually Bitcoin) to get your files back"),
        ("files_missing", "Files have vanished or moved somewhere you didn't put them"),
        ("backups_deleted", "Your backups or Windows restore points are gone"),
    ],
    "Device behaviour": [
        ("slow_device", "The device got noticeably slower recently"),
        ("cpu_high_idle", "Task Manager shows high CPU or GPU use even when you're doing nothing"),
        ("fan_loud", "The fan is loud or the device runs hot while idle"),
        ("battery_drain", "The battery drains a lot faster than it used to"),
        ("crashes", "Programs crash or the whole system freezes more often"),
        ("unknown_programs", "There are programs or apps you don't remember installing"),
        ("antivirus_disabled", "Your antivirus or Windows Defender got switched off, and you didn't do it"),
        ("popups_desktop", "Ads pop up even when the browser is closed"),
        ("webcam_light", "The webcam light comes on by itself"),
        ("mouse_moves", "The mouse moves or windows open on their own"),
    ],
    "Software & USB": [
        ("cracked_software", "You recently installed cracked or pirated software, a keygen or a game mod"),
        ("app_outside_store", "You installed an app from outside the official store (an APK, a random website)"),
        ("app_permissions", "An app asked for odd permissions: reading SMS, accessibility, device admin"),
        ("usb_plugged", "You plugged in a USB drive that you found or that isn't yours"),
        ("shortcut_files", "Files on a USB drive turned into shortcuts"),
    ],
    "Network & Wi-Fi": [
        ("data_usage_spike", "Your internet data usage jumped and you can't explain it"),
        ("internet_slow", "The internet is slow even when nobody is using much"),
        ("isp_abuse_notice", "Your ISP or someone else warned that your connection is sending spam or attacks"),
        ("public_wifi", "You recently used public or free Wi-Fi (café, airport, hotel)"),
        ("cert_warning", "Your browser showed 'Your connection is not private' or certificate warnings"),
        ("router_settings_changed", "Router settings or the Wi-Fi password changed without you"),
    ],
    "Accounts & logins": [
        ("password_not_working", "A password that worked yesterday suddenly doesn't"),
        ("login_alert_unknown", "You got a login alert from a device or city you don't recognise"),
        ("password_reset_unrequested", "Password reset emails arrived that you didn't ask for"),
        ("recovery_changed", "The recovery email or phone number on an account was changed"),
        ("posts_not_yours", "Posts, stories or messages went out from your account that you didn't send"),
        ("strange_transactions", "There are bank, card or wallet transactions you didn't make"),
        ("breach_notice", "A website said it was breached, or haveibeenpwned.com lists your email"),
        ("reused_password", "You use the same password on lots of sites"),
    ],
    "Phone & SIM": [
        ("no_signal", "Your phone suddenly shows 'No service' or the SIM stopped working"),
        ("carrier_msg_sim_change", "You got a message about a SIM replacement you didn't ask for"),
        ("otp_not_received", "OTP codes stopped arriving, or arrive for logins you didn't start"),
        ("suspicious_call", "Someone called claiming to be your bank or telco and asked for a code or details"),
    ],
    "Browser": [
        ("homepage_changed", "Your homepage or search engine changed by itself"),
        ("extensions_unknown", "There are browser extensions you didn't add"),
        ("redirects", "The browser keeps sending you to sites you didn't open"),
        ("scareware_popup", "A pop-up said your PC is infected and gave a number to call"),
        ("called_number", "You called that number or chatted with the 'support' person"),
        ("remote_tool_installed", "Someone talked you into installing AnyDesk, TeamViewer or similar"),
    ],
}

CONTEXT = [
    ("ctx_business", "This is a work or business device"),
    ("ctx_banking", "Banking, cards or mobile wallets (JazzCash, Easypaisa) are involved"),
    ("ctx_sensitive", "The device holds sensitive data (client files, ID scans, private photos)"),
    ("ctx_spread", "Other devices on the same network are acting strangely too"),
]

# ---------------------------------------------------------------- rules
MALWARE = ["attack_ransomware", "attack_spyware", "attack_cryptojacking", "attack_botnet",
           "attack_trojan", "attack_usb_malware"]
ACCOUNT = ["attack_phishing", "attack_account_takeover", "attack_sim_swap", "attack_bec",
           "attack_tech_support_scam", "attack_spyware"]

RULES = [
    # Layer 1: symptoms -> indicators
    R("R01", ["files_unreadable", "odd_extensions"], "files_encrypted", 0.90, because="Unreadable files with a new extension are the classic sign of encryption."),
    R("R02", ["ransom_note"], "files_encrypted", 0.80, because="A ransom note means someone claims to hold your files."),
    R("R03", ["cpu_high_idle"], "hidden_resource_use", 0.80, if_any=["fan_loud", "battery_drain", "slow_device"], because="Heavy load while idle means something is running in the background."),
    R("R04", ["clicked_link", "entered_password"], "credentials_exposed", 0.90, because="A password typed into a page opened from a message may have gone to the attacker."),
    R("R05", ["breach_notice", "reused_password"], "credentials_exposed", 0.70, because="A leaked password that's reused elsewhere unlocks those accounts too."),
    R("R06", ["suspicious_call"], "credentials_exposed", 0.50, because="Callers asking for codes are usually after your logins."),
    R("R07", ["email_urgent", "email_sender_odd"], "phishing_message", 0.85, because="Pressure plus a fake-looking sender is textbook phishing."),
    R("R08", ["email_urgent"], "phishing_message", 0.60, if_any=["clicked_link", "attachment_macro"], because="An urgent message that got you to click is likely bait."),
    R("R09", ["login_alert_unknown"], "suspicious_logins", 0.80, if_any=["password_reset_unrequested", "recovery_changed"], because="Strange logins plus reset activity mean someone is working on your account."),
    R("R10", ["password_not_working"], "account_hijacked", 0.85, if_any=["recovery_changed", "login_alert_unknown"], because="A changed password after an unknown login means you've been locked out."),
    R("R11", ["unknown_programs", "antivirus_disabled"], "malware_installed", 0.85, because="Malware often installs itself and switches off the antivirus."),
    R("R12", ["attachment_macro", "clicked_link"], "malware_installed", 0.70, because="Enabling macros on an emailed document is a common way malware gets in."),
    R("R13", [], "untrusted_software", 0.80, if_any=["cracked_software", "app_outside_store"], because="Cracked and side-loaded software often carries hidden payloads."),
    R("R14", ["untrusted_software"], "malware_installed", 0.70, if_any=["unknown_programs", "crashes", "slow_device", "popups_desktop"], because="Trouble started after installing untrusted software."),
    R("R15", [], "remote_control_signs", 0.75, if_any=["webcam_light", "mouse_moves"], because="A camera or mouse acting on its own suggests someone has remote access."),
    R("R16", ["data_usage_spike"], "abnormal_traffic", 0.80, if_any=["internet_slow", "isp_abuse_notice"], because="Unexplained traffic means the device is talking to someone."),
    R("R17", ["no_signal"], "sim_hijacked", 0.90, if_any=["carrier_msg_sim_change", "otp_not_received"], because="Losing signal right after a SIM change notice means your number moved."),
    R("R18", [], "browser_hijacked", 0.75, if_any=["homepage_changed", "extensions_unknown", "redirects"], because="Settings and extensions you didn't touch were changed."),
    R("R19", ["usb_plugged"], "usb_infection", 0.80, if_any=["shortcut_files", "unknown_programs"], because="Shortcut files on a USB drive are a well-known worm trick."),
    R("R20", ["public_wifi", "cert_warning"], "traffic_intercepted", 0.80, because="Certificate errors on public Wi-Fi often mean someone is in the middle."),
    R("R21", ["scareware_popup"], "scam_contact", 0.90, if_any=["called_number", "remote_tool_installed"], because="You got in touch with the people behind a fake virus alert."),

    # Layer 2: indicators -> attacks
    R("R22", ["files_encrypted"], "attack_ransomware", 0.90, because="Encrypted files point to ransomware."),
    R("R23", ["files_encrypted", "backups_deleted"], "attack_ransomware", 0.95, because="Ransomware deletes backups so you can't restore."),
    R("R24", ["files_missing", "ransom_note"], "attack_ransomware", 0.70, because="Missing files plus a ransom note suggests data theft and extortion."),
    R("R25", ["phishing_message"], "attack_phishing", 0.80, because="A phishing message reached you."),
    R("R26", ["phishing_message", "credentials_exposed"], "attack_phishing", 0.90, because="The phishing worked: details were entered."),
    R("R27", ["credentials_exposed"], "attack_account_takeover", 0.90, if_any=["suspicious_logins", "account_hijacked", "strange_transactions"], because="Exposed credentials are already being used."),
    R("R28", ["account_hijacked"], "attack_account_takeover", 0.80, because="You've been locked out of your own account."),
    R("R29", ["suspicious_logins"], "attack_account_takeover", 0.60, because="Someone is trying to get into the account."),
    R("R30", ["malware_installed", "remote_control_signs"], "attack_spyware", 0.85, because="Malware plus a camera or mouse acting on its own points to a remote access trojan."),
    R("R31", ["malware_installed"], "attack_spyware", 0.65, if_any=["suspicious_logins", "strange_transactions", "password_not_working"], because="Accounts are being hit without phishing, which suggests a keylogger."),
    R("R32", ["hidden_resource_use"], "attack_cryptojacking", 0.70, because="Hidden CPU load is what crypto-miners cause."),
    R("R33", ["hidden_resource_use", "untrusted_software"], "attack_cryptojacking", 0.85, because="Miners are often bundled with cracked software."),
    R("R34", ["abnormal_traffic", "malware_installed"], "attack_botnet", 0.85, because="Infected and sending lots of traffic: the device is likely in a botnet."),
    R("R35", ["isp_abuse_notice"], "attack_botnet", 0.75, because="Your ISP saw attack traffic coming from you."),
    R("R36", ["popups_desktop"], "attack_adware", 0.60, because="Pop-ups outside the browser come from adware."),
    R("R37", ["browser_hijacked"], "attack_adware", 0.75, because="Browser hijackers make money from ads and redirects."),
    R("R38", ["untrusted_software", "malware_installed"], "attack_trojan", 0.85, because="The untrusted program was a trojan."),
    R("R39", ["app_outside_store", "app_permissions"], "attack_trojan", 0.85, because="A side-loaded app grabbing SMS or accessibility access is a known banking-trojan pattern."),
    R("R40", ["sim_hijacked"], "attack_sim_swap", 0.90, because="Someone moved your number to their SIM."),
    R("R41", ["sim_hijacked", "strange_transactions"], "attack_sim_swap", 0.95, because="They used your number to receive OTPs and move money."),
    R("R42", ["suspicious_call", "otp_not_received"], "attack_sim_swap", 0.60, because="A pretext call followed by missing OTPs is a common SIM-swap setup."),
    R("R43", ["posts_not_yours", "account_hijacked"], "attack_social_hijack", 0.90, because="Someone took over the account and is posting as you."),
    R("R44", ["contacts_got_spam"], "attack_social_hijack", 0.80, if_any=["posts_not_yours", "suspicious_logins"], because="Your account is messaging your contacts."),
    R("R45", ["scam_contact"], "attack_tech_support_scam", 0.90, because="You talked to fake tech support."),
    R("R46", ["scareware_popup"], "attack_tech_support_scam", 0.60, because="A fake virus alert with a phone number is the scam's opening move."),
    R("R47", ["traffic_intercepted"], "attack_mitm", 0.80, because="Your traffic may be passing through an attacker."),
    R("R48", ["router_settings_changed"], "attack_mitm", 0.80, if_any=["redirects", "cert_warning"], because="A tampered router can redirect everything on your network."),
    R("R49", ["usb_infection"], "attack_usb_malware", 0.85, because="The USB drive carried a worm."),
    R("R50", ["breach_notice"], "attack_data_breach", 0.80, because="Your data was in a breach."),
    R("R51", ["boss_payment_request"], "attack_bec", 0.70, because="Urgent payment changes from a 'boss' or supplier are typical business email compromise."),
    R("R52", ["boss_payment_request", "email_sender_odd"], "attack_bec", 0.90, because="The request came from a look-alike address."),

    # Layer 3: attack + context -> severity
    R("R53", ["attack_ransomware", "ctx_business"], "sev_critical", 0.95, because="Ransomware on a business machine can stop operations."),
    R("R54", ["attack_ransomware", "ctx_spread"], "sev_critical", 0.90, because="It's spreading across the network."),
    R("R55", ["attack_bec", "ctx_banking"], "sev_critical", 0.90, because="Money is about to move or already has."),
    R("R56", ["attack_sim_swap", "ctx_banking"], "sev_critical", 0.90, because="Your number gets OTPs for your bank and wallets."),
    R("R57", ["attack_account_takeover", "strange_transactions"], "sev_critical", 0.90, because="The attacker is already spending your money."),
    R("R58", ["attack_spyware", "ctx_sensitive"], "sev_high", 0.85, because="Spyware on a device with sensitive data means likely data theft."),
    R("R59", ["attack_botnet", "ctx_business"], "sev_high", 0.80, because="A botnet node inside a company network is a foothold."),
    R("R60", ["attack_data_breach", "reused_password"], "sev_high", 0.80, because="A reused password turns one breach into many."),
    R("R61", ["attack_tech_support_scam", "remote_tool_installed"], "sev_high", 0.85, because="The scammer had remote control of your machine."),

    # Layer 3: attack + context -> extra actions
    R("R62", ["ctx_banking"], "act_call_bank", 0.95, if_any=ACCOUNT + ["attack_trojan"], because="Money could be at risk."),
    R("R63", ["ctx_spread"], "act_isolate_network", 0.90, if_any=MALWARE, because="Malware may be spreading across devices."),
    R("R64", ["ctx_business"], "act_inform_it", 0.90, if_any=MALWARE + ACCOUNT + ["attack_mitm", "attack_data_breach"], because="Company incidents need the IT/security team."),
    R("R65", [], "act_change_passwords", 0.90, if_any=["attack_account_takeover", "attack_phishing", "attack_data_breach", "attack_spyware", "attack_social_hijack", "attack_mitm"], because="Some passwords should be treated as known to the attacker."),
    R("R66", [], "act_report_nccia", 0.80, if_any=["attack_ransomware", "attack_bec", "attack_sim_swap", "attack_account_takeover", "attack_tech_support_scam"], because="This is a reportable cybercrime."),
    R("R67", [], "act_disconnect", 0.90, if_any=MALWARE, because="Cutting the connection stops data leaving and malware spreading."),
]

# ---------------------------------------------------------------- attack profiles
ATTACKS = {
    "attack_ransomware": ("Ransomware", "High",
        "Malware has encrypted your files and wants money for the key. Paying doesn't guarantee you get anything back.",
        ["Unplug the network cable and turn off Wi-Fi. Leave the machine powered on so evidence survives.",
         "Don't pay, and don't contact the attackers yet.",
         "Photograph the ransom note and write down the file extension. Look it up on nomoreransom.org, since some strains have free decryptors.",
         "Check whether you have offline or cloud backups that weren't connected.",
         "Wipe and reinstall before restoring from a clean backup."]),
    "attack_phishing": ("Phishing", "Medium",
        "A fake message tried to trick you into handing over a password, a code or a payment.",
        ["Don't click anything else in that message.",
         "If you typed a password, change it now, starting with email and banking.",
         "Turn on two-factor authentication using an app, not SMS.",
         "Report the message as phishing in your mail app, then delete it."]),
    "attack_account_takeover": ("Account takeover", "High",
        "Someone else has your login and is using the account, or is close to it.",
        ["Use the provider's 'hacked account' recovery page (Google, Meta and Microsoft all have one).",
         "Once you're back in, change the password and sign out every other session.",
         "Check the recovery email and phone, and remove anything that isn't yours.",
         "Check forwarding rules and connected apps. Attackers leave these behind to keep access.",
         "Enable two-factor authentication."]),
    "attack_spyware": ("Spyware / keylogger", "High",
        "Something on the device is watching what you type or see, and may be giving someone remote control.",
        ["Disconnect from the internet.",
         "From a different, clean device, change your important passwords.",
         "Run a full offline scan (Microsoft Defender Offline or Malwarebytes).",
         "If the camera or mouse moved by itself, assume full compromise. Back up your documents only and reinstall the OS."]),
    "attack_cryptojacking": ("Cryptojacking", "Medium",
        "A hidden miner is using your CPU or GPU to make cryptocurrency for someone else. Your hardware and power bill pay for it.",
        ["Open Task Manager, find the process hogging CPU, and note its name and location.",
         "Uninstall the cracked software or mod you installed recently.",
         "Run a full antivirus scan and check startup programs.",
         "Stick to legitimate software from here on. 'Free' cracks are how miners get in."]),
    "attack_botnet": ("Botnet infection", "High",
        "Your device has been taken over and is being used to send spam or attack other systems.",
        ["Disconnect the device from the network.",
         "Run a full offline antivirus scan.",
         "Reset your router and update its firmware and admin password.",
         "If your ISP sent a notice, reply once the device is clean."]),
    "attack_adware": ("Adware / browser hijacker", "Low",
        "Unwanted software is pushing ads and redirecting your browser. It's mostly a nuisance, but it can lead to worse sites.",
        ["Remove extensions you didn't add.",
         "Reset your browser settings (homepage and search engine).",
         "Uninstall unfamiliar programs from Apps & Features.",
         "Run Malwarebytes or AdwCleaner."]),
    "attack_trojan": ("Trojan / fake app", "High",
        "Software you installed was hiding something malicious. Banking trojans on Android read SMS codes and overlay fake login screens.",
        ["Uninstall the app or program. On Android, remove its device-admin and accessibility rights first.",
         "Run a full scan.",
         "Change passwords for anything you used on that device since installing it.",
         "Only install from the Play Store, App Store or the vendor's own site."]),
    "attack_sim_swap": ("SIM swap", "Critical",
        "Someone convinced your telco to move your number to their SIM, so your OTPs now go to them.",
        ["Call your telco from another phone or visit a franchise with your CNIC. Ask them to block the SIM and reissue it to you.",
         "Call your bank and wallet helplines to freeze accounts.",
         "Move two-factor authentication to an authenticator app where you can.",
         "Report it to the PTA and the NCCIA."]),
    "attack_social_hijack": ("Social media hijack", "Medium",
        "Your social account is being used to scam your friends and followers.",
        ["Recover the account via the platform's 'hacked account' page.",
         "Post or message your contacts so they ignore anything sent from your account.",
         "Turn on two-factor authentication and review logged-in devices."]),
    "attack_tech_support_scam": ("Tech-support scam", "Medium",
        "The 'virus warning' was fake. The people on the phone are scammers after remote access or payment.",
        ["Hang up and stop all contact.",
         "Uninstall AnyDesk, TeamViewer or whatever they had you install.",
         "Scan the PC. They often leave malware or extra remote tools behind.",
         "If you paid or shared card details, call your bank right away."]),
    "attack_mitm": ("Man-in-the-middle / rogue Wi-Fi", "Medium",
        "Someone may be sitting between you and the websites you use, able to read or alter your traffic.",
        ["Disconnect from that network.",
         "Never click through certificate warnings.",
         "Reset the router to factory settings and set a strong admin password.",
         "Change passwords you used while connected, from a trusted network."]),
    "attack_usb_malware": ("USB-borne malware", "Medium",
        "A USB drive carried a worm that spreads to every PC and drive it touches.",
        ["Don't plug that drive into anything else.",
         "Scan the PC and the drive. Recover files that were turned into shortcuts with attrib or a cleaner tool.",
         "Turn off AutoRun/AutoPlay for removable drives."]),
    "attack_data_breach": ("Data breach exposure", "Medium",
        "A service you use leaked your data. Your account isn't necessarily hacked yet, but the password is out there.",
        ["Change the password on the breached site.",
         "Change it everywhere else you reused it.",
         "Start using a password manager so every site gets a unique password.",
         "Watch out for phishing that uses the leaked details."]),
    "attack_bec": ("Business email compromise", "High",
        "A fake or hijacked email from someone you trust is trying to redirect a payment.",
        ["Don't send the money. Verify by calling the person on a number you already have, not one in the email.",
         "If money has already gone out, ask your bank to recall the transfer right now. Hours matter.",
         "Check your mailbox for forwarding rules you didn't create.",
         "Tell finance and IT so others don't fall for the same email."]),
}

ACTIONS = {
    "act_call_bank": "Call your bank or wallet helpline now and ask them to block cards and flag the account.",
    "act_isolate_network": "Disconnect every affected device from the network before cleaning any of them.",
    "act_inform_it": "Tell your IT or security team right away. Don't try to clean a work machine yourself.",
    "act_change_passwords": "From a clean device, change passwords for email first, then banking, then everything else.",
    "act_report_nccia": "File a complaint with the NCCIA (formerly the FIA Cyber Crime Wing) at complaint.nccia.gov.pk or call 1991.",
    "act_disconnect": "Disconnect this device from Wi-Fi and wired internet until it's cleaned.",
}

SEVERITY_ORDER = ["Low", "Medium", "High", "Critical"]
DIAGNOSIS_THRESHOLD = 0.30  # below this CF an attack is too weak to report


DERIVED = {
    "files_encrypted": "Files have been encrypted",
    "hidden_resource_use": "Something is secretly using the hardware",
    "credentials_exposed": "Login details are exposed",
    "phishing_message": "A phishing message arrived",
    "suspicious_logins": "Someone else is trying to log in",
    "account_hijacked": "You're locked out of an account",
    "malware_installed": "Malware is installed",
    "untrusted_software": "Untrusted software was installed",
    "remote_control_signs": "Someone may have remote control",
    "abnormal_traffic": "Unexplained network traffic",
    "sim_hijacked": "Your phone number was moved",
    "browser_hijacked": "The browser was hijacked",
    "usb_infection": "The USB drive is infected",
    "traffic_intercepted": "Traffic is being intercepted",
    "scam_contact": "You were in contact with scammers",
    "sev_critical": "Raise severity to Critical",
    "sev_high": "Raise severity to High",
    "act_call_bank": "Add: call the bank",
    "act_isolate_network": "Add: isolate the network",
    "act_inform_it": "Add: tell IT",
    "act_change_passwords": "Add: change passwords",
    "act_report_nccia": "Add: report to NCCIA",
    "act_disconnect": "Add: disconnect the device",
}


def label(fact):
    """Human-readable label for any fact id (used in explanations)."""
    if fact in DERIVED:
        return DERIVED[fact]
    for qs in QUESTIONS.values():
        for fid, text in qs:
            if fid == fact:
                return text
    for fid, text in CONTEXT:
        if fid == fact:
            return text
    if fact in ATTACKS:
        return ATTACKS[fact][0]
    return fact.replace("act_", "action: ").replace("sev_", "severity: ").replace("_", " ")


def diagnose(answers):
    """answers: {fact_id: cf}. Returns (ranked attacks, overall severity, actions, facts, trace)."""
    from engine import infer
    facts, trace = infer(answers, RULES)
    attacks = sorted(((a, facts[a]) for a in ATTACKS if facts.get(a, 0) >= DIAGNOSIS_THRESHOLD),
                     key=lambda x: -x[1])
    level = max((SEVERITY_ORDER.index(ATTACKS[a][1]) for a, _ in attacks), default=-1)
    if facts.get("sev_high", 0) >= 0.5:
        level = max(level, 2)
    if facts.get("sev_critical", 0) >= 0.5:
        level = 3
    severity = SEVERITY_ORDER[level] if level >= 0 else None
    actions = [ACTIONS[a] for a in ACTIONS if facts.get(a, 0) >= 0.5]
    return attacks, severity, actions, facts, trace


# ---------------------------------------------------------------- demo scenarios
SCENARIOS = {
    "Office PC hit by ransomware": (["files_unreadable", "odd_extensions", "ransom_note", "backups_deleted",
                                     "ctx_business", "ctx_spread"], "attack_ransomware"),
    "Phishing email, then locked out": (["email_urgent", "email_sender_odd", "clicked_link", "entered_password",
                                         "login_alert_unknown", "recovery_changed", "password_not_working",
                                         "ctx_banking"], "attack_account_takeover"),
    "Phone lost signal, money gone": (["no_signal", "carrier_msg_sim_change", "strange_transactions",
                                       "ctx_banking"], "attack_sim_swap"),
    "Laptop hot after a cracked game": (["cpu_high_idle", "fan_loud", "slow_device", "cracked_software"],
                                        "attack_cryptojacking"),
    "'Microsoft' called about a virus": (["scareware_popup", "called_number", "remote_tool_installed",
                                          "ctx_banking"], "attack_tech_support_scam"),
}
