#!/usr/bin/python

# ****************************************************************************
# Purpose:
# Assist System Administrators in implementing DMARC, SPF,
# and DKIM by asking questions and creating a file with the
# information needed to create the related DNS records.
# ****************************************************************************
# Creator:          Tim Lansing
# Creation Date:    9 September 2020
# ****************************************************************************
# Notes:
# This script was created using:
#     - Python 3.8.2.
#     - dnspython 2.0.0 ('pip3 install dnspython')
# ****************************************************************************
# History:
# 9 September 2020 - Tim Lansing - Copied from dmarc-poc.py.
# ****************************************************************************

# Imports
from DomainRecordHandler import DomainRecordHandler
from get_input import *

# Declare global variables.
domain_name = ""
subdomain_name = ""
parent_domain_name = ""
domain_is_used_for_email = True
dmarc_policy = ""
dmarc_subdomain_policy = ""
dmarc_policies = {
    "m": "none",
    "q": "quarantine",
    "r": "reject"
}
dmarc_failure_reporting_option = ""
dmarc_dkim_alignment = ""
dmarc_spf_alignment = ""
dmarc_aggregate_email_address = ""
dmarc_failure_email_address = ""
spf_servers = ""
dkim_selector = "*"
domain_record_handler = ""
dmarc_record = ""


# Main function to be ran.
def main():
    '''
    Main function of the program.
    :return: None.
    '''
    display_welcome_message()
    ask_dmarc_questions()
    ask_spf_questions()
    ask_dkim_questions()
    clear_screen()
    print_dmarc_output()
    print_spf_output()
    print_dkim_output()
    print("")


# Display the welcome message.
def display_welcome_message():
    '''
    Displays the welcome message of the program.
    :return: None.
    '''
    clear_screen()
    print("")
    print("****************************************************************************")
    print("Welcome. The purpose of this script is to assist in implementing")
    print("DMARC, SPF, and DKIM.")
    print("")
    print("WARNING: This script is a work in progress.")
    print(" 1. Confirm the validity of its output.")
    print(" 2. Ensure your input is correct.")
    print(" 3. Please report any issues at https://github.com/tdlansing/dmarc-tool-2.")
    print("****************************************************************************")


# Ask questions needed to configure DMARC.
def ask_dmarc_questions():
    '''
    Asks questions to gather information needed for DMARC.
    :return: None.
    '''

    # Declare global variables to be used.
    global domain_name
    global domain_is_used_for_email
    global dmarc_policy
    global dmarc_subdomain_policy
    global dmarc_failure_reporting_option
    global dmarc_dkim_alignment
    global dmarc_spf_alignment
    global dmarc_aggregate_email_address
    global dmarc_failure_email_address
    global domain_record_handler
    global dmarc_record

    # Get the domain name.
    domain_name = ""
    while domain_name == "":
        print("")
        domain_name = input("Domain name: ")
        clear_screen()
        domain_record_handler = DomainRecordHandler(domain_name)
        if not DomainRecordHandler.get_domain_exists(domain_name):
            print("Unable to verify that this domain currently exists.")
            print("")
        user_input = ask_yes_no_question(["Is '" + domain_name + "' the correct domain?"])
        if "n" == user_input:
            domain_name = ""

    set_subdomain()

    # Check if domain is used for email.
    clear_screen()
    user_input = ask_yes_no_question(["Is '" + domain_name + "' used to send email?"])
    if "n" == user_input:
        domain_is_used_for_email = False

    # If domain is used for email then ask these questions.
    if domain_is_used_for_email:

        # Get the DMARC policy.
        dmarc_policy = ""
        clear_screen()
        while "" == dmarc_policy:
            print("Do you want to monitor, quarantine, or reject emails from " + domain_name)
            print("that do not pass SPF and do not pass DKIM?")
            print("")
            print("Monitor- Recommended when first configuring DMARC.")
            print("Quarantine- Recommended to be used before setting to reject. This requests")
            print("    are sent to the SPAM / Junk mail folder if SPF an DKIM do not pass.")
            print("Reject- Requests emails not passing SPF and DKIM are dropped and on domains")
            print("    that don't send email. Preferred if SPF and DKIM are implemented and")
            print("    working. Legitimate emails not passing may also be dropped.")
            print("")
            print("Enter:")
            print("'m' for monitor")
            print("'q' for quarantine")
            print("'r' for reject")
            if "" != domain_record_handler.dmarc_record.p:
                print("")
                print("Note: Current domain policy is set to '" + domain_record_handler.dmarc_record.p + "'.")
            print("")
            user_input = input("Policy selection: ")
            dmarc_policy = dmarc_policies.get(user_input, "")
            if "" == dmarc_policy:
                clear_screen()
                print("Sorry, '" + user_input + "' is not a valid choice. 'm', 'q', or 'r' must be entered.")
                print("")

        # Get subdomain policy, if wanted.
        clear_screen()
        question = [
            "Do you want to set a policy for subdomains of " + domain_name + "?",
            "If not set, the policy of '" + dmarc_policy + "' will be used."
        ]
        user_input = ask_yes_no_question(question)
        if "y" == user_input:
            while "" == dmarc_subdomain_policy:
                print("")
                print("Enter:")
                print("'m' for monitor")
                print("'q' for quarantine")
                print("'r' for reject")
                if "" != domain_record_handler.dmarc_record.sp:
                    print("")
                    print("Note: Current subdomain policy is set to '" + domain_record_handler.dmarc_record.sp + "'.")
                print("")
                user_input = input("Policy selection: ")
                dmarc_subdomain_policy = dmarc_policies.get(user_input, "")
                if "" == dmarc_subdomain_policy:
                    clear_screen()
                    print("Sorry, '" + user_input + "' is not a valid choice. 'm', 'q', or 'r' must be entered.")
                    print("")

        # Get DKIM and SPF alignment settings.
        clear_screen()
        question = [
            "Will the email server's domain exactly match '" + domain_name + "'?",
            ""
        ]
        if domain_name == parent_domain_name:
            question.append("Consider if the server for '" + domain_name + "'")
            question.append("    will be used to send emails for any subdomains.")
        else:
            question.append("Consider if emails for '" + domain_name + "'")
            question.append("    will be sent by the server controlling '" + parent_domain_name + "'.")
            question.append("Or, if its own server will send emails for any subdomains under it.")
        question.append("")
        question.append("If so, then answer 'no'.")
        question.append("")
        question.append("WARNING: If unsure, we recommend answering 'no'. Answering 'yes' will")
        question.append("    increase security, but it may cause legitimate emails to be dropped")
        question.append("    if not configured correctly.")
        if "s" != domain_record_handler.dmarc_record.adkim and "s" != domain_record_handler.dmarc_record.aspf:
            question.append("")
            question.append("Note: Currently the domain is configured for 'yes'.")
        elif "r" != domain_record_handler.dmarc_record.adkim or "r" != domain_record_handler.dmarc_record.aspf:
            question.append("")
            question.append("Note: Currently the domain is configured for 'no'.")
        user_input = ask_yes_no_question(question)
        if "y" == user_input:
            dmarc_dkim_alignment = "; adkim=s"
            dmarc_spf_alignment = "; aspf=s"

    # Get aggregate reporting email address if reports are wanted.
    clear_screen()
    if "" != domain_record_handler.dmarc_record.rua:
        email_addresses = ""
        for email_address in domain_record_handler.dmarc_record.rua:
            if "" != email_addresses:
                email_addresses += ", "
            email_addresses = email_addresses + (email_address.split(":")[1]).strip()
        print("Note: Currently aggregate reports are sent to '"+email_addresses+"'.")
        print("")
    question = [
        "Would you like to receive aggregate reports? We recommend doing so.",
        "",
        "WARNING: Email addresses are public. It is recommended to use",
        "    dedicated email addresses and deploy abuse countermeasures.",
        "",
        "WARNING: If you choose to receive DMARC reports at an email address with a",
        "    different domain than '" + domain_name + "' then a DNS entry will need",
        "    to be made for that domain as well."
    ]
    user_input = ask_yes_no_question(question)
    # If the user wants to get aggregate reports then get the email address.
    if "y" == user_input:
        dmarc_aggregate_email_address = ""
        clear_screen()
        # While there is no DMARC aggregate email address set ask for one.
        while "" == dmarc_aggregate_email_address:
            dmarc_aggregate_email_address = input("Aggregate email address: ")
            # Get the root domain from the email address to compare with that of the domain being configured.
            email_domain = get_root_domain_from_email(dmarc_aggregate_email_address)
            user_input2 = ""
            # If the aggregate email address comes from a different domain ask the user to confirm.
            if email_domain != parent_domain_name:
                question2 = [
                    "",
                    "The email address '" + dmarc_aggregate_email_address + "' has a root domain of",
                    "    '" + email_domain + "' which is different than '" + parent_domain_name + "'. A DNS entry",
                    "    will need by be made at '" + email_domain + "'. Are you sure you want to use this",
                    "    email address?"
                ]
                user_input2 = ask_yes_no_question(question2)
            # If the user states they do not want to use this email address then clear the address provided and
            # ask the user for an email address again.
            if "n" == user_input2:
                dmarc_aggregate_email_address = ""
                clear_screen()
                print("Please enter a different email address.")
                print("")

    # Get failure reporting email address and reporting option if reports are wanted.
    clear_screen()
    if "" != domain_record_handler.dmarc_record.ruf:
        email_addresses = ""
        for email_address in domain_record_handler.dmarc_record.ruf:
            if "" != email_addresses:
                email_addresses += ", "
            email_addresses = email_addresses + (email_address.split(":")[1]).strip()
        print("Note: Currently failure reports are sent to '" + email_addresses + "'.")
        print("")
    question = [
        "Would you like to receive failure reports?",
        "",
        "Recommended for troubleshooting or if policy is set to quarantine or reject.",
        "",
        "WARNING: Email addresses are public. It is recommended to use",
        "    dedicated email addresses and deploy abuse countermeasures.",
        "",
        "WARNING: If SPF and/or DKIM are not implemented then reports may be",
        "    received for each email sent.",
        "",
        "WARNING: If you choose to receive DMARC reports at an email address with a",
        "    different domain than '" + domain_name + "' then a DNS entry will need",
        "    to be made for that domain as well."
    ]
    user_input = ask_yes_no_question(question)
    # If the user wants to get failure reports then get the email address.
    if "y" == user_input:
        dmarc_failure_email_address = ""
        clear_screen()
        # While there is no DMARC failure email address set ask for one.
        while "" == dmarc_failure_email_address:
            dmarc_failure_email_address = input("Failure email address: ")
            # Get the root domain from the email address to compare with that of the domain being configured.
            email_domain = get_root_domain_from_email(dmarc_failure_email_address)
            user_input2 = ""
            # While the failure email address comes from a different domain and the user input 2 is not set saying
            # the user confirms that they understand, ask the user to confirm.
            if email_domain != parent_domain_name:
                question2 = [
                    "",
                    "The email address '" + dmarc_failure_email_address + "' has a root domain of",
                    "    '" + email_domain + "' which is different than '" + parent_domain_name + "'. A DNS entry",
                    "    will need by be made at '" + email_domain + "'. Are you sure you want to use this",
                    "    email address?"
                ]
                user_input2 = ask_yes_no_question(question2)
            # If the user states they do not want to use this email address then clear the address provided and
            # ask the user for an email address again.
            if "n" == user_input2:
                dmarc_failure_email_address = ""
                clear_screen()
                print("Please enter a different email address.")
                print("")
        # Get failure reporting option
        clear_screen()
        question = [
            "By default DMARC failure reporting is only sent if SPF and DKIM both",
            "fail alignment.",
            "",
            "We recommend 'yes' so you receive reports if SPF or DKIM fail.",
            "",
            "Would you like to make this change?"
        ]
        user_input = ask_yes_no_question(question)
        if "y" == user_input:
            dmarc_failure_reporting_option = "; fo=1"


# Ask questions needed to configure SPF and have not been previously asked.
def ask_spf_questions():
    '''
    Asks questions to gather information needed for SPR, not already asked.
    :return: None.
    '''

    global spf_servers

    if domain_is_used_for_email:
        is_not_done = True
        clear_screen()
        while is_not_done:
            print("Add servers which may send email.")
            print("")
            print("Select:")
            print("1. Add by IP address or range.")
            print("    Type '1.2.3.4/32' for the single IP address of 1.2.3.4.")
            print("    Use CIDR notation for ranges needed, as appropriate.")
            print("2. Add by host name. Example: 'host.domain.com'.")
            print("3. Add for 3rd party providers. Example: '3rdPartyDomain.com'.")
            print("4. Add email servers with MX entries for your domain.")
            print("5. Done adding. Exit.")
            print("")
            user_input = input("Selection: ")
            # If spf_servers now contains something and the user selects Exit then set
            # is_not_done to false.
            if "" != spf_servers and "5" == user_input:
                is_not_done = False
            else:
                print("")
                if "1" == user_input:
                    server_input = input("Enter the IP address using CIDR notation: ")
                    spf_servers = spf_servers + " ip4:" + server_input
                    clear_screen()
                    print("'" + server_input + "' has been added.")
                    print("")
                elif "2" == user_input:
                    server_input = input("Enter the host name: ")
                    period_count = server_input.count(".")
                    # Check that there are at least two periods in the host name.
                    if period_count > 1:
                        # Check that the host name matches.
                        temp_domain = server_input[::-1]
                        first_period_position = temp_domain.find(".")
                        second_period_position = temp_domain.find(".", first_period_position + 1)
                        temp_domain = temp_domain[:second_period_position][::-1]
                        if temp_domain == parent_domain_name:
                            spf_servers = spf_servers + " a:" + server_input
                            clear_screen()
                            print("'" + server_input + "' has been added.")
                            print("")
                        else:
                            clear_screen()
                            print("Sorry, '" + server_input + "' is an invalid host name.")
                            print("The domain must end in '" + parent_domain_name + "'.")
                            print("")
                    else:
                        clear_screen()
                        print("Sorry, '" + server_input + "' is an invalid host name. Must be in the format of")
                        print("'host.domain.com'.")
                        print("")
                elif "3" == user_input:
                    server_input = input("Enter the 3rd party domain which will send email on this domain's behalf: ")
                    spf_servers = spf_servers + " include:" + server_input
                    clear_screen()
                    print("'" + server_input + "' has been added.")
                    print("")
                elif "4" == user_input:
                    spf_servers = spf_servers + " mx"
                    clear_screen()
                    print("Servers with MX entries have been added.")
                    print("")
                elif "5" == user_input:
                    clear_screen()
                    print("Sorry, at least one device must be added.")
                    print("")
                else:
                    clear_screen()
                    print("Sorry, '" + user_input + "' is not a valid choice.")
                    print("")


# Ask questions needed to configure DKIM and have not been previously asked.
def ask_dkim_questions():
    '''
    Asks questions to gather information needed for DKIM, not already asked.
    :return: None.
    '''

    global dkim_selector

    if domain_is_used_for_email:

        clear_screen()
        print("If DKIM has been configured on your server, what is the name of your selector?")
        print("")
        dkim_selector = input("Name: ")
        # If no input was provided set selector to 'selector' to allow for an example to be provided.
        if "" == dkim_selector:
            dkim_selector = "selector"


# Check to see if the domain provided is a subdomain. If so, set
# "subdomain_name" to a period followed by what is in "domain_name", but
# without the parent domain portion.
# The proceeding period is needed for the DNS host names.
# Example: "mail.domain.xyz" becomes ".mail"
def set_subdomain():
    '''
    Sets the value for the global variables subdomain_name and/or parent_domain_name.
    :return: None.
    '''
    global subdomain_name
    global parent_domain_name
    period_count = domain_name.count('.')
    # If there is more than one period then it is a subdomain.
    if period_count > 1:
        # Reverse the domain_name string. This places the parent domain at
        # the beginning and makes it easier to remove.
        temp_domain = domain_name[::-1]
        first_period_position = temp_domain.find(".")
        second_period_position = temp_domain.find(".", first_period_position + 1)
        # Set the parent domain name.
        parent_domain_name = temp_domain[:second_period_position][::-1]
        # Get all characters from the second period's position on.
        temp_domain = temp_domain[second_period_position + 1:]
        # Reverse the string again to get the characters back in the correct
        # order.
        subdomain_name = "." + temp_domain[::-1]
    else:
        parent_domain_name = domain_name


def get_root_domain_from_email(email_address):
    '''
    Takes an email address and returns the root domain for the email account.
    :param email_address: Email address to find the root domain for.
    :return: Root domain of the email address provided.
    '''

    at_position = email_address.find("@")
    root_domain = email_address[at_position + 1::]
    while root_domain.count('.') > 1:
        period_position = root_domain.find(".")
        root_domain = root_domain[period_position + 1::]
    return root_domain


def print_dmarc_output():
    '''
    Prints the information needed for DNS records needed for DMARC.
    :return: None.
    '''

    # Print DMARC TXT record information.
    print("DMARC DNS RECORD (" + parent_domain_name + ")")
    print("Record type: TXT")
    print("Host name:   _dmarc" + subdomain_name)
    if domain_is_used_for_email:
        print("Value:       v=DMARC1; p=" + dmarc_policy, end='')
        if "" != dmarc_subdomain_policy:
            print("; sp=" + dmarc_subdomain_policy, end='')
        print(dmarc_failure_reporting_option, end='')
        print(dmarc_dkim_alignment, end='')
        print(dmarc_spf_alignment, end='')
    else:
        print("Value:       v=DMARC1; p=reject; sp=reject", end='')
        print(dmarc_failure_reporting_option, end='')
    if "" != dmarc_aggregate_email_address:
        print("; rua=mailto:" + dmarc_aggregate_email_address, end='')
    if "" != dmarc_failure_email_address:
        print("; ruf=mailto:" + dmarc_failure_email_address, end='')
    print("")

    # Get domain for where emails are going.
    at_position = dmarc_aggregate_email_address.find("@")
    aggregate_email_domain = dmarc_aggregate_email_address[at_position + 1:]
    # If aggregate report emails are going to a different domain then print DNS record for that domain.
    if aggregate_email_domain != domain_name and "" != aggregate_email_domain:
        print("")
        print("DMARC DNS RECORD (" + aggregate_email_domain + ")")
        print("Record type: TXT")
        print("Host name:   " + domain_name + "._report._dmarc." + aggregate_email_domain)
        print("Value:       v=DMARC1")

    # Get domain for where emails are going.
    at_position = dmarc_failure_email_address.find("@")
    failure_email_domain = dmarc_failure_email_address[at_position + 1:]
    # If failure report emails are going to a different domain then print DNS record for that domain.

    if (
            failure_email_domain != domain_name and
            failure_email_domain != aggregate_email_domain and
            "" != failure_email_domain
    ):
        print("")
        print("DMARC DNS RECORD (" + failure_email_domain + ")")
        print("Record type: TXT")
        print("Host name:   " + domain_name + "._report._dmarc." + failure_email_domain)
        print("Value:       v=DMARC1")


def print_spf_output():
    '''
    Prints the information needed for DNS records for SPF.
    :return: None.
    '''

    # Print SPF TXT record information.
    print("")
    print("SPF DNS RECORD (" + parent_domain_name + ")")
    print("Record type: TXT")
    if "" == subdomain_name:
        print("Host name:   @")
    else:
        print("Host name:   " + subdomain_name[1:])
    print("Value:       v=spf1", end='')
    print(spf_servers + " ~all")


def print_dkim_output():
    '''
    Prints the information needed for DNS records for DKIM.
    :return: None.
    '''

    # Print DKIM TXT record information.
    print("")
    print("DKIM DNS RECORD (" + parent_domain_name + ")")
    print("Record type: TXT")
    if "" == subdomain_name:
        print("Host name:   " + dkim_selector + "._domainkey")
    else:
        print("Host name:   " + dkim_selector + "._domainkey" + subdomain_name)
    print("Value:       v=DKIM1; k=rsa; p=", end='')
    if domain_is_used_for_email:
        print("ReplaceThisTextWithYourPublicKey", end='')
    print("")


if __name__ == "__main__":
    main()
