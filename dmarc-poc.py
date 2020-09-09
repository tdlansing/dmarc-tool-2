#!/usr/bin/python

# ****************************************************************************
# Purpose:
# Assist System Administrators in implementing DMARC, SPF, 
# and DKIM by asking questions and creating a file with the 
# information needed to create the related DNS records.
# ****************************************************************************
# Creator:          Tim Lansing
# Creation Date: 1 September 2020 
# ****************************************************************************
# Notes:
# This script was created using:
#     - Python 3.8.2.
# ****************************************************************************
# History:
# 1 September 2020 - Tim Lansing - Initial creation.
# ****************************************************************************

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
dmarc_forensic_email_address = ""
spf_servers = ""
dkim_selector = "*"

# Main function to be ran.
def main():
    displayWelcomeMessage()
    askDmarcQuestions()
    askSpfQuestions()
    askDkimQuestions()
    printDmarcOutput()
    printSpfOutput()
    printDkimOutput()

# Display the welcome message.
def displayWelcomeMessage():
    print("")
    print("****************************************************************************")
    print("Welcome. The purpose of this script is to assist in implementing")
    print("DMARC, SPF, and DKIM.")
    print("")
    print("WARNING: This script is currently a proof of concept and a work")
    print("in progress.")
    print(" 1. Confirm the validity of its output.")
    print(" 2. Ensure your input is correct. Input validation needs to be added.")
    print("****************************************************************************")

# Ask questions needed to configure DMARC.
def askDmarcQuestions():
    # Declare global variables to be used.
    global domain_name
    global domain_is_used_for_email
    global dmarc_policy
    global dmarc_subdomain_policy
    global dmarc_failure_reporting_option
    global dmarc_dkim_alignment
    global dmarc_spf_alignment
    global dmarc_aggregate_email_address
    global dmarc_forensic_email_address

    # Get the domain name.
    print("")
    domain_name = input("Domain name: ")
    setSubdomain()
    
    # Check if domain is used for email.
    user_input = ""
    while "y" != user_input and "n" != user_input:
        print("")
        print("Is this domain used to send email?")
        print("Enter: 'y' for yes or 'n' for no.")
        user_input = input("Selection: ")
        if ("n" == user_input):
            domain_is_used_for_email = False

    if(domain_is_used_for_email):
    
        # Get the DMARC policy.
        dmarc_policy = ""
        while "" == dmarc_policy:
            print("")
            print("Do you want to monitor, quarantine, or reject emails to your domain")
            print("that do not pass SPF and do not pass DKIM?")
            print("")
            print("Monitor- Recommended when first configuring DMARC.")
            print("Quarantine- Recommended be used before setting to reject. Emails")
            print("    should go to the SPAM / Junk mail folder if they do not pass.")
            print("Reject- Preferred because malicious emails may not arrive to the user.")
            print("    However, legitimate emails not passing may also be dropped. This")
            print("    is also recommended for domains that do not send email.")
            print("Enter:")
            print("'m' for monitor")
            print("'q' for quarantine")
            print("'r' for reject")
            user_input = ""
            user_input = input("Policy selection: ")
            dmarc_policy = dmarc_policies.get(user_input, "")
            if ("" == dmarc_policy):
                print("")
                print("Sorry, that is not a valid choice.")

        # Get subdomain policy, if wanted.
        user_input = ""
        while "y" != user_input and "n" != user_input:
            print("")
            print("Do you want a different setting for subdomains under this domain?")
            print("Enter: 'y' for yes or 'n' for no.")
            user_input = input("Selection: ")
            if ("y" != user_input and "n" != user_input):
                print("")
                print("Sorry, that is not a valid choice.")
        if ("y" == user_input):
            while "" == dmarc_subdomain_policy:
                print("")
                print("Enter:")
                print("'m' for monitor")
                print("'q' for quarantine")
                print("'r' for reject")
                user_input = ""
                user_input = input("Policy selection: ")
                dmarc_subdomain_policy = dmarc_policies.get(user_input, "")
                if ("" == dmarc_subdomain_policy):
                    print("")
                    print("Sorry, that is not a valid choice.")

        # Get DKIM and SPF alignment settings.
        user_input = ""
        while "y" != user_input and "n" != user_input:
            print("")
            print("Will the email server used always exactly match the domain '"+domain_name+"'?")
            if (domain_name == parent_domain_name):
                print("Consider if the server for '"+domain_name+"'")
                print("    will be used to send emails for any subdomains.")
            else:
                print("Consider if emails for '"+domain_name+"'")
                print("will be sent by the server controlling '"+parent_domain_name+"'.")
                print("Or, if its own server will send emails for any subdomains under it.")
            print("If so, then answer 'no'.")
            print("WARNING: If unsure we recomend answering 'no'. Answering 'yes' will")
            print("    increase security, but it may cause legitimate emails to be dropped")
            print("    if not configured correctly.")
            print("Enter: 'y' for yes or 'n' for no.")
            user_input = input("Selection: ")
            if ("y" != user_input and "n" != user_input):
                print("")
                print("Sorry, that is not a valid choice.")
        if ("y" == user_input):
            dmarc_dkim_alignment = "; adkim=s"
            dmarc_spf_alignment = "; aspf=s"

    # Get aggregate reporting email address if reports are wanted.
    user_input = ""
    while "y" != user_input and "n" != user_input:
        print("")
        print("Would you like to receive aggregate reports? We recommend to do so.")
        print("WARNING: Email addresses are public. It is recommended to use")
        print("    dedicated email addresses and deploy abuse countermeasures.")
        print("WARNING: If emails are going to a domain other than the one being")
        print("    configured then a DNS entry will need to be made on that domain as")
        print("    well. If it goes to a DMARC services provider then they will likely take")
        print("    care of this for you. Consult with them to be sure.")
        print("Enter: 'y' for yes or 'n' for no.")
        user_input = input("Selection: ")
        if ("y" != user_input and "n" != user_input):
            print("")
            print("Sorry, that is not a valid choice.")
    if ("y" == user_input):
        dmarc_aggregate_email_address = input("Aggregate email address: ")

    # Get forensic reporting email address and reporting option if reports are wanted.
    user_input = ""
    while "y" != user_input and "n" != user_input:
        print("")
        print("Would you like to receive forensic reports?")
        print("Recommended for troubleshooting or if policy is set to quarantine or reject.")
        print("WARNING: Email addresses are public. It is recommended to use")
        print("    dedicated email addresses and deploy abuse countermeasures.")
        print("WARNING: If SPF and/or DKIM are not implemented then reports may be")
        print("    received for each email sent.")
        print("Enter: 'y' for yes or 'n' for no.")
        user_input = input("Selection: ")
        if ("y" != user_input and "n" != user_input):
            print("")
            print("Sorry, that is not a valid choice.")
    if ("y" == user_input):
        dmarc_forensic_email_address = input("Forensic email address: ")
        # Get failure reporting option
        user_input = ""
        while "y" != user_input and "n" != user_input:
            print("")
            print("By default DMARC failure reporting is only sent if SPF and DKIM both")
            print("fail alignment.")
            print("We recommend 'yes' so you receive reports if SPF or DKIM fail.")
            print("Would you like to make this change?")
            print("Enter: 'y' for yes or 'n' for no.")
            user_input = input("Selection: ")
            if ("y" != user_input and "n" != user_input):
                print("")
                print("Sorry, that is not a valid choice.")
        if ("y" == user_input):
            dmarc_failure_reporting_option = "; fo=1"

# Ask questions needed to configure SPF and have not been previously asked.
def askSpfQuestions():
    global spf_servers
    
    if(domain_is_used_for_email):
    
        is_not_done = True
        while(is_not_done):
            print("")
            print("Add servers which may send email:")
            print("Select:")
            print("1. Add by IP address or range.")
            print("    Type '1.2.3.4/32' for the single IP address of 1.2.3.4.")
            print("    Use CIDR notation for ranges needed, as appropriate.")
            print("2. Add by host name. Example: 'host.domain.com'.")
            print("3. Add for 3rd party providers. Example: '3rdPartyDomain.com'.")
            print("4. Add email servers with MX entries for your domain.")
            print("5. Done adding. Exit.")
            user_input = ""
            user_input = input("Selection: ")
            if ("" != spf_servers and "5" == user_input):
                is_not_done = False
            else:
                if ("1" == user_input):
                    server_input = input("Enter the IP address using CIDR notation: ")
                    spf_servers = spf_servers+" ip4:"+server_input
                elif ("2" == user_input):
                    server_input = input("Enter the host name: ")
                    periodCount = server_input.count(".")
                    if (periodCount > 1):
                        # Check that the host name matches.
                        tempDomain = server_input[::-1]
                        firstPeriodPosition = tempDomain.find(".")
                        secondPeriodPosition = tempDomain.find(".", firstPeriodPosition+1)
                        tempDomain = tempDomain[:secondPeriodPosition][::-1]
                        if(tempDomain == parent_domain_name):
                            spf_servers = spf_servers+" a:"+server_input
                        else:
                            print("")
                            print("Sorry, that is an invalid host name.")
                            print("The domain must include '"+parent_domain_name+"'.")
                    else:
                        print("")
                        print("Sorry, that is an invalid host name. Must be in the format of 'host.domain.com'.")
                elif ("3" == user_input):
                    server_input = input("Enter the 3rd party domain which will send email on this domain's behalf: ")
                    spf_servers = spf_servers+" include:"+server_input
                elif ("4" == user_input):
                    spf_servers = spf_servers+" mx"
                elif ("5" == user_input):
                    print("")
                    print("Sorry, at least one device must be added.")
                else:
                    print("")
                    print("Sorry, that is not a valid choice.")

# Ask questions needed to configure DKIM and have not been previously asked.
def askDkimQuestions():
    global dkim_selector
    
    if(domain_is_used_for_email):
    
        print("")
        print("If DKIM has been configured on your server, what is the name of your selector?")
        dkim_selector = input("Name: ")
        # If no input was provided set selector to 'selector' to allow for an example to be provided.
        if ("" == dkim_selector):
            dkim_selector = "selector"

# Check to see if the domain provided is a subdomain. If so, set
# "subdomain_name" to a period followed by what is in "domain_name", but
# without the parent domain portion.
# The preceeding period is needed for the DNS host names.
# Example: "mail.domain.xyz" becomes ".mail"
def setSubdomain():
    global subdomain_name
    global parent_domain_name
    periodCount = domain_name.count('.')
    # If there is more than one period then it is a subdomain.
    if (periodCount > 1):
        # Reverse the domain_name string. This places the parent domain at
        # the beginning and makes it easier to remove.
        tempDomain = domain_name[::-1]
        firstPeriodPosition = tempDomain.find(".")
        secondPeriodPosition = tempDomain.find(".", firstPeriodPosition+1)
        # Set the parent domain name.
        parent_domain_name = tempDomain[:secondPeriodPosition][::-1]
        # Get all characters from the second period's postion on.
        tempDomain = tempDomain[secondPeriodPosition+1:]
        # Reverse the string again to get the characters back in the correct
        # order.
        subdomain_name = "."+tempDomain[::-1]
    else:
        parent_domain_name = domain_name

def printDmarcOutput():
    # Print DMARC TXT record information.
    print("")
    print("DMARC DNS RECORD ("+parent_domain_name+")")
    print("Record type: TXT")
    print("Host name:   _dmarc"+subdomain_name)
    if (domain_is_used_for_email):
        print("Value:       v=DMARC1; p="+dmarc_policy, end = '')
        if ("" != dmarc_subdomain_policy):
            print("; sp="+dmarc_subdomain_policy, end = '')
        print(dmarc_failure_reporting_option, end = '')
        print(dmarc_dkim_alignment, end ='')
        print(dmarc_spf_alignment, end = '')
    else:
        print("Value:       v=DMARC1; p=reject; sp=reject", end = '')
        print(dmarc_failure_reporting_option, end = '')
    if ("" != dmarc_aggregate_email_address):
        print("; rua=mailto:"+dmarc_aggregate_email_address, end = '')
    if ("" != dmarc_forensic_email_address):
        print("; ruf=mailto:"+dmarc_forensic_email_address, end = '')
    print("")
    
    # Get domain for where emails are going.
    atPosition = dmarc_aggregate_email_address.find("@")
    aggregate_email_domain = dmarc_aggregate_email_address[atPosition+1:]
    # If aggregate report emails are going to a different domain then print DNS record for that domain.
    if (aggregate_email_domain != domain_name and "" != aggregate_email_domain):
        print("")
        print("DMARC DNS RECORD ("+aggregate_email_domain+")")
        print("Record type: TXT")
        print("Host name:   "+domain_name+"._report._dmarc."+aggregate_email_domain)
        print("Value:       v=DMARC1")

    # Get domain for where emails are going.
    atPosition = dmarc_forensic_email_address.find("@")
    forensic_email_domain = dmarc_forensic_email_address[atPosition+1:]
    # If forensic report emails are going to a different domain then print DNS record for that domain.

    if (forensic_email_domain != domain_name and forensic_email_domain != aggregate_email_domain and "" != forensic_email_domain):
        print("")
        print("DMARC DNS RECORD ("+forensic_email_domain+")")
        print("Record type: TXT")
        print("Host name:   "+domain_name+"._report._dmarc."+forensic_email_domain)
        print("Value:       v=DMARC1")

def printSpfOutput():
    # Print SPF TXT record information.
    print("")
    print("SPF DNS RECORD ("+parent_domain_name+")")
    print("Record type: TXT")
    if ("" == subdomain_name):
        print("Host name:   @")
    else:
        print("Host name:   "+subdomain_name[1:])
    print("Value:       v=spf1", end = '')
    print(spf_servers+" ~all")

def printDkimOutput():
    # Print DKIM TXT record information.
    print("")
    print("DKIM DNS RECORD ("+parent_domain_name+")")
    print("Record type: TXT")
    if ("" == subdomain_name):
        print("Host name:   "+dkim_selector+"._domainkey")
    else:
        print("Host name:   "+dkim_selector+"._domainkey"+subdomain_name)
    print("Value:       v=DKIM1; k=rsa; p=", end = '')
    if(domain_is_used_for_email):
        print("ReplaceThisTextWithYourPublicKey", end = '')
    print("")

if __name__ == "__main__":
    main()