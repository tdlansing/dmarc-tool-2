import sys
from DmarcRecord import DmarcRecord

try:
    import dns.resolver
except ModuleNotFoundError:
    print("Error: The 'dnspython' library could not be found. Please install and try again.")
    sys.exit("If using 'pip', this command may help 'sudo pip3 install dnspython'.")


class DomainRecordHandler:
    def __init__(self, domain_name):
        self.domain_name = domain_name
        self.dmarc_record = DmarcRecord()
        self.set_dmarc_record(domain_name)

    @staticmethod
    def get_domain_exists(domain_name):
        try:
            dns.resolver.resolve(domain_name)
            return True
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            return False

    def set_dmarc_record(self, domain_name):
        dmarc_host_name = "_dmarc." + domain_name
        try:
            current_dmarc_dns_record = dns.resolver.resolve(dmarc_host_name, "TXT")
            current_dmarc_record_value = (str(current_dmarc_dns_record[0])).strip('\"')
            current_dmarc_tags = current_dmarc_record_value.split(";")
            for dmarc_tag in current_dmarc_tags:
                split_dmarc_tag = dmarc_tag.split("=")
                if split_dmarc_tag[0].strip() == 'v':
                    self.dmarc_record.v = split_dmarc_tag[1].strip()
                elif split_dmarc_tag[0].strip() == 'p':
                    self.dmarc_record.p = split_dmarc_tag[1].strip()
                elif split_dmarc_tag[0].strip() == 'sp':
                    self.dmarc_record.sp = split_dmarc_tag[1].strip()
                elif split_dmarc_tag[0].strip() == 'adkim':
                    self.dmarc_record.adkim = split_dmarc_tag[1].strip()
                elif split_dmarc_tag[0].strip() == 'aspf':
                    self.dmarc_record.aspf = split_dmarc_tag[1].strip()
                elif split_dmarc_tag[0].strip() == 'pct':
                    self.dmarc_record.pct = split_dmarc_tag[1].strip()
                elif split_dmarc_tag[0].strip() == 'ri':
                    self.dmarc_record.ri = split_dmarc_tag[1].strip()
                elif split_dmarc_tag[0].strip() == 'fo':
                    self.dmarc_record.fo = split_dmarc_tag[1].strip().split(":")
                elif split_dmarc_tag[0].strip() == 'rf':
                    self.dmarc_record.rf = split_dmarc_tag[1].strip()
                elif split_dmarc_tag[0].strip() == 'rua':
                    self.dmarc_record.rua = split_dmarc_tag[1].strip().split(",")
                elif split_dmarc_tag[0].strip() == 'ruf':
                    self.dmarc_record.ruf = split_dmarc_tag[1].strip().split(",")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            pass

        def get_dmarc_record():
            return self.dmarc_record
