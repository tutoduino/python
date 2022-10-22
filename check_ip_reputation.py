#!/usr/bin/python3
# -*- coding: utf8 -*-
#
import ipaddress
import shodan
import requests
import json
import argparse
import os
from dotenv import load_dotenv


class IpAddressCheckReputation(object):
    """
    A class used to check reputation of an IP V4 address
    Based on results from Shodan, VirusTotal and IpQualityScore
    """

    def __init__(self, ip):
        if ip is None:
            raise ValueError(
                "IpAddress constructor must be called with an IP V4 address as argument")
        self.ip = ip

        # Connect to Shodan API
        try:
            self.shodan_api = shodan.Shodan(os.getenv("SHODAN_API_KEY"))
        except shodan.APIError as e:
            print('Shodan error: {}'.format(e.value))

    def virustotal_stats(self):
        try:
            url = "https://www.virustotal.com/api/v3/ip_addresses/" + \
                format(self.ip)
            headers = {
                "accept": "application/json",
                "x-apikey": os.getenv("VIRUS_TOTAL_KEY")
            }
            response = requests.get(url, headers=headers)
            res = json.loads(response.text)
            nb_malicious = res["data"]["attributes"]["last_analysis_stats"]["malicious"]
            nb_suspicious = res["data"]["attributes"]["last_analysis_stats"]["suspicious"]
            reputation = res["data"]["attributes"]["reputation"]
        except:
            print('Error while retreiving data from VirusTotal')
            return 0, 0

        return reputation, nb_malicious+nb_suspicious

    def ip_quality_score_stats(self):
        try:
            url = "https://ipqualityscore.com/api/json/ip/" + \
                os.getenv("IPQS-KEY")+"?ip="+format(self.ip)
            response = requests.get(url)
            res = json.loads(response.text)
            fraud_score = res["fraud_score"]
        except:
            print('Error while retreiving data from IpQualityScore')
            return 0

        return fraud_score

    def nb_of_open_ports(self):
        try:
            host = self.shodan_api.host(format(self.ip))
        except shodan.APIError as e:
            print('Shodan error: {}'.format(e.value))
            return 0
        return len(host['data'])


def checkArgs():
    # Parse the arguments to get IP address
    parser = argparse.ArgumentParser(
        description='IP reputation check.')
    parser.add_argument("ip", help="e.g. 192.168.1.235")
    args = parser.parse_args()
    # check the validity of CIDR
    ip_addr = args.ip.split(".")
    if len(ip_addr) != 4:
        print("Incorrect IP address")
        exit()
    if ((not 0 <= int(ip_addr[0]) <= 255)
        or (not 0 <= int(ip_addr[1]) <= 255)
            or (not 0 <= int(ip_addr[2]) <= 255)
            or (not 0 <= int(ip_addr[3]) <= 255)):
        print("Incorrect IP address")
        exit()

    return args.ip


def main():
    ip_arg = checkArgs()
    load_dotenv()
    ip_address_to_check = ipaddress.IPv4Address(ip_arg)
    ip_address_info = IpAddressCheckReputation(ip_address_to_check)
    print("{}".format(ip_address_to_check))
    if ip_address_to_check.is_private:
        print("Private IP address")
    else:
        print("Public IP address")
        print("Shodan           -> number of open ports: {} ".format(
            ip_address_info.nb_of_open_ports()))
        vt_stats = ip_address_info.virustotal_stats()
        print(
            "VirusTotal       -> Number of reports saying it is malicious/suspicious: {}".format(vt_stats[1]))
        print(
            "VirusTotal       -> reputation(-100..100): {}".format(vt_stats[0]))
        ip_qual_stats = ip_address_info.ip_quality_score_stats()
        print(
            "IpQualityScore   -> fraud score(0..100): {}".format(ip_qual_stats))


if __name__ == '__main__':
    main()
