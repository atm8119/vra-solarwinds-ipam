"""
Copyright (c) 2020 Aleksandr Istomin, https://as.zabedu.ru

This product is licensed to you under the Apache License, Version 2.0 (the "License").
You may not use this product except in compliance with the License.

This product may include a number of subcomponents with separate copyright notices
and license terms. Your use of these subcomponents is subject to the terms and
conditions of the subcomponent's license, as noted in the LICENSE file.
"""

import json
import logging
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from orionsdk import SwisClient
from vra_ipam_utils.ipam import IPAM


def handler(context, inputs):
    """
    Create IPAM object and start allocation function
    """
    ipam = IPAM(context, inputs)
    IPAM.do_get_ip_ranges = do_get_ip_ranges
    return ipam.get_ip_ranges()


def do_get_ip_ranges(self, auth_credentials, _):
    """
    Main function.
    Get inputs,
    create connection with IPAM server,
    execute operation and
    prepare results
    """
    username = auth_credentials["privateKeyId"]
    password = auth_credentials["privateKey"]
    ignore_ssl_warning = self.inputs["endpoint"]["endpointProperties"] \
                                  ["ignoreSslWarning"].lower() == "true"
    if ignore_ssl_warning:
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    swis = SwisClient(self.inputs["endpoint"]["endpointProperties"] \
                                 ["hostName"], username, password)
    page_token = self.inputs['pagingAndSorting'].get('pageToken', None)
    max_results = self.inputs['pagingAndSorting'].get('maxResults', 25)

    dns_servers = get_input_property(self.inputs, "SolarWinds.dnsServers")
    dns_domain = get_input_property(self.inputs, "SolarWinds.dnsDomain")

    ranges, next_page_token = collect_ranges(swis, page_token, max_results, \
                                             dns_servers, dns_domain)

    result = {
        "ipRanges": ranges
    }
    if next_page_token is not None:
        result["nextPageToken"] = next_page_token
    return result


def collect_ranges(swis, page_token, max_results, dns_servers, dns_domain):
    """
    Get paginator,
    get networks with parameters,
    create array of network objects
    """
    logging.info("Start collecting ranges list")
    paginator, next_page_token = get_paginator(swis, page_token, max_results)
    if paginator != "":
        logging.info("Request sent with paginator:%s", paginator)
        #query = """SELECT
        #              G.Address, G.SubnetID, G.CIDR, G.Location, GA.VRF,
        #              G.Comments, G.VLAN, GA.Tags, G.FriendlyName
        #           FROM IPAM.GroupReport AS G
        #           INNER JOIN IPAM.GroupsCustomProperties AS GA
        #              ON G.GroupID=GA.GroupID
        #           WHERE G.GroupType='8' and GA.Tags like '%VRA%'
        #           ORDER BY G.VLAN
        #        """
        query = """SELECT
                      Address, SubnetID, CIDR, Location,
                      Comments, VLAN, FriendlyName
                   FROM IPAM.GroupReport
                   WHERE GroupType='8' ORDER BY VLAN
                """
        response = swis.query(query + paginator)

    result = []
    if paginator != "" and len(response["results"]) > 0:
        for subnet in response["results"]:
            CIDR = int(subnet["CIDR"])
            network_id = "network/%d:%s/%d/%s" % \
                (subnet["SubnetID"], subnet["Address"], subnet["CIDR"], subnet["FriendlyName"])
            sanitized_cidr_ip = ip_sanitizer(subnet["Address"], CIDR)
            net_range = {
                "id": network_id,
                "name": subnet["FriendlyName"],
                "startIPAddress": get_first_usable_ip(sanitized_cidr_ip, CIDR),
                "endIPAddress": get_last_usable_ip(sanitized_cidr_ip, CIDR),
                "description": subnet["Comments"],
                "ipVersion": "IPv4",
                "addressSpaceId": "default",
                "subnetPrefixLength": subnet["CIDR"],
                "gatewayAddress": get_gateway_ip(sanitized_cidr_ip, CIDR),
                "domain": dns_domain,
                "dnsServerAddresses": [dns_servers],
                "dnsSearchDomains": [dns_domain],
                "tags": [
                #{
                #    "key": "vlan",
                #    "value": subnet["VLAN"]
                #},{
                #    "key": "location",
                #    "value": subnet["Location"]
                #}
                ],
                "properties": {
                }
            }
            result.append(net_range)
    return result, next_page_token

def ip_sanitizer(proposed_cidr_ip_address, CIDR):
    ip_parts = proposed_cidr_ip_address.split(".")

    farRightOctet = int(ip_parts[3])
    midRightOctet = int(ip_parts[2])
    midLeftOctet = int(ip_parts[1])
    farLeftOctet = int(ip_parts[0])

    difBits = (32 - CIDR) % 8 # "count of bits considered in left-most unfixed octet"
    referenceBase = 2 ** difBits   # "multiple that octet will need to align to"

    # First Octet [rightmost] should be multiple of referenceBase"
    if CIDR <= 30 and CIDR > 24:
        ip_parts[3] = str(farRightOctet - (farRightOctet % referenceBase))
    # Second Octet should be multiple of referenceBase"
    elif CIDR <= 24 and CIDR > 16:
        ip_parts[3] = "0"
        ip_parts[2] = str(midRightOctet - (midRightOctet % referenceBase))
    # Third Octet should be multiple of referenceBase"
    elif CIDR <= 16 and CIDR > 8:
        ip_parts[3] = "0"
        ip_parts[2] = "0"
        ip_parts[1] = str(midLeftOctet - (midLeftOctet % referenceBase))
    # Fourth Octet should be multiple of referenceBase"
    elif CIDR <= 8:
        ip_parts[3] = "0"
        ip_parts[2] = "0"
        ip_parts[1] = "0"
        ip_parts[0] = str(farLeftOctet - (farLeftOctet % referenceBase))
    else:
        raise ValueError("CIDR Block of size "+str(CIDR)+" is not valid.")

    return ".".join(ip_parts)

def get_gateway_ip(ip_address, CIDR):
    # """
    # Calculates the gateway IP address.
    #
    # ASSUMPTION:
    # Assignment of IP uses convention that the rightmost octet will reserve ".1" as Gateway IP.
    # """
    ip_parts = ip_address.split(".")

    # First octet [rightmost] incremented from start IP value to standard gateway value by adding '1'  (cidr: /24, /25, /26, ..)
    if CIDR <= 30 and CIDR > 24:
        return ".".join(ip_parts[:3] + [str(int(ip_parts[3]) + 1)])
    # Second Octet remains unchanged to match start IP - First Octet set to 0 then incremented to '1' (cidr: /23, /22, .. /16)
    elif CIDR <= 24 and CIDR > 16:
        return ".".join(ip_parts[:2] + [ip_parts[2]] + ["1"])
    # Third Octet remains unchanged to match start IP - First and Second set to 0.0 then incremented by '1' (ie. /15, /14, .. /8)
    elif CIDR <= 16 and CIDR > 8:
        return ".".join(ip_parts[:1] + [ip_parts[1]] + ["0.1"])
    # Fourth Octet remains unchanged to match start IP - First, Second, Third set to 0.0.0 then incremented by '1' (ie. /15, /14, .. /8) [leftmost] (ie. /7, /6, .. /0)
    elif CIDR <= 8:
        return ".".join(ip_parts[0] + ["0.0.1"])
    else:
        raise ValueError("CIDR Block of size "+str(CIDR)+" is not valid.")

def get_first_usable_ip(ip_address, CIDR):
    # """
    # Calculates the first USABLE IP address
    # Assumes through convention that the final octet will reserve ".0" as Network IP and ".1" as Gateway IP.
    # """
    ip_parts = ip_address.split(".")

    # First octet [rightmost] incremented from start IP value to usable value by adding '2'  (cidr: /24, /25, /26, ..)
    if CIDR <= 30 and CIDR > 24:
        return ".".join(ip_parts[:3] + [str(int(ip_parts[3]) + 2)])
    # Second Octet remains unchanged to match start IP - First Octet set to 0 then incremented to '2' (cidr: /23, /22, .. /16)
    elif CIDR <= 24 and CIDR > 16:
        return ".".join(ip_parts[:3] + [ip_parts[2]] + ["2"])
    # Third Octet remains unchanged to match start IP - First and Second set to 0.0 then incremented by '2' (ie. /15, /14, .. /8)
    elif CIDR <= 16 and CIDR > 8:
        return ".".join(ip_parts[:1] + [ip_parts[1]] + ["0.2"])
    # Fourth Octet remains unchanged to match start IP - First, Second, Third set to 0.0.0 then incremented by '2' (ie. /15, /14, .. /8) [leftmost] (ie. /7, /6, .. /0)
    elif CIDR <= 8:
        return ".".join(ip_parts[0] + ["0.0.2"])
    else:
        raise ValueError("CIDR Block of size "+str(CIDR)+" is not valid.")

def get_last_usable_ip(ip_address, CIDR):
    # """
    # Calculates the last USABLE IP address
    # Assumes through convention that the final octet will be 254. Where 255 is reserved as the broadcast IP.
    # """
    ip_parts = ip_address.split(".")

    difBits = (32 - CIDR) % 8 # "count of bits considered in left-most unfixed octet"
    difValue = 2 ** difBits - 1 # "decimal delta for left-most unfixed octet"

    # "First Octet adjustment [rightmost] (ie. /24, /25, /26, ..)"
    if CIDR > 24:
        return ".".join(ip_parts[:3] + [str(int(ip_parts[3]) + difValue)])
    # "Second Octet adjustment (ie. /23, /22, .. /16)"
    elif CIDR <= 24 and CIDR > 16:
        return ".".join(ip_parts[:2] + [str(int(ip_parts[2]) + difValue)] + ["254"])
    # "Third Octet adjustment (ie. /15, /14, .. /8)"
    elif CIDR <= 16 and CIDR > 8 :
        return ".".join(ip_parts[:1] + [str(int(ip_parts[1]) + difValue)] + ["255.254"])
    # "Fourth Octet adjustment [leftmost] (ie. /7, /6, .. /0)"
    else: # "CIDR <= 8"
        return ".".join([str(int(ip_parts[0]) + difValue)] + ["255.255.254"])


# def get_next_ip(ip_address, step):
#     """
#     Calculates the IP address
#     through 'step' from the initial address
#        get_next_ip("192.168.1.16", 4) -> "192.168.1.20"
#     """
#     ip_parts = ip_address.split(".")
#     return ".".join(ip_parts[:3] + [str(int(ip_parts[3]) + step)])

def get_paginator(swis, page_token, max_result):
    """
    Create paginator string.
    Get total number of networks and
    create paginator string:
        'WITH ROWS 1 TO 50'
    """
    #query = """SELECT COUNT(*) AS Nets
    #           FROM IPAM.GroupReport AS G
    #           INNER JOIN IPAM.GroupsCustomProperties AS GA
    #              ON G.GroupID=GA.GroupID
    #           WHERE G.GroupType='8' and GA.Tags like '%VRA%'
    #        """
    query = """SELECT COUNT(*) AS Nets
               FROM IPAM.GroupReport
               WHERE GroupType='8'
            """
    response = swis.query(query)
    row_count = response["results"][0]["Nets"]

    if page_token is None:
        page_number = 1
    else:
        page_number = int(page_token)
    row_start = (page_number - 1) * max_result + 1
    row_end = page_number * max_result
    if row_count < row_start:
        page = ""
        next_page_token = None
    elif row_count < row_end:
        row_end = row_count
        page = " WITH ROWS " + str(row_start) + " TO " + str(row_end)
        next_page_token = None
    else:
        page = " WITH ROWS " + str(row_start) + " TO " + str(row_end)
        next_page_token = str(page_number + 1)

    return page, next_page_token


def get_input_property(inputs, prop_key):
    """
    Get additional property from endpoint form
    """
    properties_list = inputs["endpoint"] \
                            ["endpointProperties"].get("properties", [])
    properties_list = json.loads(properties_list)
    for prop in properties_list:
        if prop.get("prop_key") == prop_key:
            logging.info("Read property: %s = %s", prop_key, prop.get("prop_value"))
            return prop.get("prop_value")
    return None
