# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_emergingthreats
# Purpose:     Checks if an IP address or netblock is malicious according to emergingthreats.net.
#
# Author:      steve@binarypool.com
#
# Created:     16/05/2020
# Copyright:   (c) Steve Micallef, 2020
# Licence:     GPL
# -------------------------------------------------------------------------------

import logging
from netaddr import IPAddress, IPNetwork

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_emergingthreats(SpiderFootPlugin):

    meta = {
        'name': "Emerging Threats",
        'summary': "Check if a netblock or IP is malicious according to emergingthreats.net.",
        'flags': [],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://rules.emergingthreats.net/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://doc.emergingthreats.net/"
            ],
            'favIcon': "",
            'logo': "",
            'description': "Emerging Threats delivers the most timely and accurate threat intelligence.\n"
            "Emerging Threat (ET) intelligence helps prevent attacks and reduce risk by "
            "helping you understand the historical context of where these threats originated, "
            "who is behind them, when have they attacked, what methods they used, and what they're after. "
            "Get on-demand access to current and historical metadata on IPs, domains, "
            "and other related threat intelligence to help research threats and investigate incidents.",
        }
    }

    # Default options
    opts = {
        'checkaffiliates': True,
        'cacheperiod': 18,
        'checknetblocks': True,
        'checksubnets': True
    }

    # Option descriptions
    optdescs = {
        'checkaffiliates': "Apply checks to affiliate IP addresses?",
        'cacheperiod': "Hours to cache list data before re-fetching.",
        'checknetblocks': "Report if any malicious IPs are found within owned netblocks?",
        'checksubnets': "Check if any malicious IPs are found within the same subnet of the target?"
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.log = logging.getLogger(f"spiderfoot.{__name__}")
        self.sf = sfc
        self.results = self.tempStorage()
        self.errorState = False

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["IP_ADDRESS", "AFFILIATE_IPADDR",
                "NETBLOCK_MEMBER", "NETBLOCK_OWNER"]

    # What events this module produces
    def producedEvents(self):
        return ["MALICIOUS_IPADDR", "MALICIOUS_AFFILIATE_IPADDR",
                "MALICIOUS_SUBNET", "MALICIOUS_NETBLOCK"]

    def query(self, qry, targetType):
        cid = "_emergingthreats"
        url = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"

        data = dict()
        data["content"] = self.sf.cacheGet("sfmal_" + cid, self.opts.get('cacheperiod', 0))

        if data["content"] is None:
            data = self.sf.fetchUrl(url, timeout=self.opts['_fetchtimeout'], useragent=self.opts['_useragent'])

            if data["code"] != "200":
                self.log.error(f"Unable to fetch {url}")
                self.errorState = True
                return None

            if data["content"] is None:
                self.log.error(f"Unable to fetch {url}")
                self.errorState = True
                return None

            self.sf.cachePut("sfmal_" + cid, data['content'])

        for line in data["content"].split('\n'):
            ip = line.strip().lower()

            if targetType == "netblock":
                try:
                    if IPAddress(ip) in IPNetwork(qry):
                        self.log.debug(f"{ip} found within netblock/subnet {qry} in emergingthreats.net list.")
                        return url
                except Exception as e:
                    self.log.debug(f"Error encountered parsing: {e}")
                    continue

            if targetType == "ip":
                if qry.lower() == ip:
                    self.log.debug(f"{qry} found in emergingthreats.net list.")
                    return url

        return None

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.log.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventData in self.results:
            self.log.debug(f"Skipping {eventData}, already checked.")
            return

        if self.errorState:
            return

        self.results[eventData] = True

        if eventName == 'IP_ADDRESS':
            targetType = 'ip'
            evtType = 'MALICIOUS_IPADDR'
        elif eventName == 'AFFILIATE_IPADDR':
            if not self.opts.get('checkaffiliates', False):
                return
            targetType = 'ip'
            evtType = 'MALICIOUS_AFFILIATE_IPADDR'
        elif eventName == 'NETBLOCK_OWNER':
            if not self.opts.get('checknetblocks', False):
                return
            targetType = 'netblock'
            evtType = 'MALICIOUS_NETBLOCK'
        elif eventName == 'NETBLOCK_MEMBER':
            if not self.opts.get('checksubnets', False):
                return
            targetType = 'netblock'
            evtType = 'MALICIOUS_SUBNET'
        else:
            return

        self.log.debug(f"Checking maliciousness of {eventData} with emergingthreats.net")

        url = self.query(eventData, targetType)

        if not url:
            return

        text = f"emergingthreats.net [{eventData}]\n<SFURL>{url}</SFURL>"
        evt = SpiderFootEvent(evtType, text, self.__name__, event)
        self.notifyListeners(evt)

# End of sfp_emergingthreats class
