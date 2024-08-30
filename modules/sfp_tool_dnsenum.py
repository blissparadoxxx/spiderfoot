# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_tool_dnsenum
# Purpose:      SpiderFoot plug-in for using dnsenum to find subdomains and nameservers.
#
# Author:      Trent Tanchin <trent@tanchin.org>
#
# Created:     2024-08-29
# Copyright:   (c) Trent Tanchin
# Licence:     MIT
# -------------------------------------------------------------------------------

import os.path
import re
from enum import Enum
from subprocess import PIPE, Popen

from netaddr import IPNetwork

from spiderfoot import SpiderFootEvent, SpiderFootPlugin

class sections(Enum):
    NONE = -1
    HOST_ADDRS = 0
    NAME_SERVERS = 1
    MAIL_SERVERS = 2
    ZONE_TRANSFERS = 3
    BRUTE_FORCE = 4
    CLASS_C_NETRANGES = 5
    REVERSE_LOOKUP = 6

class sfp_tool_dnsenum(SpiderFootPlugin):
    # The module descriptor dictionary contains all the meta data about a module necessary
    # for users to understand...
    meta = {
        # Module name: A very short but human readable name for the module.
        'name': "Tool - dnsenum",

        # Description: A sentence briefly describing the module.
        'summary': "Identify subdomains and nameservers.",

        # Flags: Attributes about this module:
        #   - apikey: Needs an API key to function
        #   - slow: Can be slow to find information
        #   - errorprone: Might generate high false positives
        #   - invasive: Interrogates the target, might be intensive
        #   - tool: Runs an external tool to collect data
        'flags': ["slow", "invasive", "tool"],

        # Use cases: The use case(s) this module should be included in, options are Footprint, Investigate and Passive.
        #   - Passive means the user's scan target is not contacted at all
        #   - Footprint means that this module is useful when understanding the target's footprint on the Internet
        #   - Investigate means that this module is useful when investigating the danger/risk of a target
        'useCases': ["Footprint", "Investigate"],

        # Categories: The categories this module belongs in, describing how it operates. Only the first category is
        # used for now.
        #   - Content Analysis: Analyses content found
        #   - Crawling and Scanning: Performs crawling or scanning of the target
        #   - DNS: Queries DNS
        #   - Leaks, Dumps and Breaches: Queries data dumps and breaches
        #   - Passive DNS: Analyses passive DNS sources
        #   - Public Registries: Queries open/public registries of information
        #   - Real World: Queries sources about the real world (addresses, names, etc.)
        #   - Reputation Systems: Queries systems that describe the reputation of other systems
        #   - Search Engines: Searches public search engines with data about the whole Internet
        #   - Secondary Networks: Queries information about participation on secondary networks, like Bitcoin
        #   - Social Media: Searches social media data sources
        'categories': ["DNS"],

        # For tool modules, have some basic information about the tool.
        'toolDetails': {
            # The name of the tool
            'name': "dnsenum",

            # Descriptive text about the tool
            'description': "dnsenum -- multithread script to enumerate information on a domain and to discover non-contiguous IP blocks",

            # The website URL for the tool. In many cases this will also be the
            # repo, but no harm in duplicating it.
            'website': 'https://github.com/SparrowOchon/dnsenum2',

            # The repo where the code of the tool lives.
            'repository': 'https://github.com/SparrowOchon/dnsenum2'
        }
    }

    # Default options. Delete any options not applicable to this module. Descriptions for each option
    # are defined in optdescs below. Options won't show up in the UI if they don't have an entry in
    # optdescs. This can be useful when you want something configured in code but not by the user.
    #
    # Note that these are just dictionary entries. The logic for how you react to these settings
    # is entirely for you to define AND IMPLEMENT in this module - nothing comes for free! :)
    #
    # Look at other modules for examples for how these settings are handled and implemented.
    #
    opts = {
        'dnsenumpath': "",
        'verify': True,
        'threads': f"{os.cpu_count()}",
        'exclude': ""
    }

    # Option descriptions. Delete any options not applicable to this module.
    optdescs = {
        'dnsenumpath': 'Path to dnsenum tool.',
        'verify': 'Verify that any hostnames found on the target domain still resolve?',
        'threads': 'The number of threads that will perform different queries.',
        'exclude': 'Exclude PTR records that match the regexp expression from reverse lookup results, useful on invalid hostnames.'
    }

    # Tracking results can be helpful to avoid reporting/processing duplicates
    results = None

    # Tracking the error state of the module can be useful to detect when a third party
    # has failed and you don't wish to process any more events.
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        # self.tempStorage() basically returns a dict(), but we use self.tempStorage()
        # instead since on SpiderFoot HX, different mechanisms are used to persist
        # data for load distribution, avoiding excess memory consumption and fault
        # tolerance. This keeps modules transparently compatible with both versions.
        self.results = self.tempStorage()

        # Clear / reset any other class member variables here
        # or you risk them persisting between threads.

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    # For a list of all events, check spiderfoot/db.py.
    def watchedEvents(self):
        return ["DOMAIN_NAME"]

    # What events this module produces
    def producedEvents(self):
        return [
            'PROVIDER_DNS',
            'PROVIDER_MAIL',
            'IP_ADDRESS',
            'INTERNET_NAME',
            'INTERNET_NAME_UNRESOLVED',
            'AFFILIATE_INTERNET_NAME',
            'AFFILIATE_INTERNET_NAME_UNRESOLVED',
            'AFFILIATE_IPADDR',
            'NETBLOCK_MEMBER'
        ]

    # Handle events sent to this module
    def handleEvent(self, event):
        # The three most used fields in SpiderFootEvent are:
        # event.eventType - the event type, e.g. INTERNET_NAME, IP_ADDRESS, etc.
        # event.module - the name of the module that generated the event, e.g. sfp_dnsresolve
        # event.data - the actual data, e.g. 127.0.0.1. This can sometimes be megabytes in size (e.g. a PDF)
        eventName = event.eventType
        eventData = event.data

        # Once we are in this state, return immediately.
        if self.errorState:
            return

        # Check if the module has already analysed this event data.
        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        # Add the event data to results dictionary to prevent duplicate queries.
        # If eventData might be something large, set the key to a hash
        # of the value instead of the value, to avoid memory abuse.
        self.results[eventData] = True

        self.debug(f"Received event, {eventName}, from {event.module}")

        if not self.opts['dnsenumpath']:
            self.error("You enabled sfp_tool_dnsenum but did not set a path to the tool!")
            self.errorState = True
            return

        # Normalize path
        if self.opts['dnsenumpath'].endswith('dnsenum'):
            exe = self.opts['dnsenumpath']
        elif self.opts['dnsenumpath'].endswith('/'):
            exe = self.opts['dnsenumpath'] + "dnsenum"
        else:
            self.error("Could not recognize your dnsenum path configuration.")
            self.errorState = True
            return

        # If tool is not found, abort
        if not os.path.isfile(exe):
            self.error("File does not exist: " + exe)
            self.errorState = True
            return

        if not self.sf.isDomain(eventData, self.opts["_internettlds"]) and not self.sf.validIpNetwork(eventData):
            self.error("Invalid input, refusing to run.")
            return

        # Create the tool cmd line
        args = [exe]
        if self.opts.get("_dnsserver", "") != "":
            args.append("--dnsserver")
            args.append(self.opts["_dnsserver"])

        if self.opts.get("exclude", "") != "":
            args.append("-e")
            args.append(self.opts["exclude"])

        args.append("--nocolor")
        args.append("-t")
        args.append(f"{self.opts['_fetchtimeout']}")
        args.append("--threads")
        args.append(self.opts["threads"])
        args.append(eventData)

        try:
            p = Popen(args, stdout=PIPE, stderr=PIPE)
            stdout, stderr = p.communicate(input=None)
            if p.returncode == 0:
                content = stdout.decode('utf-8', errors='replace')
            else:
                self.error("Unable to read dnsenum content.")
                self.debug(f"Error running dnsenum: {stderr}, {stdout}")
                return
        except Exception as e:
            self.error(f"Unable to run dnsenum: {e}")
            return

        section = sections.NONE
        # Parse output
        for line in content.split('\n'):
            if "Host's addresses:" in line:
                section = sections.HOST_ADDRS
                continue
            if "Name Servers:" in line:
                section = sections.NAME_SERVERS
                continue
            if "Mail (MX) Servers:" in line:
                section = sections.MAIL_SERVERS
                continue
            if "Trying Zone Transfers and getting Bind Versions:" in line:
                section = sections.ZONE_TRANSFERS
                continue
            if "Brute forcing" in line and ":" in line:
                section = sections.BRUTE_FORCE
                continue
            if "class C netranges:" in line:
                section = sections.CLASS_C_NETRANGES
                continue
            if "Performing reverse lookup on" in line and "ip addresses:" in line:
                section = sections.REVERSE_LOOKUP
                continue

            if section == sections.HOST_ADDRS and eventData in line:
                ipevent = SpiderFootEvent("IP_ADDRESS", line.split()[4], self.__name__, event)
                self.notifyListeners(ipevent)
                continue

            pattern = re.compile(r'(\S+)\s+\d+\s+(\S+)\s+(\S+)\s+(.+)')
            if section == section.NAME_SERVERS and line.strip() and pattern.match(line):
                match = pattern.match(line)
                ns = match.group(1).strip(".")
                ipaddr = match.group(4)
                nsevent = SpiderFootEvent("PROVIDER_DNS", ns, self.__name__, event)
                self.notifyListeners(nsevent)
                if self.sf.hostDomain(ns, self.opts["_internettlds"]) == eventData:
                    eventType = "IP_ADDRESS"
                else:
                    eventType = "AFFILIATE_IPADDR"
                ipevent = SpiderFootEvent(eventType, ipaddr, self.__name__, event)
                self.notifyListeners(ipevent)
                continue

            if section == sections.MAIL_SERVERS and line.strip() and pattern.match(line):
                match = pattern.match(line)
                ms = match.group(1).strip(".")
                ipaddr = match.group(4)
                msevent = SpiderFootEvent("PROVIDER_MAIL", ms, self.__name__, event)
                self.notifyListeners(msevent)
                if self.sf.hostDomain(ms, self.opts["_internettlds"]) == eventData:
                    eventType = "IP_ADDRESS"
                else:
                    eventType = "AFFILIATE_IPADDR"
                ipevent = SpiderFootEvent(eventType, ipaddr, self.__name__, event)
                self.notifyListeners(ipevent)
                continue

            if section == section.BRUTE_FORCE and line.strip() and pattern.match(line):
                match = pattern.match(line)
                name = match.group(1).strip(".")
                addr = match.group(4)
                if self.sf.hostDomain(name, self.opts["_internettlds"]) == eventData:
                    nameeventType = "INTERNET_NAME"
                else:
                    nameeventType = "AFFILIATE_INTERNET_NAME"
                if self.opts['verify'] and not self.sf.resolveHost(name) and not self.sf.resolveHost6(name):
                    self.debug(f"Host {name} could not be resolved")
                    nameeventType += '_UNRESOLVED'

                if self.sf.validIP(addr):
                    addreventType = "AFFILIATE_IP_ADDRESS"
                elif self.sf.hostDomain(addr.strip("."), self.opts["_internettlds"]) == eventData:
                    addr = addr.strip(".")
                    addreventType = "INTERNET_NAME"
                else:
                    addr = addr.strip(".")
                    addreventType = "AFFILIATE_INTERNET_NAME"
                if self.opts['verify'] and "INTERNET_NAME" in addreventType and not self.sf.resolveHost(addr) and not self.sf.resolveHost6(addr):
                    self.debug(f"Host {addr} could not be resolved")
                    addreventType += '_UNRESOLVED'

                nameevent = SpiderFootEvent(nameeventType, name, self.__name__, event)
                ipevent = SpiderFootEvent(addreventType, addr, self.__name__, event)
                self.notifyListeners(nameevent)
                self.notifyListeners(ipevent)
                continue

            if section == sections.CLASS_C_NETRANGES and "/" in line:
                netrangeevent = SpiderFootEvent("NETBLOCK_MEMBER", line.strip(), self.__name__, event)
                self.notifyListeners(netrangeevent)

            if section == sections.REVERSE_LOOKUP and pattern.match(line):
                match = pattern.match(line)
                name = match.group(1).strip(".")
                addr = match.group(4).strip(".")
                if self.sf.hostDomain(name, self.opts["_internettlds"]) == eventData:
                    nameeventType = "INTERNET_NAME"
                else:
                    nameeventType = "AFFILIATE_INTERNET_NAME"
                if self.opts['verify'] and not self.sf.resolveHost(name) and not self.sf.resolveHost6(name):
                    self.debug(f"Host {name} could not be resolved")
                    nameeventType += '_UNRESOLVED'


                if self.sf.hostDomain(addr, self.opts["_internettlds"]) == eventData:
                    addreventType = "INTERNET_NAME"
                else:
                    addreventType = "AFFILIATE_INTERNET_NAME"
                if self.opts['verify'] and not self.sf.resolveHost(addr) and not self.sf.resolveHost6(addr):
                    self.debug(f"Host {addr} could not be resolved")
                    addreventType += '_UNRESOLVED'

                nameevent = SpiderFootEvent(nameeventType, name, self.__name__, event)
                self.notifyListeners(nameevent)
                if "(" not in addr:
                    ipevent = SpiderFootEvent(addreventType, addr, self.__name__, event)
                    self.notifyListeners(ipevent)
                continue

# End of sfp_tool_dnsenum class
