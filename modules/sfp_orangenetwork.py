# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_orange_network
# Purpose:     Check the location of a phone number.
#
# Author:      stefan@izdrail.com
#
# Created:     06/09/2018
# Copyright:   (c) Stefan Bogdanel, 2024
# Licence:     MIT
# -------------------------------------------------------------------------------

import json
import urllib.error
import urllib.parse
import urllib.request
import requests

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_orangenetwork(SpiderFootPlugin):

    meta = {
        'name': "Orange Network Location",
        'summary': "Checks for a phone number location.",
        'flags': ["token"],
        'useCases': ["Passive", "Investigate"],
        'categories': ["Secondary Networks"],
        'dataSource': {
            'website': "https://networkapi.developer.orange.com/",
            'model': "FREE_AUTH",
            'references': [
                "https://developer.orange.com/products/network-apis/",
            ],
            'apiKeyInstructions': [
                "Visit https://developer.orange.com/products/network-apis/",
                "Register a new account with an email",
                "The API Key is listed under 'Keys'"
            ],
            'favIcon': "https://izdrail.com/assets/logo.svg",
            'logo': "https://izdrail.com/assets/logo.svg",
            'description': "Orange Network is a project dedicated to helping combat the spread of hackers,"
                           "spammers, and abusive activity on the internet.\n"
                           "Our mission is to help make the Web safer by providing a central blacklist for"
                           "webmasters, system administrators, and other interested parties to"
                           "report and find phone numbers that have been associated with malicious activity online."
        }
    }

    opts = {
        'token': '',
        'client_id': '',
        'client_secret': '',
        'your_correlator': "your_correlator",
    }

    optdescs = {
        'token': "Dev Orange.com Token.",
        'client_id': "Client ID for Orange API.",
        'client_secret': "Client Secret for Orange API.",
        'x-correlator': "your_correlator value",
    }

    results = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return [
            "PHONE_NUMBER",
        ]

    def producedEvents(self):
        return [
            "ORANGE_NETWORK_LOCATION",
        ]

    def get_access_token(self):
        """Retrieve access token from Orange API."""
        token_url = 'https://api.orange.com/oauth/v3/token'
        payload = {
            'grant_type': 'client_credentials',
            'client_id': self.opts['client_id'],
            'client_secret': self.opts['client_secret'],
        }
        response = requests.post(token_url, data=payload)
        response_data = response.json()
        print(response_data)
        return response_data.get('access_token')

    def call_api(self, phone_number, access_token):
        """Call the Orange API with the access token and phone number."""
        api_url = 'https://api.orange.com/camara/location-retrieval/orange-lab/v0/retrieve'
        headers = {
            'Authorization': f'Bearer {access_token}',

        }
        data = {
            "device": {
                "phoneNumber": phone_number,
                "networkAccessIdentifier": phone_number + "@domain.com",
            },
            "area": {
                "areaType": "CIRCLE",
                "center": {
                    "latitude": 50.735851,
                    "longitude": 7.10066
                },
                "radius": 50000
            },
            "maxAge": 60
        }
        response = requests.post(api_url, headers=headers, json=data)
        return response.json()

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if not self.opts["client_id"] or not self.opts["client_secret"]:
            self.error(
                f"You enabled {self.__class__.__name__} but did not set an API client ID or client secret!"
            )
            self.errorState = True
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        if eventName != "PHONE_NUMBER":
            self.debug(f"Unexpected event type {eventName}, skipping")
            return

        # Retrieve access token
        access_token = self.get_access_token()
        if not access_token:
            self.error("Failed to retrieve access token from Orange API.")
            return

        # Call the API
        api_response = self.call_api(eventData, access_token)
        if not api_response:
            self.error("Failed to retrieve data from Orange API.")
            return

        self.info(f"Received location data for phone number {eventData}")
        print(api_response)
        # Emit an event with the location data
        evt = SpiderFootEvent(
            "ORANGE_NETWORK_LOCATION",
            json.dumps(api_response, indent=4),
            self.__class__.__name__,
            event
        )
        self.notifyListeners(evt)
