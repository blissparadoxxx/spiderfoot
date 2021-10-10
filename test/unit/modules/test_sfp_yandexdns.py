# test_sfp_yandexdns.py
import pytest
import unittest

from modules.sfp_yandexdns import sfp_yandexdns
from sflib import SpiderFoot
from spiderfoot import SpiderFootEvent, SpiderFootTarget


@pytest.mark.usefixtures
class TestModuleyandexdns(unittest.TestCase):
    """
    Test modules.sfp_yandexdns
    """

    def test_opts(self):
        module = sfp_yandexdns()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        """
        Test setup(self, sfc, userOpts=dict())
        """
        sf = SpiderFoot(self.default_options)

        module = sfp_yandexdns()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_yandexdns()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_yandexdns()
        self.assertIsInstance(module.producedEvents(), list)

    def test_handleEvent_event_data_safe_internet_name_not_blocked_should_not_return_event(self):
        sf = SpiderFoot(self.default_options)

        module = sfp_yandexdns()
        module.setup(sf, dict())

        target_value = 'spiderfoot.net'
        target_type = 'INTERNET_NAME'
        target = SpiderFootTarget(target_value, target_type)
        module.setTarget(target)

        def new_notifyListeners(self, event):
            raise Exception(f"Raised event {event.eventType}: {event.data}")

        module.notifyListeners = new_notifyListeners.__get__(module, sfp_yandexdns)

        event_type = 'ROOT'
        event_data = 'example data'
        event_module = ''
        source_event = ''
        evt = SpiderFootEvent(event_type, event_data, event_module, source_event)

        event_type = 'INTERNET_NAME'
        event_data = 'yandex.com'
        event_module = 'example module'
        source_event = evt

        evt = SpiderFootEvent(event_type, event_data, event_module, source_event)
        result = module.handleEvent(evt)

        self.assertIsNone(result)

    def test_handleEvent_event_data_adult_internet_name_blocked_should_return_event(self):
        sf = SpiderFoot(self.default_options)

        module = sfp_yandexdns()
        module.setup(sf, dict())

        target_value = 'spiderfoot.net'
        target_type = 'INTERNET_NAME'
        target = SpiderFootTarget(target_value, target_type)
        module.setTarget(target)

        def new_notifyListeners(self, event):
            expected = 'MALICIOUS_INTERNET_NAME'
            if str(event.eventType) != expected:
                raise Exception(f"{event.eventType} != {expected}")

            expected = 'Yandex - Adult [pornhub.com]'
            if str(event.data) != expected:
                raise Exception(f"{event.data} != {expected}")

            raise Exception("OK")

        module.notifyListeners = new_notifyListeners.__get__(module, sfp_yandexdns)

        event_type = 'ROOT'
        event_data = 'example data'
        event_module = ''
        source_event = ''
        evt = SpiderFootEvent(event_type, event_data, event_module, source_event)

        event_type = 'INTERNET_NAME'
        event_data = 'pornhub.com'
        event_module = 'example module'
        source_event = evt

        evt = SpiderFootEvent(event_type, event_data, event_module, source_event)

        with self.assertRaises(Exception) as cm:
            module.handleEvent(evt)

        self.assertEqual("OK", str(cm.exception))
