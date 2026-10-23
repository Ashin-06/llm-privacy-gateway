from privgate.checksums import iban_valid
from privgate.detect import detect


def _types(text):
    return {(e.type, e.value) for e in detect(text)}


def test_iban_mod97():
    assert iban_valid("GB82 WEST 1234 5698 7654 32") and iban_valid("DE89370400440532013000")
    assert not iban_valid("GB82WEST12345698765433")


def test_international_identifiers_with_labels():
    assert ("ACCOUNT", "DE89370400440532013000") in _types("Please pay to IBAN: DE89370400440532013000 today")
    assert ("PHONE", "(123) 456-7890") in _types("Phone: (123) 456-7890")
    assert ("CVV", "624") in _types("Credit Card Security Code: 624")
    assert ("PASSPORT", "W03043789") in _types("Passport Number: W03043789")
    assert ("DOB", "September 16, 1910") in _types("Date of Birth: September 16, 1910")
    assert ("CARD", "2713-1315-3956-8471") in _types("Credit Card Number: 2713-1315-3956-8471")  # fails Luhn, still a card
    assert ("PERSON", "Stefan A. Håkansson") in _types("Dear Stefan A. Håkansson, thank you")


def test_labels_must_be_the_nearest_one():
    # a tracking number after a mention of a card, or an order id after "called", is not a card or a phone
    assert not {t for t, _ in _types("card was charged twice. Tracking no 4111111111111112")} & {"CARD"}
    assert not {t for t, _ in _types("Customer called about order 555-123-4567")} & {"PHONE"}
