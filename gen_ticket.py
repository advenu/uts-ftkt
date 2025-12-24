import hashlib
import json
import random
import string
from datetime import datetime, timedelta

from icecream import ic

from custom_cipher import Json_ECB_Cipher, Secret

ic.disable()


def generate_key(phone_no: str, uts_no: str):
    key_str = f"c{phone_no[:5]}UTS{uts_no[5:10]}{phone_no[5:10]}ri{uts_no[:5]}s71986"
    key = key_str.lower().encode()
    ic(key)
    return key


def generate_uts_no():
    # Define the character pool (letters and digits)
    char_pool = string.ascii_letters + string.digits

    # Generate the uts_no
    uts_no = (
        "X"  # 1st character, 'X' appears frequently
        + "".join(random.choices(char_pool, k=4))  # Characters 2-5
        + "Y"  # 6th character is always 'Y'
        + "".join(random.choices(char_pool, k=4))  # Characters 7-10
    )
    return uts_no


def calc_validity(dt: datetime):
    return (dt + timedelta(days=1)).replace(hour=23, minute=59, second=0)


def create_fake_ticket(
    src: str,
    dst: str,
    via: str,
    dist: int,
    cost: int,
    train_type: str,
    dt: datetime,
    person: int,
):
    # load sample ticket
    with open("ticket.json") as f:
        ticket: dict = json.load(f)

    # update the required fields
    ticket.update(
        {
            "utsno": generate_uts_no().upper(),
            "source": src.upper(),
            "destination": dst.upper(),
            "via": via.upper(),
            "distance": str(dist),
            "cashReceived": f"{cost:.2f}",
            "trainType": train_type.upper(),
            "txnTime": dt.strftime("%d/%m/%Y %H:%M:%S"),
            "adult": str(person),
            "jrnyDate": dt.strftime("%d/%m/%Y"),
            "validUpto": calc_validity(dt).strftime("%d/%m/%Y %H:%M:%S"),
        }
    )

    phone_no = ticket["linkMob"]  # "9091197493"
    uts_no: str = ticket["utsno"]

    key = generate_key(phone_no, uts_no)
    iv = b"0" * 16

    secret = Secret(key, iv)
    cipher = Json_ECB_Cipher(secret)

    cipher_text = cipher.encrypt(ticket, no_colon=True)
    encrypted_text = f"{uts_no[:5].lower()}{cipher_text}#{uts_no[5:].upper()}"

    hash_object = hashlib.sha256(encrypted_text.encode())
    sha256_hash = hash_object.hexdigest()
    ic(sha256_hash)

    enc_ticket = f"{encrypted_text}#{sha256_hash.upper()}"
    ic(enc_ticket)

    return enc_ticket


def read_ticket(ticket_enc_data: str):

    parts = ticket_enc_data.split("#")
    ic(len(parts))

    hash_object = hashlib.sha256("#".join(parts[:2]).encode())
    sha256_hash = hash_object.hexdigest()

    ic(sha256_hash)
    assert sha256_hash == parts[2].lower()

    uts_no_start_part = parts[0][:5]
    uts_no_end_part = parts[1]

    uts_no = uts_no_start_part + uts_no_end_part
    ic(uts_no)

    cipher_text = parts[0][5:]

    phone_no = "9091197493"

    key_str = f"c{phone_no[:5]}UTS{uts_no[5:10]}{phone_no[5:10]}ri{uts_no[:5]}s71986"
    key = key_str.lower().encode()

    iv = b"0" * 16

    secret = Secret(key, iv)
    cipher = Json_ECB_Cipher(secret)

    ticket_data = cipher.decrypt(cipher_text)
    # print(json.dumps(ticket_data, indent=3))

    fields_to_show = {
        "utsno": "UTS No.",
        "source": "Source",
        "destination": "Destination",
        "via": "Via",
        "distance": "Distance",
        "adult": "Adult",
        "trainType": "Train Type",
        "jrnyDate": "Jrny Date",
        "cashReceived": "Cash Received",
        "txnTime": "Txn Time",
        "validUpto": "Valid Upto",
    }

    text = ""
    for key, value in fields_to_show.items():
        text += f"{value}: {ticket_data[key]}\n"

    return text


if __name__ == "__main__":
    ticket_enc_data = create_fake_ticket(
        "BSB", "AME", "---", 200, 70, "O", datetime.now(), 2
    )

    print(read_ticket(ticket_enc_data))
