#!/usr/bin/env python3

import base64
import ctypes
import datetime
import json
import os
import sys

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from fido2.client import _Ctap2ClientAssertionSelection, _Ctap2ClientBackend, _user_keepalive, WindowsClient, UserInteraction
from fido2.ctap import CtapError
from fido2.ctap2 import Ctap2
from fido2.ctap2.pin import ClientPin, PinProtocol
from fido2.hid import CtapHidDevice
from fido2.server import Fido2Server
from fido2.utils import sha256
from fido2.webauthn import AttestationObject, AuthenticatorAttestationResponse, CredentialCreationOptions, UserVerificationRequirement
from getpass import getpass
from threading import Event
from typing import Optional


def err_exit(msg: str, status: int = 1):
    print(msg, file=sys.stderr)
    sys.exit(status)


def usage_exit(msg: str, status: int = 1):
    print(msg, file=sys.stderr)
    print()
    print_usage()
    sys.exit(status)


# Handle user interaction
class CliInteraction(UserInteraction):
    def prompt_up(self):
        print("\nTouch your authenticator device now...\n")

    def request_pin(self, permissions, rd_id):
        return getpass("Enter PIN: ")

    def request_uv(self, permissions, rd_id):
        print("User Verification required.")
        return True


def get_device():
    if WindowsClient.is_available() and not ctypes.windll.shell32.IsUserAnAdmin():
        raise Exception("TODO")
    else:
        # Locate a device
        dev = next(CtapHidDevice.list_devices(), None)
        if dev is not None:
            print("Using USB HID channel.")
        else:
            try:
                from fido2.pcsc import CtapPcscDevice

                dev = next(CtapPcscDevice.list_devices(), None)
                print("Using NFC channel.")
            except Exception as e:
                print("NFC channel search error:", e)

        if not dev:
            err_exit("No FIDO device found.")

        # Can't use ctap1, because minisign only supports EdDSA
        return dev


class RawSignCtap2ClientBackend(_Ctap2ClientBackend):
    def _get_auth_params(
        self, is_make_credential, client_data_hash, rp_id, user_verification, permissions, event, on_keepalive
    ):
        mc = is_make_credential
        self.info = self.ctap2.get_info()  # Make sure we have "fresh" info

        pin_protocol = None
        pin_token = None
        pin_auth = None
        internal_uv = False
        if self._should_use_uv(user_verification, mc) or permissions:
            client_pin = ClientPin(self.ctap2)
            allow_internal_uv = not permissions
            permissions |= (
                ClientPin.PERMISSION.MAKE_CREDENTIAL
                if mc
                else ClientPin.PERMISSION.GET_ASSERTION
            )
            pin_token = self._get_token(
                client_pin, permissions, rp_id, event, on_keepalive, allow_internal_uv
            )
            if pin_token:
                pin_protocol = client_pin.protocol
                pin_auth = client_pin.protocol.authenticate(pin_token, client_data_hash)
            else:
                internal_uv = True
        return pin_protocol, pin_token, pin_auth, internal_uv

    def do_make_credential(
        self,
        client_data,
        rp,
        user,
        key_params,
        user_verification,
    ):
        options = None
        exclude_list = None
        extension_inputs = None
        permissions = ClientPin.PERMISSION(0)
        on_keepalive = _user_keepalive(self.user_interaction)
        client_data_hash = sha256(client_data)
        enterprise_attestation = None
        event = None

        # Handle auth
        pin_protocol, pin_token, pin_auth, internal_uv = self._get_auth_params(
            True, client_data_hash, rp["id"], user_verification, permissions, event, on_keepalive
        )

        att_obj = self.ctap2.make_credential(
            client_data_hash,
            rp,
            user,
            key_params,
            exclude_list or None,
            extension_inputs or None,
            options,
            pin_auth,
            pin_protocol.VERSION if pin_protocol else None,
            enterprise_attestation,
            event=event,
            on_keepalive=on_keepalive,
        )

        return (
            client_data,
            AttestationObject.create(att_obj.fmt, att_obj.auth_data, att_obj.att_stmt),
        )

    def do_get_assertion(
            self,
            client_data,
            rp_id,
            allow_list,
            user_verification,
            user_presence,
    ):
        if allow_list:
            # Filter out credential IDs which are too long
            max_len = self.info.max_cred_id_length
            if max_len:
                allow_list = [e for e in allow_list if len(e) <= max_len]
            if not allow_list:
                raise CtapError(CtapError.ERR.NO_CREDENTIALS)

            # Reject the request if too many credentials remain.
            max_creds = self.info.max_creds_in_list
            if max_creds and len(allow_list) > max_creds:
                raise ClientError.ERR.BAD_REQUEST("allow_list too long")

        extension_inputs = None
        used_extensions = []
        permissions = ClientPin.PERMISSION(0)
        on_keepalive = _user_keepalive(self.user_interaction)
        event = None

        client_data_hash = sha256(client_data)

        pin_protocol, pin_token, pin_auth, internal_uv = self._get_auth_params(
            False, client_data_hash, rp_id, user_verification, permissions, event, on_keepalive
        )
        options = {"up": user_presence}

        assertions = self.ctap2.get_assertions(
            rp_id,
            client_data_hash,
            allow_list or None,
            extension_inputs or None,
            options,
            pin_auth,
            pin_protocol.VERSION if pin_protocol else None,
            event=event,
            on_keepalive=on_keepalive,
        )

        return _Ctap2ClientAssertionSelection(
            client_data,
            assertions,
            used_extensions,
            pin_token,
            pin_protocol,
        )


def get_client():
    dev = get_device()
    return RawSignCtap2ClientBackend(dev, CliInteraction(), [])


def blakehash(data: bytes) -> bytes:
    h = hashes.Hash(hashes.BLAKE2b(64), default_backend())
    h.update(data)
    return h.finalize()


def make_minisig_pubkey(
        signature_algorithm: bytes,
        key_id: bytes,
        pubkey: bytes,
        untrusted_comment: str = "",
):
    return "\n".join([
        f"untrusted comment: {untrusted_comment}",
        base64.b64encode(signature_algorithm + key_id + pubkey).decode('utf-8'),
        ""
    ])


def make_minisig_signature(
        signature_algorithm: bytes,
        key_id: bytes,
        rp_id: str,
        credential_id: bytes,
        file_contents: bytes,
        untrusted_comment: str = "",
        trusted_comment: str = "",
) -> bytes:
    signature_client_data = blakehash(file_contents)
    allow_credentials = [{"type": "public-key", "id": credential_id}]
    client = get_client()

    assertion = client.do_get_assertion(
        signature_client_data,
        rp_id,
        allow_credentials,
        UserVerificationRequirement.DISCOURAGED,
        True,
    ).get_assertions()[0]
    signature = assertion.signature
    auth_data = assertion.auth_data

    global_signature_client_data = signature + trusted_comment.encode('utf-8')
    global_assertion = client.do_get_assertion(
        global_signature_client_data,
        rp_id,
        allow_credentials,
        UserVerificationRequirement.DISCOURAGED,
        False,
    ).get_assertions()[0]
    global_signature = global_assertion.signature
    global_auth_data = global_assertion.auth_data

    return "\n".join([
        f"untrusted comment: {untrusted_comment}",
        base64.b64encode(signature_algorithm + key_id + signature + auth_data).decode('utf-8'),
        f"trusted comment: {trusted_comment}",
        base64.b64encode(global_signature + global_auth_data).decode('utf-8'),
        ""
    ])


def generate_key(
        pubkey_outfile: str,
        prikey_outfile: str,
        rp_id: str,
):
    if os.path.exists(pubkey_outfile):
        err_exit(f"File already exists: {pubkey_outfile}")

    if os.path.exists(prikey_outfile):
        err_exit(f"File already exists: {prikey_outfile}")

    key_id = os.urandom(8)
    key_id_base64 = base64.b64encode(key_id).decode('utf-8')

    client_data = json.dumps({
        "type": "minisign.create",
        "challenge": base64.b64encode(os.urandom(64)).decode('utf-8'),
        "minisign_key_id": key_id_base64,
    }).encode('utf-8')

    rp = {"id": rp_id, "name": ""}  # name is irrelevant for non-resident keys
    user = {"id": key_id, "name": key_id_base64, "displayName": key_id_base64}  # Irrelevant for non-resident keys
    key_params = [{"type": "public-key", "alg": -8}]  # minisign only supports Ed25519
    user_verification = UserVerificationRequirement.DISCOURAGED

    client = get_client()

    print("Creating FIDO credential...")

    registration_client_data, att_obj = client.do_make_credential(
        client_data,
        rp,
        user,
        key_params,
        user_verification,
    )

    minisig_pub = make_minisig_pubkey(
        b"FD",
        key_id,
        att_obj.auth_data.credential_data.public_key[-2],
        untrusted_comment=f"minisign public key {key_id.hex()}",
    )

    prikey_contents = json.dumps({
        "minisign": {
            "key_id": base64.b64encode(key_id).decode('utf-8'),
        },
        "fido": {
            "rp_id": rp_id,
            "credential_id": base64.b64encode(att_obj.auth_data.credential_data.credential_id).decode('utf-8'),
            "client_data": base64.b64encode(client_data).decode('utf-8'),
            "attestation_object": base64.b64encode(att_obj).decode('utf-8'),
        },
    })

    with open(pubkey_outfile, "wb") as f:
        f.write(minisig_pub.encode('utf-8'))
        print(f"Successfully wrote public key to: {pubkey_outfile}")

    with open(prikey_outfile, "wb") as f:
        f.write(prikey_contents.encode('utf-8'))
        print(f"Successfully wrote private key handle to: {prikey_outfile}")


def sign_file(
        data_file: str,
        prikey_file: str,
        sig_outfile: Optional[str],
):
    sig_outfile = sig_outfile or data_file + '.minisig'
    if os.path.exists(sig_outfile):
        err_exit(f"File already exists: {sig_outfile}")

    with open(prikey_file, "rb") as f:
        prikey_contents = json.load(f)
    if not "minisign" in prikey_contents and "fido" in prikey_contents:
        err_exit("Malformed private key handle file.")

    key_id = base64.b64decode(prikey_contents["minisign"]["key_id"])
    rp_id = prikey_contents["fido"]["rp_id"]
    credential_id = base64.b64decode(prikey_contents["fido"]["credential_id"])
    timestamp = int(datetime.datetime.now().timestamp())

    with open(data_file, "rb") as f:
        data = f.read()

    print(f"Signing data with FIDO key...")

    minisig = make_minisig_signature(
        b'FD',
        key_id,
        rp_id,
        credential_id,
        data,
        untrusted_comment="signature from minisign FIDO key",
        trusted_comment=f"timestamp: {timestamp}\tfile:{data_file}\thashed",
    )

    with open(sig_outfile, 'wb') as f:
        f.write(minisig.encode('utf-8'))
        print(f"Successfully wrote signature to: {sig_outfile}")


def print_usage():
    print(f"""
USAGE:

{sys.argv[0]} generate [--priout minisign.key] [--pubout minisign.pub] [--rp-id minisign:]

  Options:
    --priout   File to write private key handle to
    --pubout   File to write public key to
    --rp-id    FIDO RP ID to bind credential to


{sys.argv[0]} sign <DATA_FILE> [--key minisign.key] [--sigout <DATA_FILE>.minisig]

  Arguments:
    DATA_FILE  File to sign

  Options:
    --key      File with private key handle
    --sigout   File to write signature key to
""")


def main(argv):
    if len(argv) < 2:
        print_usage()
        sys.exit(1)

    cmd = argv[1]

    if cmd == "generate":
        pubkey_outfile: str = "minisign.pub"
        prikey_outfile: str = "minisign.key"
        rp_id: str = "minisign:"

        argi = 2
        while argi < len(argv):
            if argv[argi] == "--pubout":
                pubkey_outfile = argv[argi+1]
                argi += 2
            elif argv[argi] == "--priout":
                prikey_outfile = argv[argi+1]
                argi += 2
            elif argv[argi] == "--rp-id":
                rp_id = argv[argi+1]
                argi += 2
            else:
                usage_exit(f"Unknown option: {argv[argi]}")

        generate_key(pubkey_outfile, prikey_outfile, rp_id)

    elif cmd == "sign":
        data_file: Optional[str] = None
        prikey_file: str = "minisign.key"
        sig_outfile: Optional[str] = None

        argi = 2
        while argi < len(argv):
            if argv[argi] == "--key":
                prikey_file = argv[argi+1]
                argi += 2
            elif argv[argi] == "--sigout":
                sig_outfile = argv[argi+1]
                argi += 2
            else:
                if data_file is None:
                    data_file = argv[argi]
                    argi += 1
                else:
                    usage_exit(f"Unknown argument: {argv[argi]}")

        if data_file is None:
            usage_exit("Unspecified data file.")

        sign_file(data_file, prikey_file, sig_outfile)

    else:
        usage_exit(f"Unknown command: {cmd}")


if __name__ == "__main__":
    main(sys.argv)
