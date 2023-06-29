#!/usr/bin/env python3

import base64
import ctypes
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
from fido2.webauthn import AttestationObject, AuthenticatorAttestationResponse, CredentialCreationOptions
from getpass import getpass
from threading import Event


# Handle user interaction
class CliInteraction(UserInteraction):
    def prompt_up(self):
        print("\nTouch your authenticator device now...\n")

    def request_pin(self, permissions, rd_id):
        return getpass("Enter PIN: ")

    def request_uv(self, permissions, rd_id):
        print("User Verification required.")
        return True


uv = "discouraged"

if WindowsClient.is_available() and not ctypes.windll.shell32.IsUserAnAdmin():
    raise Exception("TODO")
else:
    # Locate a device
    dev = next(CtapHidDevice.list_devices(), None)
    if dev is not None:
        print("Use USB HID channel.")
    else:
        try:
            from fido2.pcsc import CtapPcscDevice

            dev = next(CtapPcscDevice.list_devices(), None)
            print("Use NFC channel.")
        except Exception as e:
            print("NFC channel search error:", e)

    if not dev:
        print("No FIDO device found")
        sys.exit(1)

    #try:
    ctap = Ctap2(dev)
    #except ValueError:
        #ctap = Ctap1(dev)
        # Can't use ctap1 because minisign requires EdDSA


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
        exclude_list,
        extensions,
        rk,
        user_verification,
        enterprise_attestation,
        event,
    ):
        if exclude_list:
            # Filter out credential IDs which are too long
            max_len = self.info.max_cred_id_length
            if max_len:
                exclude_list = [e for e in exclude_list if len(e) <= max_len]

            # Reject the request if too many credentials remain.
            max_creds = self.info.max_creds_in_list
            if max_creds and len(exclude_list) > max_creds:
                raise ClientError.ERR.BAD_REQUEST("exclude_list too long")

        # Process extensions
        client_inputs = extensions or {}
        extension_inputs = {}
        used_extensions = []
        permissions = ClientPin.PERMISSION(0)
        try:
            for ext in [cls(self.ctap2) for cls in self.extensions]:
                auth_input, req_perms = ext.process_create_input_with_permissions(
                    client_inputs
                )
                if auth_input is not None:
                    used_extensions.append(ext)
                    permissions |= req_perms
                    extension_inputs[ext.NAME] = auth_input
        except ValueError as e:
            raise ClientError.ERR.CONFIGURATION_UNSUPPORTED(e)

        on_keepalive = _user_keepalive(self.user_interaction)

        client_data_hash = sha256(client_data)

        # Handle auth
        pin_protocol, pin_token, pin_auth, internal_uv = self._get_auth_params(
            True, client_data_hash, rp["id"], user_verification, permissions, event, on_keepalive
        )

        if not (rk or internal_uv):
            options = None
        else:
            options = {}
            if rk:
                options["rk"] = True
            if internal_uv:
                options["uv"] = True

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

        # Process extenstion outputs
        extension_outputs = {}
        try:
            for ext in used_extensions:
                output = ext.process_create_output(att_obj, pin_token, pin_protocol)
                if output is not None:
                    extension_outputs.update(output)
        except ValueError as e:
            raise ClientError.ERR.CONFIGURATION_UNSUPPORTED(e)

        return (
            client_data,
            AttestationObject.create(att_obj.fmt, att_obj.auth_data, att_obj.att_stmt),
            extension_outputs,
        )

    def do_get_assertion(
        self,
        client_data,
        rp_id,
        allow_list,
        extensions,
        user_verification,
        event,
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

        # Process extensions
        client_inputs = extensions or {}
        extension_inputs = {}
        used_extensions = []
        permissions = ClientPin.PERMISSION(0)
        try:
            for ext in [cls(self.ctap2) for cls in self.extensions]:
                auth_input, req_perms = ext.process_get_input_with_permissions(
                    client_inputs
                )
                if auth_input is not None:
                    used_extensions.append(ext)
                    permissions |= req_perms
                    extension_inputs[ext.NAME] = auth_input
        except ValueError as e:
            raise ClientError.ERR.CONFIGURATION_UNSUPPORTED(e)

        on_keepalive = _user_keepalive(self.user_interaction)

        client_data_hash = sha256(client_data)

        pin_protocol, pin_token, pin_auth, internal_uv = self._get_auth_params(
            False, client_data_hash, rp_id, user_verification, permissions, event, on_keepalive
        )
        options = {"uv": True} if internal_uv else None

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


client_data = b'DATA TO SIGN'
rp = {"id": "example.com", "name": "Example RP"}
user = {"id": b"user_id", "name": "A. User"}
key_params = [{'type':'public-key', 'alg': -8}]
exclude_list = []
extensions = {}
rk = False
user_verification = "discouraged"
enterprise_attestation = None
event = None

client = RawSignCtap2ClientBackend(dev, CliInteraction(), [])

registration_client_data, att_obj, registration_extension_outputs = client.do_make_credential(
    client_data,
    rp,
    user,
    key_params,
    exclude_list,
    extensions,
    rk,
    user_verification,
    enterprise_attestation,
    event,
)

# assertions = client.do_get_assertion(
#     client_data,
#     rp["id"],
#     [{"type": "public-key", "id": att_obj.auth_data.credential_data.credential_id}],
#     {},
#     "discouraged",
#     event
# )

# assertion = assertions.get_assertions()[0]
# auth_data = assertion.auth_data
# sig = assertion.signature

key_id = os.urandom(8)




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
        file_contents: bytes,
        untrusted_comment: str = "",
        trusted_comment: str = "",
) -> bytes:
    signature_client_data = blakehash(file_contents)
    assertion = client.do_get_assertion(
        signature_client_data,
        rp["id"],
        [{"type": "public-key", "id": att_obj.auth_data.credential_data.credential_id}],
        {},
        "discouraged",
        event
    ).get_assertions()[0]
    signature = assertion.signature
    auth_data = assertion.auth_data

    global_signature_client_data = signature + trusted_comment.encode('utf-8')
    global_assertion = client.do_get_assertion(
        global_signature_client_data,
        rp["id"],
        [{"type": "public-key", "id": att_obj.auth_data.credential_data.credential_id}],
        {},
        "discouraged",
        event
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


with open('fido-key.pub', 'wb') as f:
    minisig_pub = make_minisig_pubkey(
        b'FD',
        key_id,
        att_obj.auth_data.credential_data.public_key[-2],
        untrusted_comment="minisign FIDO key",
    )
    f.write(minisig_pub.encode('utf-8'))

with open('fido-msg.txt', 'rb') as f:
    minisig = make_minisig_signature(
        b'FD',
        key_id,
        f.read(),
        untrusted_comment="signature from minisign FIDO key",
        trusted_comment="hashed",
    )

with open('fido-msg.txt.minisigfido', 'wb') as f:
    f.write(minisig.encode('utf-8'))
