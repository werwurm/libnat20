#! /usr/bin/env python3

# Copyright %year% Aurora Operations, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import subprocess
import os
import click
from contextlib import contextmanager
from hashlib import sha512
import time
from cryptography.x509 import load_der_x509_certificate
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

service_binary = "./nat20_service_bin"
client_binary = "./n20_client_stateless_bin"


def make_unique_socket_name():
    # generate a statistically unique socket path name using os.urandom
    random_bytes = os.urandom(16)
    socket_path = f"/tmp/n20_service_{random_bytes.hex()}.sock"
    return socket_path


# A contextmanager that starts the service binary and kills it on exit using @contextlib.contextmanager
@contextmanager
def service_context(output_path=None):
    socket_path = make_unique_socket_name()
    cmd = [service_binary, "--socket-path", socket_path]
    if output_path is not None:
        cmd.extend(["--uds-cert-path-ed25519", f"{output_path}/uds_cert_ed25519.der"])
        cmd.extend(["--uds-cert-path-p256", f"{output_path}/uds_cert_p256.der"])
        cmd.extend(["--uds-cert-path-p384", f"{output_path}/uds_cert_p384.der"])
    process = subprocess.Popen(
        cmd,
        # stdout=subprocess.PIPE,
        # stderr=subprocess.STDOUT,
        text=True,
    )
    while not os.path.exists(socket_path):
        print("Waiting for service to start...")
        time.sleep(0.1)
    print(f"Started service with socket path: {socket_path}")
    try:
        yield socket_path
    finally:
        print(f"Stopping service with socket path: {socket_path}")
        process.terminate()
        process.wait()
        print(f"Service stopped with socket path: {socket_path}")
        # Print output of process
        std_out, std_err = process.communicate()
        print(f"Service output:\n{std_out}\n")
        if std_err:
            print(f"Service error output:\n{std_err}\n")


# A function that invokes the n20_stateless_client with the given socket path, command, and options
def invoke_client(socket_path, command, options, open_dice_input=None):
    cmd = [client_binary, "--socket-path", socket_path, command]

    def hexify(value):
        if isinstance(value, bytes):
            return value.hex()
        return value

    def optify(key, value):
        if isinstance(value, list):
            return [x for v in value for x in optify(key, v)]
        return [f"--{key}", hexify(value)]

    for key, value in options.items():
        cmd.extend(optify(key, value))
    if open_dice_input is not None:
        for key, value in open_dice_input.items():
            cmd.extend(optify(key, value))
    print("Invoking:", " ".join(cmd))
    subprocess.check_call(cmd)


def make_open_dice_input():
    open_dice_inputs = []
    open_dice_input = {}
    open_dice_input["code-desc"] = (
        "ySub-2.3.4:38c459cfadfa2b8953369954e12f7548d3a1ac973c888005c3b6db2346cbc8f1".encode(
            "utf-8"
        )
    )
    open_dice_input["code"] = sha512(open_dice_input["code-desc"]).digest()
    open_dice_input["conf-desc"] = "Extraordinary normal configuration".encode("utf-8")
    open_dice_input["conf"] = sha512(open_dice_input["conf-desc"]).digest()
    open_dice_input["auth-desc"] = "A certificate".encode("utf-8")
    open_dice_input["auth"] = sha512(open_dice_input["auth-desc"]).digest()
    open_dice_input["mode"] = "normal"
    open_dice_input["hidden"] = sha512(b"nothing to see").digest()
    open_dice_inputs.append(open_dice_input)

    open_dice_input = {}
    open_dice_input["code-desc"] = (
        "LTF-3.1415927:588e862e1b633cb359fe67e1836906d8717ed0a78c35aa3ac51ac664d0511526".encode(
            "utf-8"
        )
    )
    open_dice_input["code"] = sha512(open_dice_input["code-desc"]).digest()
    open_dice_input["conf-desc"] = "Leg day configuration".encode("utf-8")
    open_dice_input["conf"] = sha512(open_dice_input["conf-desc"]).digest()
    open_dice_input["auth-desc"] = "LEG Inc. Firmware Signing Certificate".encode(
        "utf-8"
    )
    open_dice_input["auth"] = sha512(open_dice_input["auth-desc"]).digest()
    open_dice_input["mode"] = "normal"
    open_dice_input["hidden"] = sha512(b"nothing to hide").digest()
    open_dice_inputs.append(open_dice_input)

    open_dice_input = {}
    open_dice_input["code-desc"] = (
        "Finux-5.4.3:2f3c4d0d3617f29e77bc35d66b6fe7decf5f2a763c2bb6d2012b5035411b937f".encode(
            "utf-8"
        )
    )
    open_dice_input["code"] = sha512(open_dice_input["code-desc"]).digest()
    open_dice_input["conf-desc"] = "Mildly chaotic configuration".encode("utf-8")
    open_dice_input["conf"] = sha512(open_dice_input["conf-desc"]).digest()
    open_dice_input["auth-desc"] = "Another certificate".encode("utf-8")
    open_dice_input["auth"] = sha512(open_dice_input["auth-desc"]).digest()
    open_dice_input["mode"] = "recovery"
    open_dice_input["hidden"] = sha512(b"Geh' heim!").digest()
    open_dice_inputs.append(open_dice_input)

    return open_dice_inputs


mode_to_int = {
    "not-configured": b"\x00",
    "normal": b"\x01",
    "debug": b"\x02",
    "recovery": b"\x03",
}


def compress_input(open_dice_inputs):
    h = sha512()
    h.update(open_dice_inputs["code"])
    h.update(open_dice_inputs["conf"])
    h.update(open_dice_inputs["auth"])
    h.update(mode_to_int[open_dice_inputs["mode"]])
    h.update(open_dice_inputs["hidden"])
    return h.digest()


def experiment1(output_path, key_type, cert_type):
    # Check that the output path does not exist and then create it, potentially
    # creating parent directories in the process.
    os.makedirs(output_path, exist_ok=True)

    parent_path = []
    with service_context(output_path) as socket_path:
        for i, open_dice_input in enumerate(make_open_dice_input()):
            options = {
                "key-type": key_type,
                "parent-key-type": key_type,
                "output": f'{output_path}/cdi_{i}.{"der" if cert_type == "x509" else "cwt"}',
                "parent-path-element": parent_path,
                "certificate-format": cert_type,
            }

            invoke_client(
                socket_path, "cdi-cert", options, open_dice_input=open_dice_input
            )

            parent_path.append(compress_input(open_dice_input))

        eca_cert_options = {
            "key-type": key_type,
            "parent-key-type": key_type,
            "output": f'{output_path}/cdi_2_eca.{"der" if cert_type == "x509" else "cwt"}',
            "parent-path-element": parent_path,
            "challenge": sha512(b"expected").digest(),
            "certificate-format": cert_type,
        }

        invoke_client(socket_path, "eca-cert", eca_cert_options)

        eca_ee_cert_options = {
            "key-type": key_type,
            "parent-key-type": key_type,
            "output": f'{output_path}/cdi_2_eca_ee.{"der" if cert_type == "x509" else "cwt"}',
            "parent-path-element": parent_path,
            "challenge": sha512(b"expected2").digest(),
            "certificate-format": cert_type,
            "name": "end-entity-cert",
            "key-usage": ["sign"],
        }

        invoke_client(socket_path, "eca-ee-cert", eca_ee_cert_options)

        eca_ee_sign_options = {
            "key-type": key_type,
            "output": f"{output_path}/cdi_2_eca_sign.bin",
            "parent-path-element": parent_path,
            "name": "end-entity-cert",
            "key-usage": ["sign"],
            "message": b"expected message",
        }

        invoke_client(socket_path, "eca-ee-sign", eca_ee_sign_options)

    if cert_type == "x509":
        eca_ee_cert = load_der_x509_certificate(
            open(f"{output_path}/cdi_2_eca_ee.der", "rb").read()
        )

        # h = hashes.Hash(hashes.SHA256())
        # h.update(b"expected message")
        # message_digest = h.finalize()

        signature = open(f"{output_path}/cdi_2_eca_sign.bin", "rb").read()
        print(f"Signature: {signature.hex()}")

        try:
            if key_type == "ed25519":
                eca_ee_cert.public_key().verify(
                    signature=signature,
                    data=b"expected message",
                    # padding=eca_ee_cert.signature_algorithm.padding,
                    # algorithm=eca_ee_cert.signature_algorithm.hash_algorithm,
                )
            elif key_type == "p256":

                signature = encode_dss_signature(
                    int.from_bytes(signature[: len(signature) // 2], "big"),
                    int.from_bytes(signature[len(signature) // 2 :], "big"),
                )

                eca_ee_cert.public_key().verify(
                    signature,
                    b"expected message",
                    # padding=eca_ee_cert.signature_algorithm.padding,
                    # algorithm=hashes.SHA256(),
                    ec.ECDSA(hashes.SHA256()),
                )
            elif key_type == "p384":
                signature = encode_dss_signature(
                    int.from_bytes(signature[: len(signature) // 2], "big"),
                    int.from_bytes(signature[len(signature) // 2 :], "big"),
                )

                eca_ee_cert.public_key().verify(
                    signature=signature,
                    data=b"expected message",
                    # padding=eca_ee_cert.signature_algorithm.padding,
                    # algorithm=hashes.SHA384(),
                    signature_algorithm=ec.ECDSA(hashes.SHA384()),
                )
            else:
                raise ValueError(f"Unsupported key type for verification: {key_type}")
            print("Signature verification succeeded")
        except Exception as e:
            print(f"Signature verification failed: {e}")


if __name__ == "__main__":
    experiment1("output/experiment2", "ed25519", "x509")

# a116584088d7843cbc23d4308254bfe83c552ed5992f0916e705feddb8ccae46e353a49a972609c99345628806b37fe5bdd50dfd4a7c096f378bc68c8588932833b5d30b
# a1165840ba5c7449c8fc6915179917e4b6e28948ae201841d392f1d3c850017615f881991e0834e269899b7e7eaae1108c9ade087aa5b8d8d8bb3faec1bf9b80c72acb0c
