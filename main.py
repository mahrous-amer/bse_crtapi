import base64
import logging
import os
import subprocess

import aiohttp
from aioprometheus import REGISTRY, Counter, Gauge
from aioprometheus.pusher import Pusher
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.bindings._rust import ObjectIdentifier
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

PUSH_GATEWAY_ADDR = os.environ.get('PUSH_GATEWAY_ADDR')
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI()
pusher = Pusher("crtapi", PUSH_GATEWAY_ADDR,
                grouping_key={"instance": 'crtapi'})
counter = Counter('req_cnt', "Total count of requests")


class CSRRequest(BaseModel):
    csr_type: str
    C: str
    CN: str
    O: str
    OU: str
    SN: str
    UID: str
    TITLE: str
    CATEGORY: str
    ADDRESS: str

    @validator("C")
    def validate_country_name(cls, value):
        if len(value) != 2:
            raise ValueError("Country name must be exactly 2 characters")
        return value

def generate_key():
    private_key = ec.generate_private_key(
        ec.SECP256K1(), backend=default_backend())
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    return private_key_pem


def create_custom_extension(oid_string, value):
    oid = ObjectIdentifier(oid_string)
    ext = x509.extensions.UnrecognizedExtension(oid, value)
    return ext


def generate_csr(csr_type, C, CN, O, OU, SN, UID, TITLE, CATEGORY, ADDRESS):
    if csr_type == "sandbox":
        customoid = b"..TESTZATCA-Code-Signing"
    elif csr_type == "simulation":
        customoid = b"..PREZATCA-Code-Signing"
    else:
        customoid = b"..ZATCA-Code-Signing"

    private_key_pem = generate_key()
    private_key = serialization.load_pem_private_key(
        private_key_pem, password=None, backend=default_backend())
    custom_oid_string = "1.3.6.1.4.1.311.20.2"
    custom_value = customoid
    custom_extension = create_custom_extension(custom_oid_string, custom_value)
    dn = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, CN),
        x509.NameAttribute(NameOID.COUNTRY_NAME, C),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, O),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, OU),
    ])
    alt_name = x509.SubjectAlternativeName({
        x509.DirectoryName(x509.Name([
            x509.NameAttribute(NameOID.SURNAME, SN),
            x509.NameAttribute(NameOID.USER_ID, UID),
            x509.NameAttribute(NameOID.TITLE, TITLE),
            x509.NameAttribute(NameOID.BUSINESS_CATEGORY,
                               CATEGORY + "/registeredAddress=" + ADDRESS),
        ])),
    })

    try:
        with open("config.cnf", "w") as config_file:
            config_file.write(f"""
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = {CN}

[v3_req]
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = {CN}
""")

        command = f"openssl req -new -newkey rsa:2048 -nodes -keyout private_key.pem -out csr.pem -config config.cnf"
        subprocess.run(command, shell=True, check=True)

        with open("csr.pem", "r") as csr_file:
            csr_data = csr_file.read()

        return private_key_pem.decode('utf-8'), csr_data
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"CSR generation failed: {str(e)}")


def validate_csr_type(csr_type: str):
    valid_types = ["sandbox", "simulation", "production"]
    if csr_type not in valid_types:
        raise HTTPException(status_code=400, detail="Invalid csr_type. Accepted values: sandbox, simulation, production")


app.post("/generate-csr/")
async def generate_csr_route(request_data: CSRRequest):
    counter.inc({"type": "generate-csr"})
    await pusher.replace(REGISTRY)
    try:
        validate_csr_type(request_data.csr_type)
        private_key_pem, csr_data = generate_csr(
            request_data.csr_type,
            request_data.C,
            request_data.CN,
            request_data.O,
            request_data.OU,
            request_data.SN,
            request_data.UID,
            request_data.TITLE,
            request_data.CATEGORY,
            request_data.ADDRESS
        )
        return {"private_key": private_key_pem, "csr": csr_data}
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Private key generation failed: {str(e)}")


@app.get("/generate-private-key/")
async def generate_private_key():
    try:
        counter.inc({"type": "generate-private-key"})
        await pusher.replace(REGISTRY)
        command = "openssl ecparam -genkey -name secp256k1 -noout -out private_key.pem"
        subprocess.run(command, shell=True, check=True)

        with open("private_key.pem", "r") as private_key_file:
            private_key_data = private_key_file.read()

        return {"private_key": private_key_data}
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Private key generation failed: {str(e)}")


@app.get("/generate-public-key/")
async def generate_public_key():
    try:
        counter.inc({"type": "generate-public-key"})
        await pusher.replace(REGISTRY)
        command = "openssl ec -in private_key.pem -pubout -out public_key.pem"
        subprocess.run(command, shell=True, check=True)

        with open("public_key.pem", "r") as public_key_file:
            public_key_data = public_key_file.read()
            return {"public_key": public_key_data}
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Public key generation failed: {str(e)}")


@app.post("/test-certificate/")
async def test_certificate(certificate: str):
    try:
        csr_data = {"csr": certificate}
        target_uri = "https://gw-apic-gov.gazt.sa/e-invoicing/developer-portal/compliance"
        counter.inc({"type": "test-certificate"})

        async with aiohttp.ClientSession() as session:
            async with session.post(target_uri, json=csr_data) as response:
                if response.status == 200:
                    counter.inc({"type": "test-certificate",
                                "status": "Failed", "reason": response.status})
                    return {"message": "Certificate tested successfully"}
                else:
                    counter.inc(
                        {"type": "test-certificate", "status": "Success"})
                    raise HTTPException(
                        status_code=500, detail=f"Failed to send CSR to target. Response code: {response.status}")
        await pusher.replace(REGISTRY)
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Certificate testing failed: {str(e)}")


@app.get("/health")
async def health_check():
    counter.inc({"type": "health"})
    await pusher.replace(REGISTRY)
    logger.info("Health check request received")
    return "Kicking!"
