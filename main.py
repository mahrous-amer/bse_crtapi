import base64
import logging
import os
import subprocess
import requests
import json

import asyncio
import aiohttp
import redis.asyncio as redis
from aioprometheus import REGISTRY, Counter, Gauge
from aioprometheus.pusher import Pusher
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, validator

PUSH_GATEWAY_ADDR = os.environ.get("PUSH_GATEWAY_ADDR")
REDIS = os.environ.get("REDIS")

logger = logging.getLogger("uvicorn")
logger.setLevel(logging.DEBUG)

app = FastAPI()
pusher = Pusher("crtapi", PUSH_GATEWAY_ADDR,
                grouping_key={"instance": "crtapi"})
counter = Counter("req_cnt", "Total count of requests")


class CSRRequest(BaseModel):
    csr_type: str
    EMAIL: str
    C: str  # Country
    O: str  # Organization
    OU: str  # Organixational Unit
    CN: str  # Common Name
    SN: str
    UID: str  # VAT Number
    TITLE: str
    CATEGORY: str
    ADDRESS: str

    @validator("C")
    def validate_country_name(cls, value):
        if len(value) != 2:
            raise ValueError("Country name must be exactly 2 characters")
        return value


def validate_csr_type(csr_type: str):
    valid_types = ["sandbox", "simulation", "production"]
    if csr_type not in valid_types:
        raise HTTPException(
            status_code=400,
            detail="Invalid csr_type. Accepted values: sandbox, simulation, production",
        )


def generate_csr(csr_type, EMAIL, C, CN, O, OU, SN, UID, TITLE, CATEGORY, ADDRESS):
    if csr_type == "sandbox":
        customoid = "TESTZATCA-Code-Signing"
    elif csr_type == "simulation":
        customoid = "PREZATCA-Code-Signing"
    else:
        customoid = "ZATCA-Code-Signing"

    with open("config.cnf", "w") as config_file:
        config_file.write(
            f"""
oid_section = OIDs
[ OIDs ]
certificateTemplateName = 1.3.6.1.4.1.311.20.2
[req]
default_bits = 2048
emailAddress = {EMAIL}
req_extensions = v3_req
x509_extensions = v3_ca
prompt = no
default_md = sha256
req_extensions = req_ext
distinguished_name = dn
[ dn ]
C = {C}
OU = {OU}
O = {O}
CN = {CN}
[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment
[req_ext]
certificateTemplateName = ASN1:PRINTABLESTRING:{customoid}
subjectAltName = dirName:alt_names
[alt_names]
SN = {SN}
UID = {UID}
title = {TITLE}
registeredAddress = {ADDRESS}
businessCategory = {CATEGORY}
"""
        )
    command = "openssl ecparam -name secp256k1 -genkey -noout -out privatekey.pem"
    subprocess.run(command, shell=True, check=True)
    command = "openssl req -new -sha256 -key privatekey.pem -extensions v3_req -config config.cnf -out req.csr"
    subprocess.run(command, shell=True, check=True)
    with open("req.csr", "r") as csr_file:
        csr_data = csr_file.read()
    command = f"openssl enc -base64 -A -in req.csr -out encoded_csr.txt"
    subprocess.run(command, shell=True, check=True)
    with open("encoded_csr.txt", "r") as csr_file:
        csr_data = csr_file.read()
    return {"csr": csr_data}


@app.get("/health")
async def health_check():
    counter.inc({"type": "health"})
    await pusher.replace(REGISTRY)
    logger.info("Health check request received")
    return "Kicking!"


@app.post("/generate-csr/")
async def generate_csr_route(request_data: CSRRequest):
    counter.inc({"type": "generate-csr"})
    await pusher.replace(REGISTRY)
    try:
        validate_csr_type(request_data.csr_type)
        csr_data = generate_csr(
            request_data.csr_type,
            request_data.EMAIL,
            request_data.C,
            request_data.CN,
            request_data.O,
            request_data.OU,
            request_data.SN,
            request_data.UID,
            request_data.TITLE,
            request_data.CATEGORY,
            request_data.ADDRESS,
        )
        return {"csr": csr_data}
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Private key generation failed: {str(e)}"
        )

@app.post("/test-cert/")
async def test_cert(certificate: str, otp: str):
    try:
        counter.inc({"type": "test-cert"})
        await pusher.replace(REGISTRY)
        csr_data = {"csr": certificate}
        target_uri = "https://gw-fatoora.zatca.gov.sa/e-invoicing/developer-portal/compliance"

        headers = {
            "accept": "application/json",
            "OTP": otp,
            "Accept-Version": "V2",
            "Content-Type": "application/json"
        }

        json_payload = {
            "csr": certificate
        }

        response = requests.post(
            target_uri, headers=headers, json=json_payload)
        response_content = json.loads(response.content.decode('utf-8'))
        if response.status_code == 200:
            return response_content
        else:
            raise HTTPException(
                status_code=500, detail=f"Failed to send CSR to target. Response code: {response.status_code}")
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Certificate testing failed: {str(e)}")