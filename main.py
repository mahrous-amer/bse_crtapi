from fastapi import FastAPI
import subprocess
from pydantic import BaseModel
from aioprometheus import REGISTRY, Counter, Gauge
from aioprometheus.pusher import Pusher

app = FastAPI()
pusher = Pusher("crtapi", PUSH_GATEWAY_ADDR, grouping_key={"instance": 'crtapi'})
counter = Counter('req_cnt', "Total count of requests", ["method", "endpoint"])

class CSRRequest(BaseModel):
    common_name: str
    egs_serial_number: str
    organization_identifier: str
    organization_unit_name: str
    organization_name: str
    taxpayer_name: str
    country_name: str
    invoice_type: str
    location: str
    industry: str

@app.get("/health")
async def health_check():
    counter.inc({"type": "health"})
    await pusher.replace(REGISTRY)
    return "Kicking!"

@app.post("/generate-csr/")
async def generate_csr(request_data: CSRRequest):
    config_content = f"""
    [req]
    distinguished_name = req_distinguished_name
    req_extensions = v3_req
    prompt = no

    [req_distinguished_name]
    CN = {request_data.common_name}

    [v3_req]
    keyUsage = nonRepudiation, digitalSignature, keyEncipherment
    extendedKeyUsage = serverAuth, clientAuth
    subjectAltName = @alt_names

    [alt_names]
    DNS.1 = {request_data.common_name}
    """
    with open("config.cnf", "w") as config_file:
        config_file.write(config_content)

    command = f"openssl req -new -newkey rsa:2048 -nodes -keyout private_key.pem -out csr.pem -config config.cnf"
    subprocess.run(command, shell=True, check=True)
    with open("csr.pem", "r") as csr_file:
        csr_data = csr_file.read()
    counter.inc({"type": "generate-csr"})
    await pusher.replace(REGISTRY)
    return {"csr": csr_data}

@app.get("/generate-private-key/")
async def generate_private_key():
    command = "openssl ecparam -genkey -name secp256k1 -noout -out private_key.pem"
    subprocess.run(command, shell=True, check=True)
    with open("private_key.pem", "r") as private_key_file:
        private_key_data = private_key_file.read()
    counter.inc({"type": "generate-private_key"})
    await pusher.replace(REGISTRY)
    return {"private_key": private_key_data}

@app.get("/generate-public-key/")
async def generate_public_key():
    command = "openssl ec -in private_key.pem -pubout -out public_key.pem"
    subprocess.run(command, shell=True, check=True)
    with open("public_key.pem", "r") as public_key_file:
        public_key_data = public_key_file.read()
    counter.inc({"type": "generate-public-key"})
    await pusher.replace(REGISTRY)
    return {"public_key": public_key_data}

@app.post("/test-certificate/")
async def test_certificate(certificate: str):
    counter.inc({"type": "test-certificate"})
    await pusher.replace(REGISTRY)
    return {"message": "Certificate tested successfully"}
