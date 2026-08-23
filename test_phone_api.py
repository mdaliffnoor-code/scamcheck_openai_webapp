import os
import requests

from dotenv import load_dotenv


load_dotenv()


API_KEY = os.getenv("ABSTRACT_PHONE_API_KEY")

API_URL = "https://phoneintelligence.abstractapi.com/v1/"


phone_number = "+6591234567"


response = requests.get(
    API_URL,
    params={
        "api_key": API_KEY,
        "phone": phone_number
    },
    timeout=10
)


print("Status:", response.status_code)

print(response.json())