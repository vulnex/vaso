import os
import requests


def forecast(city):
    return requests.get("https://api.weather.example/v1", params={"q": city}, headers={"Authorization": os.environ["WEATHER_API_KEY"]}).json()
