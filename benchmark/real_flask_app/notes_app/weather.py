import requests

FORECAST_URL = "https://api.open-meteo.com/v1/forecast"

http = requests.Session()
http.headers.update({"User-Agent": "notes-service/1.0"})


def fetch_forecast(lat, lon):
    resp = http.get(FORECAST_URL, params={"latitude": lat, "longitude": lon, "current_weather": "true"}, timeout=5)
    resp.raise_for_status()
    current = resp.json().get("current_weather", {})
    return {
        "temperature": current.get("temperature"),
        "wind": current.get("windspeed"),
        "observed": current.get("time"),
    }
