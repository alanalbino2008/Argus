"""Where the sun was: for checking when (and where) a photo was taken from its shadows.

Investigators confirm a photo's time by its shadows ("chronolocation"): at a given place and
moment the sun has a known direction (azimuth, degrees clockwise from north) and height above the
horizon (elevation). Shadows point the opposite way, and an upright object's shadow is
``1 / tan(elevation)`` times its height. If a photo claims to show noon in July but its shadows
are long, the claim is wrong.

This is the US National Oceanic and Atmospheric Administration (NOAA) solar position algorithm,
accurate to well under a degree for dates between 1901 and 2099, which is far finer than anyone
can measure a shadow in a photo. Atmospheric refraction is included near the horizon.
"""

from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Any

COMPASS = ("N", "NNE", "NE", "ENE", "E", "ESE", "SE", "SSE", "S", "SSW", "SW", "WSW", "W", "WNW", "NW", "NNW")


def compass(degrees: float) -> str:
    return COMPASS[round(degrees % 360 / 22.5) % 16]


def sun_position(lat: float, lon: float, when: datetime) -> dict[str, Any]:
    """Azimuth and elevation of the sun's centre (degrees) at ``when`` (timezone-aware) for lat/lon."""
    if not -90 <= lat <= 90 or not -180 <= lon <= 180:
        raise ValueError("latitude must be -90..90 and longitude -180..180")
    if when.tzinfo is None:
        raise ValueError("the time must include its time zone (or be UTC)")
    utc = when.astimezone(timezone.utc)
    jd = utc.timestamp() / 86400.0 + 2440587.5  # Julian day
    t = (jd - 2451545.0) / 36525.0  # Julian centuries since J2000

    mean_lon = (280.46646 + t * (36000.76983 + t * 0.0003032)) % 360
    mean_anom = 357.52911 + t * (35999.05029 - 0.0001537 * t)
    ecc = 0.016708634 - t * (0.000042037 + 0.0000001267 * t)
    m = math.radians(mean_anom)
    centre = (math.sin(m) * (1.914602 - t * (0.004817 + 0.000014 * t)) + math.sin(2 * m) * (0.019993 - 0.000101 * t)
              + math.sin(3 * m) * 0.000289)  # fmt: skip
    true_lon = mean_lon + centre
    omega = 125.04 - 1934.136 * t
    app_lon = true_lon - 0.00569 - 0.00478 * math.sin(math.radians(omega))
    obliq0 = 23 + (26 + (21.448 - t * (46.815 + t * (0.00059 - t * 0.001813))) / 60) / 60
    obliq = obliq0 + 0.00256 * math.cos(math.radians(omega))
    decl = math.degrees(math.asin(math.sin(math.radians(obliq)) * math.sin(math.radians(app_lon))))

    y = math.tan(math.radians(obliq / 2)) ** 2
    l0 = math.radians(mean_lon)
    eq_time = 4 * math.degrees(y * math.sin(2 * l0) - 2 * ecc * math.sin(m) + 4 * ecc * y * math.sin(m) * math.cos(2 * l0)
                               - 0.5 * y * y * math.sin(4 * l0) - 1.25 * ecc * ecc * math.sin(2 * m))  # fmt: skip

    minutes = utc.hour * 60 + utc.minute + utc.second / 60 + utc.microsecond / 6e7
    true_solar = (minutes + eq_time + 4 * lon) % 1440
    hour_angle = true_solar / 4 - 180 if true_solar / 4 >= 0 else true_solar / 4 + 180

    lat_r, decl_r, ha_r = math.radians(lat), math.radians(decl), math.radians(hour_angle)
    cos_zenith = math.sin(lat_r) * math.sin(decl_r) + math.cos(lat_r) * math.cos(decl_r) * math.cos(ha_r)
    zenith = math.degrees(math.acos(max(-1.0, min(1.0, cos_zenith))))
    elevation = 90 - zenith
    elevation += _refraction(elevation)

    denominator = math.cos(lat_r) * math.sin(math.radians(zenith))
    if abs(denominator) < 1e-9:
        azimuth = 180.0 if lat > decl else 0.0
    else:
        cos_az = (math.sin(lat_r) * math.cos(math.radians(zenith)) - math.sin(decl_r)) / denominator
        az = math.degrees(math.acos(max(-1.0, min(1.0, cos_az))))
        azimuth = (az + 180) % 360 if hour_angle > 0 else (540 - az) % 360

    up = elevation > 0
    shadow = (azimuth + 180) % 360
    ratio = 1 / math.tan(math.radians(elevation)) if elevation > 0.5 else None
    return {
        "time_utc": utc.isoformat(), "latitude": lat, "longitude": lon,
        "azimuth": round(azimuth, 1), "elevation": round(elevation, 1), "sun_up": up,
        "sun_direction": compass(azimuth), "shadow_azimuth": round(shadow, 1), "shadow_direction": compass(shadow),
        "shadow_ratio": round(ratio, 2) if ratio is not None and ratio < 100 else None,
        "summary": _summary(up, azimuth, elevation, shadow, ratio),
    }  # fmt: skip


def _refraction(elevation: float) -> float:
    """Atmospheric refraction (degrees) that lifts the sun's apparent position near the horizon."""
    if elevation > 85:
        return 0.0
    te = math.tan(math.radians(elevation))
    if elevation > 5:
        arcsec = 58.1 / te - 0.07 / te**3 + 0.000086 / te**5
    elif elevation > -0.575:
        arcsec = 1735 + elevation * (-518.2 + elevation * (103.4 + elevation * (-12.79 + elevation * 0.711)))
    else:
        arcsec = -20.774 / te
    return arcsec / 3600


def _summary(up: bool, azimuth: float, elevation: float, shadow: float, ratio: float | None) -> str:
    if not up:
        return "The sun was below the horizon: it was night (or twilight), so there were no sun shadows."
    text = (f"The sun was in the {compass(azimuth)} ({azimuth:.0f}°), {elevation:.0f}° above the horizon. "
            f"Shadows pointed {compass(shadow)} ({shadow:.0f}°)")  # fmt: skip
    if ratio is not None and ratio < 100:
        text += f" and were about {ratio:.1f} times as long as the object casting them"
    return text + "."
