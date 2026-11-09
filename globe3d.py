# globe3d.py - A 3D night-time Earth (city lights, atmosphere glow, stars) for the threat maps.
# Built with globe.gl (three.js / WebGL), loaded from a CDN in your browser.

import hashlib
import html
import json

import streamlit as st

GLOBE_JS = "https://cdn.jsdelivr.net/npm/globe.gl@2/dist/globe.gl.min.js"
COUNTRIES = "https://raw.githubusercontent.com/vasturiano/globe.gl/master/example/datasets/ne_110m_admin_0_countries.geojson"
IMG = "https://cdn.jsdelivr.net/npm/three-globe/example/img/"

TEMPLATE = """
<meta name="referrer" content="no-referrer">
<div id="wrap" style="position:relative;width:100%;height:calc(100vh - 4px);border-radius:8px;overflow:hidden;background:#000">
<style>html,body{margin:0;background:#000}</style>
  <div id="globe"></div>
  <div style="position:absolute;left:12px;bottom:12px;display:flex;gap:6px;font:12px -apple-system,Segoe UI,sans-serif">
    <button id="spin" style="__BTN__">❚❚ Pause</button>
    <button id="reset" style="__BTN__">⟲ Reset view</button>
    <button id="zin" style="__BTN__">＋</button>
    <button id="zout" style="__BTN__">－</button>
  </div>
  <div id="layers" style="position:absolute;right:12px;top:10px;color:#E8F1FF;font:12px -apple-system,Segoe UI,sans-serif;
              background:rgba(12,22,42,0.8);border:1px solid rgba(77,159,255,0.3);border-radius:8px;padding:8px 12px;
              line-height:1.9;max-width:230px">__LEGEND__</div>
  <div id="err" style="display:none;position:absolute;inset:0;color:#8B949E;font:14px sans-serif;
              align-items:center;justify-content:center">The 3D globe needs WebGL and an internet connection.</div>
</div>
<script src="__JS__"></script>
<script>
const DATA = __DATA__;
const el = document.getElementById("globe");
try {
  const globe = Globe()(el)
    .width(document.getElementById("wrap").clientWidth || 800).height(document.getElementById("wrap").clientHeight || __H__)
    .backgroundImageUrl("__IMG__night-sky.png")       // star field
    .showAtmosphere(true).atmosphereColor("#3D8BFF").atmosphereAltitude(0.13)
    .pointLat("lat").pointLng("lng").pointColor("color").pointAltitude("alt").pointRadius("r")
    .pointLabel("label").pointsMerge(false)
    .ringLat("lat").ringLng("lng").ringColor(r => t => `rgba(${r.rgb},${1 - t})`).ringMaxRadius("max")
    .ringPropagationSpeed(2.5).ringRepeatPeriod(1100)
    .arcStartLat("slat").arcStartLng("slng").arcEndLat("elat").arcEndLng("elng")
    .arcColor(() => ["rgba(255,90,140,0.05)", "rgba(255,90,140,0.95)"]).arcStroke(0.45)
    .arcDashLength(0.35).arcDashGap(1.2).arcDashInitialGap(() => Math.random() * 1.5)
    .arcDashAnimateTime(2200).arcAltitudeAutoScale(0.45).arcLabel("label");

  // Layers: each has its own points / rings / arcs and a checkbox to show or hide it
  const layers = DATA.layers;
  const panel = document.getElementById("layers");
  const refresh = () => {
    const on = layers.filter(l => l.on);
    globe.pointsData(on.flatMap(l => l.points || []))
         .ringsData(on.flatMap(l => l.rings || []))
         .arcsData(on.flatMap(l => l.arcs || []));
  };
  if (layers.length > 1) {
    panel.innerHTML = '<div style="font-weight:600;margin-bottom:2px">Layers</div>' + layers.map((l, i) =>
      `<label style="display:flex;align-items:center;gap:6px;cursor:pointer;white-space:nowrap">
         <input type="checkbox" data-i="${i}" ${l.on ? "checked" : ""} style="accent-color:${l.color};margin:0">
         <span style="color:${l.color}">●</span> ${l.name}
         <span style="color:#8FA6C8;margin-left:auto;padding-left:8px">${l.count}</span></label>`).join("");
    panel.querySelectorAll("input").forEach(box => box.onchange = () => {
      layers[box.dataset.i].on = box.checked;
      refresh();
      if (layers[box.dataset.i].redraw) layers[box.dataset.i].redraw();
    });
  }
  if (layers.length <= 1 && !panel.textContent.trim()) panel.style.display = "none";
  refresh();

  // Blue night look. We recolor NASA's "Black Marble" city-lights image pixel by pixel:
  // dark areas become navy slate, dim lights deep blue, brighter lights azure, the brightest icy white.
  const RAMP = [[0, [14, 20, 34]], [0.1, [18, 26, 44]], [0.2, [28, 58, 128]],
                [0.4, [38, 118, 220]], [0.65, [92, 190, 255]], [1, [226, 246, 255]]];
  const ramp = L => {
    for (let k = 1; k < RAMP.length; k++) {
      const [x1, c1] = RAMP[k - 1], [x2, c2] = RAMP[k];
      if (L <= x2) {
        const f = (L - x1) / (x2 - x1);
        return c1.map((v, j) => v + (c2[j] - v) * f);
      }
    }
    return RAMP[RAMP.length - 1][1];
  };
  const material = globe.globeMaterial();
  material.color.set("#141E30");  // plain slate until the image is ready
  material.shininess = 0;
  const img = new Image();
  img.crossOrigin = "anonymous";
  img.onload = () => {
    const c = document.createElement("canvas");
    c.width = img.width; c.height = img.height;
    const ctx = c.getContext("2d");
    ctx.drawImage(img, 0, 0);
    const d = ctx.getImageData(0, 0, c.width, c.height), p = d.data;
    for (let i = 0; i < p.length; i += 4) {
      const [r, g, b] = ramp((0.3 * p[i] + 0.59 * p[i + 1] + 0.11 * p[i + 2]) / 255);
      p[i] = r; p[i + 1] = g; p[i + 2] = b;
    }
    ctx.putImageData(d, 0, 0);
    material.color.set("#FFFFFF");
    globe.globeImageUrl(c.toDataURL("image/jpeg", 0.92));
  };
  img.onerror = () => { material.color.set("#FFFFFF"); globe.globeImageUrl("__IMG__earth-night.jpg"); };
  img.src = "__IMG__earth-night.jpg";

  // Even, soft lighting so the whole visible side glows like the reference
  globe.scene().children.forEach(obj => {
    if (obj.isAmbientLight) obj.intensity *= 1.8;
    else if (obj.isDirectionalLight) obj.intensity *= 0.6;
  });

  // Countries: thin glowing borders, plus an optional "heat" fill by how many malicious IPs each hosts
  const heat = DATA.heat || {};
  const heatMax = Math.max(1, ...Object.values(heat).map(h => h.total));
  const heatLayer = layers.find(l => l.heat);
  const codeOf = f => {
    const p = f.properties;
    if (p.ISO_A2 && p.ISO_A2 !== "-99") return p.ISO_A2;
    return {France: "FR", Norway: "NO"}[p.ADMIN] || null;
  };
  const intensity = f => {
    const h = heat[codeOf(f)];
    return h ? Math.log(1 + h.total) / Math.log(1 + heatMax) : 0;
  };
  const heatOn = () => heatLayer && heatLayer.on;
  const capColor = f => {
    const t = heatOn() ? intensity(f) : 0;
    if (!t) return "rgba(5,10,22,0.3)";
    const c = [60 + 195 * t, 140 - 80 * t, 255 - 175 * t];  // blue -> red
    return `rgba(${c.map(Math.round).join(",")},${(0.28 + 0.42 * t).toFixed(2)})`;
  };
  const polyLabel = f => {
    const h = heat[codeOf(f)];
    if (!h || !heatOn()) return f.properties.NAME;
    const rows = Object.entries(h.groups).sort((a, b) => b[1] - a[1]).slice(0, 5)
      .map(([g, n]) => `${g}: ${n.toLocaleString()}`).join("<br>");
    return `<div style="background:rgba(12,22,42,0.94);border:1px solid rgba(77,159,255,0.3);border-radius:6px;
      padding:6px 9px;font:12px -apple-system,sans-serif;color:#E6EDF3"><b>${f.properties.NAME}</b><br>
      ${h.total.toLocaleString()} malicious IPs<br><span style="color:#A3BEE3">${rows}</span></div>`;
  };
  let countries = [];
  const drawCountries = () => globe.polygonsData(countries)
      .polygonCapColor(capColor)
      .polygonSideColor(() => "rgba(77,159,255,0.08)")
      .polygonStrokeColor(() => "rgba(150,200,255,0.22)")
      .polygonAltitude(f => 0.003 + (heatOn() ? 0.025 * intensity(f) : 0))
      .polygonLabel(polyLabel)
      .polygonsTransitionDuration(400);
  fetch("__COUNTRIES__").then(r => r.json()).then(geo => { countries = geo.features; drawCountries(); }).catch(() => {});
  if (heatLayer) heatLayer.redraw = drawCountries;

  const home = {lat: __LAT__, lng: __LNG__, altitude: 2.1};
  globe.pointOfView(home, 0);
  const controls = globe.controls();
  controls.autoRotate = true; controls.autoRotateSpeed = 0.55;
  controls.enableZoom = false;  // let the mouse wheel scroll the page; zoom with the buttons instead
  const zoom = factor => {
    const pov = globe.pointOfView();
    globe.pointOfView({...pov, altitude: Math.min(4, Math.max(0.35, pov.altitude * factor))}, 400);
  };
  document.getElementById("zin").onclick = () => zoom(0.7);
  document.getElementById("zout").onclick = () => zoom(1.4);
  const spin = document.getElementById("spin");
  spin.onclick = () => {
    controls.autoRotate = !controls.autoRotate;
    spin.textContent = controls.autoRotate ? "❚❚ Pause" : "▶ Spin";
  };
  document.getElementById("reset").onclick = () => globe.pointOfView(home, 1200);
  // Hidden tabs start at width 0, so resize the globe whenever its box changes size
  new ResizeObserver(() => {
    const box = document.getElementById("wrap");
    if (box.clientWidth > 0) globe.width(box.clientWidth);
    if (box.clientHeight > 0) globe.height(box.clientHeight);
  }).observe(document.getElementById("wrap"));
} catch (e) {
  document.getElementById("err").style.display = "flex";
}
</script>
"""

BUTTON_STYLE = ("background:rgba(12,22,42,0.85);color:#E6EDF3;border:1px solid rgba(77,159,255,0.3);"
                "border-radius:6px;padding:5px 10px;cursor:pointer")


def severity_color(value, high, medium):
    """Red for the worst, orange for the middle, yellow for the rest."""
    if value >= high:
        return "#FF4D6D", "255,77,109"
    if value >= medium:
        return "#FF9F43", "255,159,67"
    return "#FFD166", "255,209,102"


def label(*lines):
    """Hover tooltip. Everything is escaped so feed data can't inject HTML."""
    body = "<br>".join(html.escape(str(line)) for line in lines if line not in (None, ""))
    return (f'<div style="background:rgba(12,22,42,0.94);border:1px solid rgba(77,159,255,0.3);border-radius:6px;'
            f'padding:6px 9px;font:12px -apple-system,sans-serif;color:#E6EDF3">{body}</div>')


def render_layers(layers, center=(25, -40), legend="", height=560, heat=None):
    """layers: list of {name, color, on, count, points, rings, arcs}. heat: {ISO2: {total, groups}}."""
    data = json.dumps({"layers": layers, "heat": heat or {}}).replace("</", "<\\/")
    page = (TEMPLATE.replace("__DATA__", data).replace("__JS__", GLOBE_JS).replace("__IMG__", IMG)
            .replace("__COUNTRIES__", COUNTRIES)
            .replace("__H__", str(height)).replace("__LAT__", str(center[0])).replace("__LNG__", str(center[1]))
            .replace("__BTN__", BUTTON_STYLE).replace("__LEGEND__", legend))
    st.iframe(page, height=height + 4)


def render(points, rings=None, arcs=None, center=(25, -40), legend="", height=560):
    """A globe with a single layer (no layer checkboxes)."""
    render_layers([{"name": "Data", "color": "#FFFFFF", "on": True, "count": len(points),
                    "points": points, "rings": rings or [], "arcs": arcs or []}], center, legend, height)


# -----------------------------------------------------------------------------
# Ready-made globes for each map
# -----------------------------------------------------------------------------
LEGEND_SEVERITY = ('<span style="color:#FF2E63">●</span> Critical &nbsp; <span style="color:#FF7A2E">●</span> High'
                   ' &nbsp; <span style="color:#FFB020">●</span> Medium &nbsp; <span style="color:#FFE66D">●</span> Low')


def ip_globe(points_df, value_col, value_name, high, medium, center=(25, -40)):
    """points_df needs ip, lat, lon, country, isp and a numeric column. Taller spikes = worse."""
    top = points_df[value_col].max() or 1
    points, rings = [], []
    for row in points_df.itertuples():
        value = getattr(row, value_col)
        color, rgb = severity_color(value, high, medium)
        points.append({"lat": row.lat, "lng": row.lon, "color": color, "r": 0.22,
                       "alt": 0.01 + 0.12 * value / top,
                       "label": label(row.ip, f"{row.country} · {row.isp}", f"{value_name}: {value:,}")})
    for row in points_df.nlargest(12, value_col).itertuples():
        rings.append({"lat": row.lat, "lng": row.lon, "rgb": severity_color(getattr(row, value_col), high, medium)[1],
                      "max": 4})
    return points, rings


def show_ip_globe(points_df, value_col, value_name, high, medium):
    points, rings = ip_globe(points_df, value_col, value_name, high, medium)
    render(points, rings, legend=LEGEND_SEVERITY + " &nbsp;· spike height = " + value_name.lower())


def show_honeypot_globe(points_df, honeypot_location):
    """Animated attack arcs from each attacker to the honeypot."""
    points, rings = ip_globe(points_df, "attempts", "Attempts", high=100, medium=20)
    hp_lat, hp_lng = honeypot_location
    arcs = [{"slat": r.lat, "slng": r.lon, "elat": hp_lat, "elng": hp_lng,
             "label": label(f"{r.ip} → honeypot", f"{r.attempts:,} attempts")}
            for r in points_df.nlargest(150, "attempts").itertuples()]
    points.append({"lat": hp_lat, "lng": hp_lng, "color": "#4DA3FF", "r": 0.6, "alt": 0.05,
                   "label": label("My honeypot (Azure)")})
    rings.append({"lat": hp_lat, "lng": hp_lng, "rgb": "77,163,255", "max": 6})
    render(points, rings, arcs, center=(hp_lat, hp_lng - 30),
           legend=LEGEND_SEVERITY + ' &nbsp;<span style="color:#4DA3FF">●</span> Honeypot')


STATE_CENTERS = {
    "AL": (32.8, -86.8), "AK": (64.2, -152.5), "AZ": (34.3, -111.7), "AR": (34.9, -92.4), "CA": (37.2, -119.5),
    "CO": (39.0, -105.5), "CT": (41.6, -72.7), "DE": (39.0, -75.5), "DC": (38.9, -77.0), "FL": (28.6, -82.4),
    "GA": (32.7, -83.4), "HI": (20.8, -156.3), "ID": (44.4, -114.6), "IL": (40.0, -89.2), "IN": (39.9, -86.3),
    "IA": (42.1, -93.5), "KS": (38.5, -98.4), "KY": (37.5, -85.3), "LA": (31.1, -92.0), "ME": (45.4, -69.2),
    "MD": (39.0, -76.8), "MA": (42.3, -71.8), "MI": (44.3, -85.4), "MN": (46.3, -94.3), "MS": (32.7, -89.7),
    "MO": (38.4, -92.5), "MT": (47.0, -109.6), "NE": (41.5, -99.8), "NV": (39.3, -116.6), "NH": (43.7, -71.6),
    "NJ": (40.2, -74.7), "NM": (34.4, -106.1), "NY": (42.9, -75.5), "NC": (35.6, -79.4), "ND": (47.5, -100.5),
    "OH": (40.3, -82.8), "OK": (35.6, -97.5), "OR": (43.9, -120.6), "PA": (40.9, -77.8), "RI": (41.7, -71.5),
    "SC": (33.9, -80.9), "SD": (44.4, -100.2), "TN": (35.9, -86.4), "TX": (31.5, -99.3), "UT": (39.3, -111.7),
    "VT": (44.1, -72.7), "VA": (37.5, -78.8), "WA": (47.4, -120.5), "WV": (38.6, -80.6), "WI": (44.6, -89.9),
    "WY": (43.0, -107.6),
}


def show_scam_call_globe(state_counts):
    """state_counts: Series indexed by state abbreviation. Taller, redder bars = more reports."""
    top = state_counts.max() or 1
    points = []
    for state, n in state_counts.items():
        if state not in STATE_CENTERS:
            continue
        lat, lng = STATE_CENTERS[state]
        color, _ = severity_color(n / top, 0.6, 0.25)
        points.append({"lat": lat, "lng": lng, "color": color, "r": 0.7, "alt": 0.01 + 0.15 * n / top,
                       "label": label(state, f"{n:,} scam call reports")})
    rings = [{"lat": STATE_CENTERS[s][0], "lng": STATE_CENTERS[s][1], "rgb": "255,77,109", "max": 5}
             for s in state_counts.nlargest(5).index if s in STATE_CENTERS]
    render(points, rings, center=(38, -96),
           legend="Bar height = scam call reports per state")


# -----------------------------------------------------------------------------
# The combined threat globe (Overview page)
# -----------------------------------------------------------------------------
LAYER_COLORS = {
    "Botnet C2": "#FF2E63", "Brute force": "#FF9F43", "Web attacks": "#FFD166", "Spam & mail": "#F78FB3",
    "Scanner": "#A3E635", "Tor exit": "#4DA3FF", "Blocklisted": "#A9D1FF", "Scam calls (US)": "#2EE6C5",
    "Alerts": "#FFFFFF", "Honeypot attacks": "#FF5A8C", "Ransomware victims": "#FF6B9D",
}
SEVERITY_RGB = {"Critical": "255,46,99", "High": "255,122,46", "Medium": "255,176,32", "Low": "255,230,109"}
SEVERITY_SIZE = {"Critical": 7, "High": 5.5, "Medium": 4, "Low": 3}


def threat_globe(ips, state_counts=None, alerts=None, honeypot_points=None, honeypot_location=None, height=640,
                 victims=None, country_heat=None):
    """ips: DataFrame with ip, group, tags, score, risk, lat, lon, country, isp.
    country_heat: DataFrame (index = country code, columns = threat groups, values = IP counts)."""
    layers, heat = [], {}
    if country_heat is not None and not country_heat.empty:
        totals = country_heat.sum(axis=1)
        heat = {str(code): {"total": int(totals[code]),
                            "groups": {g: int(n) for g, n in row.items() if n}}
                for code, row in country_heat.iterrows()}
        layers.append({"name": "Country heat", "color": "#3D8BFF", "on": True, "count": int(totals.sum()),
                       "heat": True, "points": []})
    if ips is not None and not ips.empty:
        top = ips["risk"].max() or 1
        for group in LAYER_COLORS:
            frame = ips[ips["group"] == group]
            if frame.empty:
                continue
            color = LAYER_COLORS[group]
            points = [{"lat": r.lat, "lng": r.lon, "color": color, "r": 0.22,
                       "alt": 0.01 + 0.14 * r.risk / top,
                       "label": label(r.ip, r.tags, f"{COUNTRY_NAMES.get(r.country, r.country)} · {r.isp}",
                                      f"Blocklist score {r.score} · risk {r.risk}")}
                      for r in frame.itertuples()]
            layers.append({"name": group, "color": color, "on": group != "Tor exit", "count": len(points),
                           "points": points})

    if state_counts is not None and not state_counts.empty:
        top = state_counts.max() or 1
        color = LAYER_COLORS["Scam calls (US)"]
        points = [{"lat": STATE_CENTERS[s][0], "lng": STATE_CENTERS[s][1], "color": color, "r": 0.5,
                   "alt": 0.01 + 0.18 * n / top, "label": label(f"{s}: {n:,} scam call reports", "Source: FTC")}
                  for s, n in state_counts.items() if s in STATE_CENTERS]
        layers.append({"name": "Scam calls (US)", "color": color, "on": True, "count": int(state_counts.sum()),
                       "points": points})

    if victims is not None and not victims.empty:
        layer = ransomware_layer(victims)
        if layer["points"]:
            layers.append(layer)

    if alerts is not None and not alerts.empty:
        placed = alerts.dropna(subset=["lat", "lon"])
        rings = [{"lat": r.lat, "lng": r.lon, "rgb": SEVERITY_RGB[r.Severity], "max": SEVERITY_SIZE[r.Severity]}
                 for r in placed.itertuples()]
        points = [{"lat": r.lat, "lng": r.lon, "color": f"rgb({SEVERITY_RGB[r.Severity]})", "r": 0.35, "alt": 0.02,
                   "label": label(f"{r.Severity} alert: {r.Alert}", r.Entity, r.Details)}
                  for r in placed.itertuples()]
        if rings:
            layers.append({"name": "Alerts", "color": LAYER_COLORS["Alerts"], "on": True, "count": len(rings),
                           "points": points, "rings": rings})

    if honeypot_points is not None and not honeypot_points.empty and honeypot_location:
        hp_lat, hp_lng = honeypot_location
        arcs = [{"slat": r.lat, "slng": r.lon, "elat": hp_lat, "elng": hp_lng,
                 "label": label(f"{r.ip} → honeypot", f"{r.attempts:,} attempts")}
                for r in honeypot_points.nlargest(150, "attempts").itertuples()]
        layers.append({"name": "Honeypot attacks", "color": LAYER_COLORS["Honeypot attacks"], "on": True,
                       "count": int(honeypot_points["attempts"].sum()), "arcs": arcs,
                       "points": [{"lat": hp_lat, "lng": hp_lng, "color": "#4DA3FF", "r": 0.6, "alt": 0.05,
                                   "label": label("My honeypot (Azure)")}],
                       "rings": [{"lat": hp_lat, "lng": hp_lng, "rgb": "77,163,255", "max": 6}]})

    render_layers(layers, height=height, heat=heat)


# Approximate center of each country (ISO code -> lat, lon), for data that only has a country
COUNTRY_CENTERS = {
    "US": (39.8, -98.6), "CA": (56.1, -106.3), "MX": (23.6, -102.5), "BR": (-14.2, -51.9), "AR": (-38.4, -63.6),
    "CL": (-35.7, -71.5), "CO": (4.6, -74.3), "PE": (-9.2, -75.0), "VE": (6.4, -66.6), "EC": (-1.8, -78.2),
    "UY": (-32.5, -55.8), "PY": (-23.4, -58.4), "BO": (-16.3, -63.6), "CR": (9.7, -83.8), "PA": (8.5, -80.8),
    "DO": (18.7, -70.2), "PR": (18.2, -66.6), "GT": (15.8, -90.2), "GB": (54.0, -2.5), "IE": (53.4, -8.2),
    "FR": (46.2, 2.2), "DE": (51.2, 10.4), "IT": (41.9, 12.6), "ES": (40.5, -3.7), "PT": (39.4, -8.2),
    "NL": (52.1, 5.3), "BE": (50.5, 4.5), "LU": (49.8, 6.1), "CH": (46.8, 8.2), "AT": (47.5, 14.6),
    "SE": (60.1, 18.6), "NO": (60.5, 8.5), "DK": (56.3, 9.5), "FI": (61.9, 25.7), "IS": (64.9, -19.0),
    "PL": (51.9, 19.1), "CZ": (49.8, 15.5), "SK": (48.7, 19.7), "HU": (47.2, 19.5), "RO": (45.9, 25.0),
    "BG": (42.7, 25.5), "GR": (39.1, 21.8), "HR": (45.1, 15.2), "SI": (46.2, 15.0), "RS": (44.0, 21.0),
    "UA": (48.4, 31.2), "RU": (61.5, 105.3), "LT": (55.2, 23.9), "LV": (56.9, 24.6), "EE": (58.6, 25.0),
    "TR": (39.0, 35.2), "IL": (31.0, 34.9), "AE": (23.4, 53.8), "SA": (23.9, 45.1), "QA": (25.4, 51.2),
    "KW": (29.3, 47.5), "OM": (21.5, 55.9), "JO": (30.6, 36.2), "LB": (33.9, 35.9), "EG": (26.8, 30.8),
    "MA": (31.8, -7.1), "NG": (9.1, 8.7), "KE": (-0.02, 37.9), "ZA": (-30.6, 22.9), "IN": (20.6, 79.0),
    "PK": (30.4, 69.3), "BD": (23.7, 90.4), "LK": (7.9, 80.8), "CN": (35.9, 104.2), "HK": (22.3, 114.2),
    "TW": (23.7, 121.0), "JP": (36.2, 138.3), "KR": (35.9, 127.8), "SG": (1.35, 103.8), "MY": (4.2, 102.0),
    "TH": (15.9, 100.9), "VN": (14.1, 108.3), "PH": (12.9, 121.8), "ID": (-0.8, 113.9), "AU": (-25.3, 133.8),
    "NZ": (-40.9, 174.9), "CY": (35.1, 33.4), "MT": (35.9, 14.4),
    "DZ": (28.0, 1.7), "TN": (33.9, 9.5), "LY": (26.3, 17.2), "SD": (12.9, 30.2), "ET": (9.1, 40.5),
    "TZ": (-6.4, 34.9), "UG": (1.4, 32.3), "GH": (7.9, -1.0), "CI": (7.5, -5.5), "SN": (14.5, -14.5),
    "CM": (7.4, 12.4), "AO": (-11.2, 17.9), "ZM": (-13.1, 27.8), "ZW": (-19.0, 29.2), "MZ": (-18.7, 35.5),
    "NA": (-22.96, 18.5), "BW": (-22.3, 24.7), "MG": (-18.8, 46.9), "CD": (-4.0, 21.8), "RW": (-1.9, 29.9),
    "ML": (17.6, -4.0), "NE": (17.6, 8.1), "BF": (12.2, -1.6), "BJ": (9.3, 2.3), "TG": (8.6, 0.8),
    "MU": (-20.3, 57.6), "SC": (-4.7, 55.5), "SO": (5.2, 46.2), "KZ": (48.0, 66.9), "UZ": (41.4, 64.6),
    "KG": (41.2, 74.8), "TJ": (38.9, 71.3), "TM": (38.97, 59.6), "AZ": (40.1, 47.6), "GE": (42.3, 43.4),
    "AM": (40.1, 45.0), "IR": (32.4, 53.7), "IQ": (33.2, 43.7), "SY": (34.8, 39.0), "AF": (33.9, 67.7),
    "MN": (46.9, 103.8), "NP": (28.4, 84.1), "MM": (21.9, 95.96), "KH": (12.6, 104.99), "LA": (19.9, 102.5),
    "BY": (53.7, 27.95), "MD": (47.4, 28.4), "BA": (43.9, 17.7), "MK": (41.6, 21.7), "AL": (41.2, 20.2),
    "ME": (42.7, 19.4), "BZ": (17.2, -88.5), "HN": (15.2, -86.2), "SV": (13.8, -88.9), "NI": (12.9, -85.2),
    "JM": (18.1, -77.3), "TT": (10.7, -61.2), "VG": (18.4, -64.6), "BH": (26.0, 50.6), "YE": (15.6, 48.5),
}

COUNTRY_NAMES = {
    "US": "United States", "CA": "Canada", "MX": "Mexico", "BR": "Brazil", "AR": "Argentina", "CL": "Chile",
    "CO": "Colombia", "PE": "Peru", "VE": "Venezuela", "EC": "Ecuador", "GB": "United Kingdom", "IE": "Ireland",
    "FR": "France", "DE": "Germany", "IT": "Italy", "ES": "Spain", "PT": "Portugal", "NL": "Netherlands",
    "BE": "Belgium", "LU": "Luxembourg", "CH": "Switzerland", "AT": "Austria", "SE": "Sweden", "NO": "Norway",
    "DK": "Denmark", "FI": "Finland", "PL": "Poland", "CZ": "Czechia", "SK": "Slovakia", "HU": "Hungary",
    "RO": "Romania", "BG": "Bulgaria", "GR": "Greece", "HR": "Croatia", "SI": "Slovenia", "RS": "Serbia",
    "UA": "Ukraine", "RU": "Russia", "BY": "Belarus", "MD": "Moldova", "LT": "Lithuania", "LV": "Latvia",
    "EE": "Estonia", "TR": "Turkey", "IL": "Israel", "AE": "UAE", "SA": "Saudi Arabia", "IR": "Iran",
    "IQ": "Iraq", "EG": "Egypt", "MA": "Morocco", "DZ": "Algeria", "TN": "Tunisia", "NG": "Nigeria",
    "KE": "Kenya", "ZA": "South Africa", "GH": "Ghana", "ET": "Ethiopia", "TZ": "Tanzania", "SC": "Seychelles",
    "IN": "India", "PK": "Pakistan", "BD": "Bangladesh", "CN": "China", "HK": "Hong Kong", "TW": "Taiwan",
    "JP": "Japan", "KR": "South Korea", "SG": "Singapore", "MY": "Malaysia", "TH": "Thailand", "VN": "Vietnam",
    "PH": "Philippines", "ID": "Indonesia", "AU": "Australia", "NZ": "New Zealand", "KZ": "Kazakhstan",
    "UZ": "Uzbekistan", "AZ": "Azerbaijan", "GE": "Georgia", "AM": "Armenia", "CY": "Cyprus", "PA": "Panama",
    "VG": "British Virgin Islands", "BZ": "Belize",
}


def country_point(country, seed=""):
    """A point near a country's center. Each item gets its own small offset so they don't stack."""
    center = COUNTRY_CENTERS.get(str(country or "").upper())
    if not center:
        return None, None
    h = hashlib.md5(str(seed).encode()).digest()
    return center[0] + (h[0] / 255 - 0.5) * 3, center[1] + (h[1] / 255 - 0.5) * 3


def ransomware_layer(victims):
    color = LAYER_COLORS["Ransomware victims"]
    points = []
    for r in victims.itertuples():
        lat, lng = country_point(r.country, r.victim)
        if lat is None:
            continue
        when = r.discovered.strftime("%Y-%m-%d") if hasattr(r.discovered, "strftime") else ""
        points.append({"lat": lat, "lng": lng, "color": color, "r": 0.35, "alt": 0.06,
                       "label": label(r.victim, f"Ransomware gang: {r.gang}", f"{r.sector or 'Unknown sector'} · {r.country}",
                                      f"Posted {when}")})
    return {"name": "Ransomware victims", "color": color, "on": True, "count": len(points), "points": points}
