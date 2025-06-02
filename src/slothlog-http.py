import functools
import time
import json
import re
import socket
from collections import defaultdict
from typing import Dict, List
from functools import wraps
import pandas as pd
import streamlit as st
import requests
import altair as alt


# HTTP response status codes
HTTP_OK = [200, 201, 202, 203, 204, 205, 206, 207, 208, 226, 300,
           301, 302, 303, 304, 305, 306, 307, 308]

HTTP_NOT_OK = [400, 401, 402, 403, 404, 405, 406, 407, 408, 409, 410,
          411, 412, 413, 414, 415, 416, 417, 418, 421,422, 423, 424,
          425, 426, 428, 429, 431, 451, 500, 501, 502, 503, 504, 505,
          506, 507, 508, 510, 511]

HTTP_VERBS = [
    # Standard HTTP methods (RFC 7231, RFC 5789)
    "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH",
    # WebDAV methods (RFC 4918)
    "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK",
    # DeltaV (experimental WebDAV extension)
    "ORDERPATCH",
    # Microsoft-specific (used in legacy SharePoint, Exchange, etc.)
    "SEARCH",
    # Non-standard / custom (seen in some servers/tools)
    "DEBUG","PURGE", "LINK", "UNLINK", "VIEW"]

USER_AGENTS = ["Chrome", "Firefox", "Safari", "Edge", "Internet Explorer", "Opera", "cURL", "wget",
                "Python Script", "Postman", "Java Client", "Go Client", "PHP Client", "NetFront", "Other"]

DROP_COLUMNS = ["method", "protocol"]

###########################
# Timing count
###########################
def timing(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        start = time.time()
        result = func(*args, **kwargs)
        end = time.time()
        print(f"⏱️ {func.__name__} took {end - start:.4f} seconds")
        return result
    return wrapper

# ─────────────────────────────────────────────
# 0.  GEO-IP (cached)
# ─────────────────────────────────────────────
@functools.lru_cache(maxsize=1024)
def geo_lookup(hostname: str) -> dict | None:
    """Return ipinfo.io JSON (country, org, city …) or None on error."""
    try:
        ip = socket.gethostbyname(hostname)
        r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=3)
        return r.json() if r.ok else None
    except requests.RequestException:
        return None
    except Exception :
        return None

# ──────────────────────────
# 1.  Helper methods
# ──────────────────────────
@timing
@st.cache_data(show_spinner=True)
def build_requested_map(df: pd.DataFrame) -> pd.DataFrame:
    """
    Returns a table of requested paths and the number of time they were
    *successfully* accessed, along with the hostnames that accessed them
    Return DataFrame: file  |  [hostnames]  |  count
    """
    # --- 1. keep only successfully requested paths 
    ok_mask = df["status"].isin(HTTP_OK)
    df_ok_req = df[ok_mask]

    # --- 2. aggregate per file and count number of times accessed 
    g = (
        df_ok_req
        .groupby("path", dropna=True)
        .agg(
            host=("host", lambda x: list(map(str, pd.unique(x)))),
            request_count=("host", "count"),
        )
        .reset_index(names="path")
        .sort_values("request_count", ascending=False, ignore_index=True)
    )
    
    return g

@timing
@st.cache_data(show_spinner=True)
def command_histogram(df: pd.DataFrame) -> pd.DataFrame:
    """Return DataFrame: verb | count (sorted desc)."""
    return (
        df["verb"]
        .value_counts(dropna=True)
        .rename_axis("verb")
        .reset_index(name="count")
    )


@timing
@st.cache_data(show_spinner=False)
def load_log(upload, sheet_name=0) -> pd.DataFrame:
    """Read the chosen worksheet and normalise columns."""
    df = pd.read_excel(upload, sheet_name=sheet_name)
    
    df.columns = (
        df.columns.str.strip()
        .str.lower()
        .str.replace(" ", "_")
        .str.replace(r"[^a-z0-9_]", "", regex=True)
    )

    try:
        df["timestamp"] = pd.to_datetime(
            df["timestamp"], format="%d/%b/%Y:%H:%M:%S %z", errors="coerce")

        # capture first part of the command (verb), like POST/GET, the path by removing query params, query params, and the version, like HTTP/1.1
        df[["verb", "path", "query", "version"]] = df["request"].str.extract(r"(\S+)\s+([^\s\?]+)(?:\?([^\s]+))?\s+(\S+)", expand=True) # r"(\w+)\s*(.*)"
        df["verb"] = df["verb"].str.upper()

        # adding file_extension column
        df["file_extension"] = df["path"].str.extract(r'\.([a-zA-Z0-9]+)$')[0]
    except KeyError as k:
        print("[D] Error loading log file:", k)
        return pd.DataFrame([])
    
    # Dropping useless columns to speed things up
    try:
        df = df.drop(columns=DROP_COLUMNS)
    except KeyError as k:
        print("[W] Warning dropping column:",k)

    return df

@timing
@st.cache_data(show_spinner=True)
def build_host_profiles(df: pd.DataFrame, host_list: List[str]) -> Dict[str, dict]:
    """
    Build a dictionary of host profiles, with the following fields:
      • first_seen
      • last_seen
      • command_mix
      • user_agent
      • requests      
    """
    profiles = {}
    for host, group in df[df.host.isin(host_list)].groupby("host"):
        profiles[host] = {
            "first_seen": group["timestamp"].min(),
            "last_seen": group["timestamp"].max(),
            "command_mix": group["verb"].value_counts().to_dict(),
            "user_agent": group["user_agent"].value_counts().to_dict(),
            "requests": group["path"].dropna().value_counts().to_dict() # .tolist(),

        }

    return profiles


##########
# File to actor mapping
##########
@timing
@st.cache_data(show_spinner=False)
def resource_to_host_map(df: pd.DataFrame) -> Dict[str, List[Dict[str, str]]]:
    """
    Creates a dictionary mapping of resource paths to their associated access events in the HTTP log.

    NOTE: it only processes rows where verb is one in HTTP_VERBS. 
        If needed, add more verbs to the list.
    """
    df_filtered = df[df["verb"].isin(HTTP_VERBS)].copy()

    # Select only necessary columns to reduce memory footprint
    df_filtered = df_filtered[["timestamp", "host", "request", "status", "bytes","path"]]
   
    fmap = defaultdict(list)
    # Group by path
    for path, group in df_filtered.groupby("path"):
        fmap[path] = group.to_dict(orient="records")

    return dict(fmap)


##########
#  Activity history functionality
##########
@timing
@st.cache_data(show_spinner=True)
def host_event_history(df: pd.DataFrame, host: str) -> pd.DataFrame:
    """Return host’s actions, chronological"""
    
    hist = (
        df[df["host"] == host]
          .sort_values("timestamp")[
              ["timestamp", "host", "request", "status","verb", "path"]
          ]
          .reset_index(drop=True)
    )
    return hist


# Detect user agent
def detect_user_agent(ua):
    ua = str(ua).lower()
    if "chrome" in ua and "edg" not in ua and "opr" not in ua:
        return "Chrome"
    elif "firefox" in ua:
        return "Firefox"
    elif "safari" in ua and "chrome" not in ua:
        return "Safari"
    elif "edg" in ua:
        return "Edge"
    elif "msie" in ua or "trident" in ua:
        return "Internet Explorer"
    elif "opr" in ua or "opera" in ua:
        return "Opera"
    elif "curl" in ua:
        return "cURL"
    elif "wget" in ua:
        return "wget"
    elif "python" in ua:
        return "Python Script"
    elif "postman" in ua:
        return "Postman"
    elif "java" in ua:
        return "Java Client"
    elif "go" in ua:
        return "Go Client"
    elif "php" in ua:
        return "PHP Client"
    elif "NetFront" in ua:
        return "NetFront"
    elif ua == "unknown" or ua.strip() == "":
        return "Unknown"
    else:
        return "Other"

# User agent pie chart implementation
@timing
def show_user_agent_pie(df):
    """
    Show user agent distribution as a pie chart.
    """
    st.subheader("🧭 User Agent Distribution (Filtered)")
    if "user_agent" not in df.columns:
        st.warning("No 'user_agent' column found.")
        return
    # Simplify user agents
    df["ua_category"] = df["user_agent"].fillna("Unknown").apply(detect_user_agent)
    # Count and display
    ua_counts = df["ua_category"].value_counts().reset_index()
    ua_counts.columns = ["user_agent", "count"]
    pie = alt.Chart(ua_counts).mark_arc(innerRadius=40).encode(
        theta=alt.Theta(field="count", type="quantitative"),
        color=alt.Color(field="user_agent", type="nominal", legend=alt.Legend(title="User Agent")),
        tooltip=["user_agent", "count"]
    )#.properties(width=200, height=200)
    st.altair_chart(pie, use_container_width=True)

@timing
def extract_query_params(series):
    """
    Extract query parameter keys from a df.series
    """
    keys = set()
    for item in series.dropna():
        if not isinstance(item, str) or '=' not in item:
            continue
        pairs = item.split('&')
        for pair in pairs:
            if '=' in pair:
                key = pair.split('=')[0].strip()
                if key:
                    keys.add(key)
    return list(keys)


###########################################################################
###########################################################################

# ──────────────────────────
#       STREAMLIT UI
# ──────────────────────────
st.set_page_config(page_title="🦥 SlothLog-HTTP", layout="wide")
st.title("🦥 SlothLog-HTTP Dashboard")

uploaded = st.file_uploader("Upload the Excel log file", type=["xlsx", "xls"])
if not uploaded:
    st.info("👈 Please upload an Excel file to begin.")
    st.stop()

# ---- enumerate worksheets (consumes stream) ----
xls = pd.ExcelFile(uploaded)
sheet_names = xls.sheet_names

with st.sidebar:
    st.header("Worksheet")
    sheet_choice = st.selectbox("Select sheet", options=sheet_names, index=0)

with st.spinner("Parsing log …", show_time=True):
    # Load log file and parse it
    df = load_log(uploaded, sheet_name=sheet_choice)

if df.empty:
    st.error("Missing required columns in the log file. Columns must be:\n " \
    "host, timestamp, request, status, bytes, referer, user_agent")
    st.stop()

# ───────── Dashboard metrics ─────────
col1, col2, col3 = st.columns(3)
col1.metric("Total log lines", len(df))
col2.metric("Unique hosts", df["host"].nunique())
col3.metric("Time span", f"{df['timestamp'].min()}\n → {df['timestamp'].max()}")

# array of unique hostnames in the log
host_list = df["host"].dropna().unique().tolist()

# noisy hosts 
if "noisy_hosts" not in st.session_state:
    st.session_state.noisy_hosts = set()

with st.sidebar:
    st.subheader("Suppress noisy hosts")
    new_noisy = st.multiselect(
        "Choose hosts to ignore in Raw Log table",
        options=host_list,
        default=list(st.session_state.noisy_hosts),
    )

st.session_state.noisy_hosts = set(new_noisy)


# ───────── Build insights (post-filter) ─────────
host_profiles = build_host_profiles(df, host_list)
path_map      = resource_to_host_map(df)
query_params  = extract_query_params(df["query"])
fileExtension_params = df["path"].str.extract(r'\.([a-zA-Z0-9]+)$')[0].dropna().unique().tolist()

# ───────── Sidebar filters & Geo-IP ─────────
with st.sidebar:
    # Filter panel
    st.header("Filters & Exploration")
    host_selected = st.selectbox("Investigate host", ["—"] + host_list, accept_new_options=True,)
    path_selected = st.selectbox("Investigate path", ["—"] + sorted(path_map), help="Select path to filter. " \
                    "Touch-Points table will contain exact matches only.\nInstead, the Raw Log table will contain" \
                    " paths that contain the string selected, too.", accept_new_options=True,)
    query_params_selected = st.selectbox("Investigate query parameter", ["—"] + sorted(query_params), 
                                         help="Select query parameter to filter. Touch-Points table will contain " \
                                         "exact matches only.\nInstead, the Raw Log table will contain also the value matches.", accept_new_options=True)
    userAgent_selected = st.selectbox("Investigate user agent", ["—"] + USER_AGENTS, help="Select user agent to filter. Raw Log " \
                         "Table will contain only hosts that match the selected u-a." )
    
    fileExtension_selected = st.selectbox("Investigate file extension", ["—"] + sorted(fileExtension_params) , help="Select file extension to filter." )
    st.markdown("---")

    # ─────────  Verb panel  ─────────
    verbs = sorted(df["verb"].dropna().unique())
    with st.sidebar.expander("Verb filter", expanded=False):
        selected_verbs = st.multiselect(
        "Commands",
        verbs,
        default=verbs,
        label_visibility="collapsed",
    )
    
    #  ─────────  Geo-IP panel  ───────── 
    if host_selected != "—":
        st.markdown("---")
        # getting geo-IP info for ip_selected
        info = geo_lookup(host_selected)
        print("[D] Geo-IP info:", info)
        if info:
            host_clean = re.sub(r"[^\w\s\.\-]", "", host_selected)
            country = re.sub(r"[^\w\s\.\-]", "", info.get('country','-'))
            org  = re.sub(r"[^\w\s\.\-]", "", info.get('org','-'))
            city = re.sub(r"[^\w\s\.\-]", "", info.get('city','-'))
            flag = f":flag-{country.lower()}:" if country!="-" else ""

            st.markdown(
                f"**Geo-IP:** {flag}  {host_clean}<br>"
                f"**Org:** {org}<br>"
                f"**City:** {city}",
                unsafe_allow_html=True,
            )
        else:
            st.markdown(f"**Geo-IP:** {host_selected} (no info found)")

    st.markdown("---")

    # ─────────  Quick operations panel ─────────
    st.header("Quick Operations")
    op_choice = st.selectbox(
        "Pick an analysis",
        options=[
        "—",
        "Requested path ↔ hostnames",
        "Command histogram for all",
        "Host activity history",
        ],
        help = "Choose an operation among the ones listed below."
    )


# ─────────  Main pane  ─────────
if host_selected != "—":
    st.subheader(f"💻 Profile for host {host_selected}")
    try:
        st.json(host_profiles[host_selected])
        ip_profile = host_profiles[host_selected]
        ip_profile["ip"] = host_selected
        ip_profile_json = json.dumps(ip_profile, indent=2, default=str)
        # button to download the profile as JSON
        st.download_button(
            label="📥 Download host Profile as JSON",
            data=ip_profile_json,
            file_name=f"profile_host_{host_selected}.json",
            mime="application/json",
        )
    except KeyError:
        st.warning(f"❌ No {host_selected} host found")

if path_selected != "—" :
    st.subheader(f"🛤️ Touch-points for path (exact match): {path_selected}")
    try:
        st.dataframe(path_map[path_selected], use_container_width=True)
    except KeyError:
        st.warning(f"❌ No touch-points found for path (exact match): {path_selected}")

if query_params_selected != "—":
    st.subheader(f"❔ Touch-points for query param: {query_params_selected}")
    try:
        pattern = rf"(?:^|&){re.escape(query_params_selected)}="
        st.dataframe(df[df["query"].str.contains(pattern, na=False, regex=True)], use_container_width=True)

    except KeyError:
        st.warning(f"❌ No touch-points found for query parameter: {query_params_selected}")


######
# Quick operations results
######
if op_choice != "—":
    st.markdown(f"### 🔍 {op_choice}")
    # 1️⃣  Requested path ↔ hostnames
    if op_choice == "Requested path ↔ hostnames":
        req_map = build_requested_map(df)

        st.dataframe(req_map, use_container_width=True)
        csv_bytes = req_map.to_csv(index=False).encode()
        st.download_button(
            "📥 Download CSV",
            data=csv_bytes,
            file_name="downloaded_files_ips.csv",
            mime="text/csv",
        )
    
    #  2️⃣  Command histogram
    elif op_choice == "Command histogram for all":
        cmd_hist = command_histogram(df)
        cmd_hist = cmd_hist[cmd_hist["verb"].isin(HTTP_VERBS)]
        chart = (
            alt.Chart(cmd_hist)
            .mark_bar()
            .encode(
                x=alt.X("verb:N", sort="-y", title="HTTP Command"),
                y=alt.Y("count:Q", title="Count"),
                tooltip=["verb", "count"],
            )
        )
        st.altair_chart(chart, use_container_width=True)

        csv_bytes = cmd_hist.to_csv(index=False).encode()
        st.download_button(
            "📥 Download CSV",
            data=csv_bytes,
            file_name="command_histogram.csv",
            mime="text/csv",
        )

    # 3️⃣  Host activity history
    elif op_choice == "Host activity history":
        if host_selected == "—":
            st.warning("Select a host in the sidebar first.")
        else:
            hist = host_event_history(df, host_selected)
            st.markdown(f"### Activity history for **{host_selected}** "f"({len(hist)} actions)")
            st.dataframe(hist, use_container_width=True)
            
            # export CSV/JSON buttons
            st.download_button(
                "📥 Download CSV",
                data=hist.to_csv(index=False),
                file_name=f"host_history_{host_selected}.csv",
                mime="text/csv",
                )
            st.download_button(
                "📥 Download JSON",
                data=hist.to_json(orient="records", date_format="iso"),
                file_name=f"host_history_{host_selected}.json",
                mime="application/json",
                )

            # mini-timeline
            chart = (
                alt.Chart(hist)
                .mark_bar(size=4) #.mark_tick()
                .encode(
                   x="timestamp:T",
                   y=alt.Y("verb:N", sort="-x"),
                   color="verb:N",
                   tooltip=["timestamp", "verb", "path", "host", "status"]
                   )
                .properties(
                    width=900, 
                    height=130
                    )
                )
            
            st.altair_chart(chart, use_container_width=True)        

st.markdown("---")

######
# Creating the Raw Log table based on the filters applied by the 
# user in the sidebar.
######
st.subheader("Raw Log (filtered)")
filtered = df[df["verb"].isin(selected_verbs)]

# Filtering noisy hosts out
if st.session_state.noisy_hosts:
    filtered = filtered[~filtered["host"].isin(st.session_state.noisy_hosts)]

if host_selected != "—":
    filtered = filtered[filtered["host"] == host_selected]
    if host_selected in st.session_state.noisy_hosts:
        st.warning(f"Host {host_selected} is in the noisy hosts list. It will not be shown in the Raw Log table \
                   nor its User-Agent distribution pie chart.")

if path_selected != "—":
    #filtering by sub-paths. So, if the user selects "test", it will show all the subpaths that contain "test"
    #  e.g. "test", "test/1", "test/2", etc.
    filtered = filtered[filtered["path"].str.contains(path_selected, na=False)]
    #the following line is used to filter by exact match instead. Uncomment it if needed and comment the one above.
    #filtered = filtered[filtered["path"] == path_selected]

if query_params_selected != "—":    
    # Match query params and their values string and substring. 
    #  For instance, if ?test is selected, will match ?test=2 and ?x=test and atest=1 and x=btest
    filtered = filtered[filtered["query"].str.contains(re.escape(query_params_selected), regex=True, na=False)]

if fileExtension_selected != "—":
    # Match file extension
    filtered = filtered[filtered["file_extension"] == fileExtension_selected]

if userAgent_selected != "—":
    # Match user agent
    filtered = filtered[filtered["user_agent"].apply(detect_user_agent) == userAgent_selected]


st.dataframe(filtered.sort_values(by="timestamp"), use_container_width=True)
show_user_agent_pie(filtered)
