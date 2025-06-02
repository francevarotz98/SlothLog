import functools
from collections import defaultdict
from typing import Dict, List
from functools import wraps
import time
import json
import re
import pandas as pd
import streamlit as st
import requests
import altair as alt


# FTP response codes
FTP_OK= [100,110,120,125,150,200,202,211,212,213,214,215,220,221,
         225,226,227,228,229,230,232,234,235,250,300,331,332,334,336]
FTP_NOT_OK = [421,425,426,430,431,434,450,451,452,500,501,502,503,
              504,530,532,533,534,535,536,537,550,551,552,553,600,
              631,632,633]
DOWNLOAD_VERBS = {"RETR"} 
UPLOAD_VERBS = {"STOR","SITE"}
FTP_COMMANDS = ["ABOR","ACCT","ADAT","ALLO","APPE","AUTH","AVBL","CCC","CDUP","CONF","CWD","DELE",
                "ENC","EPRT","EPSV","FEAT","HELP","HOST","LANG","LIST","LPRT","LPSV","MDTM","MIC",
                "MLSD","MLST","MODE","MKD","NLST","NOOP","OPTS","PASS","PASV","PBSZ","PORT","PROT",
                "PWD","QUIT","REIN","REST","RETR","RMD","RNFR","RNTO","SITE","SIZE","SMNT","STAT",
                "STOR","STOU","STRU","SYST","TYPE","USER"]



# Timing counter for functions
def timing(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        start = time.time()
        result = func(*args, **kwargs)
        end = time.time()
        print(f"⏱️ {func.__name__} took {end - start:.4f} seconds")
        return result
    return wrapper


# Geo-IP for IP addresses
@functools.lru_cache(maxsize=1024)
@timing
def geo_lookup(ip: str) -> dict | None:
    """Return ipinfo.io JSON (country, org, city …) or None on error."""
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=3)
        return r.json() if r.ok else None
    except requests.RequestException:
        return None


# ──────────────────────────────────
# Helper methods for data processing
# ──────────────────────────────────
@timing
@st.cache_data(show_spinner=False)
def build_downloads_map(df: pd.DataFrame) -> pd.DataFrame:
    """
    Return dataframe containing the mapping of files to the IPs that 
    **successfully** downloaded them.
    
    DataFrame: file  |  [IPs]  |  download_count
    """
    # 1. keep only successfully downloaded files
    #  using mask to filter out failed operations
    ok_mask = df["response_code"].isin(FTP_OK)
    verb_mask = df["verb"].isin(DOWNLOAD_VERBS)
    df_ok_downl = df[ok_mask & verb_mask]

    # 2. aggregate per file (arg) and count number of times downloaded 
    g = (
        df_ok_downl
        .groupby("arg", dropna=True)
        .agg(
            ips=("ip_address", lambda x: list(pd.unique(x))),
            download_count=("ip_address", "count"),
        )
        .reset_index(names="file")
        .sort_values("download_count", ascending=False, ignore_index=True)
    )

    return g

@timing
@st.cache_data(show_spinner=False)
def build_uploads_map(df: pd.DataFrame) -> pd.DataFrame:
    """
    Return dataframe containing the mapping of files to the IPs that 
    **successfully** uploaded them.

    Return DataFrame: file  |  [IPs]  |  upload_count
    """
    # 1. keep only successfully uploaded files
    #  using mask to filter out failed operations
    ok_mask = df["response_code"].isin(FTP_OK)
    verb_mask = df["verb"].isin(UPLOAD_VERBS)
    df_ok_upl = df[ok_mask & verb_mask]

    # 2. aggregate per file and count number of times uploaded
    g = (
        df_ok_upl
        .groupby("arg", dropna=True)
        .agg(
            ips=("ip_address", lambda x: list(pd.unique(x))),
            upload_count=("ip_address", "count"),
        )
        .reset_index(names="file")
        .sort_values("upload_count", ascending=False, ignore_index=True)
    )

    return g


@timing
@st.cache_data(show_spinner=False)
def command_histogram(df: pd.DataFrame) -> pd.DataFrame:
    """
    Create a histogram of the commands present in the log.
    Return DataFrame: verb | count (sorted desc).
    """
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

    df["timestamp"] = pd.to_datetime(
        df["timestamp"], format="%d/%b/%Y:%H:%M:%S %z", errors="coerce"
    )

    df[["verb", "arg"]] = df["command"].str.extract(r"(\w+)\s*(.*)", expand=True)
    df["verb"] = df["verb"].str.upper()

    # creating new column with cleaned user_id, i.e., without the PID or session number in name
    df["clean_user"] = df["user_id"].apply(clean_username)
    return df

@timing
@st.cache_data(show_spinner=False)
def build_ip_profiles(df: pd.DataFrame, ip_list: List[str]) -> Dict[str, dict]:
    """
    Build IP profiles.
    Return a dictionary of dictionaries, where each key is an IP address
    and the value is a dictionary with the following keys:
    • users: list of unique users
    • first_seen: timestamp of the first event
    • last_seen: timestamp of the last event
    • command_mix: dictionary with the count of each command
    • uploads: list of files uploaded
    • downloads: list of files downloaded
    """
    profiles = {}
    for ip, group in df[df.ip_address.isin(ip_list)].groupby("ip_address"):
        # mask to filter out failed operations
        ok_resp_code = group["response_code"].isin(FTP_OK)

        # Uploads: STOR / SITE + success response code
        uploads = group[group.verb.isin(UPLOAD_VERBS) & ok_resp_code]["arg"].dropna() #.tolist()
        
        # Downloads: RETR + success response code
        downloads = group[group.verb.isin(DOWNLOAD_VERBS) & ok_resp_code]["arg"].dropna() #.tolist()

        profiles[ip] = {
            "users": group["user_id"].dropna().unique().tolist(),
            "first_seen": group["timestamp"].min(),
            "last_seen": group["timestamp"].max(),
            "command_mix": group["verb"].value_counts().to_dict(),
            "uploads_success":uploads.value_counts().to_dict(), 
            "downloads_success": downloads.value_counts().to_dict(),
        }
    return profiles

@st.cache_data(show_spinner=False)
def clean_username(user_id: str) -> str:
    """
    Strip .PID or session-number suffix from username.
    That is, john.1234 and john.5678 will be treated as 
     unique user → john
    Or: test.ttt.123 → test.ttt
    
    Returns empty string if user_id is NaN. Otherwise, 
    returns the cleaned username.
    """
    if pd.isna(user_id):
        return ""
    return re.sub(r"\.\d+$", "", str(user_id).strip())


@st.cache_data(show_spinner=False)
def build_user_profiles(df: pd.DataFrame) -> Dict[str, dict]:
    return _build_user_profiles_fast(df)

@timing
@st.cache_data(show_spinner=False)
def _build_user_profiles_fast(df: pd.DataFrame) -> Dict[str, dict]:
    """
    Build user profiles using vectorised operations to speed things up.
    Return a dictionary of dictionaries, where each key is a username
    and the value is a dictionary with the following keys:
    • ips: list of unique IPs
    • first_seen: timestamp of the first event
    • last_seen: timestamp of the last event
    • command_mix: dictionary with the count of each command
    • uploads: list of files uploaded
    • downloads: list of files downloaded
    """
    df = df.copy()
    # mask to filter out the failed operations
    ok_resp_code = df["response_code"].isin(FTP_OK)

    # remove the failed upload/donwload operations and display only the successful ones
    df["is_upload"]   = df["verb"].isin(UPLOAD_VERBS) & ok_resp_code
    df["is_download"] = df["verb"].isin(DOWNLOAD_VERBS) & ok_resp_code
 
    grouped = df.groupby("clean_user", dropna=True).agg(
        ips            = ("ip_address",  lambda x: x.dropna().value_counts().to_dict()), # ordered by number of occurrences
        first_seen     = ("timestamp",   "min"),
        last_seen      = ("timestamp",   "max"),
        command_mix    = ("verb",        lambda x: x.value_counts().to_dict()),
        uploads_success        = ("arg",         lambda s: s[df.loc[s.index, "is_upload"]  ].dropna().value_counts().to_dict()), # .tolist()),
        downloads_success      = ("arg",         lambda s: s[df.loc[s.index, "is_download"]].dropna().value_counts().to_dict()), # .tolist()),
    )
 
    profiles = {str(u).strip(): row.to_dict() for u, row in grouped.iterrows()}
    return profiles



#  User Activity History functionality
@timing
@st.cache_data(show_spinner=False)
def user_event_history(df: pd.DataFrame, user: str) -> pd.DataFrame:
    """
    Return user’s actions, chronological, with cleaned username logic.
    Returns a DataFrame with the following columns:
    • timestamp
    • IP
    • command
    • verb
    • file
    • response_code
    """
    clean = clean_username(user)
    hist = (
        df[df["clean_user"] == clean] # use the pre-cleaned column
          .sort_values("timestamp")[
              ["timestamp", "ip_address", "command", "verb", "arg", "response_code"]
          ]
          .rename(columns={
              "arg": "file",
              "ip_address": "IP",
          })
          .reset_index(drop=True)
    )
    return hist

# IP Activity History functionality
@timing
@st.cache_data(show_spinner=False)
def ip_event_history(df: pd.DataFrame, ip: str) -> pd.DataFrame:
    """
    Return IP’s actions, chronological.
    Returns a DataFrame with the following columns:
    • timestamp
    • user
    • command
    • verb
    • file
    • response_code
    """
    hist = (
        df[df["ip_address"] == ip]
          .sort_values("timestamp")[
              ["timestamp", "user_id", "command", "verb", "arg", "response_code"]
          ]
          .rename(columns={
              "arg": "file",
              "user_id": "user",
              #"response_code": "resp"
          })
          .reset_index(drop=True)
    )
    return hist

# File to actor mapping
@timing
@st.cache_data(show_spinner=False)
def file_to_actor_map(df: pd.DataFrame):
    """
    Creates a dictionary mapping of file paths to their associated access events in the FTP log.

    NOTE: it only processes rows where verb is one of: 'STOR', 'RETR', 'SITE'. 
        If needed, add more verbs to the set
    """
    fmap = defaultdict(list)
    rows = df[df.verb.isin({"STOR", "RETR", "SITE"})]
    for _, r in rows.iterrows():
        fmap[r["arg"]].append(
            {
                "timestamp": r["timestamp"],
                "ip": r["ip_address"],
                "user": r["user_id"],
                "action": r["verb"],
                "response_code": r["response_code"],
            }
        )
    return dict(fmap)
 

# ──────────────────────────
#       STREAMLIT UI
# ──────────────────────────
st.set_page_config(page_title="🦥 SlothLog-FTP", layout="wide")
st.title("🦥 SlothLog-FTP Dashboard")

uploaded = st.file_uploader("Upload the Excel log file", type=["xlsx", "xls"])
if not uploaded:
    st.info("👈 Please upload an Excel file to begin.")
    st.stop()

# ---- enumerate worksheets (consumes stream) ----
xls = pd.ExcelFile(uploaded)
sheet_names = xls.sheet_names

with st.sidebar:
    st.header("Worksheet")
    st.caption("Select the worksheet to load")
    sheet_choice = st.selectbox("Select sheet", options=sheet_names, index=0)


uploaded.seek(0)
with st.spinner("Parsing log …", show_time=True):
    try:
        df = load_log(uploaded, sheet_name=sheet_choice)
    except Exception as e:
        st.error(f"[!] Error while loading file \"{uploaded.name}:{sheet_choice}\": {e}")
        print("[!] Error: while loading file", e)
        st.stop()
# ───────── Dashboard metrics ─────────
col1, col2, col3 = st.columns(3)
col1.metric("Total log lines", len(df))
col2.metric("Unique IPs", df["ip_address"].nunique())
col3.metric("Time span", f"{df['timestamp'].min()}\n → {df['timestamp'].max()}")


# array of unique IPs in the log
ip_list = df["ip_address"].dropna().unique().tolist()

# ───────── Noisy-IP manager ─────────
if "noisy_ips" not in st.session_state:
    st.session_state.noisy_ips = set()

with st.sidebar:
    st.subheader("Suppress noisy hosts")
    new_noisy = st.multiselect(
        "Choose hosts to ignore in Raw Log table",
        options=ip_list,
        default=list(st.session_state.noisy_ips),
        help="Hosts to not be displayed for analysis in Raw Log Table" \
    )

st.session_state.noisy_ips = set(new_noisy)

# ───────── Build insights (post-filter) ─────────
ip_profiles   = build_ip_profiles(df, ip_list)
file_map      = file_to_actor_map(df)
user_profiles = build_user_profiles(df)
all_users     = sorted(user_profiles.keys())    # list for the dropdown


# ───────── Sidebar filters & Geo-IP ─────────
with st.sidebar:
    # Filter panel
    st.markdown("---")
    st.header("Filters")
    st.caption("Select the host, file or user to investigate")
    ip_selected = st.selectbox("Investigate host", ["—"] + ip_list, help="Host to analyze. Note: downloads and " \
    "uploads only include the successful ones.")
    file_selected = st.selectbox("Investigate File", ["—"] + sorted(file_map))
    user_selected = st.selectbox("Investigate User", ["—"] + all_users, help="User to analyze. Note: downloads and " \
    "uploads only include the successful ones.")


    # ─────────  Verb panel  ─────────
    st.markdown("---")
    verbs = sorted(df["verb"].dropna().unique())
    with st.sidebar.expander("Verb filter", expanded=False):
        selected_verbs = st.multiselect(
        "Commands",
        verbs,
        default=verbs,
        label_visibility="collapsed",
    )
    

    #  ─────────  Geo-IP panel  ─────────
    if ip_selected != "—":
        st.markdown("---")
        # getting geo-IP info for ip_selected
        info = geo_lookup(ip_selected)
        print("[D] Geo-IP info:", info)
        if info:
            ip_clean = re.sub(r"[^\w\s\.\-]", "", ip_selected)
            country = re.sub(r"[^\w\s\.\-]", "", info.get('country','-'))
            org  = re.sub(r"[^\w\s\.\-]", "", info.get('org','-'))
            city = re.sub(r"[^\w\s\.\-]", "", info.get('city','-'))
            flag = f":flag-{country.lower()}:" if country else ""

            st.markdown(
                f"**Geo-IP:** {flag}  {ip_clean}<br>"
                f"**Org:** {org}<br>"
                f"**City:** {city}",
                unsafe_allow_html=True,
            )
        else:
            st.markdown(f"**Geo-IP:** {ip_selected} (no info found)")

    st.markdown("---")

    # ─────────  Quick operations panel ─────────
    st.header("Quick Operations")

    op_choice = st.selectbox(
        "Pick an analysis",
        options=[
        "—",
        "Downloaded files ↔ IPs",
        "Uploaded files ↔ IPs",
        "Command histogram for all",
        "User activity history",
        "Host activity history",
        ],
    )


# ─────────  Main pane  ─────────
if ip_selected != "—":
    st.subheader(f"💻 Profile for host {ip_selected}")
    try:
        st.json(ip_profiles[ip_selected])
        ip_profile = ip_profiles[ip_selected]
        # adding ip address to its profile so that it can be downloaded
        #   in the JSON file 
        ip_profile["ip"] = ip_selected

        # button to download the profile as JSON
        ip_profile_json = json.dumps(ip_profile, indent=2, default=str)
        st.download_button(
            label="📥 Download IP Profile as JSON",
            data=ip_profile_json,
            file_name=f"profile_ip_{ip_selected}.json",
            mime="application/json",
        )
    except Exception as e:
        st.error(f"[!] Error while loading profile for host {ip_selected}: {e}")

if file_selected != "—":
    st.subheader(f"Touch-points for file {file_selected}")
    try:
        st.table(pd.DataFrame(file_map[file_selected]))
    except Exception as e:
        st.error(f"[!] Error while loading touch-points for file {file_selected}: {e}")

if user_selected != "—":
    st.subheader(f"👤 Profile for user **{user_selected}**")
    try:
        st.json(user_profiles[user_selected])
        user_profile = user_profiles[user_selected]
        profile_json = json.dumps(user_profile, indent=2, default=str)

        # button to download the profile as JSON
        st.download_button(
            label="📥 Download User Profile as JSON",
            data=profile_json,
            file_name=f"profile_user_{user_selected}.json",
            mime="application/json",
        )
    except Exception as e:
        st.error(f"[!] Error while loading profile for user {user_selected}: {e}")


if op_choice != "—":
    st.markdown(f"### 🔍 {op_choice}")

    # 1️⃣ Downloaded files ↔ IPs
    if op_choice == "Downloaded files ↔ IPs":
        dl_map = build_downloads_map(df)
        st.dataframe(dl_map, use_container_width=True)

        csv_bytes = dl_map.to_csv(index=False).encode()
        st.download_button(
            "📥 Download CSV",
            data=csv_bytes,
            file_name="downloaded_files_ips.csv",
            mime="text/csv",
        )

    # 2️⃣ Uploaded files ↔ IPs
    elif op_choice == "Uploaded files ↔ IPs":
        up_map = build_uploads_map(df)
        st.dataframe(up_map, use_container_width=True)

        csv_bytes = up_map.to_csv(index=False).encode()
        st.download_button(
            "📥 Download CSV",
            data=csv_bytes,
            file_name="uploaded_files_ips.csv",
            mime="text/csv",
        )

    # 3️⃣  Command histogram
    elif op_choice == "Command histogram for all":
        cmd_hist = command_histogram(df)
        cmd_hist = cmd_hist[cmd_hist["verb"].isin(FTP_COMMANDS)]
        chart = (
            alt.Chart(cmd_hist)
            .mark_bar()
            .encode(
                x=alt.X("verb:N", sort="-y", title="FTP Command"),
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

    # 4️⃣  User activity history
    elif op_choice == "User activity history":
        if user_selected == "—":
            st.warning("Select a user to investigate in the sidebar first.")
        else:
            hist = user_event_history(df, user_selected)
            st.markdown(f"### 📜 Activity history for **{user_selected}** "f"({len(hist)} actions)")
            st.dataframe(hist, use_container_width=True)

            # mini-timeline
            # NOTE: the timestamp showed can be different from the logs due to
            #  a timezone conversion made implicitly by altair.
            chart = (
                alt.Chart(hist)
                .mark_tick()
                .encode(
                   x="timestamp:T",
                   y=alt.Y("verb:N", sort="-x"),
                   color="verb:N",
                   tooltip=["timestamp", "verb", "file", "IP", "response_code"]
                   ))
            st.altair_chart(chart, use_container_width=True)

            # export CSV/JSON buttons
            st.download_button(
                "📥 Download CSV",
                data=hist.to_csv(index=False),
                file_name=f"user_history_{user_selected}.csv",
                mime="text/csv",
                )
            st.download_button(
                "📥 Download JSON",
                data=hist.to_json(orient="records", date_format="iso"),
                file_name=f"user_history_{user_selected}.json",
                mime="application/json",
                )

    # 5️⃣  Host activity history
    elif op_choice == "Host activity history":
        if ip_selected == "—":
            st.warning("Select a host to investigate in the sidebar first.")
        else:
            hist = ip_event_history(df, ip_selected)
            st.markdown(f"### 📜 Activity history for **{ip_selected}** "f"({len(hist)} actions)")
            st.dataframe(hist, use_container_width=True)

            # mini-timeline
            chart = (
                alt.Chart(hist)
                .mark_tick()
                .encode(
                   x="timestamp:T",
                   y=alt.Y("verb:N", sort="-x"),
                   color="verb:N",
                   tooltip=["timestamp", "verb", "file", "user", "response_code"]
                   ))
            st.altair_chart(chart, use_container_width=True)

            # export CSV/JSON buttons
            st.download_button(
                "📥 Download CSV",
                data=hist.to_csv(index=False),
                file_name=f"ip_history_{ip_selected}.csv",
                mime="text/csv",
                )
            st.download_button(
                "📥 Download JSON",
                data=hist.to_json(orient="records", date_format="iso"),
                file_name=f"ip_history_{ip_selected}.json",
                mime="application/json",
                )


st.subheader("Raw Log (filtered)")

#### Creating Raw Log table ####
filtered = df[df["verb"].isin(selected_verbs)]

#filtering noisy IPs out
if st.session_state.noisy_ips:
    filtered = filtered[~filtered["ip_address"].isin(st.session_state.noisy_ips)]
if ip_selected != "—":
    filtered = filtered[filtered["ip_address"] == ip_selected]
    if ip_selected in st.session_state.noisy_ips:
        st.warning(f"Host {ip_selected} is in the noisy hosts list, so it will not be displayed in the Raw Log table.")
if file_selected != "—":
    filtered = filtered[filtered["arg"] == file_selected]
if user_selected != "—":
    filtered = filtered[filtered["user_id"].apply(clean_username) == user_selected] 

st.dataframe(filtered.sort_values(by="timestamp"), use_container_width=True)
