import logging

# --- Configure Logging ---
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')
logger = logging.getLogger(__name__)

import dash
import dash_bootstrap_components as dbc
from dash import dcc, html, dash_table, Input, Output, State, callback, ctx
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
import numpy as np
import re
from datetime import datetime, timedelta
import io
import base64 # For embedding images in HTML report
from collections import Counter
import requests
import time
import ipaddress
from user_agents import parse
import kaleido # For exporting plotly charts to static images

# --- MAPBOX Configuration ---
MAPBOX_ACCESS_TOKEN = "YOUR_MAPBOX_ACCESS_TOKEN"
if MAPBOX_ACCESS_TOKEN == "YOUR_MAPBOX_ACCESS_TOKEN":
    MAPBOX_ACCESS_TOKEN = None

# Regex for NGINX log parsing
LOG_REGEX = re.compile(
    r'^(?P<ip_address>\S+) (?P<ident>\S+) (?P<user>\S+) '
    r'\[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>[^"\s]*) (?P<protocol>HTTP/\d\.\d)" '
    r'(?P<status_code>\d{3}) (?P<response_size>\d+) '
    r'"(?P<referrer>[^"]*)" "(?P<user_agent_string>[^"]*)"$'
)

# --- IP Geolocation Cache ---
ip_geocache = {}

# --- Helper Functions ---
def parse_log_line(line):
    match = LOG_REGEX.match(line)
    if match:
        data = match.groupdict()
        try:
            data['timestamp'] = datetime.strptime(data['timestamp'], '%d/%b/%Y:%H:%M:%S %z')
        except ValueError:
            data['timestamp'] = datetime.strptime(data['timestamp'], '%d/%b/%Y:%H:%M:%S')
        data['status_code'] = int(data['status_code'])
        data['response_size'] = int(data['response_size'])
        
        ua_string = data.get('user_agent_string', '')
        user_agent = parse(ua_string)
        data['browser_family'] = user_agent.browser.family
        data['browser_version'] = user_agent.browser.version_string # Keep for potential future use
        data['os_family'] = user_agent.os.family
        data['device_family'] = user_agent.device.family # Keep for potential future use
        data['is_bot'] = user_agent.is_bot
        
        if data['referrer'] == "-" or not data['referrer']:
            data['referrer_domain'] = "Direct/Unknown"
        else:
            try:
                # Extract domain: scheme://domain.tld/... -> domain.tld
                domain_match = re.match(r'https?://(?:www\.)?([^/]+)', data['referrer'])
                if domain_match:
                    data['referrer_domain'] = domain_match.group(1)
                else:
                    data['referrer_domain'] = "Other/Invalid" # If regex doesn't match expected format
            except Exception: # General catch-all if regex or access fails
                data['referrer_domain'] = "ErrorParsingReferrer"
        return data
    return None

def parse_log_content(content_string, filename):
    logger.info(f"Starting to parse log file: {filename}")
    if content_string is None:
        logger.warning("parse_log_content called with no content.")
        return pd.DataFrame(), "No file uploaded."
    try:
        content_type, content_data = content_string.split(',')
        decoded = base64.b64decode(content_data)
        log_text = decoded.decode('utf-8')
    except Exception as e:
        logger.error(f"Error decoding file {filename}: {e}", exc_info=True) # exc_info logs traceback
        return pd.DataFrame(), f"Error decoding file: {e}"
    
    lines = log_text.splitlines()
    parsed_data = []
    malformed_lines = 0
    logger.info(f"Processing {len(lines)} lines from {filename}.")
    for i, line in enumerate(lines):
        if (i + 1) % 1000 == 0: # Log progress every 1000 lines
            logger.info(f"Parsing line {i+1}/{len(lines)} of {filename}...")
        if line.strip():
            parsed_line = parse_log_line(line)
            if parsed_line:
                parsed_data.append(parsed_line)
            else:
                malformed_lines += 1
                
    df = pd.DataFrame(parsed_data)
    status_message = f"Successfully parsed '{filename}'. {len(df)} lines processed."
    if malformed_lines > 0:
        status_message += f" {malformed_lines} lines were malformed and skipped."
        logger.warning(f"{malformed_lines} malformed lines in {filename}.")
    logger.info(f"Finished parsing {filename}. {len(df)} valid entries. {malformed_lines} malformed.")
    if df.empty and not parsed_data: # if all lines were malformed or file was empty
        status_message = f"Uploaded file '{filename}' contained no valid log entries."
    return df, status_message

def is_public_ip(ip_str):
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return not (ip_obj.is_private or 
                    ip_obj.is_loopback or 
                    ip_obj.is_link_local or 
                    ip_obj.is_multicast or 
                    ip_obj.is_reserved)
    except ValueError:
        return False

def geolocate_ip(ip_address):
    if not is_public_ip(ip_address):
        return {"ip": ip_address, "status": "private_or_reserved", "lat": None, "lon": None, "country": "N/A", "city": "N/A"}
    if ip_address in ip_geocache:
        return ip_geocache[ip_address]
    
    geo_data = {"ip": ip_address, "status": "error", "lat": None, "lon": None, "country": "Error", "city": "Error"}
    try:
        response = requests.get(f"http://ip-api.com/json/{ip_address}?fields=status,message,country,city,lat,lon,query", timeout=3)
        response.raise_for_status() 
        data = response.json()
        if data.get("status") == "success":
            geo_data = {
                "ip": data.get("query"), 
                "status": "success",
                "lat": data.get("lat"),
                "lon": data.get("lon"),
                "country": data.get("country", "N/A"),
                "city": data.get("city", "N/A")
            }
    except Exception:
        # Keep geo_data as error state if API fails
        pass 
    ip_geocache[ip_address] = geo_data
    time.sleep(1.4) # Be slightly more aggressive: ~42 req/min
    return geo_data

# --- Anomaly Detection Functions ---
def detect_error_bursts(df, time_window_minutes=1, threshold_factor=2.0, min_errors=3):
    if df.empty or 'timestamp' not in df.columns or 'status_code' not in df.columns:
        return []
    errors_df = df[df['status_code'] >= 400].copy()
    if errors_df.empty:
        return []
    errors_df['timestamp'] = pd.to_datetime(errors_df['timestamp'])
    errors_df.set_index('timestamp', inplace=True)
    error_counts_per_window = errors_df['status_code'].resample(f'{time_window_minutes}min').count()
    if error_counts_per_window.empty:
        return []
    
    mean_errors = error_counts_per_window.mean()
    std_errors = error_counts_per_window.std()
    dynamic_threshold = mean_errors + float(threshold_factor) * (std_errors if pd.notna(std_errors) else 0)
    current_threshold = max(float(min_errors), dynamic_threshold)
    
    bursts = []
    for period_start, count in error_counts_per_window.items():
        if count >= current_threshold:
            period_end = period_start + timedelta(minutes=time_window_minutes)
            burst_details_df = errors_df[(errors_df.index >= period_start) & (errors_df.index < period_end)]
            bursts.append({
                "time_period": f"{period_start.strftime('%Y-%m-%d %H:%M')} - {period_end.strftime('%H:%M')}",
                "error_count": count, 
                "ips_involved_count": burst_details_df['ip_address'].nunique(),
                "status_codes": dict(Counter(burst_details_df['status_code'].astype(str))), # For display
                "threshold_exceeded": f"{count} errors >= threshold ({current_threshold:.2f})"
            })
    return bursts

def detect_high_traffic_ips(df, threshold_factor=2.0, min_requests=10):
    if df.empty or 'ip_address' not in df.columns:
        return []
    ip_counts = df['ip_address'].value_counts()
    if ip_counts.empty:
        return []
    mean_requests = ip_counts.mean()
    std_requests = ip_counts.std()
    dynamic_threshold = mean_requests + threshold_factor * (std_requests if pd.notna(std_requests) else 0)
    current_threshold = max(min_requests, dynamic_threshold)
    
    anomalous_ips = []
    for ip, count in ip_counts.items():
        if count >= current_threshold:
            anomalous_ips.append({
                "ip_address": ip, 
                "request_count": count,
                "detail": f"{count} requests > threshold ({current_threshold:.2f})"
            })
    return anomalous_ips

# --- Initialize Dash App ---
app = dash.Dash(__name__, external_stylesheets=[dbc.themes.LUX, dbc.icons.FONT_AWESOME])
server = app.server

ANOMALIES_PER_PAGE = 10 # For pagination

# --- App Layout ---
app.layout = dbc.Container(fluid=True, children=[
    dcc.Store(id='log-data-store'),
    dcc.Store(id='filtered-log-data-store'),
    dcc.Store(id='error-bursts-page-store', data=1), 
    dcc.Store(id='high-traffic-ips-page-store', data=1),
    dcc.Store(id='full-error-bursts-store'), 
    dcc.Store(id='full-high-traffic-ips-store'),

    # ... (Header, Upload, Filters, Summary Cards - largely same layout as before)
    dbc.Row(dbc.Col(html.H1("NGINX Log Anomaly Dashboard", className="text-center my-4"))),
    dbc.Row([dbc.Col([ dcc.Upload(id='upload-log-file', children=html.Div(['Drag and Drop or ', html.A('Select NGINX Log File')]), style={'width': '100%', 'height': '60px', 'lineHeight': '60px', 'borderWidth': '1px', 'borderStyle': 'dashed', 'borderRadius': '5px', 'textAlign': 'center', 'margin': '10px 0'}, multiple=False), 
                      dcc.Loading(
                        id="loading-parse",
                        type="circle", # or "default", "cube", "dot"
                        children=[html.Div(id='upload-status', className="mt-2")] 
                        # If you want to show loading over more content, include that content here or in a parent Div
                    )
                ], width=12)
            ], className="mb-3"),
    dbc.Row([ dbc.Col(dcc.DatePickerRange(id='date-picker-range', min_date_allowed=datetime(2000, 1, 1).date(), max_date_allowed=datetime.now().date() + timedelta(days=1), start_date_placeholder_text="Start Date", end_date_placeholder_text="End Date", className="mb-2"), width=12, lg=3), dbc.Col(dcc.Dropdown(id='hour-filter-dropdown', placeholder="Filter by Hour(s)", multi=True, options=[{'label': f'{h:02}:00-{h:02}:59', 'value': h} for h in range(24)], className="mb-2"), width=12, lg=2), dbc.Col(dcc.Dropdown(id='ip-filter-dropdown', placeholder="Filter by IP", multi=True, className="mb-2"), width=12, lg=3), dbc.Col(dcc.Dropdown(id='status-code-filter-dropdown', placeholder="Filter by Status", multi=True, className="mb-2"), width=12, lg=2), dbc.Col(html.Button("Apply Filters", id="apply-filters-button", n_clicks=0, className="btn btn-info w-100"), width=12, lg=2)], className="mb-3 bg-light p-3 border rounded"),
    dbc.Row([dbc.Col(dbc.Card(dbc.CardBody([html.H4(id='total-requests-card', className="card-title"), html.P("Total Requests")])),width=6,md=3,className="mb-2"), dbc.Col(dbc.Card(dbc.CardBody([html.H4(id='unique-ips-card', className="card-title"), html.P("Unique IPs")])),width=6,md=3,className="mb-2"), dbc.Col(dbc.Card(dbc.CardBody([html.H4(id='error-rate-card', className="card-title"), html.P("Error Rate (4xx/5xx)")])),width=6,md=3,className="mb-2"), dbc.Col(dbc.Card(dbc.CardBody([html.H4(id='avg-response-size-card', className="card-title"), html.P("Avg. Resp. Size")])),width=6,md=3,className="mb-2")], className="mb-3"),
    dbc.Row([dbc.Col(dcc.Graph(id='requests-over-time-chart'),width=12,lg=6,className="mb-3"), dbc.Col(dcc.Graph(id='status-code-dist-chart'),width=12,lg=6,className="mb-3")]), dbc.Row([dbc.Col(dcc.Graph(id='top-ips-chart'),width=12,lg=6,className="mb-3"), dbc.Col(dcc.Graph(id='top-paths-chart'),width=12,lg=6,className="mb-3")]), dbc.Row([dbc.Col(dcc.Graph(id='http-methods-chart'),width=12,lg=4,className="mb-3"), dbc.Col(dcc.Graph(id='browser-dist-chart'),width=12,lg=4,className="mb-3"), dbc.Col(dcc.Graph(id='os-dist-chart'),width=12,lg=4,className="mb-3")]), dbc.Row([dbc.Col(dcc.Graph(id='human-vs-bot-chart'),width=12,lg=4,className="mb-3"), dbc.Col(dcc.Graph(id='top-referrers-chart'),width=12,lg=4,className="mb-3"), dbc.Col(dcc.Graph(id='response-size-dist-chart'),width=12,lg=4,className="mb-3")]), dbc.Row([dbc.Col(dbc.Card([dbc.CardHeader(html.H5("IP Geolocation Map (Public IPs in Filtered View)",className="card-title")), dbc.CardBody([dcc.Loading(id="loading-map",type="default",children=[dcc.Graph(id='ip-location-map-chart',style={'height':'450px'})])])]),width=12,className="mb-3")]),


    dbc.Row([ # Anomalies Section with dbc.Pagination
        dbc.Col([
            html.H3("Detected Anomalies (entire dataset)", className="mt-4 mb-3"),
            dbc.Row([
                dbc.Col(dbc.Label("Error Burst Factor:"), width="auto"),
                dbc.Col(dcc.Input(id='error-burst-threshold-factor-input', type='number', value=2.0, step=0.1, min=1.0, className="form-control form-control-sm"), width=2),
                dbc.Col(dbc.Label("Min Errors:"), width="auto"),
                dbc.Col(dcc.Input(id='error-burst-min-errors-input', type='number', value=3, step=1, min=1, className="form-control form-control-sm"), width=2),
            ], className="mb-2 align-items-center"),
            
            html.Div([
                html.H5("Error Bursts", className="mt-2"),
                html.Div(id='anomaly-error-bursts-div'),
                dbc.Pagination(id='eb-pagination', max_value=1, first_last=True, previous_next=True, size="sm", className="mt-1 mb-3 justify-content-center")
            ]),
            html.Div([
                html.H5("High Traffic IPs", className="mt-2"),
                html.Div(id='anomaly-high-traffic-ips-div'),
                dbc.Pagination(id='htip-pagination', max_value=1, first_last=True, previous_next=True, size="sm", className="mt-1 mb-3 justify-content-center")
            ]),
        ], width=12)
    ], className="mb-3"),
    
    # ... (Data Table and Export Section - layout same)
    dbc.Row([dbc.Col([html.H3("Log Data Table (Filtered)", className="mt-4 mb-3"), dbc.Row([ dbc.Col(html.Button([html.I(className="fas fa-download mr-2"), " Export Filtered Data (CSV)"], id="export-csv-button", className="btn btn-primary mb-2", n_clicks=0), width="auto"), dbc.Col(html.Button([html.I(className="fas fa-file-alt mr-2"), " Export Summary Report (HTML)"], id="export-summary-button", className="btn btn-success mb-2", n_clicks=0), width="auto"), ]), dcc.Download(id="download-csv"), dcc.Download(id="download-summary-html"), html.Div(id='data-table-container', children=[ dash_table.DataTable( id='log-data-table', columns=[], page_size=10, style_table={'overflowX': 'auto'}, style_cell={'textAlign': 'left', 'minWidth': '100px', 'maxWidth': '300px', 'whiteSpace': 'normal', 'height': 'auto', 'padding': '5px'}, filter_action="native", sort_action="native", ) ]) ], width=12)], className="mb-3")
])

# --- Helper to create an empty figure ---
def create_empty_figure(message="No data"):
    layout = dict(
        template='plotly_white', 
        xaxis={"visible": False}, 
        yaxis={"visible": False}, 
        annotations=[dict(text=message, xref="paper", yref="paper", showarrow=False, font=dict(size=16))]
    )
    return go.Figure(layout=layout)

# --- Chart Generation Functions (to be used by main callback and HTML report) ---
# These functions will take a DataFrame (df_filtered) and return a Plotly figure
# This promotes reusability and makes the HTML report generation cleaner.

def generate_requests_over_time_chart(df):
    if df.empty: return create_empty_figure("No data for Requests Over Time")
    data = df.set_index('timestamp').resample('h').size().reset_index(name='count')
    fig = px.line(data, x='timestamp', y='count', title='Requests Over Time (Hourly)', markers=True)
    fig.update_layout(template='plotly_white')
    return fig

def generate_status_code_dist_chart(df):
    if df.empty: return create_empty_figure("No data for Status Codes")
    counts = df['status_code'].astype(str).value_counts().reset_index()
    counts.columns = ['status_code', 'count']
    fig = px.pie(counts, names='status_code', values='count', title='Status Code Distribution', hole=0.3)
    fig.update_layout(template='plotly_white')
    return fig

def generate_top_ips_chart(df, top_n=10):
    if df.empty: return create_empty_figure(f"No data for Top {top_n} IPs")
    data = df['ip_address'].value_counts().nlargest(top_n).reset_index()
    data.columns = ['ip_address', 'count']
    fig = px.bar(data, x='ip_address', y='count', title=f'Top {top_n} IP Addresses')
    fig.update_layout(template='plotly_white')
    return fig

def generate_top_paths_chart(df, top_n=10):
    if df.empty: return create_empty_figure(f"No data for Top {top_n} Paths")
    data = df['path'].value_counts().nlargest(top_n).reset_index()
    data.columns = ['path', 'count']
    data['short_path'] = data['path'].apply(lambda x: (x[:15] + '...') if len(x) > 18 else x)
    fig = px.bar(data, x='short_path', y='count', title=f'Top {top_n} Requested Paths',
                 hover_data={'path': True, 'short_path': False})
    fig.update_layout(template='plotly_white', xaxis_title="Path (truncated)")
    return fig
    
def generate_http_methods_chart(df):
    if df.empty: return create_empty_figure("No data for HTTP Methods")
    counts = df['method'].value_counts().reset_index()
    counts.columns = ['method', 'count']
    fig = px.pie(counts, names='method', values='count', title='HTTP Method Distribution', hole=0.3)
    fig.update_layout(template='plotly_white')
    return fig

def generate_browser_dist_chart(df, top_n=10):
    if df.empty or 'browser_family' not in df.columns: return create_empty_figure(f"No data for Top {top_n} Browsers")
    counts = df['browser_family'].value_counts().nlargest(top_n).reset_index()
    counts.columns = ['browser_family', 'count']
    fig = px.pie(counts, names='browser_family', values='count', title=f'Top {top_n} Browsers', hole=0.3)
    fig.update_layout(template='plotly_white')
    return fig

def generate_os_dist_chart(df, top_n=10):
    if df.empty or 'os_family' not in df.columns: return create_empty_figure(f"No data for Top {top_n} OS")
    counts = df['os_family'].value_counts().nlargest(top_n).reset_index()
    counts.columns = ['os_family', 'count']
    fig = px.pie(counts, names='os_family', values='count', title=f'Top {top_n} Operating Systems', hole=0.3)
    fig.update_layout(template='plotly_white')
    return fig

def generate_human_vs_bot_chart(df):
    if df.empty or 'is_bot' not in df.columns: return create_empty_figure("No data for Human vs. Bot")
    counts = df['is_bot'].value_counts().reset_index()
    counts.columns = ['is_bot', 'count']
    counts['label'] = counts['is_bot'].apply(lambda x: 'Bot' if x else 'Human')
    fig = px.pie(counts, names='label', values='count', title='Human vs. Bot Traffic', hole=0.3)
    fig.update_layout(template='plotly_white')
    return fig

def generate_top_referrers_chart(df, top_n=10):
    if df.empty or 'referrer_domain' not in df.columns: return create_empty_figure(f"No data for Top {top_n} Referrers")
    counts = df['referrer_domain'].value_counts().nlargest(top_n).reset_index()
    counts.columns = ['referrer_domain', 'count']
    fig = px.bar(counts, x='referrer_domain', y='count', title=f'Top {top_n} Referrer Domains')
    fig.update_layout(template='plotly_white')
    return fig

def generate_response_size_dist_chart(df):
    if df.empty: return create_empty_figure("No data for Response Size")
    fig = px.histogram(df, x="response_size", nbins=30, title="Response Size Distribution (Bytes)")
    fig.update_layout(template='plotly_white', yaxis_title="Frequency", xaxis_title="Response Size (Bytes)")
    return fig


# --- Callbacks ---
@app.callback(
    [Output('log-data-store', 'data'), Output('upload-status', 'children'),
     Output('date-picker-range', 'min_date_allowed'), Output('date-picker-range', 'max_date_allowed'),
     Output('date-picker-range', 'start_date'), Output('date-picker-range', 'end_date'),
     Output('ip-filter-dropdown', 'options'), Output('ip-filter-dropdown', 'value'),
     Output('status-code-filter-dropdown', 'options'), Output('status-code-filter-dropdown', 'value'),
     Output('hour-filter-dropdown', 'value'),
     Output('error-bursts-page-store', 'data', allow_duplicate=True), # Allow duplicate for reset
     Output('high-traffic-ips-page-store', 'data', allow_duplicate=True)], # Allow duplicate for reset
    [Input('upload-log-file', 'contents')],
    [State('upload-log-file', 'filename')],
    prevent_initial_call=True 
)
def upload_and_parse_log(contents, filename):
    if contents is None:
        return (pd.DataFrame().to_dict('records'), "Please upload an NGINX access log file.",
                datetime(2000,1,1).date(), datetime.now().date(), None, None, [], None, [], None, None, 1, 1)
    logger.info(f"Upload received for file: {filename}. Initiating parsing.")
    df, status_msg = parse_log_content(contents, filename)
    if df.empty:
        return (pd.DataFrame().to_dict('records'), dbc.Alert(status_msg, color="warning", dismissable=True),
                datetime(2000,1,1).date(), datetime.now().date(), None, None, [], None, [], None, None, 1, 1)
    
    if 'timestamp' not in df.columns or df['timestamp'].isnull().all():
         return (pd.DataFrame().to_dict('records'), dbc.Alert(f"{status_msg} Could not parse timestamps.", color="danger", dismissable=True),
                datetime(2000,1,1).date(), datetime.now().date(), None, None, [], None, [], None, None, 1, 1)

    df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
    df.dropna(subset=['timestamp'], inplace=True)

    if df.empty:
        return (pd.DataFrame().to_dict('records'), dbc.Alert(f"{status_msg} No valid timestamps found after parsing.", color="danger", dismissable=True),
                datetime(2000,1,1).date(), datetime.now().date(), None, None, [], None, [], None, None, 1, 1)

    min_date = df['timestamp'].min().date()
    max_date = df['timestamp'].max().date()
    ip_options = [{'label': ip, 'value': ip} for ip in sorted(df['ip_address'].unique())]
    # Ensure status codes are strings for dropdown options if they are treated as strings by user
    status_options = [{'label': str(sc), 'value': sc} for sc in sorted(df['status_code'].unique())] 
    logger.info(f"Parsing complete for {filename}. Status: {status_msg}")
    return (df.to_dict('records'), dbc.Alert(status_msg, color="success", dismissable=True),
            min_date, max_date, min_date, max_date,
            ip_options, None, status_options, None, None, 1, 1) # Reset page stores


@app.callback(
    Output('filtered-log-data-store', 'data'),
    [Input('apply-filters-button', 'n_clicks')],
    [State('log-data-store', 'data'),
     State('date-picker-range', 'start_date'), State('date-picker-range', 'end_date'),
     State('hour-filter-dropdown', 'value'), 
     State('ip-filter-dropdown', 'value'), State('status-code-filter-dropdown', 'value')]
)
def filter_log_data(n_clicks, log_data_json, start_date_str, end_date_str, selected_hours, selected_ips, selected_status_codes_str):
    if not log_data_json or n_clicks == 0:
        # Return empty if button clicked and no data, else no_update
        return pd.DataFrame().to_dict('records') if n_clicks > 0 else dash.no_update 

    logger.info(f"Apply Filters button clicked (n_clicks={n_clicks}). Filtering data...")
    df = pd.DataFrame(log_data_json)
    if df.empty:
        return pd.DataFrame().to_dict('records')
    
    df['timestamp'] = pd.to_datetime(df['timestamp']) # Ensure datetime type
    
    # Apply date filters
    if start_date_str:
        filter_start_datetime = pd.to_datetime(start_date_str)
        # Localize if DataFrame timestamps are timezone-aware
        if df['timestamp'].dt.tz is not None:
            filter_start_datetime = filter_start_datetime.tz_localize(df['timestamp'].dt.tz)
        df = df[df['timestamp'] >= filter_start_datetime]
    
    if end_date_str:
        filter_end_datetime_exclusive = pd.to_datetime(end_date_str) + timedelta(days=1)
        if df['timestamp'].dt.tz is not None:
            filter_end_datetime_exclusive = filter_end_datetime_exclusive.tz_localize(df['timestamp'].dt.tz)
        df = df[df['timestamp'] < filter_end_datetime_exclusive]
    
    # Filter by hour
    if selected_hours:
        df = df[df['timestamp'].dt.hour.isin(selected_hours)]
        
    # Filter by IP
    if selected_ips:
        df = df[df['ip_address'].isin(selected_ips)]
    
    # Filter by Status Code (ensure conversion to int for comparison with df['status_code'])
    if selected_status_codes_str:
        try:
            # Dropdown might pass numbers as numbers or strings; DataFrame status_code is int
            selected_status_codes_int = [int(sc) for sc in selected_status_codes_str]
            df = df[df['status_code'].isin(selected_status_codes_int)]
        except ValueError:
            # Handle case where a non-integer string might be passed (shouldn't happen with current options)
            pass 

    logger.info(f"Filtering complete. {len(df) if not df.empty else 0} records after filtering.")        
    return df.to_dict('records')


@app.callback(
    [Output('total-requests-card', 'children'), Output('unique-ips-card', 'children'),
     Output('error-rate-card', 'children'), Output('avg-response-size-card', 'children'),
     Output('requests-over-time-chart', 'figure'), Output('status-code-dist-chart', 'figure'),
     Output('top-ips-chart', 'figure'), Output('top-paths-chart', 'figure'),
     Output('http-methods-chart', 'figure'), Output('browser-dist-chart', 'figure'), 
     Output('os-dist-chart', 'figure'), Output('human-vs-bot-chart', 'figure'), 
     Output('top-referrers-chart', 'figure'), Output('response-size-dist-chart', 'figure'),
     Output('log-data-table', 'data'), Output('log-data-table', 'columns'),
     Output('log-data-table', 'style_data_conditional'),
     Output('full-error-bursts-store', 'data'), Output('full-high-traffic-ips-store', 'data'),
     Output('eb-pagination', 'max_value'), Output('htip-pagination', 'max_value'),
     Output('eb-pagination', 'active_page', allow_duplicate=True), # For resetting page on filter change
     Output('htip-pagination', 'active_page', allow_duplicate=True)], # For resetting page on filter change
    [Input('filtered-log-data-store', 'data'), 
     Input('log-data-store', 'data'), 
     Input('error-burst-threshold-factor-input', 'value'), 
     Input('error-burst-min-errors-input', 'value')],
    prevent_initial_call=True
)
def update_dashboard_elements_and_calc_anomalies(filtered_log_data_json, original_log_data_json,
                                                 anomaly_thresh_factor, anomaly_min_errors):
    
    logger.info("Updating dashboard elements and calculating anomalies...")
    df_filtered = pd.DataFrame(filtered_log_data_json) if filtered_log_data_json else pd.DataFrame()
    df_original = pd.DataFrame(original_log_data_json) if original_log_data_json else pd.DataFrame()

    # --- Anomaly Calculation (always on original data) ---
    full_eb_list = []
    full_htip_list = []
    if not df_original.empty:
        df_original['timestamp'] = pd.to_datetime(df_original['timestamp']) # Ensure datetime
        full_eb_list = detect_error_bursts(df_original, 
                                           threshold_factor=float(anomaly_thresh_factor or 2.0), 
                                           min_errors=int(anomaly_min_errors or 3))
        full_htip_list = detect_high_traffic_ips(df_original) # Add dynamic thresholds if UI added

    eb_max_pages = (len(full_eb_list) + ANOMALIES_PER_PAGE - 1) // ANOMALIES_PER_PAGE if full_eb_list else 1
    htip_max_pages = (len(full_htip_list) + ANOMALIES_PER_PAGE - 1) // ANOMALIES_PER_PAGE if full_htip_list else 1
    
    # --- If no filtered data, show empty state for charts and table but anomalies are calculated ---
    if df_filtered.empty:
        no_data_msg = "No data matching filters" if ctx.triggered_id == 'filtered-log-data-store' and filtered_log_data_json is not None else "No data loaded"
        empty_fig_custom = create_empty_figure(no_data_msg)
        return (
            "0", "0", "0%", "0 B", 
            empty_fig_custom, empty_fig_custom, empty_fig_custom, empty_fig_custom,
            empty_fig_custom, empty_fig_custom, empty_fig_custom, empty_fig_custom,
            empty_fig_custom, empty_fig_custom,
            [], [], [], # Table
            full_eb_list, full_htip_list, # Full anomaly data
            eb_max_pages, htip_max_pages, # Pagination max values
            1, 1 # Reset active page for pagination
        )

    # --- Process Filtered Data ---
    df_filtered['timestamp'] = pd.to_datetime(df_filtered['timestamp']) # Ensure datetime

    # Summary Cards
    total_requests = len(df_filtered)
    unique_ips_count = df_filtered['ip_address'].nunique()
    error_count = df_filtered[df_filtered['status_code'] >= 400].shape[0]
    error_rate = (error_count / total_requests * 100) if total_requests > 0 else 0
    avg_response_size_bytes = df_filtered['response_size'].mean() if total_requests > 0 else 0
    avg_response_size_str = f"{avg_response_size_bytes:,.0f} B" # Simplified for brevity

    # Generate Charts using helper functions
    fig_req_time = generate_requests_over_time_chart(df_filtered)
    fig_status_dist = generate_status_code_dist_chart(df_filtered)
    fig_top_ips = generate_top_ips_chart(df_filtered)
    fig_top_paths = generate_top_paths_chart(df_filtered)
    fig_methods = generate_http_methods_chart(df_filtered)
    fig_browser_dist = generate_browser_dist_chart(df_filtered)
    fig_os_dist = generate_os_dist_chart(df_filtered)
    fig_human_bot = generate_human_vs_bot_chart(df_filtered)
    fig_top_referrers = generate_top_referrers_chart(df_filtered)
    fig_resp_size = generate_response_size_dist_chart(df_filtered)

    # Data Table
    df_display = df_filtered.copy()
    if pd.api.types.is_datetime64_any_dtype(df_display['timestamp']):
        # Format timestamp for display
        if df_display['timestamp'].dt.tz is not None:
            df_display['timestamp'] = df_display['timestamp'].dt.strftime('%Y-%m-%d %H:%M:%S %Z')
        else:
            df_display['timestamp'] = df_display['timestamp'].dt.strftime('%Y-%m-%d %H:%M:%S')
    
    # Define table columns, explicitly set 'status_code' to numeric for filtering
    table_cols = []
    for col in df_display.columns:
        if col not in ['browser_version', 'device_family']: # Example: exclude some less relevant columns
            col_def = {"name": col, "id": col}
            if col == 'status_code':
                col_def['type'] = 'numeric' # Important for native filtering
            table_cols.append(col_def)
            
    table_data = df_display.to_dict('records')
    style_data_conditional = [
        {'if': {'filter_query': '{status_code} >= 200 && {status_code} < 300'}, 'backgroundColor': '#d4edda', 'color': 'black'},
        {'if': {'filter_query': '{status_code} >= 300 && {status_code} < 400'}, 'backgroundColor': '#fff3cd', 'color': 'black'},
        {'if': {'filter_query': '{status_code} >= 400 && {status_code} < 500'}, 'backgroundColor': '#f8d7da', 'color': 'black'},
        {'if': {'filter_query': '{status_code} >= 500'}, 'backgroundColor': '#d6d8db', 'color': 'black'},
    ]

    return (
        f"{total_requests:,}", f"{unique_ips_count:,}", f"{error_rate:.2f}%", avg_response_size_str,
        fig_req_time, fig_status_dist, fig_top_ips, fig_top_paths, fig_methods,
        fig_browser_dist, fig_os_dist, fig_human_bot, fig_top_referrers, fig_resp_size,
        table_data, table_cols, style_data_conditional,
        full_eb_list, full_htip_list,
        eb_max_pages, htip_max_pages,
        1, 1 # Reset active page for pagination as filters changed
    )

@app.callback(
    Output('anomaly-error-bursts-div', 'children'),
    [Input('full-error-bursts-store', 'data'),
     Input('eb-pagination', 'active_page')]
)
def display_paginated_error_bursts(full_bursts_data, active_page):
    if not full_bursts_data:
        return dbc.Alert("No error bursts detected or data not loaded.", color="info", className="mb-1")
    
    active_page = active_page if active_page else 1 # Default to page 1
    start_index = (active_page - 1) * ANOMALIES_PER_PAGE
    end_index = start_index + ANOMALIES_PER_PAGE
    paginated_bursts = full_bursts_data[start_index:end_index]
    
    if not paginated_bursts: # Should not happen if active_page is managed correctly with max_value
        return dbc.Alert("No error bursts on this page.", color="light", className="mb-1")
        
    elements = [
        dbc.Alert(
            f"Period: {b['time_period']}, Errors: {b['error_count']}, IPs: {b['ips_involved_count']} ({b['threshold_exceeded']})", 
            color="warning", dismissable=False, className="mb-1 small"
        ) for b in paginated_bursts
    ]
    return elements

@app.callback(
    Output('anomaly-high-traffic-ips-div', 'children'),
    [Input('full-high-traffic-ips-store', 'data'),
     Input('htip-pagination', 'active_page')]
)
def display_paginated_high_traffic_ips(full_htip_data, active_page):
    if not full_htip_data:
        return dbc.Alert("No high traffic IPs detected or data not loaded.", color="info", className="mb-1")

    active_page = active_page if active_page else 1 # Default to page 1
    start_index = (active_page - 1) * ANOMALIES_PER_PAGE
    end_index = start_index + ANOMALIES_PER_PAGE
    paginated_htips = full_htip_data[start_index:end_index]

    if not paginated_htips:
        return dbc.Alert("No high traffic IPs on this page.", color="light", className="mb-1")

    elements = [
        dbc.Alert(
            f"IP: {ip_info['ip_address']}, Requests: {ip_info['request_count']} ({ip_info['detail']})", 
            color="danger", dismissable=False, className="mb-1 small"
        ) for ip_info in paginated_htips
    ]
    return elements

# Anomaly pagination active_page updates (from dbc.Pagination component)
@app.callback(
    Output('error-bursts-page-store', 'data'),
    [Input('eb-pagination', 'active_page')],
    prevent_initial_call=True
)
def update_eb_page_store(active_page):
    return active_page if active_page else 1

@app.callback(
    Output('high-traffic-ips-page-store', 'data'),
    [Input('htip-pagination', 'active_page')],
    prevent_initial_call=True
)
def update_htip_page_store(active_page):
    return active_page if active_page else 1


@app.callback(
    Output('ip-location-map-chart', 'figure'),
    [Input('filtered-log-data-store', 'data')]
)
def update_ip_map(filtered_log_data_json):
    # ... (update_ip_map logic from previous version, using go.Scattermap) ...
    empty_map_fig = go.Figure(data=[go.Scattermap(lat=[], lon=[])])
    empty_map_fig.update_layout(margin={"r":0,"t":0,"l":0,"b":0}, map_style="open-street-map", map_center={"lat":0,"lon":0},map_zoom=1, annotations=[{"text":"No IP data / geolocation failed.","align":"center","showarrow":False,"xref":"paper","yref":"paper","x":0.5,"y":0.5}])
    if not filtered_log_data_json: return empty_map_fig
    df_filtered = pd.DataFrame(filtered_log_data_json)
    if df_filtered.empty: return empty_map_fig
    unique_ips_in_filtered_view = df_filtered['ip_address'].unique()
    geo_locations_data = []
    if len(unique_ips_in_filtered_view) > 0:
        ips_to_process_for_map = unique_ips_in_filtered_view[:20] # Limit for performance
        for ip_addr in ips_to_process_for_map:
            loc_data = geolocate_ip(ip_addr)
            if loc_data and loc_data.get("status") == "success" and loc_data.get("lat") is not None: 
                geo_locations_data.append(loc_data)
        if geo_locations_data:
            geo_df = pd.DataFrame(geo_locations_data)
            ip_counts = df_filtered['ip_address'].value_counts().reset_index()
            ip_counts.columns=['ip','request_count']
            geo_df = pd.merge(geo_df, ip_counts, on='ip', how='left').fillna({'request_count':1})
            geo_df['marker_size'] = np.log1p(geo_df['request_count']) * 5 + 5 # Scale marker size
            
            fig_ip_map = go.Figure(data=[go.Scattermap(
                lat=geo_df['lat'], lon=geo_df['lon'], mode='markers', 
                marker=dict(size=geo_df['marker_size'],color="#007bff",opacity=0.7), 
                text=geo_df.apply(lambda r: f"IP: {r['ip']}<br>City: {r.get('city','N/A')}<br>Country: {r.get('country','N/A')}<br>Requests: {int(r['request_count'])}", axis=1), 
                hoverinfo='text'
            )])
            map_center_lat = geo_df['lat'].mean() if not geo_df.empty else 0
            map_center_lon = geo_df['lon'].mean() if not geo_df.empty else 0
            map_zoom = 1.5 if not geo_df.empty else 1

            fig_ip_map.update_layout(
                map_style="open-street-map", 
                map_center={"lat": map_center_lat, "lon": map_center_lon}, 
                map_zoom=map_zoom, 
                margin={"r":0,"t":0,"l":0,"b":0}
            )
            return fig_ip_map
    return empty_map_fig


@app.callback(
    Output("download-csv", "data"),
    Input("export-csv-button", "n_clicks"),
    [State("log-data-table", "derived_virtual_data"), 
     State("log-data-table", "derived_virtual_selected_rows"), # If you want to export only selected
     State("filtered-log-data-store", "data")], # Fallback
    prevent_initial_call=True,
)
def export_csv_data(n_clicks, table_virtual_data, selected_table_rows, main_filtered_data_json):
    if not n_clicks:
        raise dash.exceptions.PreventUpdate
    
    df_export = pd.DataFrame()
    
    # Prioritize data from the table as it's displayed (including native filters)
    if table_virtual_data:
        df_export = pd.DataFrame(table_virtual_data)
        # If you implement row selection in DataTable and want to export only selected:
        # if selected_table_rows and len(selected_table_rows) > 0:
        #     df_export = df_export.iloc[selected_table_rows]
    elif main_filtered_data_json: # Fallback to the data from the main filters
        df_export = pd.DataFrame(main_filtered_data_json)

    if df_export.empty:
        # Optionally, provide user feedback here (e.g., a dbc.Alert)
        raise dash.exceptions.PreventUpdate
        
    return dcc.send_data_frame(df_export.to_csv, f"nginx_log_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv", index=False)


@app.callback(
    Output("download-summary-html", "data"),
    Input("export-summary-button", "n_clicks"),
    [State('total-requests-card', 'children'), State('unique-ips-card', 'children'),
     State('error-rate-card', 'children'), State('avg-response-size-card', 'children'),
     State('full-error-bursts-store', 'data'), State('full-high-traffic-ips-store', 'data'),
     State('date-picker-range', 'start_date'), State('date-picker-range', 'end_date'),
     State('hour-filter-dropdown', 'value'), State('ip-filter-dropdown', 'value'),
     State('status-code-filter-dropdown', 'value'),
     State('filtered-log-data-store', 'data') # Needed to regenerate charts for the report
     ], 
    prevent_initial_call=True,
)
def export_summary_html_with_charts(n_clicks, total_req, unique_ip, err_rate, avg_size,
                                    error_bursts, high_traffic_ips,
                                    start_date, end_date, hours, ips, statuses_str,
                                    filtered_log_data_json_for_report):
    if not n_clicks:
        raise dash.exceptions.PreventUpdate

    df_report_filtered = pd.DataFrame(filtered_log_data_json_for_report) if filtered_log_data_json_for_report else pd.DataFrame()
    if not df_report_filtered.empty:
         df_report_filtered['timestamp'] = pd.to_datetime( df_report_filtered['timestamp'])


    html_content = "<html><head><title>NGINX Log Summary Report</title>"
    html_content += "<style>body{font-family: sans-serif; margin: 20px;} table{border-collapse: collapse; width: 80%; margin-bottom:20px; margin-left:auto; margin-right:auto;} th,td{border:1px solid #ddd; padding:8px; text-align:left;} th{background-color:#f2f2f2;} .chart-container{text-align:center; margin-bottom:30px;}</style>"
    html_content += "</head><body>"
    html_content += f"<h1 style='text-align:center;'>NGINX Log Summary Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</h1>"
    
    html_content += "<h2>Current Filter Settings:</h2><ul>"
    html_content += f"<li>Date Range: {start_date or 'N/A'} to {end_date or 'N/A'}</li>"
    html_content += f"<li>Hours: {', '.join(map(str, hours)) if hours else 'All'}</li>"
    html_content += f"<li>IPs: {', '.join(ips) if ips else 'All'}</li>"
    statuses_display = [str(s) for s in statuses_str] if statuses_str else ['All']
    html_content += f"<li>Status Codes: {', '.join(statuses_display)}</li></ul>"

    html_content += "<h2>Summary Statistics (based on filtered data):</h2><ul>"
    html_content += f"<li>Total Requests: {total_req}</li>"
    html_content += f"<li>Unique IPs: {unique_ip}</li>"
    html_content += f"<li>Error Rate: {err_rate}</li>"
    html_content += f"<li>Average Response Size: {avg_size}</li></ul>"

    # --- Embed Charts ---
    html_content += "<hr><h2>Charts (based on filtered data):</h2>"
    chart_functions = {
        "Requests Over Time": generate_requests_over_time_chart,
        "Status Code Distribution": generate_status_code_dist_chart,
        "Top IP Addresses": generate_top_ips_chart,
        "Top Requested Paths": generate_top_paths_chart,
        "HTTP Methods": generate_http_methods_chart,
        "Browser Distribution": generate_browser_dist_chart,
        "OS Distribution": generate_os_dist_chart,
        "Human vs. Bot": generate_human_vs_bot_chart,
        "Top Referrers": generate_top_referrers_chart,
        "Response Size Distribution": generate_response_size_dist_chart
    }

    for chart_title, chart_func in chart_functions.items():
        html_content += f"<div class='chart-container'><h3>{chart_title}</h3>"
        if not df_report_filtered.empty:
            try:
                fig = chart_func(df_report_filtered.copy()) # Pass a copy to avoid modification issues
                img_bytes = fig.to_image(format="png", engine="kaleido", width=700, height=450) # Adjust size as needed
                img_base64 = base64.b64encode(img_bytes).decode()
                html_content += f"<img src='data:image/png;base64,{img_base64}' alt='{chart_title}'/>"
            except Exception as e:
                html_content += f"<p><i>Error generating chart '{chart_title}': {e}</i></p>"
        else:
            html_content += "<p><i>No data to display chart.</i></p>"
        html_content += "</div>"


    html_content += "<hr><h2>Top Detected Anomalies (from entire dataset):</h2>"
    if error_bursts:
        html_content += "<h3>Error Bursts (Top 10):</h3><table><tr><th>Time Period</th><th>Error Count</th><th>IPs Involved</th><th>Details</th></tr>"
        for b in error_bursts[:10]: # Show top 10 for brevity in report
            html_content += f"<tr><td>{b.get('time_period','N/A')}</td><td>{b.get('error_count','N/A')}</td><td>{b.get('ips_involved_count','N/A')}</td><td>{b.get('threshold_exceeded','N/A')}</td></tr>"
        html_content += "</table>"
    else:
        html_content += "<p>No error bursts detected in the full dataset.</p>"

    if high_traffic_ips:
        html_content += "<h3>High Traffic IPs (Top 10):</h3><table><tr><th>IP Address</th><th>Request Count</th><th>Details</th></tr>"
        for ip_info in high_traffic_ips[:10]: # Show top 10
            html_content += f"<tr><td>{ip_info.get('ip_address','N/A')}</td><td>{ip_info.get('request_count','N/A')}</td><td>{ip_info.get('detail','N/A')}</td></tr>"
        html_content += "</table>"
    else:
        html_content += "<p>No high traffic IPs detected in the full dataset.</p>"
    
    html_content += "</body></html>"
    
    return dict(content=html_content, filename=f"nginx_summary_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html")


if __name__ == '__main__':
    app.run(debug=True)