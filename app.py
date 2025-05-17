import dash
import dash_bootstrap_components as dbc
from dash import dcc, html, dash_table, Input, Output, State, callback
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
import numpy as np # For histogram bins
import re
from datetime import datetime, timedelta
import io
import base64
from collections import Counter
import requests 
import time     
import ipaddress 
from user_agents import parse # For User-Agent parsing

# --- MAPBOX Configuration ---
MAPBOX_ACCESS_TOKEN = "YOUR_MAPBOX_ACCESS_TOKEN" 
if MAPBOX_ACCESS_TOKEN == "YOUR_MAPBOX_ACCESS_TOKEN":
    MAPBOX_ACCESS_TOKEN = None 

# Regex for NGINX log parsing (common format)
LOG_REGEX = re.compile(
    r'^(?P<ip_address>\S+) (?P<ident>\S+) (?P<user>\S+) '
    r'\[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>[^"\s]*) (?P<protocol>HTTP/\d\.\d)" '
    r'(?P<status_code>\d{3}) (?P<response_size>\d+) '
    r'"(?P<referrer>[^"]*)" "(?P<user_agent_string>[^"]*)"$' # Renamed for clarity
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
        
        # User-Agent Parsing
        ua_string = data.get('user_agent_string', '')
        user_agent = parse(ua_string)
        data['browser_family'] = user_agent.browser.family
        data['browser_version'] = user_agent.browser.version_string
        data['os_family'] = user_agent.os.family
        data['device_family'] = user_agent.device.family
        data['is_bot'] = user_agent.is_bot
        
        # Referrer simplification
        if data['referrer'] == "-" or not data['referrer']:
            data['referrer_domain'] = "Direct/Unknown"
        else:
            try:
                data['referrer_domain'] = re.match(r'https?://([^/]+)', data['referrer']).group(1)
            except:
                data['referrer_domain'] = "Other"
        return data
    return None

def parse_log_content(content_string, filename):
    # ... (parse_log_content function remains largely the same as before)
    if content_string is None: return pd.DataFrame(), "No file uploaded."
    try:
        content_type, content_data = content_string.split(',')
        decoded = base64.b64decode(content_data)
        log_text = decoded.decode('utf-8')
    except Exception as e: return pd.DataFrame(), f"Error decoding file: {e}"
    lines = log_text.splitlines()
    parsed_data = []
    malformed_lines = 0
    for line_num, line in enumerate(lines):
        if line.strip():
            parsed_line = parse_log_line(line)
            if parsed_line:
                parsed_data.append(parsed_line)
            else:
                # print(f"Skipping malformed line {line_num+1}: {line[:100]}...") # For debugging
                malformed_lines += 1
    df = pd.DataFrame(parsed_data)
    status_message = f"Successfully parsed '{filename}'. {len(df)} lines processed."
    if malformed_lines > 0: status_message += f" {malformed_lines} lines were malformed and skipped."
    if df.empty and not parsed_data: status_message = f"Uploaded file '{filename}' contained no valid log entries."
    return df, status_message


def is_public_ip(ip_str):
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_reserved)
    except ValueError: return False

def geolocate_ip(ip_address):
    # ... (geolocate_ip function remains the same)
    if not is_public_ip(ip_address):
        return {"ip": ip_address, "status": "private_or_reserved", "lat": None, "lon": None, "country": "N/A", "city": "N/A"}
    if ip_address in ip_geocache: return ip_geocache[ip_address]
    geo_data = {"ip": ip_address, "status": "error", "message": "Initial error state", "lat": None, "lon": None, "country": "Error", "city": "Error"}
    try:
        response = requests.get(f"http://ip-api.com/json/{ip_address}?fields=status,message,country,countryCode,city,lat,lon,query", timeout=3)
        response.raise_for_status()
        data = response.json()
        if data.get("status") == "success":
            geo_data = {"ip": data.get("query"), "status": "success", "lat": data.get("lat"), "lon": data.get("lon"), 
                        "country": data.get("country", "Unknown"), "city": data.get("city", "Unknown")}
        else: geo_data["status"] = "fail"; geo_data["message"] = data.get("message", "API failed")
    except requests.exceptions.Timeout: geo_data["message"] = "API request timed out"
    except requests.exceptions.RequestException as e: geo_data["message"] = str(e)
    ip_geocache[ip_address] = geo_data
    time.sleep(1.5) 
    return geo_data

# --- Anomaly Detection Functions ---
def detect_error_bursts(df, time_window_minutes=1, threshold_factor=2.0, min_errors=3): # Default values here
    # Corrected resampling to 'min'
    if df.empty or 'timestamp' not in df.columns or 'status_code' not in df.columns: return []
    errors_df = df[df['status_code'] >= 400].copy()
    if errors_df.empty: return []
    
    # Ensure timestamp is datetime64 for resampling
    errors_df['timestamp'] = pd.to_datetime(errors_df['timestamp'])
    errors_df.set_index('timestamp', inplace=True)
    
    error_counts_per_window = errors_df['status_code'].resample(f'{time_window_minutes}min').count() # Use 'min'
    if error_counts_per_window.empty: return []
    
    mean_errors = error_counts_per_window.mean()
    std_errors = error_counts_per_window.std()
    dynamic_threshold = mean_errors + float(threshold_factor) * (std_errors if pd.notna(std_errors) else 0)
    current_threshold = max(float(min_errors), dynamic_threshold)
    bursts = []
    for period_start, count in error_counts_per_window.items():
        if count >= current_threshold:
            period_end = period_start + timedelta(minutes=time_window_minutes)
            burst_details_df = errors_df[(errors_df.index >= period_start) & (errors_df.index < period_end)]
            ips_in_burst = burst_details_df['ip_address'].nunique()
            status_codes_in_burst = dict(Counter(burst_details_df['status_code'].astype(str)))
            bursts.append({
                "time_period": f"{period_start.strftime('%Y-%m-%d %H:%M:%S')} - {period_end.strftime('%H:%M:%S')}",
                "error_count": count, "ips_involved_count": ips_in_burst,
                "status_codes": status_codes_in_burst,
                "threshold_exceeded": f"{count} errors >= threshold ({current_threshold:.2f})"
            })
    return bursts

def detect_high_traffic_ips(df, threshold_factor=2.0, min_requests=10):
    # ... (detect_high_traffic_ips function remains largely the same)
    if df.empty or 'ip_address' not in df.columns: return []
    ip_counts = df['ip_address'].value_counts()
    if ip_counts.empty: return []
    mean_requests = ip_counts.mean()
    std_requests = ip_counts.std()
    dynamic_threshold = mean_requests + threshold_factor * (std_requests if pd.notna(std_requests) else 0)
    current_threshold = max(min_requests, dynamic_threshold)
    anomalous_ips = []
    for ip, count in ip_counts.items():
        if count >= current_threshold:
            anomalous_ips.append({
                "ip_address": ip, "request_count": count,
                "detail": f"{count} requests > threshold ({current_threshold:.2f})"
            })
    return anomalous_ips

# --- Initialize Dash App ---
app = dash.Dash(__name__, external_stylesheets=[dbc.themes.LUX, dbc.icons.FONT_AWESOME])
server = app.server

# --- App Layout ---
app.layout = dbc.Container(fluid=True, children=[
    dcc.Store(id='log-data-store'),
    dcc.Store(id='filtered-log-data-store'),

    dbc.Row(dbc.Col(html.H1("NGINX Log Anomaly Dashboard", className="text-center my-4"))),

    dbc.Row([ # Upload Row
        dbc.Col([
            dcc.Upload(id='upload-log-file', children=html.Div(['Drag and Drop or ', html.A('Select NGINX Log File')]),
                       style={'width': '100%', 'height': '60px', 'lineHeight': '60px', 'borderWidth': '1px', 
                              'borderStyle': 'dashed', 'borderRadius': '5px', 'textAlign': 'center', 'margin': '10px 0'},
                       multiple=False),
            html.Div(id='upload-status', className="mt-2")
        ], width=12)
    ], className="mb-3"),

    dbc.Row([ # Filter Row
        dbc.Col(dcc.DatePickerRange(
            id='date-picker-range',
            min_date_allowed=datetime(2000, 1, 1).date(),
            max_date_allowed=datetime.now().date() + timedelta(days=1), # Allow future for logs
            start_date_placeholder_text="Start Date", end_date_placeholder_text="End Date",
            className="mb-2"), width=12, lg=3),
        dbc.Col(dcc.Dropdown(id='hour-filter-dropdown', placeholder="Filter by Hour(s)", multi=True,
                             options=[{'label': f'{h:02}:00-{h:02}:59', 'value': h} for h in range(24)],
                             className="mb-2"), width=12, lg=2),
        dbc.Col(dcc.Dropdown(id='ip-filter-dropdown', placeholder="Filter by IP", multi=True, className="mb-2"), width=12, lg=3),
        dbc.Col(dcc.Dropdown(id='status-code-filter-dropdown', placeholder="Filter by Status", multi=True, className="mb-2"), width=12, lg=2),
        dbc.Col(html.Button("Apply Filters", id="apply-filters-button", n_clicks=0, className="btn btn-info w-100"), width=12, lg=2) # Explicit Apply Button
    ], className="mb-3 bg-light p-3 border rounded"),

    dbc.Row([ # Summary Cards
        dbc.Col(dbc.Card(dbc.CardBody([html.H4(id='total-requests-card', className="card-title"), html.P("Total Requests")])), width=6,md=3,className="mb-2"),
        dbc.Col(dbc.Card(dbc.CardBody([html.H4(id='unique-ips-card', className="card-title"), html.P("Unique IPs")])), width=6,md=3,className="mb-2"),
        dbc.Col(dbc.Card(dbc.CardBody([html.H4(id='error-rate-card', className="card-title"), html.P("Error Rate (4xx/5xx)")])), width=6,md=3,className="mb-2"),
        dbc.Col(dbc.Card(dbc.CardBody([html.H4(id='avg-response-size-card', className="card-title"), html.P("Avg. Resp. Size")])), width=6,md=3,className="mb-2"),
    ], className="mb-3"),

    dbc.Row([ # Main Charts Row 1
        dbc.Col(dcc.Graph(id='requests-over-time-chart'), width=12, lg=6, className="mb-3"),
        dbc.Col(dcc.Graph(id='status-code-dist-chart'), width=12, lg=6, className="mb-3"),
    ]),
    dbc.Row([ # Main Charts Row 2
        dbc.Col(dcc.Graph(id='top-ips-chart'), width=12, lg=6, className="mb-3"),
        dbc.Col(dcc.Graph(id='top-paths-chart'), width=12, lg=6, className="mb-3"),
    ]),
     dbc.Row([ # Main Charts Row 3 (New Charts)
        dbc.Col(dcc.Graph(id='http-methods-chart'), width=12, lg=4, className="mb-3"),
        dbc.Col(dcc.Graph(id='browser-dist-chart'), width=12, lg=4, className="mb-3"),
        dbc.Col(dcc.Graph(id='os-dist-chart'), width=12, lg=4, className="mb-3"),
    ]),
    dbc.Row([ # Main Charts Row 4 (New Charts + Map)
        dbc.Col(dcc.Graph(id='human-vs-bot-chart'), width=12, lg=4, className="mb-3"),
        dbc.Col(dcc.Graph(id='top-referrers-chart'), width=12, lg=4, className="mb-3"),
        dbc.Col(dcc.Graph(id='response-size-dist-chart'), width=12, lg=4, className="mb-3"),
    ]),
    dbc.Row([ # Map Row
        dbc.Col(dbc.Card([
            dbc.CardHeader(html.H5("IP Geolocation Map (Public IPs in Filtered View)", className="card-title")),
            dbc.CardBody([
                dcc.Loading(id="loading-map", type="default", children=[
                    dcc.Graph(id='ip-location-map-chart', style={'height': '450px'})
                ])
            ])
        ]), width=12, className="mb-3")
    ]),


    dbc.Row([ # Anomalies Section
        dbc.Col([
            html.H3("Detected Anomalies (based on entire dataset)", className="mt-4 mb-3"),
            dbc.Row([
                dbc.Col(dbc.Label("Error Burst Threshold Factor:"), width="auto"),
                dbc.Col(dcc.Input(id='error-burst-threshold-factor-input', type='number', value=2.0, step=0.1, min=1.0, className="form-control form-control-sm"), width=2),
                dbc.Col(dbc.Label("Min Errors for Burst:"), width="auto"),
                dbc.Col(dcc.Input(id='error-burst-min-errors-input', type='number', value=3, step=1, min=1, className="form-control form-control-sm"), width=2),
            ], className="mb-2 align-items-center"),
            dbc.Accordion([
                dbc.AccordionItem(html.Div(id='anomaly-error-bursts-div'), title="Error Bursts (Top 10)"),
                dbc.AccordionItem(html.Div(id='anomaly-high-traffic-ips-div'), title="High Traffic IPs (Top 10)"),
            ], flush=True, always_open=True)
        ], width=12)
    ], className="mb-3"),
    
    dbc.Row([ # Data Table Section
        dbc.Col([
            html.H3("Log Data Table (Filtered)", className="mt-4 mb-3"),
             html.Button([html.I(className="fas fa-download mr-2"), " Export Filtered Data (CSV)"], 
                         id="export-button", className="btn btn-primary mb-2", n_clicks=0),
            dcc.Download(id="download-csv"),
            html.Div(id='data-table-container', children=[
                dash_table.DataTable(
                    id='log-data-table', columns=[], page_size=10,
                    style_table={'overflowX': 'auto'},
                    style_cell={'textAlign': 'left', 'minWidth': '100px', 'maxWidth': '300px', 
                                'whiteSpace': 'normal', 'height': 'auto', 'padding': '5px'},
                    filter_action="native", sort_action="native",
                    # style_data_conditional added in callback
                )
            ])
        ], width=12)
    ], className="mb-3")
])

# --- Callbacks ---

# Callback to parse uploaded log file
@app.callback(
    [Output('log-data-store', 'data'), Output('upload-status', 'children'),
     Output('date-picker-range', 'min_date_allowed'), Output('date-picker-range', 'max_date_allowed'),
     Output('date-picker-range', 'start_date'), Output('date-picker-range', 'end_date'),
     Output('ip-filter-dropdown', 'options'), Output('ip-filter-dropdown', 'value'),
     Output('status-code-filter-dropdown', 'options'), Output('status-code-filter-dropdown', 'value'),
     Output('hour-filter-dropdown', 'value')],
    [Input('upload-log-file', 'contents')],
    [State('upload-log-file', 'filename')],
    prevent_initial_call=True 
)
def upload_and_parse_log(contents, filename):
    # ... (upload_and_parse_log remains largely the same, ensures df['timestamp'] is datetime)
    if contents is None:
        return (pd.DataFrame().to_dict('records'), "Please upload an NGINX access log file.",
                datetime(2000,1,1).date(), datetime.now().date(), None, None, [], None, [], None, None)
    df, status_msg = parse_log_content(contents, filename)
    if df.empty:
        return (pd.DataFrame().to_dict('records'), dbc.Alert(status_msg, color="warning", dismissable=True),
                datetime(2000,1,1).date(), datetime.now().date(), None, None, [], None, [], None, None)
    
    if 'timestamp' not in df.columns or df['timestamp'].isnull().all():
         return (pd.DataFrame().to_dict('records'), dbc.Alert(f"{status_msg} Could not parse timestamps.", color="danger", dismissable=True),
                datetime(2000,1,1).date(), datetime.now().date(), None, None, [], None, [], None, None)

    df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce') # Coerce errors to NaT
    df.dropna(subset=['timestamp'], inplace=True) # Drop rows where timestamp couldn't be parsed

    if df.empty: # If all timestamps were bad
        return (pd.DataFrame().to_dict('records'), dbc.Alert(f"{status_msg} No valid timestamps found after parsing.", color="danger", dismissable=True),
                datetime(2000,1,1).date(), datetime.now().date(), None, None, [], None, [], None, None)

    min_date = df['timestamp'].min().date()
    max_date = df['timestamp'].max().date()
    ip_options = [{'label': ip, 'value': ip} for ip in sorted(df['ip_address'].unique())]
    status_options = [{'label': str(sc), 'value': sc} for sc in sorted(df['status_code'].unique())]
    return (df.to_dict('records'), dbc.Alert(status_msg, color="success", dismissable=True),
            min_date, max_date, min_date, max_date,
            ip_options, None, status_options, None, None) # Reset hour filter


# Callback to filter data based on user selections
@app.callback(
    Output('filtered-log-data-store', 'data'),
    [Input('apply-filters-button', 'n_clicks')], # Triggered by apply button
    [State('log-data-store', 'data'),
     State('date-picker-range', 'start_date'), State('date-picker-range', 'end_date'),
     State('hour-filter-dropdown', 'value'), # New hour filter
     State('ip-filter-dropdown', 'value'), State('status-code-filter-dropdown', 'value')]
)
def filter_log_data(n_clicks, log_data_json, start_date_str, end_date_str, selected_hours, selected_ips, selected_status_codes):
    if not log_data_json or n_clicks == 0: # Also check n_clicks if using explicit apply button
        return pd.DataFrame().to_dict('records') if n_clicks > 0 else dash.no_update # No update if button not clicked

    df = pd.DataFrame(log_data_json)
    if df.empty: return pd.DataFrame().to_dict('records')
    
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    
    if start_date_str:
        filter_start_datetime = pd.to_datetime(start_date_str)
        if df['timestamp'].dt.tz is not None: filter_start_datetime = filter_start_datetime.tz_localize(df['timestamp'].dt.tz)
        df = df[df['timestamp'] >= filter_start_datetime]
    
    if end_date_str:
        filter_end_datetime_exclusive = pd.to_datetime(end_date_str) + timedelta(days=1)
        if df['timestamp'].dt.tz is not None: filter_end_datetime_exclusive = filter_end_datetime_exclusive.tz_localize(df['timestamp'].dt.tz)
        df = df[df['timestamp'] < filter_end_datetime_exclusive]
    
    if selected_hours: # Filter by hour
        df = df[df['timestamp'].dt.hour.isin(selected_hours)]
        
    if selected_ips: df = df[df['ip_address'].isin(selected_ips)]
    
    if selected_status_codes:
        # Ensure selected_status_codes are integers if they come from dropdown as strings
        selected_status_codes_int = [int(sc) for sc in selected_status_codes]
        df = df[df['status_code'].isin(selected_status_codes_int)]
            
    return df.to_dict('records')


# --- Callback for main dashboard elements (excluding map) ---
@app.callback(
    [Output('total-requests-card', 'children'), Output('unique-ips-card', 'children'),
     Output('error-rate-card', 'children'), Output('avg-response-size-card', 'children'),
     Output('requests-over-time-chart', 'figure'), Output('status-code-dist-chart', 'figure'),
     Output('top-ips-chart', 'figure'), Output('top-paths-chart', 'figure'),
     Output('http-methods-chart', 'figure'), 
     Output('browser-dist-chart', 'figure'), Output('os-dist-chart', 'figure'), # New chart outputs
     Output('human-vs-bot-chart', 'figure'), Output('top-referrers-chart', 'figure'),
     Output('response-size-dist-chart', 'figure'),
     Output('log-data-table', 'data'), Output('log-data-table', 'columns'),
     Output('log-data-table', 'style_data_conditional'),
     Output('anomaly-error-bursts-div', 'children'), Output('anomaly-high-traffic-ips-div', 'children')],
    [Input('filtered-log-data-store', 'data'), Input('log-data-store', 'data')], # Original data for anomalies
    [State('error-burst-threshold-factor-input', 'value'), # Anomaly threshold states
     State('error-burst-min-errors-input', 'value')]
)
def update_dashboard_elements(filtered_log_data_json, original_log_data_json,
                              anomaly_thresh_factor, anomaly_min_errors):
    empty_fig_layout = dict(template='plotly_white', xaxis={"visible": False}, yaxis={"visible": False}, annotations=[dict(text="No data", xref="paper", yref="paper",showarrow=False, font=dict(size=16))])
    empty_fig = go.Figure(layout=empty_fig_layout)
    
    if not filtered_log_data_json:
        return ("0", "0", "0%", "0 B", empty_fig, empty_fig, empty_fig, empty_fig, empty_fig, 
                empty_fig, empty_fig, empty_fig, empty_fig, empty_fig, # For new charts
                [], [], [], [], [])

    df_filtered = pd.DataFrame(filtered_log_data_json)
    df_original = pd.DataFrame(original_log_data_json)

    if df_filtered.empty:
        no_match_fig = go.Figure(layout=empty_fig_layout).update_layout(annotations=[dict(text="No data matching filters")])
        return ("0", "0", "0%", "0 B", no_match_fig, no_match_fig, no_match_fig, no_match_fig, no_match_fig,
                no_match_fig, no_match_fig, no_match_fig, no_match_fig, no_match_fig, # For new charts
                [], [], [], html.P("No data for anomaly detection based on filters."), html.P("No data for anomaly detection based on filters."))
    
    df_filtered['timestamp'] = pd.to_datetime(df_filtered['timestamp'])
    if not df_original.empty: df_original['timestamp'] = pd.to_datetime(df_original['timestamp'])

    # --- Summary Cards ---
    total_requests = len(df_filtered)
    unique_ips_count_filtered = df_filtered['ip_address'].nunique()
    error_count = df_filtered[df_filtered['status_code'] >= 400].shape[0]
    error_rate = (error_count / total_requests * 100) if total_requests > 0 else 0
    avg_response_size_bytes = df_filtered['response_size'].mean() if total_requests > 0 else 0
    # ... (response size formatting as before) ...
    avg_response_size_str = f"{avg_response_size_bytes:,.0f} B" # Simplified for now

    # --- Charts ---
    # Requests over time (Corrected resampling to 'h')
    requests_over_time_data = df_filtered.set_index('timestamp').resample('h').size().reset_index(name='count') # Use 'h'
    fig_req_time = px.line(requests_over_time_data, x='timestamp', y='count', title='Requests Over Time (Hourly)', markers=True)
    fig_req_time.update_layout(template='plotly_white')

    # Status code distribution (with color)
    status_counts = df_filtered['status_code'].astype(str).value_counts().reset_index()
    status_counts.columns = ['status_code', 'count']
    status_color_map = {
        '2xx': 'green', '3xx': 'orange', '4xx': 'red', '5xx': 'darkred', 'Other': 'grey'
    }
    status_counts['group'] = status_counts['status_code'].apply(lambda x: x[0]+'xx' if x[0] in '2345' else 'Other')
    fig_status_dist = px.pie(status_counts, names='status_code', values='count', title='Status Code Distribution', 
                             color='group', color_discrete_map=status_color_map, hole=0.3)
    fig_status_dist.update_layout(template='plotly_white')

    # Top IPs
    top_n = 10
    top_ips_data = df_filtered['ip_address'].value_counts().nlargest(top_n).reset_index()
    top_ips_data.columns = ['ip_address', 'count']
    fig_top_ips = px.bar(top_ips_data, x='ip_address', y='count', title=f'Top {top_n} IP Addresses')
    fig_top_ips.update_layout(template='plotly_white', xaxis_title="IP Address", yaxis_title="Request Count")

    # Top Paths (Shortened URL)
    top_paths_data = df_filtered['path'].value_counts().nlargest(top_n).reset_index()
    top_paths_data.columns = ['path', 'count']
    top_paths_data['short_path'] = top_paths_data['path'].apply(lambda x: (x[:15] + '...') if len(x) > 18 else x)
    fig_top_paths = px.bar(top_paths_data, x='short_path', y='count', title=f'Top {top_n} Requested Paths',
                           hover_data={'path': True, 'short_path': False}) # Show full path on hover
    fig_top_paths.update_layout(template='plotly_white', xaxis_title="Path (truncated)", yaxis_title="Request Count")
    
    # HTTP Methods
    method_counts = df_filtered['method'].value_counts().reset_index()
    method_counts.columns = ['method', 'count']
    fig_methods = px.pie(method_counts, names='method', values='count', title='HTTP Method Distribution', hole=0.3)
    fig_methods.update_layout(template='plotly_white')

    # Browser Distribution
    browser_counts = df_filtered['browser_family'].value_counts().nlargest(top_n).reset_index()
    browser_counts.columns = ['browser_family', 'count']
    fig_browser_dist = px.pie(browser_counts, names='browser_family', values='count', title=f'Top {top_n} Browsers', hole=0.3)
    fig_browser_dist.update_layout(template='plotly_white')

    # OS Distribution
    os_counts = df_filtered['os_family'].value_counts().nlargest(top_n).reset_index()
    os_counts.columns = ['os_family', 'count']
    fig_os_dist = px.pie(os_counts, names='os_family', values='count', title=f'Top {top_n} Operating Systems', hole=0.3)
    fig_os_dist.update_layout(template='plotly_white')

    # Human vs Bot
    bot_counts = df_filtered['is_bot'].value_counts().reset_index()
    bot_counts.columns = ['is_bot', 'count']
    bot_counts['label'] = bot_counts['is_bot'].apply(lambda x: 'Bot' if x else 'Human')
    fig_human_bot = px.pie(bot_counts, names='label', values='count', title='Human vs. Bot Traffic', hole=0.3,
                           color_discrete_map={'Bot':'skyblue', 'Human':'royalblue'})
    fig_human_bot.update_layout(template='plotly_white')
    
    # Top Referrers
    referrer_counts = df_filtered['referrer_domain'].value_counts().nlargest(top_n).reset_index()
    referrer_counts.columns = ['referrer_domain', 'count']
    fig_top_referrers = px.bar(referrer_counts, x='referrer_domain', y='count', title=f'Top {top_n} Referrer Domains')
    fig_top_referrers.update_layout(template='plotly_white', xaxis_title="Referrer Domain", yaxis_title="Count")

    # Response Size Distribution
    # Use numpy for potentially better binning with log scales if needed, but px.histogram is fine
    fig_resp_size = px.histogram(df_filtered, x="response_size", nbins=30, title="Response Size Distribution (Bytes)")
    fig_resp_size.update_layout(template='plotly_white', yaxis_title="Frequency", xaxis_title="Response Size (Bytes)")


    # --- Data Table ---
    df_display = df_filtered.copy()
    if pd.api.types.is_datetime64_any_dtype(df_display['timestamp']):
        df_display['timestamp'] = df_display['timestamp'].dt.strftime('%Y-%m-%d %H:%M:%S %Z' if df_display['timestamp'].dt.tz else '%Y-%m-%d %H:%M:%S')
    
    table_cols = [{"name": i, "id": i} for i in df_display.columns if i not in ['browser_version', 'device_family']] # Select relevant cols
    table_data = df_display.to_dict('records')
    
    # Table conditional styling for status codes
    style_data_conditional = [
        {'if': {'filter_query': '{status_code} >= 200 && {status_code} < 300'}, 'backgroundColor': '#d4edda', 'color': 'black'},
        {'if': {'filter_query': '{status_code} >= 300 && {status_code} < 400'}, 'backgroundColor': '#fff3cd', 'color': 'black'},
        {'if': {'filter_query': '{status_code} >= 400 && {status_code} < 500'}, 'backgroundColor': '#f8d7da', 'color': 'black'},
        {'if': {'filter_query': '{status_code} >= 500'}, 'backgroundColor': '#d6d8db', 'color': 'black'}, # Darker for 5xx
    ]


    # --- Anomaly Detection (on original, unfiltered data) ---
    error_bursts_detected_elements = []
    high_traffic_ips_detected_elements = []
    if not df_original.empty:
        # Use user-provided thresholds for error bursts
        error_bursts = detect_error_bursts(df_original, 
                                           threshold_factor=float(anomaly_thresh_factor) if anomaly_thresh_factor else 2.0, 
                                           min_errors=int(anomaly_min_errors) if anomaly_min_errors else 3)
        if error_bursts:
            for burst in error_bursts[:10]: # Show top 10
                error_bursts_detected_elements.append(dbc.Alert(
                    f"Period: {burst['time_period']}, Errors: {burst['error_count']}, IPs: {burst['ips_involved_count']}", 
                    color="warning", dismissable=True, className="mb-1 small"
                ))
            if len(error_bursts) > 10:
                error_bursts_detected_elements.append(html.P(f"... and {len(error_bursts)-10} more bursts.", className="small text-muted"))
        else: error_bursts_detected_elements = dbc.Alert("No significant error bursts detected.", color="success", className="mb-1")
        
        high_traffic_ips = detect_high_traffic_ips(df_original) # Could add threshold inputs for this too
        if high_traffic_ips:
            for anom_ip in high_traffic_ips[:10]: # Show top 10
                high_traffic_ips_detected_elements.append(dbc.Alert(
                    f"IP: {anom_ip['ip_address']}, Requests: {anom_ip['request_count']}. ({anom_ip['detail']})", 
                    color="danger", dismissable=True, className="mb-1 small"
                ))
            if len(high_traffic_ips) > 10:
                 high_traffic_ips_detected_elements.append(html.P(f"... and {len(high_traffic_ips)-10} more high traffic IPs.", className="small text-muted"))
        else: high_traffic_ips_detected_elements = dbc.Alert("No IPs with unusually high traffic detected.", color="success", className="mb-1")
    else:
        error_bursts_detected_elements = dbc.Alert("No data loaded for anomaly detection.", color="info", className="mb-1")
        high_traffic_ips_detected_elements = dbc.Alert("No data loaded for anomaly detection.", color="info", className="mb-1")

    return (f"{total_requests:,}", f"{unique_ips_count_filtered:,}", f"{error_rate:.2f}%", avg_response_size_str,
            fig_req_time, fig_status_dist, fig_top_ips, fig_top_paths, fig_methods,
            fig_browser_dist, fig_os_dist, fig_human_bot, fig_top_referrers, fig_resp_size, # New chart figures
            table_data, table_cols, style_data_conditional,
            error_bursts_detected_elements, high_traffic_ips_detected_elements)


# --- Callback for IP Geolocation Map (separated for dcc.Loading) ---
@app.callback(
    Output('ip-location-map-chart', 'figure'),
    [Input('filtered-log-data-store', 'data')] # Triggered when filtered data changes
)
def update_ip_map(filtered_log_data_json):
    # Default empty map using go.Scattermap
    empty_map_fig = go.Figure(data=[go.Scattermap(lat=[], lon=[])])
    empty_map_fig.update_layout(
        margin={"r":0,"t":0,"l":0,"b":0},
        map_style="open-street-map", # MapLibre style
        map_center={"lat": 0, "lon": 0}, map_zoom=1,
        annotations=[{
            "text": "No IP data for map or geolocation failed.", "align": "center",
            "showarrow": False, "xref": "paper", "yref": "paper", "x": 0.5, "y": 0.5
        }]
    )
    if not filtered_log_data_json: return empty_map_fig

    df_filtered = pd.DataFrame(filtered_log_data_json)
    if df_filtered.empty: return empty_map_fig

    unique_ips_in_filtered_view = df_filtered['ip_address'].unique()
    geo_locations_data = []
    
    if len(unique_ips_in_filtered_view) > 0:
        max_ips_to_geolocate_per_render = 25 # Reduced slightly for faster map load
        ips_to_process_for_map = unique_ips_in_filtered_view[:max_ips_to_geolocate_per_render]
        
        # print(f"MAP: Attempting to geolocate {len(ips_to_process_for_map)} IPs...")
        for ip_addr in ips_to_process_for_map:
            loc_data = geolocate_ip(ip_addr)
            if loc_data and loc_data.get("status") == "success" and loc_data.get("lat") is not None:
                geo_locations_data.append(loc_data)
        
        if geo_locations_data:
            geo_df = pd.DataFrame(geo_locations_data)
            ip_counts_in_filtered = df_filtered['ip_address'].value_counts().reset_index()
            ip_counts_in_filtered.columns = ['ip', 'request_count']
            geo_df = pd.merge(geo_df, ip_counts_in_filtered, on='ip', how='left').fillna({'request_count':1})
            geo_df['marker_size'] = np.log1p(geo_df['request_count']) * 5 + 5 # Log scale for size
            
            # Using go.Scattermap directly
            fig_ip_map = go.Figure(data=[go.Scattermap(
                lat=geo_df['lat'],
                lon=geo_df['lon'],
                mode='markers',
                marker=dict(
                    size=geo_df['marker_size'],
                    color="#007bff", # Example color
                    opacity=0.7
                ),
                text=geo_df.apply(lambda row: f"IP: {row['ip']}<br>City: {row['city']}<br>Country: {row['country']}<br>Requests: {int(row['request_count'])}", axis=1),
                hoverinfo='text'
            )])
            
            map_layout_style = "open-street-map" # Default MapLibre style
            # If Mapbox token was provided AND you prefer mapbox styles (needs different config)
            # For now, sticking to MapLibre compatible styles.
            
            fig_ip_map.update_layout(
                map_style=map_layout_style,
                map_center={"lat": geo_df['lat'].mean(), "lon": geo_df['lon'].mean()} if not geo_df.empty else {"lat":0, "lon":0},
                map_zoom=1.5 if not geo_df.empty else 1,
                margin={"r":0,"t":0,"l":0,"b":0}
            )
            return fig_ip_map
        # else: print("MAP: No successful geolocations.")
            
    return empty_map_fig


# Callback for CSV export
@app.callback(
    Output("download-csv", "data"),
    Input("export-button", "n_clicks"),
    State("filtered-log-data-store", "data"),
    prevent_initial_call=True,
)
def export_csv(n_clicks, filtered_log_data_json):
    if not n_clicks or not filtered_log_data_json:
        raise dash.exceptions.PreventUpdate
    df_export = pd.DataFrame(filtered_log_data_json)
    if df_export.empty:
        # Optionally, provide feedback to the user that there's nothing to export
        # For now, just prevent update.
        raise dash.exceptions.PreventUpdate
    return dcc.send_data_frame(df_export.to_csv, f"nginx_log_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv", index=False)


if __name__ == '__main__':
    app.run(debug=True) # Use app.run instead of app.run_server