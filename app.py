import dash
import dash_bootstrap_components as dbc
from dash import dcc, html, dash_table, Input, Output, State, callback # Removed Patch as it wasn't used
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
import re
from datetime import datetime, timedelta
import io
import base64
from collections import Counter
import requests # For IP geolocation API
import time     # For rate limiting API calls
import ipaddress # For checking if IP is private/public

# --- MAPBOX Configuration ---
# IMPORTANT: For Mapbox styles other than 'open-street-map', 'carto-positron', etc.,
# you'll need a Mapbox Access Token.
# Get a free token from https://www.mapbox.com/
# and set it here or as an environment variable.
MAPBOX_ACCESS_TOKEN = "YOUR_MAPBOX_ACCESS_TOKEN" # <<< REPLACE THIS or set to None
if MAPBOX_ACCESS_TOKEN == "YOUR_MAPBOX_ACCESS_TOKEN":
    MAPBOX_ACCESS_TOKEN = None # Use default if not replaced by user

# Regex for NGINX log parsing (common format)
LOG_REGEX = re.compile(
    r'^(?P<ip_address>\S+) (?P<ident>\S+) (?P<user>\S+) '
    r'\[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>[^"\s]*) (?P<protocol>HTTP/\d\.\d)" '
    r'(?P<status_code>\d{3}) (?P<response_size>\d+) '
    r'"(?P<referrer>[^"]*)" "(?P<user_agent>[^"]*)"$'
)

# --- IP Geolocation Cache ---
ip_geocache = {}

# --- Helper Functions ---
def parse_log_line(line):
    match = LOG_REGEX.match(line)
    if match:
        data = match.groupdict()
        try:
            # Ensure timezone information is parsed if present
            data['timestamp'] = datetime.strptime(data['timestamp'], '%d/%b/%Y:%H:%M:%S %z')
        except ValueError: # Fallback for timestamps without timezone
             data['timestamp'] = datetime.strptime(data['timestamp'], '%d/%b/%Y:%H:%M:%S')
        data['status_code'] = int(data['status_code'])
        data['response_size'] = int(data['response_size'])
        return data
    return None

def parse_log_content(content_string, filename):
    if content_string is None:
        return pd.DataFrame(), "No file uploaded."
    try:
        content_type, content_data = content_string.split(',')
        decoded = base64.b64decode(content_data)
        log_text = decoded.decode('utf-8')
    except Exception as e:
        return pd.DataFrame(), f"Error decoding file: {e}"
    lines = log_text.splitlines()
    parsed_data = []
    malformed_lines = 0
    for line in lines:
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
    if df.empty and not parsed_data:
        status_message = f"Uploaded file '{filename}' contained no valid log entries."
    return df, status_message

def is_public_ip(ip_str):
    """Checks if an IP address string is likely a public IP."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return not (ip_obj.is_private or 
                    ip_obj.is_loopback or 
                    ip_obj.is_link_local or 
                    ip_obj.is_multicast or 
                    ip_obj.is_reserved)
    except ValueError:
        # Invalid IP string format
        return False

def geolocate_ip(ip_address):
    """Geolocates a single IP address using ip-api.com and caches results."""
    if not is_public_ip(ip_address):
        # Don't query for private/reserved IPs
        return {"ip": ip_address, "status": "private_or_reserved", "lat": None, "lon": None, "country": "N/A", "city": "N/A"}

    if ip_address in ip_geocache:
        return ip_geocache[ip_address]
    
    geo_data = {"ip": ip_address, "status": "error", "message": "Initial error state", "lat": None, "lon": None, "country": "Error", "city": "Error"}
    try:
        # ip-api.com: free for non-commercial use, 45 reqs/min from same IP.
        # Fields selected: status, message (for errors), country, city, lat, lon, query (the input IP)
        response = requests.get(f"http://ip-api.com/json/{ip_address}?fields=status,message,country,countryCode,city,lat,lon,query", timeout=3) # Increased timeout slightly
        response.raise_for_status() # Raise an exception for HTTP errors (4xx or 5xx)
        data = response.json()
        
        if data.get("status") == "success":
            geo_data = {
                "ip": data.get("query"), # The IP address that was looked up
                "status": "success",
                "lat": data.get("lat"),
                "lon": data.get("lon"),
                "country": data.get("country", "Unknown"),
                "city": data.get("city", "Unknown")
            }
        else:
            geo_data["status"] = "fail"
            geo_data["message"] = data.get("message", "API failed but no message provided")
        
    except requests.exceptions.Timeout:
        geo_data["message"] = "API request timed out"
    except requests.exceptions.RequestException as e:
        geo_data["message"] = str(e)
    
    ip_geocache[ip_address] = geo_data
    time.sleep(1.5) # BE NICE to the API: 45 reqs/min = 1 req per 1.33 seconds. Add a small buffer.
    return geo_data

# --- Anomaly Detection Functions (Unchanged from your provided code) ---
def detect_error_bursts(df, time_window_minutes=1, threshold_factor=2, min_errors=3):
    if df.empty or 'timestamp' not in df.columns or 'status_code' not in df.columns: return []
    errors_df = df[df['status_code'] >= 400].copy()
    if errors_df.empty: return []
    errors_df.set_index('timestamp', inplace=True)
    error_counts_per_window = errors_df['status_code'].resample(f'{time_window_minutes}T').count()
    if error_counts_per_window.empty: return []
    mean_errors = error_counts_per_window.mean()
    std_errors = error_counts_per_window.std()
    dynamic_threshold = mean_errors + threshold_factor * (std_errors if pd.notna(std_errors) else 0)
    current_threshold = max(min_errors, dynamic_threshold)
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

    dbc.Row([
        dbc.Col([
            dcc.Upload(
                id='upload-log-file',
                children=html.Div(['Drag and Drop or ', html.A('Select NGINX Log File')]),
                style={
                    'width': '100%', 'height': '60px', 'lineHeight': '60px',
                    'borderWidth': '1px', 'borderStyle': 'dashed',
                    'borderRadius': '5px', 'textAlign': 'center', 'margin': '10px 0'
                },
                multiple=False
            ),
            html.Div(id='upload-status', className="mt-2")
        ], width=12)
    ], className="mb-3"),

    dbc.Row([
        dbc.Col(dcc.DatePickerRange(
            id='date-picker-range',
            min_date_allowed=datetime(2000, 1, 1).date(),
            max_date_allowed=datetime.now().date() + timedelta(days=1),
            start_date_placeholder_text="Start Date",
            end_date_placeholder_text="End Date",
            className="mb-2"
        ), width=12, lg=4),
        dbc.Col(dcc.Dropdown(id='ip-filter-dropdown', placeholder="Filter by IP Address", multi=True, className="mb-2"), width=12, lg=4),
        dbc.Col(dcc.Dropdown(id='status-code-filter-dropdown', placeholder="Filter by Status Code", multi=True, className="mb-2"), width=12, lg=4),
    ], className="mb-3 bg-light p-3 border rounded"),

    dbc.Row([
        dbc.Col(dbc.Card(dbc.CardBody([html.H4(id='total-requests-card', className="card-title"), html.P("Total Requests", className="card-text")])), width=6, md=3, className="mb-2"),
        dbc.Col(dbc.Card(dbc.CardBody([html.H4(id='unique-ips-card', className="card-title"), html.P("Unique IPs", className="card-text")])), width=6, md=3, className="mb-2"),
        dbc.Col(dbc.Card(dbc.CardBody([html.H4(id='error-rate-card', className="card-title"), html.P("Error Rate (4xx/5xx)", className="card-text")])), width=6, md=3, className="mb-2"),
        dbc.Col(dbc.Card(dbc.CardBody([html.H4(id='avg-response-size-card', className="card-title"), html.P("Avg. Response Size", className="card-text")])), width=6, md=3, className="mb-2"),
    ], className="mb-3"),

    # Row for Charts including the new IP Map
    dbc.Row([
        dbc.Col(dcc.Graph(id='requests-over-time-chart'), width=12, lg=6, className="mb-3"),
        dbc.Col(dcc.Graph(id='status-code-dist-chart'), width=12, lg=6, className="mb-3"),
    ]),
    dbc.Row([
        dbc.Col(dcc.Graph(id='top-ips-chart'), width=12, lg=6, className="mb-3"),
        dbc.Col(dcc.Graph(id='top-paths-chart'), width=12, lg=6, className="mb-3"),
    ]),
     dbc.Row([
        dbc.Col(dcc.Graph(id='http-methods-chart'), width=12, lg=6, className="mb-3"),
        # --- NEW: IP Geolocation Map Card ---
        dbc.Col(
            dbc.Card([
                dbc.CardHeader(html.H5("IP Geolocation Map", className="card-title")),
                dbc.CardBody([
                    dcc.Graph(id='ip-location-map-chart', style={'height': '450px'}) # Set a height for the map
                ])
            ]), width=12, lg=6, className="mb-3"
        )
    ]),

    dbc.Row([
        dbc.Col([
            html.H3("Detected Anomalies", className="mt-4 mb-3"),
            dbc.Accordion([
                dbc.AccordionItem(html.Div(id='anomaly-error-bursts-div'), title="Error Bursts"),
                dbc.AccordionItem(html.Div(id='anomaly-high-traffic-ips-div'), title="High Traffic IPs"),
            ], flush=True, always_open=True)
        ], width=12)
    ], className="mb-3"),
    
    dbc.Row([
        dbc.Col([
            html.H3("Log Data Table", className="mt-4 mb-3"),
             html.Button([html.I(className="fas fa-download mr-2"), " Export Filtered Data (CSV)"], id="export-button", className="btn btn-primary mb-2", n_clicks=0),
            dcc.Download(id="download-csv"),
            html.Div(id='data-table-container', children=[
                dash_table.DataTable(
                    id='log-data-table',
                    columns=[],
                    page_size=10,
                    style_table={'overflowX': 'auto'},
                    style_cell={'textAlign': 'left', 'minWidth': '100px', 'maxWidth': '300px', 'whiteSpace': 'normal', 'height': 'auto'},
                    filter_action="native",
                    sort_action="native",
                )
            ])
        ], width=12)
    ], className="mb-3")
])

# --- Callbacks ---

# Callback to parse uploaded log file (Unchanged from your working version)
@app.callback(
    [Output('log-data-store', 'data'),
     Output('upload-status', 'children'),
     Output('date-picker-range', 'min_date_allowed'),
     Output('date-picker-range', 'max_date_allowed'),
     Output('date-picker-range', 'start_date'),
     Output('date-picker-range', 'end_date'),
     Output('ip-filter-dropdown', 'options'),
     Output('ip-filter-dropdown', 'value'),
     Output('status-code-filter-dropdown', 'options'),
     Output('status-code-filter-dropdown', 'value')],
    [Input('upload-log-file', 'contents')],
    [State('upload-log-file', 'filename')]
)
def upload_and_parse_log(contents, filename):
    if contents is None:
        return (pd.DataFrame().to_dict('records'), 
                "Please upload an NGINX access log file.",
                datetime(2000,1,1).date(), datetime.now().date(), None, None, [], None, [], None)
    df, status_msg = parse_log_content(contents, filename)
    if df.empty:
        return (pd.DataFrame().to_dict('records'), 
                dbc.Alert(status_msg, color="warning", dismissable=True), # More visible for empty/malformed
                datetime(2000,1,1).date(), datetime.now().date(), None, None, [], None, [], None)
    
    # Convert timestamp to datetime objects properly before finding min/max
    # This should happen if parse_log_line is correct
    if 'timestamp' not in df.columns or df['timestamp'].isnull().all():
         return (pd.DataFrame().to_dict('records'), 
                dbc.Alert(f"{status_msg} Could not parse timestamps.", color="danger", dismissable=True),
                datetime(2000,1,1).date(), datetime.now().date(), None, None, [], None, [], None)

    df['timestamp'] = pd.to_datetime(df['timestamp']) # Ensure it's datetime dtype

    min_date = df['timestamp'].min().date()
    max_date = df['timestamp'].max().date()
    ip_options = [{'label': ip, 'value': ip} for ip in sorted(df['ip_address'].unique())]
    status_options = [{'label': str(sc), 'value': sc} for sc in sorted(df['status_code'].unique())]
    return (df.to_dict('records'), 
            dbc.Alert(status_msg, color="success", dismissable=True),
            min_date, max_date, min_date, max_date,
            ip_options, None,
            status_options, None)


# Callback to filter data (Using your timezone fix)
@app.callback(
    Output('filtered-log-data-store', 'data'),
    [Input('log-data-store', 'data'),
     Input('date-picker-range', 'start_date'),
     Input('date-picker-range', 'end_date'),
     Input('ip-filter-dropdown', 'value'),
     Input('status-code-filter-dropdown', 'value')]
)
def filter_log_data(log_data_json, start_date_str, end_date_str, selected_ips, selected_status_codes):
    if not log_data_json: return pd.DataFrame().to_dict('records')
    df = pd.DataFrame(log_data_json)
    if df.empty: return pd.DataFrame().to_dict('records')
    
    df['timestamp'] = pd.to_datetime(df['timestamp']) # Ensure conversion from store
    
    if start_date_str:
        filter_start_datetime = pd.to_datetime(start_date_str)
        if df['timestamp'].dt.tz is not None: # Check if Series is timezone-aware
            # Localize the naive filter_start_datetime to the Series' timezone
            filter_start_datetime = filter_start_datetime.tz_localize(df['timestamp'].dt.tz)
        df = df[df['timestamp'] >= filter_start_datetime]
    
    if end_date_str:
        # Add one day to end_date to make it inclusive for the whole day, then localize
        filter_end_datetime_exclusive = pd.to_datetime(end_date_str) + timedelta(days=1)
        if df['timestamp'].dt.tz is not None: # Check if Series is timezone-aware
            filter_end_datetime_exclusive = filter_end_datetime_exclusive.tz_localize(df['timestamp'].dt.tz)
        df = df[df['timestamp'] < filter_end_datetime_exclusive]
        
    if selected_ips: df = df[df['ip_address'].isin(selected_ips)]
    
    if selected_status_codes:
        selected_status_codes_int = [int(sc) for sc in selected_status_codes] # Assume status codes in df are int
        df = df[df['status_code'].isin(selected_status_codes_int)]
            
    return df.to_dict('records')


# --- MODIFIED: Callback to update all dashboard elements including the IP Map ---
@app.callback(
    [Output('total-requests-card', 'children'),
     Output('unique-ips-card', 'children'),
     Output('error-rate-card', 'children'),
     Output('avg-response-size-card', 'children'),
     Output('requests-over-time-chart', 'figure'),
     Output('status-code-dist-chart', 'figure'),
     Output('top-ips-chart', 'figure'),
     Output('top-paths-chart', 'figure'),
     Output('http-methods-chart', 'figure'),
     Output('ip-location-map-chart', 'figure'), # New output for the map
     Output('log-data-table', 'data'),
     Output('log-data-table', 'columns'),
     Output('anomaly-error-bursts-div', 'children'),
     Output('anomaly-high-traffic-ips-div', 'children')],
    [Input('filtered-log-data-store', 'data'),
     Input('log-data-store', 'data')] # Original data for anomalies
)
def update_dashboard_elements(filtered_log_data_json, original_log_data_json):
    # Define empty figures for when no data is available
    empty_fig_layout = dict(template='plotly_white', xaxis={"visible": False}, yaxis={"visible": False})
    empty_fig = go.Figure(layout=empty_fig_layout).update_layout(title_text="No data to display")
    
    # Default empty map figure
    empty_map_fig = go.Figure(go.Scattermapbox())
    empty_map_fig.update_layout(
        margin={"r":0,"t":30,"l":0,"b":0},
        mapbox_style="open-street-map", # Basic style, works without token
        mapbox_accesstoken=MAPBOX_ACCESS_TOKEN,
        mapbox_center={"lat": 0, "lon": 0}, # Default center
        mapbox_zoom=1,
        annotations=[{ # Annotation for no data
            "text": "No IP data for map or geolocation failed.",
            "align": "center", "showarrow": False, "xref": "paper", "yref": "paper",
            "x": 0.5, "y": 0.5
        }]
    )

    if not filtered_log_data_json:
        return ("0", "0", "0%", "0 B", 
                empty_fig, empty_fig, empty_fig, empty_fig, empty_fig, 
                empty_map_fig, # Return the styled empty map
                [], [], [], [])

    df_filtered = pd.DataFrame(filtered_log_data_json)
    df_original = pd.DataFrame(original_log_data_json) # For anomalies on the whole dataset

    if df_filtered.empty: # If filters result in empty data
        no_match_fig = go.Figure(layout=empty_fig_layout).update_layout(title_text="No data matching filters")
        no_match_map_fig = go.Figure(go.Scattermapbox(lat=[], lon=[])) # Ensure it's a mapbox type
        no_match_map_fig.update_layout(
            margin={"r":0,"t":30,"l":0,"b":0},
            mapbox_style="open-street-map", mapbox_accesstoken=MAPBOX_ACCESS_TOKEN,
            mapbox_center={"lat": 0, "lon": 0}, mapbox_zoom=1,
             annotations=[{
                "text": "No data matching filters for map.", "align": "center",
                "showarrow": False, "xref": "paper", "yref": "paper", "x": 0.5, "y": 0.5
            }]
        )
        return ("0", "0", "0%", "0 B",
                no_match_fig, no_match_fig, no_match_fig, no_match_fig, no_match_fig,
                no_match_map_fig,
                [], [], 
                html.P("No data for anomaly detection based on filters."), 
                html.P("No data for anomaly detection based on filters."))
    
    # Ensure timestamp is datetime (already done in filter_log_data for df_filtered)
    df_filtered['timestamp'] = pd.to_datetime(df_filtered['timestamp'])
    if not df_original.empty:
        df_original['timestamp'] = pd.to_datetime(df_original['timestamp'])

    # --- Summary Cards ---
    total_requests = len(df_filtered)
    unique_ips_count_filtered = df_filtered['ip_address'].nunique()
    error_count = df_filtered[df_filtered['status_code'] >= 400].shape[0]
    error_rate = (error_count / total_requests * 100) if total_requests > 0 else 0
    avg_response_size_bytes = df_filtered['response_size'].mean() if total_requests > 0 else 0
    avg_response_size_str = f"{avg_response_size_bytes:,.0f} B"
    if avg_response_size_bytes > 1024 * 1024 : # MB
        avg_response_size_str = f"{avg_response_size_bytes/(1024*1024):,.2f} MB"
    elif avg_response_size_bytes > 1024: # KB
        avg_response_size_str = f"{avg_response_size_bytes/1024:,.1f} KB"


    # --- Charts (existing ones) ---
    requests_over_time_data = df_filtered.set_index('timestamp').resample('1H').size().reset_index(name='count')
    fig_req_time = px.line(requests_over_time_data, x='timestamp', y='count', title='Requests Over Time (Hourly)', markers=True)
    fig_req_time.update_layout(template='plotly_white')

    status_counts = df_filtered['status_code'].astype(str).value_counts().reset_index()
    status_counts.columns = ['status_code', 'count']
    fig_status_dist = px.pie(status_counts, names='status_code', values='count', title='Status Code Distribution', hole=0.3)
    fig_status_dist.update_layout(template='plotly_white')

    top_n = 10
    top_ips_data = df_filtered['ip_address'].value_counts().nlargest(top_n).reset_index()
    top_ips_data.columns = ['ip_address', 'count']
    fig_top_ips = px.bar(top_ips_data, x='ip_address', y='count', title=f'Top {top_n} IP Addresses')
    fig_top_ips.update_layout(template='plotly_white', xaxis_title="IP Address", yaxis_title="Request Count")

    top_paths_data = df_filtered['path'].value_counts().nlargest(top_n).reset_index()
    top_paths_data.columns = ['path', 'count']
    fig_top_paths = px.bar(top_paths_data, x='path', y='count', title=f'Top {top_n} Requested Paths')
    fig_top_paths.update_layout(template='plotly_white', xaxis_title="Path", yaxis_title="Request Count")
    
    method_counts = df_filtered['method'].value_counts().reset_index()
    method_counts.columns = ['method', 'count']
    fig_methods = px.pie(method_counts, names='method', values='count', title='HTTP Method Distribution', hole=0.3)
    fig_methods.update_layout(template='plotly_white')

    # --- IP Geolocation Map ---
    fig_ip_map = empty_map_fig # Default to empty map
    unique_ips_in_filtered_view = df_filtered['ip_address'].unique()
    
    geo_locations_data = [] # To store [{"ip": ..., "lat": ..., "lon": ..., "city": ..., "country": ...}]
    
    if len(unique_ips_in_filtered_view) > 0:
        # Limit number of IPs to geolocate per render to avoid long waits/API limits
        # For a real app, this logic would be more sophisticated (e.g., background job)
        max_ips_to_geolocate_per_render = 30 # Adjust as needed
        ips_to_process_for_map = unique_ips_in_filtered_view[:max_ips_to_geolocate_per_render]
        
        print(f"Attempting to geolocate {len(ips_to_process_for_map)} IPs for map...") # For debugging

        for ip_addr in ips_to_process_for_map:
            loc_data = geolocate_ip(ip_addr) # This function now handles caching and rate limiting
            if loc_data and loc_data.get("status") == "success" and loc_data.get("lat") is not None and loc_data.get("lon") is not None:
                geo_locations_data.append(loc_data)
        
        if geo_locations_data:
            geo_df = pd.DataFrame(geo_locations_data)
            
            # Get request counts for these geolocated IPs from the filtered data
            ip_counts_in_filtered = df_filtered['ip_address'].value_counts().reset_index()
            ip_counts_in_filtered.columns = ['ip', 'request_count']
            
            # Merge geolocation data with request counts
            geo_df = pd.merge(geo_df, ip_counts_in_filtered, on='ip', how='left')
            geo_df['request_count'] = geo_df['request_count'].fillna(1) # Should find a match
            
            # Scale marker size based on request count (adjust scaling as needed)
            geo_df['marker_size'] = geo_df['request_count'].apply(lambda x: min(max(x / 2, 8), 25))

            fig_ip_map = px.scatter_mapbox(
                geo_df,
                lat="lat",
                lon="lon",
                hover_name="ip",
                hover_data={"city": True, "country": True, "request_count": True, "lat": False, "lon": False}, # Hide lat/lon from default hover
                color_discrete_sequence=["#007bff"], # Bootstrap primary blue
                size="marker_size",
                size_max=30, 
                zoom=1.5, 
                center={"lat": geo_df['lat'].mean(), "lon": geo_df['lon'].mean()} if not geo_df.empty else {"lat":0, "lon":0},
            )
            
            current_mapbox_style = "open-street-map"
            if MAPBOX_ACCESS_TOKEN: # Use a richer style if token is available
                current_mapbox_style = "streets" # e.g., 'streets', 'satellite-streets', 'dark'
            
            fig_ip_map.update_layout(
                mapbox_style=current_mapbox_style,
                mapbox_accesstoken=MAPBOX_ACCESS_TOKEN,
                margin={"r":0,"t":0,"l":0,"b":0} # Use full card space
            )
        else:
            # If geo_locations_data is empty after trying, keep empty_map_fig with a message
            # This case is covered by the initial `fig_ip_map = empty_map_fig`
            print("No successful geolocations to display on map.") # For debugging
            pass # fig_ip_map is already the empty_map_fig

    # --- Data Table ---
    df_display = df_filtered.copy()
    # Ensure timestamp is string for display in table if it's timezone aware
    if pd.api.types.is_datetime64_any_dtype(df_display['timestamp']):
        if df_display['timestamp'].dt.tz is not None:
            df_display['timestamp'] = df_display['timestamp'].dt.strftime('%Y-%m-%d %H:%M:%S %Z')
        else:
            df_display['timestamp'] = df_display['timestamp'].dt.strftime('%Y-%m-%d %H:%M:%S')

    table_cols = [{"name": i, "id": i} for i in df_display.columns]
    table_data = df_display.to_dict('records')

    # --- Anomaly Detection (on original, unfiltered data) ---
    error_bursts_detected = []
    high_traffic_ips_detected = []
    if not df_original.empty:
        error_bursts = detect_error_bursts(df_original)
        if error_bursts:
            for burst in error_bursts:
                error_bursts_detected.append(dbc.Alert(
                    f"Period: {burst['time_period']}, Errors: {burst['error_count']}, IPs: {burst['ips_involved_count']}, Codes: {burst['status_codes']}. ({burst['threshold_exceeded']})", 
                    color="warning", dismissable=True, className="mb-1"
                ))
        else: error_bursts_detected = dbc.Alert("No significant error bursts detected.", color="success", className="mb-1")
        
        high_traffic_ips = detect_high_traffic_ips(df_original)
        if high_traffic_ips:
            for anom_ip in high_traffic_ips:
                high_traffic_ips_detected.append(dbc.Alert(
                    f"IP: {anom_ip['ip_address']}, Requests: {anom_ip['request_count']}. ({anom_ip['detail']})", 
                    color="danger", dismissable=True, className="mb-1"
                ))
        else: high_traffic_ips_detected = dbc.Alert("No IPs with unusually high traffic detected.", color="success", className="mb-1")
    else:
        error_bursts_detected = dbc.Alert("No data loaded for anomaly detection.", color="info", className="mb-1")
        high_traffic_ips_detected = dbc.Alert("No data loaded for anomaly detection.", color="info", className="mb-1")

    return (f"{total_requests:,}", f"{unique_ips_count_filtered:,}", f"{error_rate:.2f}%", avg_response_size_str,
            fig_req_time, fig_status_dist, fig_top_ips, fig_top_paths, fig_methods,
            fig_ip_map, # Return the map figure
            table_data, table_cols,
            error_bursts_detected, high_traffic_ips_detected)

# Callback for CSV export (Unchanged)
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
    if df_export.empty: raise dash.exceptions.PreventUpdate
    return dcc.send_data_frame(df_export.to_csv, f"nginx_log_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv", index=False)


if __name__ == '__main__':
    app.run(debug=True)