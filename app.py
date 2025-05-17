import dash
import dash_bootstrap_components as dbc
from dash import dcc, html, dash_table, Input, Output, State, callback, Patch
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
import re
from datetime import datetime, timedelta
import io
import base64
from collections import Counter

# Regex for NGINX log parsing (common format)
LOG_REGEX = re.compile(
    r'^(?P<ip_address>\S+) (?P<ident>\S+) (?P<user>\S+) '
    r'\[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>[^"\s]*) (?P<protocol>HTTP/\d\.\d)" '
    r'(?P<status_code>\d{3}) (?P<response_size>\d+) '
    r'"(?P<referrer>[^"]*)" "(?P<user_agent>[^"]*)"$'
)

# --- Helper Functions ---
def parse_log_line(line):
    match = LOG_REGEX.match(line)
    if match:
        data = match.groupdict()
        try:
            data['timestamp'] = datetime.strptime(data['timestamp'], '%d/%b/%Y:%H:%M:%S %z')
        except ValueError: # Fallback for timestamps without timezone (less common for NGINX default)
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
        if line.strip(): # ensure line is not empty
            parsed_line = parse_log_line(line)
            if parsed_line:
                parsed_data.append(parsed_line)
            else:
                malformed_lines += 1
    
    df = pd.DataFrame(parsed_data)
    status_message = f"Successfully parsed '{filename}'. {len(df)} lines processed."
    if malformed_lines > 0:
        status_message += f" {malformed_lines} lines were malformed and skipped."
    
    if df.empty and not parsed_data: # if all lines were malformed or file was empty after decoding
        status_message = f"Uploaded file '{filename}' contained no valid log entries."

    return df, status_message

# --- Anomaly Detection Functions ---
def detect_error_bursts(df, time_window_minutes=1, threshold_factor=2, min_errors=3):
    """Detects bursts of errors (status codes 4xx or 5xx)."""
    if df.empty or 'timestamp' not in df.columns or 'status_code' not in df.columns:
        return []
    
    errors_df = df[df['status_code'] >= 400].copy()
    if errors_df.empty:
        return []

    errors_df.set_index('timestamp', inplace=True)
    error_counts_per_window = errors_df['status_code'].resample(f'{time_window_minutes}T').count()
    
    if error_counts_per_window.empty:
        return []

    mean_errors = error_counts_per_window.mean()
    std_errors = error_counts_per_window.std()
    
    # Define dynamic threshold, ensure std_errors is not NaN (e.g. if only one window)
    # and a minimum fixed threshold
    dynamic_threshold = mean_errors + threshold_factor * (std_errors if pd.notna(std_errors) else 0)
    current_threshold = max(min_errors, dynamic_threshold)

    bursts = []
    for period_start, count in error_counts_per_window.items():
        if count >= current_threshold:
            period_end = period_start + timedelta(minutes=time_window_minutes)
            # Find specific IPs and status codes in this burst window
            burst_details_df = errors_df[(errors_df.index >= period_start) & (errors_df.index < period_end)]
            ips_in_burst = burst_details_df['ip_address'].nunique()
            status_codes_in_burst = dict(Counter(burst_details_df['status_code'].astype(str)))

            bursts.append({
                "time_period": f"{period_start.strftime('%Y-%m-%d %H:%M:%S')} - {period_end.strftime('%H:%M:%S')}",
                "error_count": count,
                "ips_involved_count": ips_in_burst,
                "status_codes": status_codes_in_burst,
                "threshold_exceeded": f"{count} errors >= threshold ({current_threshold:.2f})"
            })
    return bursts

def detect_high_traffic_ips(df, threshold_factor=2.0, min_requests=10):
    """Identifies IPs with unusually high request counts."""
    if df.empty or 'ip_address' not in df.columns:
        return []
    
    ip_counts = df['ip_address'].value_counts()
    if ip_counts.empty:
        return []

    mean_requests = ip_counts.mean()
    std_requests = ip_counts.std()

    # Define dynamic threshold, ensure std_requests is not NaN
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
server = app.server # For PaaS deployment

# --- App Layout ---
app.layout = dbc.Container(fluid=True, children=[
    dcc.Store(id='log-data-store'),
    dcc.Store(id='filtered-log-data-store'), # To store filtered data for export

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
                multiple=False # Allow only one file
            ),
            html.Div(id='upload-status', className="mt-2")
        ], width=12)
    ], className="mb-3"),

    dbc.Row([
        dbc.Col(dcc.DatePickerRange(
            id='date-picker-range',
            min_date_allowed=datetime(2000, 1, 1).date(), # Placeholder
            max_date_allowed=datetime.now().date() + timedelta(days=1), # Placeholder
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
        dbc.Col(width=12, lg=6, className="mb-3") # Placeholder for potential 6th chart or spacing
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

# Callback to parse uploaded log file
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
                status_msg,
                datetime(2000,1,1).date(), datetime.now().date(), None, None, [], None, [], None)

    # Update filter options based on the new data
    min_date = df['timestamp'].min().date()
    max_date = df['timestamp'].max().date()
    
    ip_options = [{'label': ip, 'value': ip} for ip in sorted(df['ip_address'].unique())]
    status_options = [{'label': str(sc), 'value': sc} for sc in sorted(df['status_code'].unique())]

    return (df.to_dict('records'), 
            dbc.Alert(status_msg, color="success", dismissable=True),
            min_date, max_date, min_date, max_date,  # Set date picker to full range
            ip_options, None,  # Clear IP filter
            status_options, None) # Clear status code filter


# Callback to filter data based on user selections
@app.callback(
    Output('filtered-log-data-store', 'data'),
    [Input('log-data-store', 'data'),
     Input('date-picker-range', 'start_date'), # This is start_date_str
     Input('date-picker-range', 'end_date'),   # This is end_date_str
     Input('ip-filter-dropdown', 'value'),
     Input('status-code-filter-dropdown', 'value')]
)
def filter_log_data(log_data_json, start_date_str, end_date_str, selected_ips, selected_status_codes):
    if not log_data_json:
        return pd.DataFrame().to_dict('records')

    df = pd.DataFrame(log_data_json)
    if df.empty:
        return pd.DataFrame().to_dict('records')

    # Ensure timestamp is datetime. This conversion should preserve the timezone
    # information if it was correctly parsed and stored.
    df['timestamp'] = pd.to_datetime(df['timestamp'])

    # Apply date filters
    if start_date_str:
        # Convert the start_date string from the picker to a pandas Timestamp.
        # This will be a timezone-naive Timestamp by default.
        filter_start_datetime = pd.to_datetime(start_date_str)
        
        # Check if the DataFrame's timestamp column is timezone-aware
        if df['timestamp'].dt.tz is not None:
            # If yes, localize the naive filter_start_datetime to the DataFrame's timezone
            filter_start_datetime = filter_start_datetime.tz_localize(df['timestamp'].dt.tz)
        
        # Now, both df['timestamp'] and filter_start_datetime are compatible for comparison
        df = df[df['timestamp'] >= filter_start_datetime]
    
    if end_date_str:
        # Convert the end_date string and add one day to make the range inclusive of the end date.
        # This creates a timezone-naive Timestamp.
        filter_end_datetime_exclusive = pd.to_datetime(end_date_str) + timedelta(days=1)
        
        # Check if the DataFrame's timestamp column is timezone-aware
        if df['timestamp'].dt.tz is not None:
            # If yes, localize the naive filter_end_datetime_exclusive to the DataFrame's timezone
            filter_end_datetime_exclusive = filter_end_datetime_exclusive.tz_localize(df['timestamp'].dt.tz)
            
        # Now, both df['timestamp'] and filter_end_datetime_exclusive are compatible
        df = df[df['timestamp'] < filter_end_datetime_exclusive]
    
    if selected_ips:
        df = df[df['ip_address'].isin(selected_ips)]
    
    if selected_status_codes:
        # Ensure selected_status_codes are integers if they are not already
        # (Dropdowns might sometimes pass string values if not explicitly typed)
        # The status_code column in df should already be int from parsing.
        selected_status_codes_int = [int(sc) for sc in selected_status_codes] if selected_status_codes else None
        if selected_status_codes_int:
            df = df[df['status_code'].isin(selected_status_codes_int)]
        
    return df.to_dict('records')


# Callback to update summary cards, charts, table, and anomalies
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
     Output('log-data-table', 'data'),
     Output('log-data-table', 'columns'),
     Output('anomaly-error-bursts-div', 'children'),
     Output('anomaly-high-traffic-ips-div', 'children')],
    [Input('filtered-log-data-store', 'data'), # Use filtered data for display
     Input('log-data-store', 'data')] # Use original full data for anomaly detection
)
def update_dashboard_elements(filtered_log_data_json, original_log_data_json):
    if not filtered_log_data_json:
        empty_fig = go.Figure().update_layout(template='plotly_white', title_text="No data to display")
        return "0", "0", "0%", "0 B", empty_fig, empty_fig, empty_fig, empty_fig, empty_fig, [], [], [], []

    df_filtered = pd.DataFrame(filtered_log_data_json)
    df_original = pd.DataFrame(original_log_data_json) # For anomalies on the whole dataset

    if df_filtered.empty: # If filters result in empty data
        empty_fig = go.Figure().update_layout(template='plotly_white', title_text="No data matching filters")
        return "0", "0", "0%", "0 B", empty_fig, empty_fig, empty_fig, empty_fig, empty_fig, [], [], html.P("No data for anomaly detection based on filters."), html.P("No data for anomaly detection based on filters.")
    
    # Ensure timestamp is datetime
    df_filtered['timestamp'] = pd.to_datetime(df_filtered['timestamp'])
    if not df_original.empty:
        df_original['timestamp'] = pd.to_datetime(df_original['timestamp'])

    # --- Summary Cards ---
    total_requests = len(df_filtered)
    unique_ips = df_filtered['ip_address'].nunique()
    error_count = df_filtered[df_filtered['status_code'] >= 400].shape[0]
    error_rate = (error_count / total_requests * 100) if total_requests > 0 else 0
    avg_response_size = df_filtered['response_size'].mean() if total_requests > 0 else 0

    # --- Charts ---
    # Requests over time
    requests_over_time_data = df_filtered.set_index('timestamp').resample('1H').size().reset_index(name='count')
    fig_req_time = px.line(requests_over_time_data, x='timestamp', y='count', title='Requests Over Time (Hourly)', markers=True)
    fig_req_time.update_layout(template='plotly_white')

    # Status code distribution
    status_counts = df_filtered['status_code'].astype(str).value_counts().reset_index()
    status_counts.columns = ['status_code', 'count']
    fig_status_dist = px.pie(status_counts, names='status_code', values='count', title='Status Code Distribution', hole=0.3)
    fig_status_dist.update_layout(template='plotly_white')

    # Top IPs
    top_n = 10
    top_ips_data = df_filtered['ip_address'].value_counts().nlargest(top_n).reset_index()
    top_ips_data.columns = ['ip_address', 'count']
    fig_top_ips = px.bar(top_ips_data, x='ip_address', y='count', title=f'Top {top_n} IP Addresses')
    fig_top_ips.update_layout(template='plotly_white')

    # Top Paths
    top_paths_data = df_filtered['path'].value_counts().nlargest(top_n).reset_index()
    top_paths_data.columns = ['path', 'count']
    fig_top_paths = px.bar(top_paths_data, x='path', y='count', title=f'Top {top_n} Requested Paths')
    fig_top_paths.update_layout(template='plotly_white')
    
    # HTTP Methods
    method_counts = df_filtered['method'].value_counts().reset_index()
    method_counts.columns = ['method', 'count']
    fig_methods = px.pie(method_counts, names='method', values='count', title='HTTP Method Distribution', hole=0.3)
    fig_methods.update_layout(template='plotly_white')

    # --- Data Table ---
    # Displaying all columns. For better UX, could select a subset.
    # Convert datetime to string for DataTable display
    df_display = df_filtered.copy()
    df_display['timestamp'] = df_display['timestamp'].dt.strftime('%Y-%m-%d %H:%M:%S %z')
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
                    color="warning"
                ))
        else:
            error_bursts_detected = dbc.Alert("No significant error bursts detected.", color="success")

        high_traffic_ips = detect_high_traffic_ips(df_original)
        if high_traffic_ips:
            for anom_ip in high_traffic_ips:
                high_traffic_ips_detected.append(dbc.Alert(
                    f"IP: {anom_ip['ip_address']}, Requests: {anom_ip['request_count']}. ({anom_ip['detail']})", 
                    color="danger"
                ))
        else:
            high_traffic_ips_detected = dbc.Alert("No IPs with unusually high traffic detected.", color="success")
    else: # If original data is empty
        error_bursts_detected = dbc.Alert("No data loaded for anomaly detection.", color="info")
        high_traffic_ips_detected = dbc.Alert("No data loaded for anomaly detection.", color="info")


    return (f"{total_requests:,}", f"{unique_ips:,}", f"{error_rate:.2f}%", f"{avg_response_size:,.0f} B",
            fig_req_time, fig_status_dist, fig_top_ips, fig_top_paths, fig_methods,
            table_data, table_cols,
            error_bursts_detected, high_traffic_ips_detected)

# Callback for CSV export
@app.callback(
    Output("download-csv", "data"),
    Input("export-button", "n_clicks"),
    State("filtered-log-data-store", "data"), # Use filtered data for export
    prevent_initial_call=True,
)
def export_csv(n_clicks, filtered_log_data_json):
    if not n_clicks or not filtered_log_data_json:
        raise dash.exceptions.PreventUpdate
    
    df_export = pd.DataFrame(filtered_log_data_json)
    if df_export.empty:
        raise dash.exceptions.PreventUpdate
        
    return dcc.send_data_frame(df_export.to_csv, f"nginx_log_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv", index=False)


if __name__ == '__main__':
    app.run(debug=True)