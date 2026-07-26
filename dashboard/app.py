import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import json
from datetime import datetime
from pathlib import Path
import numpy as np

# Configure page
st.set_page_config(
    page_title="Security Posture Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for dark theme
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #58a6ff;
        text-align: center;
        padding: 1rem 0;
    }
    .metric-card {
        background-color: #161b22;
        border: 1px solid #30363d;
        border-radius: 8px;
        padding: 1.5rem;
        margin: 0.5rem 0;
    }
    .finding-critical { color: #ff6b6b; }
    .finding-high { color: #ffa502; }
    .finding-medium { color: #ffd93d; }
    .finding-low { color: #1e90ff; }
    .stTabs [data-baseweb="tab-list"] {
        gap: 2px;
    }
    .stTabs [data-baseweb="tab"] {
        background-color: #21262d;
        border-radius: 4px 4px 0 0;
        border: 1px solid #30363d;
        border-bottom: none;
    }
    .stTabs [data-baseweb="tab"][aria-selected="true"] {
        background-color: #58a6ff;
        color: white;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if 'scan_data' not in st.session_state:
    st.session_state.scan_data = None
if 'environment' not in st.session_state:
    st.session_state.environment = 'prod'

# Load sample data
@st.cache_data
def load_sample_data():
    return {
        'scan_metadata': {
            'environment': 'Production',
            'timestamp': datetime.now().isoformat(),
            'benchmark': 'CIS AWS Foundations Benchmark v1.2.0',
            'scanner_version': '1.0.0'
        },
        'summary': {
            'total': 12,
            'critical': 0,
            'high': 4,
            'medium': 8,
            'low': 3,
            'passed': 85,
            'compliance_score': 87.0
        },
        'findings': [
            {'control_id': '2.1.2', 'control_name': 'CloudWatch Alarms', 'status': 'FAIL', 'severity': 'HIGH', 'remediation': 'Configure 3+ CloudWatch alarms'},
            {'control_id': '3.2', 'control_name': 'GuardDuty Disabled', 'status': 'FAIL', 'severity': 'HIGH', 'remediation': 'Enable GuardDuty in all regions'},
            {'control_id': '5.6', 'control_name': 'S3 Versioning Disabled', 'status': 'FAIL', 'severity': 'MEDIUM', 'remediation': 'Enable versioning on audit buckets'},
            {'control_id': '1.4', 'control_name': 'Password Policy', 'status': 'FAIL', 'severity': 'LOW', 'remediation': 'Enforce 14-char password minimum'}
        ]
    }

# Sidebar
with st.sidebar:
    st.markdown("## 🛡️ Security Posture")
    st.markdown("---")

    environment = st.selectbox(
        "Environment",
        ["Production", "Staging", "Development"],
        index=0
    )
    st.session_state.environment = environment.lower()

    st.markdown("### Metrics")
    data = load_sample_data()
    summary = data['summary']

    st.metric("Compliance Score", f"{summary['compliance_score']}%", delta="+45%")
    st.metric("Critical Findings", summary['critical'], delta="0")
    st.metric("High Findings", summary['high'], delta="-14")
    st.metric("Total Findings", summary['total'], delta="-43")

    st.markdown("---")
    st.markdown("### Quick Actions")
    if st.button("🔄 Run New Scan", use_container_width=True):
        st.success("Scan initiated!")
    if st.button("📥 Export Report", use_container_width=True):
        st.success("Report exported!")
    if st.button("🔧 Auto-Remediate", use_container_width=True):
        st.warning("Dry-run mode: use scripts/remediate.py")

# Main content
st.markdown('<p class="main-header">Cloud Security Posture Dashboard</p>', unsafe_allow_html=True)

# Tabs
tab1, tab2, tab3, tab4 = st.tabs([
    "📊 Overview",
    "🔍 Findings",
    "🔧 Remediation",
    "✅ Compliance"
])

with tab1:
    st.markdown("## Security Posture Overview")

    # Top metrics row
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric(
            label="Compliance Score",
            value=f"{summary['compliance_score']}%",
            delta="+45% from baseline",
            delta_color="normal"
        )
    with col2:
        st.metric(
            label="Critical Findings",
            value=summary['critical'],
            delta="0 (all fixed)",
            delta_color="normal"
        )
    with col3:
        st.metric(
            label="High Findings",
            value=summary['high'],
            delta="-14 fixed",
            delta_color="normal"
        )
    with col4:
        st.metric(
            label="Medium Findings",
            value=summary['medium'],
            delta="-17 fixed",
            delta_color="normal"
        )

    st.markdown("---")

    # Charts row
    col_left, col_right = st.columns(2)

    with col_left:
        st.markdown("### Findings by Severity")
        fig_severity = go.Figure(data=[
            go.Bar(
                x=['Critical', 'High', 'Medium', 'Low'],
                y=[12, 18, 25, 8],
                name='Before',
                marker_color='#e74c3c',
                opacity=0.7
            ),
            go.Bar(
                x=['Critical', 'High', 'Medium', 'Low'],
                y=[0, 4, 8, 3],
                name='After',
                marker_color='#2ecc71',
                opacity=0.9
            )
        ])
        fig_severity.update_layout(
            barmode='group',
            template='plotly_dark',
            height=400,
            showlegend=True,
            xaxis_title="Severity",
            yaxis_title="Number of Findings"
        )
        st.plotly_chart(fig_severity, use_container_width=True)

    with col_right:
        st.markdown("### Compliance Score by Category")
        categories = ['Identity', 'Logging', 'Networking', 'Compute', 'Storage']
        before = [40, 20, 45, 35, 25]
        after = [95, 75, 85, 90, 90]

        fig_radar = go.Figure()
        fig_radar.add_trace(go.Scatterpolar(
            r=before + before[:1],
            theta=categories + categories[:1],
            fill='toself',
            name='Before',
            line_color='#e74c3c',
            opacity=0.5
        ))
        fig_radar.add_trace(go.Scatterpolar(
            r=after + after[:1],
            theta=categories + categories[:1],
            fill='toself',
            name='After',
            line_color='#2ecc71',
            opacity=0.5
        ))
        fig_radar.update_layout(
            polar=dict(
                radialaxis=dict(
                    visible=True,
                    range=[0, 100],
                    tickcolor='white'
                ),
                bgcolor='#161b22'
            ),
            template='plotly_dark',
            height=400,
            showlegend=True
        )
        st.plotly_chart(fig_radar, use_container_width=True)

    # Timeline chart
    st.markdown("### Remediation Progress")
    weeks = ['Week 1', 'Week 2', 'Week 3', 'Week 4']
    findings = [55, 55, 55, 55]
    remediated = [0, 12, 30, 43]

    fig_timeline = go.Figure()
    fig_timeline.add_trace(go.Scatter(
        x=weeks,
        y=remediated,
        mode='lines+markers',
        name='Remediated',
        line=dict(color='#2ecc71', width=3),
        marker=dict(size=10)
    ))
    fig_timeline.add_trace(go.Scatter(
        x=weeks,
        y=findings,
        mode='lines',
        name='Total Findings',
        line=dict(color='#e74c3c', width=2, dash='dash')
    ))
    fig_timeline.update_layout(
        template='plotly_dark',
        height=400,
        xaxis_title="Timeline",
        yaxis_title="Findings Count",
        showlegend=True
    )
    st.plotly_chart(fig_timeline, use_container_width=True)

with tab2:
    st.markdown("## Findings Explorer")

    # Filters
    col1, col2, col3 = st.columns(3)
    with col1:
        severity_filter = st.multiselect(
            "Filter by Severity",
            ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
            default=["HIGH", "MEDIUM", "LOW"]
        )
    with col2:
        status_filter = st.multiselect(
            "Filter by Status",
            ["FAIL", "PASS", "NEEDS_WORK"],
            default=["FAIL"]
        )
    with col3:
        search_term = st.text_input("Search findings...")

    # Sample findings data
    findings_data = [
        {'id': 'CLOUD-SEC-001', 'control': 'CIS 1.16', 'title': 'IAM Excessive Permissions', 'severity': 'HIGH', 'status': 'FIXED', 'category': 'Identity'},
        {'id': 'CLOUD-SEC-002', 'control': 'CIS 5.1', 'title': 'S3 Public Access', 'severity': 'CRITICAL', 'status': 'FIXED', 'category': 'Storage'},
        {'id': 'CLOUD-SEC-003', 'control': 'CIS 2.1.1', 'title': 'CloudTrail Disabled', 'severity': 'HIGH', 'status': 'FIXED', 'category': 'Logging'},
        {'id': 'CLOUD-SEC-004', 'control': 'CIS 5.3', 'title': 'RDS Unencrypted', 'severity': 'CRITICAL', 'status': 'FIXED', 'category': 'Storage'},
        {'id': 'CLOUD-SEC-005', 'control': 'CIS 4.1', 'title': 'SG SSH Open', 'severity': 'HIGH', 'status': 'FIXED', 'category': 'Network'},
        {'id': 'CLOUD-SEC-006', 'control': 'CIS 2.1.2', 'title': 'CloudWatch Alarms', 'severity': 'MEDIUM', 'status': 'NEEDS_WORK', 'category': 'Monitoring'}
    ]

    df = pd.DataFrame(findings_data)

    # Apply filters
    if severity_filter:
        df = df[df['severity'].isin(severity_filter)]
    if status_filter:
        df = df[df['status'].isin(status_filter)]
    if search_term:
        df = df[df['title'].str.contains(search_term, case=False)]

    # Display findings
    for _, row in df.iterrows():
        severity_color = {
            'CRITICAL': '🔴',
            'HIGH': '🟠',
            'MEDIUM': '🟡',
            'LOW': '🔵'
        }.get(row['severity'], '⚪')

        with st.expander(f"{severity_color} {row['id']} - {row['title']}"):
            col1, col2 = st.columns(2)
            with col1:
                st.write(f"**Control:** {row['control']}")
                st.write(f"**Severity:** {row['severity']}")
                st.write(f"**Category:** {row['category']}")
            with col2:
                st.write(f"**Status:** {row['status']}")
                st.write(f"**Remediation:** Required" if row['status'] != 'FIXED' else "**Remediation:** Complete")
                if row['status'] != 'FIXED':
                    st.button("Remediate", key=f"remediate_{row['id']}")

with tab3:
    st.markdown("## Remediation Tracker")

    remediation_data = [
        {'week': 1, 'finding': 'S3 Public Access', 'control': 'CIS 5.1', 'status': 'Complete', 'owner': 'Security Team', 'risk': 'CRITICAL'},
        {'week': 2, 'finding': 'IAM Excessive Permissions', 'control': 'CIS 1.16', 'status': 'Complete', 'owner': 'Cloud Team', 'risk': 'HIGH'},
        {'week': 2, 'finding': 'RDS Encryption', 'control': 'CIS 5.4', 'status': 'Complete', 'owner': 'Database Team', 'risk': 'CRITICAL'},
        {'week': 3, 'finding': 'CloudTrail', 'control': 'CIS 2.1', 'status': 'Complete', 'owner': 'Security Team', 'risk': 'HIGH'},
        {'week': 4, 'finding': 'GuardDuty', 'control': 'CIS 3.2', 'status': 'In Progress', 'owner': 'Security Team', 'risk': 'MEDIUM'},
    ]

    df_remediation = pd.DataFrame(remediation_data)

    # Progress metrics
    col1, col2, col3 = st.columns(3)
    with col1:
        completed = len(df_remediation[df_remediation['status'] == 'Complete'])
        st.metric("Completed", completed)
    with col2:
        in_progress = len(df_remediation[df_remediation['status'] == 'In Progress'])
        st.metric("In Progress", in_progress)
    with col3:
        remaining = len(df_remediation[df_remediation['status'] == 'Pending'])
        st.metric("Pending", remaining)

    st.markdown("---")

    # Gantt-like chart
    fig_gantt = go.Figure()
    colors = {'Complete': '#2ecc71', 'In Progress': '#f1c40f', 'Pending': '#e74c3c'}

    for i, row in df_remediation.iterrows():
        fig_gantt.add_trace(go.Bar(
            x=[1],
            y=[row['finding']],
            orientation='h',
            marker_color=colors.get(row['status'], '#95a5a6'),
            name=row['status'],
            showlegend=False,
            text=row['week'],
            textposition='inside'
        ))

    fig_gantt.update_layout(
        title='Remediation Timeline',
        template='plotly_dark',
        height=300,
        xaxis=dict(showgrid=False, showticklabels=False),
        yaxis=dict(title='Finding'),
        barmode='stack'
    )
    st.plotly_chart(fig_gantt, use_container_width=True)

    # Table view
    st.markdown("### Remediation Details")
    st.dataframe(
        df_remediation,
        use_container_width=True,
        hide_index=True,
        column_config={
            "week": st.column_config.NumberColumn("Week", format="%d"),
            "finding": "Finding",
            "control": "CIS Control",
            "status": st.column_config.TextColumn("Status"),
            "owner": "Owner",
            "risk": st.column_config.TextColumn("Risk Level")
        }
    )

with tab4:
    st.markdown("## CIS Compliance Matrix")

    compliance_data = [
        {'section': '1. Identity & Access', 'control': '1.1', 'title': 'Root MFA', 'before': '✅', 'after': '✅', 'status': 'PASS'},
        {'section': '1. Identity & Access', 'control': '1.2', 'title': 'IAM MFA', 'before': '❌', 'after': '✅', 'status': 'PASS'},
        {'section': '1. Identity & Access', 'control': '1.16', 'title': 'Least Privilege', 'before': '❌', 'after': '✅', 'status': 'PASS'},
        {'section': '2. Logging', 'control': '2.1', 'title': 'CloudTrail', 'before': '❌', 'after': '✅', 'status': 'PASS'},
        {'section': '2. Logging', 'control': '2.4', 'title': 'AWS Config', 'before': '❌', 'after': '✅', 'status': 'PASS'},
        {'section': '3. Monitoring', 'control': '3.2', 'title': 'GuardDuty', 'before': '❌', 'after': '✅', 'status': 'PASS'},
        {'section': '4. Network', 'control': '4.1', 'title': 'VPC Flow Logs', 'before': '❌', 'after': '✅', 'status': 'PASS'},
        {'section': '4. Network', 'control': '4.2', 'title': 'IMDSv2', 'before': '❌', 'after': '✅', 'status': 'PASS'},
        {'section': '5. Storage', 'control': '5.1', 'title': 'S3 Public Block', 'before': '❌', 'after': '✅', 'status': 'PASS'},
        {'section': '5. Storage', 'control': '5.2', 'title': 'S3 Encryption', 'before': '❌', 'after': '✅', 'status': 'PASS'},
        {'section': '5. Storage', 'control': '5.4', 'title': 'RDS Encryption', 'before': '❌', 'after': '✅', 'status': 'PASS'},
    ]

    df_compliance = pd.DataFrame(compliance_data)

    # Heatmap visualization
    st.markdown("### Compliance Heatmap")
    heatmap_data = []
    for _, row in df_compliance.iterrows():
        heatmap_data.append({
            'Control': f"{row['control']} - {row['title']}",
            'Before': 1 if row['before'] == '✅' else 0,
            'After': 1 if row['after'] == '✅' else 0
        })

    df_heatmap = pd.DataFrame(heatmap_data)

    fig_heatmap = go.Figure(data=go.Heatmap(
        z=df_heatmap[['Before', 'After']].values.T,
        x=df_heatmap['Control'],
        y=['Before Remediation', 'After Remediation'],
        colorscale=[[0, '#e74c3c'], [1, '#2ecc71']],
        showscale=False,
        text=df_heatmap[['Before', 'After']].values.T,
        texttemplate=['❌' if v == 0 else '✅' for v in df_heatmap[['Before', 'After']].values.T.flatten()],
        textfont={"size": 12}
    ))
    fig_heatmap.update_layout(
        template='plotly_dark',
        height=400,
        xaxis=dict(tickangle=-45),
        title='CIS Controls: Before vs After'
    )
    st.plotly_chart(fig_heatmap, use_container_width=True)

    # Detailed table
    st.markdown("### Detailed Compliance Matrix")
    st.dataframe(
        df_compliance,
        use_container_width=True,
        hide_index=True,
        column_config={
            "section": "Category",
            "control": "Control",
            "title": "Title",
            "before": "Before",
            "after": "After",
            "status": "Final Status"
        }
    )

# Footer
st.markdown("---")
st.markdown(
    f"<div style='text-align: center; color: #8b949e;'>"
    f"Cloud Security Posture Audit Dashboard | "
    f"Environment: {st.session_state.environment} | "
    f"Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    f"</div>",
    unsafe_allow_html=True
)
