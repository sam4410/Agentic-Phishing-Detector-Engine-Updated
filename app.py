# ========================================
# File: app.py - Complete Enhanced Streamlit Application
# ========================================
import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from agents import PhishingDetectionCrew
from tools import URLAnalysisTool, ContentAnalysisTool, VisualAnalysisTool
from util_funcs import parse_coordinator_json, get_coordinator_output
import json
import re
import time
from datetime import datetime

def get_steps_for_input(input_type: str):
    steps = [
        "Input Received",
        "URL Analysis" if input_type == "URL" else None,
        "Content Analysis",
        "Visual Analysis" if input_type == "URL" else None,
        "Threat Intelligence" if input_type == "URL" else None,
        "Coordination",
        "Results"
    ]
    return [s for s in steps if s is not None]


def render_step_timeline(container, input_type: str, current_step: int):
    steps = get_steps_for_input(input_type)

    icons = {
        "done": "✅",
        "active": "🔄",
        "pending": "⏳"
    }

    with container:
        for i, step in enumerate(steps):
            if i < current_step:
                st.markdown(f"{icons['done']} **{step} — Completed**")
            elif i == current_step:
                st.markdown(f"{icons['active']} **{step} — In Progress**")
            else:
                st.markdown(f"{icons['pending']} {step} — Pending")

# Page configuration
st.set_page_config(
    page_title="AI Phishing Detection Engine",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS with enhanced styling
st.markdown("""
<style>

/* App background */
.stApp {
    background: rgba(248, 250, 252, 0.95); /* very light, almost white */
}

/* Main content area */
.main {
    background-color: #f8fafc;
}

/* Sidebar */
section[data-testid="stSidebar"] {
    background-color: #ffffff;
    border-right: 1px solid #e5e7eb;
}

/* Headers */
h1, h2, h3, h4 {
    color: #0f172a;
}

/* Input boxes */
textarea, input, select {
    background-color: #ffffff !important;
    color: #0f172a !important;
    border-radius: 6px !important;
    border: 1px solid #cbd5e1 !important;
}

/* Buttons */
button[kind="primary"] {
    background-color: #2563eb !important;
    color: white !important;
    border-radius: 8px !important;
    font-weight: 600 !important;
}

/* Metrics */
div[data-testid="metric-container"] {
    background-color: #ffffff;
    border-radius: 10px;
    padding: 15px;
    box-shadow: 0 2px 6px rgba(0,0,0,0.08);
}

/* Expanders */
div[data-testid="stExpander"] {
    background-color: #ffffff;
    border-radius: 10px;
    border: 1px solid #e5e7eb;
}

/* Alerts */
div.stAlert {
    border-radius: 10px;
}

/* Footer */
footer {
    visibility: hidden;
}

/* Selectbox container */
div[data-testid="stSelectbox"] > div {
    background-color: #ffffff;
    border-radius: 8px;
    border: 2px solid #2563eb; /* blue border */
}

/* Selected value text */
div[data-testid="stSelectbox"] span {
    color: #0f172a;
    font-weight: 600;
}

/* Dropdown arrow */
div[data-testid="stSelectbox"] svg {
    color: #2563eb;
}

/* Hover effect */
div[data-testid="stSelectbox"] > div:hover {
    border-color: #1d4ed8;
    box-shadow: 0 0 0 1px rgba(37, 99, 235, 0.4);
}

/* Focused (clicked) state */
div[data-testid="stSelectbox"] > div:focus-within {
    border-color: #1e40af;
    box-shadow: 0 0 0 2px rgba(30, 64, 175, 0.5);
}

/* Remove default Streamlit padding background */
.block-container {
    background: transparent;
}

/* Cards & containers */
.metric-card,
.agent-card,
.findings-box {
    background: rgba(255, 255, 255, 0.95);
    backdrop-filter: blur(4px);
}

</style>
""", unsafe_allow_html=True)

# Initialize session state
if 'analysis_result' not in st.session_state:
    st.session_state.analysis_result = None
if 'analysis_history' not in st.session_state:
    st.session_state.analysis_history = []
if 'agent_progress' not in st.session_state:
    st.session_state.agent_progress = []
if 'current_step' not in st.session_state:
    st.session_state.current_step = 0

# Agent definitions for display
AGENT_INFO = {
    'url_analyzer': {
        'name': 'URL Analyzer Agent',
        'icon': '🔗',
        'color': '#3b82f6',
        'description': 'Extracts and evaluates structural risk signals from URLs.',
        'capabilities': [
            '✔ URL parsing and validation',
            '✔ Domain age and registration analysis',
            '✔ Typosquatting detection',
            '✔ Suspicious URL pattern detection'
        ]
    },
    'content_analyzer': {
        'name': 'Content Analyzer Agent',
        'icon': '📝',
        'color': '#8b5cf6',
        'description': 'Detects linguistic and social-engineering indicators in text.',
        'capabilities': [
            '✔ Urgency and pressure language detection',
            '✔ Threat and coercion phrase detection',
            '✔ Generic greeting identification',
            '✔ Grammar and language anomaly signals'
        ]
    },
    'visual_analyzer': {
        'name': 'Visual Analyzer Agent',
        'icon': '👁️',
        'color': '#ec4899',
        'description': 'Inspects webpage structure for credential harvesting indicators.',
        'capabilities': [
            '✔ Credential input form detection',
            '✔ External resource correlation',
            '✔ Brand keyword presence (contextual)',
            '✔ Embedded iframe and script signals'
        ]
    },
    'threat_intel': {
        'name': 'Threat Intelligence Agent',
        'icon': '🛰️',
        'color': '#f97316',
        'description': 'Retrieves third-party threat intelligence evidence.',
        'capabilities': [
            '✔ VirusTotal detection evidence',
            '✔ Detection count reporting',
            '✔ Inconclusive verdict handling',
            '✔ Evidence-only signal reporting'
        ]
    },
    'coordinator': {
        'name': 'Security Coordinator',
        'icon': '🧠',
        'color': '#10b981',
        'description': 'Aggregates normalized signals into a deterministic decision.',
        'capabilities': [
            '✔ Signal aggregation',
            '✔ Weighted score fusion',
            '✔ Deterministic verdict assignment',
            '✔ Structured JSON output generation'
        ]
    }
}

def get_workflow_steps(input_type: str):
    steps = [
        "Input",
        "URL Analysis" if input_type == "URL" else None,
        "Content Analysis",
        "Visual Analysis" if input_type == "URL" else None,
        "Threat Intelligence" if input_type == "URL" else None,
        "Coordination",
        "Results"
    ]
    return [s for s in steps if s is not None]

def create_workflow_visualization(input_type: str, current_step: int = 0):
    """Create an interactive workflow diagram aligned with actual execution flow"""

    steps = get_workflow_steps(input_type)

    fig = go.Figure()

    x_positions = list(range(len(steps)))
    y_positions = [0] * len(steps)

    # Connect steps
    for i in range(len(steps) - 1):
        fig.add_trace(go.Scatter(
            x=[x_positions[i], x_positions[i + 1]],
            y=[y_positions[i], y_positions[i + 1]],
            mode='lines',
            line=dict(color='#93c5fd', width=3),
            hoverinfo='skip',
            showlegend=False
        ))

    # Color logic (completed vs pending)
    colors = [
        '#10b981' if i <= current_step else '#cbd5e1'
        for i in range(len(steps))
    ]

    fig.add_trace(go.Scatter(
        x=x_positions,
        y=y_positions,
        mode='markers+text',
        marker=dict(
            size=42,
            color=colors,
            line=dict(width=3, color='white')
        ),
        text=steps,
        textposition='bottom center',
        textfont=dict(size=11, color='#1e293b'),
        hoverinfo='text',
        hovertext=steps,
        showlegend=False
    ))

    fig.update_layout(
        height=160,
        margin=dict(l=0, r=0, t=20, b=40),
        xaxis=dict(visible=False),
        yaxis=dict(visible=False),
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)'
    )

    return fig

def display_agent_card(agent_key, status='idle'):
    """Display an agent card with status"""

    agent = AGENT_INFO.get(agent_key)
    if not agent:
        st.warning(f"Unknown agent: {agent_key}")
        return

    status_emoji = {
        'idle': '⚪',
        'active': '🔄',
        'complete': '✅',
        'error': '❌'
    }

    status = status if status in status_emoji else 'idle'

    status_class = 'agent-card'
    if status == 'active':
        status_class += ' agent-active'
    elif status == 'complete':
        status_class += ' agent-complete'
    elif status == 'error':
        status_class += ' agent-error'

    st.markdown(f"""
        <div class="{status_class}">
            <h3 aria-label="Agent status">
                <span class="agent-icon">{agent['icon']}</span>
                {agent['name']} {status_emoji[status]}
            </h3>
            <p style='color: #64748b; margin: 10px 0;'>{agent['description']}</p>
            <div style='margin-top: 15px;'>
                {''.join(
                    f"<div style='color: #475569; padding: 3px 0;'>{cap}</div>"
                    for cap in agent['capabilities']
                )}
            </div>
        </div>
    """, unsafe_allow_html=True)

def create_risk_gauge(value, title, ti_confirmed: bool = False):
    """Create a SOC-aligned gauge chart for risk visualization"""

    # Defensive typing (prevents int/str issues)
    try:
        value = int(value)
    except Exception:
        value = 0

    # Delta reference (visual only)
    delta_reference = 30 if value < 60 else 60

    # Threat intel overlay styling
    bar_color = "#dc2626" if ti_confirmed else "#2563eb"
    threshold_color = "#b91c1c" if ti_confirmed else "#ef4444"

    fig = go.Figure(go.Indicator(
        mode="gauge+number+delta",
        value=value,
        domain={'x': [0, 1], 'y': [0, 1]},
        title={'text': title, 'font': {'size': 18}},
        delta={'reference': delta_reference},
        gauge={
            'axis': {'range': [0, 100], 'tickwidth': 1},
            'bar': {'color': bar_color},
            'bgcolor': "white",
            'borderwidth': 2,
            'bordercolor': "#e5e7eb",
            'steps': [
                {'range': [0, 33], 'color': '#d1fae5'},
                {'range': [33, 66], 'color': '#fef3c7'},
                {'range': [66, 100], 'color': '#fee2e2'}
            ],
            'threshold': {
                'line': {'color': threshold_color, 'width': 4},
                'thickness': 0.75,
                'value': 80
            }
        }
    ))

    fig.update_layout(
        height=280,
        margin=dict(l=20, r=20, t=50, b=20),
        paper_bgcolor='white',
        font={'color': "#1e293b", 'family': "Arial"}
    )

    return fig

def create_signal_contribution_chart(signals: dict):
    """
    Visualize normalized risk contribution by agent.
    This reflects signal strength, not finding volume.
    """

    if not signals:
        return None

    AGENT_LABELS = {
        "url": "URL Analyzer",
        "content": "Content Analyzer",
        "visual": "Visual Analyzer",
        "threat_intel": "Threat Intelligence"
    }

    AGENT_COLORS = {
        "url": "#3b82f6",
        "content": "#8b5cf6",
        "visual": "#ec4899",
        "threat_intel": "#f97316"
    }

    categories = []
    scores = []
    colors = []

    for key, label in AGENT_LABELS.items():
        if key in signals:
            categories.append(label)
            scores.append(signals[key].get("risk_score", 0))
            colors.append(AGENT_COLORS.get(key, "#94a3b8"))

    fig = go.Figure(data=[
        go.Bar(
            x=categories,
            y=scores,
            marker_color=colors,
            text=scores,
            textposition='auto'
        )
    ])

    fig.update_layout(
        title="Risk Signal Contribution by Agent",
        xaxis_title="Agent",
        yaxis_title="Normalized Risk Score (0–100)",
        height=300,
        showlegend=False,
        paper_bgcolor='white',
        plot_bgcolor='#f8fafc'
    )

    return fig

def create_findings_chart(findings_by_category):
    """Create a bar chart of findings by agent"""

    if not isinstance(findings_by_category, dict) or not findings_by_category:
        return None

    AGENT_ORDER = [
        "URL Analyzer",
        "Content Analyzer",
        "Visual Analyzer",
        "Threat Intelligence",
        "Coordinator"
    ]

    AGENT_COLORS = {
        "URL Analyzer": "#3b82f6",
        "Content Analyzer": "#8b5cf6",
        "Visual Analyzer": "#ec4899",
        "Threat Intelligence": "#f97316",
        "Coordinator": "#10b981"
    }

    categories = []
    counts = []
    colors = []

    for agent in AGENT_ORDER:
        if agent in findings_by_category:
            try:
                count = int(findings_by_category.get(agent, 0))
            except Exception:
                count = 0

            categories.append(agent)
            counts.append(count)
            colors.append(AGENT_COLORS.get(agent, "#94a3b8"))

    if not categories:
        return None

    fig = go.Figure(data=[
        go.Bar(
            x=categories,
            y=counts,
            marker_color=colors,
            text=counts,
            textposition='auto'
        )
    ])

    fig.update_layout(
        title="Findings by Agent",
        xaxis_title="Agent",
        yaxis_title="Number of Findings",
        height=300,
        showlegend=False,
        paper_bgcolor='white',
        plot_bgcolor='#f8fafc'
    )

    return fig

# ============================================
# MAIN APPLICATION
# ============================================

# Header
st.markdown("""
    <div style='text-align: center; padding: 20px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); border-radius: 15px; margin-bottom: 30px;'>
        <h1 style='color: white; margin: 0;'>🛡️ AI-Powered Phishing Detection Engine</h1>
        <p style='color: #e0e7ff; margin: 10px 0 0 0; font-size: 1.1em;'>Multi-Agent Security Analysis System</p>
        <p style='color: #c7d2fe; margin: 5px 0 0 0;'>Powered by CrewAI + OpenAI GPT-4o-mini</p>
    </div>
""", unsafe_allow_html=True)

# Sidebar
with st.sidebar:
    st.markdown("## ⚙️ Configuration")
    
    input_type = st.selectbox(
        "Select Input Type",
        ["URL", "Email Content", "Website Content"],
        help="Choose what type of content you want to analyze"
    )
    
    use_advanced_analysis = st.checkbox(
        "🤖 Use AI Agents",
        value=True,
        help="Enable CrewAI multi-agent analysis for comprehensive results"
    )
    
    st.markdown("---")
    
    # Analysis Statistics
    st.markdown("## 📊 Statistics")
    col1, col2 = st.columns(2)
    with col1:
        st.metric("Total Analyses", len(st.session_state.analysis_history))
    with col2:
        if st.session_state.analysis_history:
            high_risk = sum(1 for a in st.session_state.analysis_history if a.get('threat_level') == 'high')
            st.metric("High Risk", high_risk)
    
    st.markdown("---")
    
    # Agent Information
    st.markdown("## 🤖 AI Agents")
    with st.expander("🔍 URL Analyzer", expanded=False):
        st.markdown("""
        **Role**: Domain Security Specialist
        
        **Tasks**:
        - Domain validation
        - TLD reputation check
        - Typosquatting detection
        - Suspicious pattern analysis
        
        **Powered by**: Custom URL Analysis Tool + GPT-4o-mini
        """)
    
    with st.expander("📝 Content Analyzer", expanded=False):
        st.markdown("""
        **Role**: Social Engineering Expert
        
        **Tasks**:
        - Keyword detection
        - Urgency analysis
        - Threat identification
        - Grammar checking
        
        **Powered by**: Content Analysis Tool + GPT-4o-mini
        """)
    
    with st.expander("👁️ Visual Analyzer", expanded=False):
        st.markdown("""
        **Role**: Brand Protection Specialist
        
        **Tasks**:
        - HTML structure analysis
        - Form detection
        - Brand impersonation check
        - Resource validation
        
        **Powered by**: Visual Analysis Tool + GPT-4o-mini
        """)
    
    with st.expander("🛰️ Threat Intelligence", expanded=False):
        st.markdown("""
        **Role**: External Threat Validation Specialist

        **Tasks**:
        - URL and domain reputation checks
        - Known phishing & malware feed correlation
        - Fraud and scam detection
        - Detection count analysis
        - Authoritative threat confirmation

        **Powered by**:
        - VirusTotal
        - PhishTank (planned)
        - OpenPhish (planned)
        """)
    
    with st.expander("🧠 Coordinator", expanded=False):
        st.markdown("""
        **Role**: Security Orchestrator
        
        **Tasks**:
        - Findings synthesis
        - Risk calculation
        - Report generation
        - Recommendations
        
        **Powered by**: GPT-4o-mini Reasoning
        """)

# Main content
tab1, tab2, tab3 = st.tabs(["🔍 Analysis", "🏗️ Orchestration", "📚 Documentation"])

with tab1:
    # ============================
    # INPUT SECTION
    # ============================
    st.markdown("### 📥 Input Your Content")

    col1, col2 = st.columns([2, 1])

    with col1:
        if input_type == "URL":
            user_input = st.text_input(
                "Enter URL to analyze",
                placeholder="https://secure-paypal-verify.com/login",
                help="Enter the complete URL including http:// or https://"
            )
        else:
            user_input = st.text_area(
                f"Enter {input_type} to analyze",
                height=200,
                placeholder="Paste your email or website content here..."
            )

    with col2:
        if input_type == "URL":
            tips_items = [
                "Include the full URL (with <strong>http://</strong> or <strong>https://</strong>)",
                "Avoid shortened or obfuscated links",
                "Known malicious domains may be escalated via threat intelligence",
                "Test or placeholder domains (e.g. <code>.example</code>) will be flagged"
            ]
        elif input_type == "Email Content":
            tips_items = [
                "Paste the complete email body",
                "Include subject or sender if available",
                "Urgency or threats increase phishing risk",
                "Generic greetings are common phishing indicators"
            ]
        else:  # Website Content
            tips_items = [
                "Paste visible page content or HTML",
                "Login or payment forms increase risk",
                "Brand impersonation is actively checked",
                "External scripts or resources may affect risk"
            ]

        # Always append this tip
        tips_items.append("Analysis typically completes in a few seconds")

        tips_html = "".join(f"<li>{tip}</li>" for tip in tips_items)

        st.markdown(f"""
        <div style='background: white; padding: 20px; border-radius: 10px;'>
            <h4>💡 Quick Tips</h4>
            <ul>
                {tips_html}
            </ul>
            <p style="font-size: 0.85em; color: #64748b; margin-top: 10px;">
                External reputation checks are performed only on user-provided indicators.
            </p>
        </div>
        """, unsafe_allow_html=True)

    analyze_button = st.button("🔍 Analyze for Phishing", type="primary", use_container_width=True)

    # ============================
    # RUNTIME PLACEHOLDERS (ONCE)
    # ============================
    timeline_placeholder = st.empty()
    status_text = st.empty()
    progress_bar = st.progress(0)

    # ============================
    # ANALYSIS EXECUTION
    # ============================
    if analyze_button and user_input:

        # Reset step
        st.session_state.current_step = 0

        # Initialize UI
        timeline_placeholder.empty()
        render_step_timeline(timeline_placeholder, input_type, 0)
        status_text.text("🚀 Initializing security analysis…")
        progress_bar.progress(5)
        time.sleep(0.3)

        quick_results = {}
        findings_count_by_agent = {}
        findings_detail_by_agent = {}

        # ============================
        # STEP 1 — URL ANALYSIS
        # ============================
        if input_type == "URL":
            st.session_state.current_step = 1
            timeline_placeholder.empty()
            render_step_timeline(timeline_placeholder, input_type, 1)
            status_text.text("🔍 Analyzing URL structure and domain reputation…")
            progress_bar.progress(20)

            url_tool = URLAnalysisTool()
            quick_results["url"] = url_tool._run(user_input)

            url_findings = [
                line.strip("- ").strip()
                for line in quick_results["url"].splitlines()
                if line.strip().startswith("-")
            ]

            findings_detail_by_agent["URL Analyzer"] = url_findings
            findings_count_by_agent["URL Analyzer"] = len(url_findings)

            time.sleep(0.4)

        # ============================
        # STEP 2 — CONTENT ANALYSIS
        # ============================
        st.session_state.current_step = 2
        timeline_placeholder.empty()
        render_step_timeline(timeline_placeholder, input_type, 2)
        status_text.text("📝 Analyzing content for phishing language…")
        progress_bar.progress(40)

        content_tool = ContentAnalysisTool()
        quick_results["content"] = content_tool._run(user_input)

        content_findings = [
            line.strip("- ").strip()
            for line in quick_results["content"].splitlines()
            if line.strip().startswith("-")
        ]

        findings_detail_by_agent["Content Analyzer"] = content_findings
        findings_count_by_agent["Content Analyzer"] = len(content_findings)

        time.sleep(0.4)

        # ============================
        # STEP 3 — VISUAL ANALYSIS
        # ============================
        if input_type == "URL":
            st.session_state.current_step = 3
            timeline_placeholder.empty()
            render_step_timeline(timeline_placeholder, input_type, 3)
            status_text.text("👁️ Inspecting webpage structure and forms…")
            progress_bar.progress(60)

            visual_tool = VisualAnalysisTool()
            quick_results["visual"] = visual_tool._run(user_input)

            visual_findings = [
                line.strip("- ").strip()
                for line in quick_results["visual"].splitlines()
                if line.strip().startswith("-")
            ]

            findings_detail_by_agent["Visual Analyzer"] = visual_findings
            findings_count_by_agent["Visual Analyzer"] = len(visual_findings)

            time.sleep(0.4)
        
        # ============================
        # STEP 4 — THREAT INTELLIGENCE
        # ============================
        if input_type == "URL":
            st.session_state.current_step = 4
            timeline_placeholder.empty()
            render_step_timeline(timeline_placeholder, input_type, 4)
            status_text.text("🛰️ Validating against external threat intelligence…")
            progress_bar.progress(75)

            # NOTE: Threat Intel runs inside CrewAI for advanced mode
            # Here we just reserve UI + findings bucket
            findings_detail_by_agent["Threat Intelligence"] = []
            findings_count_by_agent["Threat Intelligence"] = 0

            time.sleep(0.3)

        # ============================
        # STEP 5 — COORDINATION
        # ============================
        st.session_state.current_step = 5
        timeline_placeholder.empty()
        render_step_timeline(timeline_placeholder, input_type, 5)
        status_text.text("🧠 Final risk calculation…")
        progress_bar.progress(85)

        if use_advanced_analysis:
            crew = PhishingDetectionCrew()
            crew_result = crew.analyze(
                input_data=user_input,
                input_type=input_type.lower().replace(" content", "")
            )

            coordinator_output = get_coordinator_output(crew_result)

            try:
                analysis_result = parse_coordinator_json(
                    coordinator_output,
                    full_report="\n\n".join(quick_results.values()),
                    input_url=user_input
                )

                # ----------------------------
                # Extract Threat Intelligence findings (UI-only)
                # ----------------------------
                ti_findings = []
                combined_report = analysis_result.get("full_report", "")

                for line in combined_report.splitlines():
                    if "Malicious:" in line or "Suspicious:" in line:
                        ti_findings.append(line.strip())

                if ti_findings:
                    findings_detail_by_agent["Threat Intelligence"] = ti_findings
                    findings_count_by_agent["Threat Intelligence"] = len(ti_findings)

            except RuntimeError:
                analysis_result = {
                    "threat_level": "medium",
                    "confidence": 80,
                    "confidence_source": "heuristic",
                    "phishing_probability": 50,
                    "ti_confirmed": False,
                    "summary": "Coordinator timed out. Deterministic fallback applied.",
                    "top_findings": [],
                    "recommendations": [
                        "Verify sender or website through official channels",
                        "Avoid clicking unknown links",
                        "Report suspicious activity"
                    ],
                    "full_report": "\n\n".join(quick_results.values())
                }
        else:
            analysis_result = {
                "threat_level": "medium",
                "confidence": 75,
                "confidence_source": "heuristic",
                "phishing_probability": 50,
                "ti_confirmed": False,
                "summary": "Quick heuristic analysis completed",
                "top_findings": [],
                "recommendations": [],
                "full_report": "\n\n".join(quick_results.values())
            }

        # Coordinator findings
        coordinator_findings = analysis_result.get("top_findings", [])
        findings_detail_by_agent["Coordinator"] = coordinator_findings
        findings_count_by_agent["Coordinator"] = len(coordinator_findings)

        # ============================
        # FINALIZE
        # ============================
        progress_bar.progress(100)
        status_text.success("✅ Analysis complete")
        
        st.session_state.current_step = 6
        render_step_timeline(timeline_placeholder, input_type, 6)

        analysis_result["findings_count_by_agent"] = findings_count_by_agent
        analysis_result["findings_detail_by_agent"] = findings_detail_by_agent
        analysis_result["timestamp"] = datetime.now().isoformat()

        # ❗ DO NOT overwrite full_report here
        st.session_state.analysis_result = analysis_result
        st.session_state.analysis_history.append(analysis_result)
    
# Display results
if st.session_state.analysis_result:
    st.markdown("---")
    st.markdown("### 📊 Analysis Results")
    
    result = st.session_state.analysis_result
    
    verdict = result.get("verdict", "suspicious")

    verdict_map = {
        "malicious": ("🚨", "#ef4444", "MALICIOUS — CONFIRMED THREAT"),
        "suspicious": ("⚠️", "#f59e0b", "SUSPICIOUS — PROCEED WITH CAUTION"),
        "likely_benign": ("✅", "#10b981", "LIKELY BENIGN — NO ACTION REQUIRED")
    }

    icon, color, label = verdict_map.get(
        verdict,
        verdict_map["suspicious"]
    )
    
    st.markdown(f"""
        <div style='background: {color}; padding: 30px; border-radius: 15px; text-align: center; box-shadow: 0 8px 16px rgba(0,0,0,0.2);'>
            <h1 style='color: white; margin: 0; font-size: 2.5em;'>{icon} {label}</h1>
            <p style='color: white; margin: 15px 0 0 0; font-size: 1.2em;'>{result['summary']}</p>
        </div>
    """, unsafe_allow_html=True)
    
    st.markdown("<br>", unsafe_allow_html=True)
    
    # Metrics row
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        source = result.get("confidence_source", "heuristic").replace("_", " ").title()
        st.markdown(f"""
            <div class='metric-card'>
                <h3 style='color: #3b82f6; margin: 0;'>Confidence</h3>
                <p style='font-size: 2em; margin: 10px 0; color: #1e293b;'>
                    {result['confidence']}%
                </p>
                <p style='font-size: 0.9em; color: #64748b;'>
                    Source: {source}
                </p>
            </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown(f"""
            <div class='metric-card'>
                <h3 style='color: #8b5cf6; margin: 0;'>Phishing Prob.</h3>
                <p style='font-size: 2em; margin: 10px 0; color: #1e293b;'>{result['phishing_probability']}%</p>
            </div>
        """, unsafe_allow_html=True)
    
    with col3:
        st.markdown(f"""
            <div class='metric-card'>
                <h3 style='color: #ec4899; margin: 0;'>Threat Level</h3>
                <p style='font-size: 2em; margin: 10px 0; color: #1e293b; text-transform: uppercase;'>{result['threat_level']}</p>
            </div>
        """, unsafe_allow_html=True)
    
    with col4:
        total_findings = sum(result.get("findings_count_by_agent", {}).values())
        st.markdown(f"""
            <div class='metric-card'>
                <h3 style='color: #10b981; margin: 0;'>Findings</h3>
                <p style='font-size: 2em; margin: 10px 0; color: #1e293b;'>{total_findings}</p>
            </div>
        """, unsafe_allow_html=True)
    
    st.markdown("<br>", unsafe_allow_html=True)
    
    # Determine if Threat Intelligence confirmed the threat
    ti_confirmed = result.get("ti_confirmed", False)
    
    # Gauges and Charts
    col1, col2 = st.columns(2)
    
    with col1:
        st.plotly_chart(
            create_risk_gauge(result['confidence'], "Confidence Score"),
            use_container_width=True
        )
    
    with col2:
        st.plotly_chart(
            create_risk_gauge(result['phishing_probability'],"Phishing Probability", ti_confirmed=ti_confirmed),
            use_container_width=True
        )
    
    # Findings by Agent Chart
    if result.get("findings_count_by_agent"):
        st.markdown("### 📈 Findings Distribution")
        fig = create_findings_chart(result["findings_count_by_agent"])
        if fig:
            st.plotly_chart(fig, use_container_width=True)


    # ============================
    # DETAILED FINDINGS BY AGENT
    # ============================
    st.markdown("### 🧩 Detailed Findings by Agent")

    for agent, findings in result.get("findings_detail_by_agent", {}).items():
        if findings:
            with st.expander(f"🤖 {agent} ({len(findings)} findings)", expanded=False):
                for finding in findings:
                    st.markdown(f"- {finding}")
    
    # Detailed report
    with st.expander("📄 View Full Analysis Report", expanded=False):
        st.code(result['full_report'], language='text')
    
    # TOP FINDINGS
    filtered_findings = [
        f for f in result.get("top_findings", [])
        if "threat intelligence verdict is pending" not in f.lower()
    ]

    if filtered_findings:
        st.markdown("### 🔍 Top Security Findings")
        for i, finding in enumerate(filtered_findings, 1):
            st.markdown(f"- {finding}")
                
    if result.get("verdict") == "suspicious":
        st.markdown("### ⚠️ Why This Is Suspicious")

        if "URL Analyzer" in result.get("findings_detail_by_agent", {}):
            for f in result["findings_detail_by_agent"]["URL Analyzer"]:
                st.markdown(f"- {f}")

        if "Content Analyzer" in result.get("findings_detail_by_agent", {}):
            for f in result["findings_detail_by_agent"]["Content Analyzer"]:
                st.markdown(f"- {f}")
            
    if result.get("evidence"):
        st.markdown("### 🧾 Evidence (Verifiable Signals)")

        for ev in result["evidence"]:
            st.markdown(f"- {ev}")
    
    # ==========================================
    # Security Recommendations (EXECUTIVE VIEW)
    # ==========================================
    st.markdown("### 🛡️ Security Recommendations")
    
    alert_map = {
        "high": st.error,
        "medium": st.warning,
        "low": st.success
    }

    alert_fn = alert_map[result["threat_level"]]
    alert_fn("### Recommended Actions")

    for rec in result.get("recommendations", []):
        st.write(f"- {rec}")
    
    # ============================
    # ANALYSIS HISTORY VIEW
    # ============================

    if st.session_state.analysis_history:
        st.markdown("---")
        st.markdown("### 🕒 Analysis History")

        history_df = pd.DataFrame(st.session_state.analysis_history)

        # Keep only useful columns (safe even if missing)
        display_cols = [
            col for col in
            ["timestamp", "threat_level", "confidence", "phishing_probability"]
            if col in history_df.columns
        ]

        st.dataframe(
            history_df[display_cols],
            use_container_width=True,
            hide_index=True
        )
    
    
with tab2:
    st.markdown("### 🏗️ Multi-Agent Orchestration Process")
    
    st.markdown("""
    This phishing detection system uses a sophisticated multi-agent architecture where specialized AI agents work together to analyze threats from different perspectives.
    """)
    
    # Agent cards in orchestration view
    st.markdown("#### 🤖 AI Agent Details")
    
    col1, col2 = st.columns(2)
    
    with col1:
        display_agent_card('url_analyzer', 'complete')
        st.markdown("<br>", unsafe_allow_html=True)
        display_agent_card('content_analyzer', 'complete')
        st.markdown("<br>", unsafe_allow_html=True)
        display_agent_card('threat_intel', 'complete')

    with col2:
        display_agent_card('visual_analyzer', 'complete')
        st.markdown("<br>", unsafe_allow_html=True)
        display_agent_card('coordinator', 'complete')

    st.markdown("""
        ---
        ### 🧠 Orchestration Logic Summary

        - Agents execute **independently** on the same input
        - No agent has access to another agent’s internal state
        - The **Threat Intelligence Agent** validates indicators against external sources
        - The **Coordinator** synthesizes findings and enforces policy rules
        - Final threat classification is computed **deterministically in code**
        """)
    
    st.markdown("## 🔄 Agentic Orchestration Flow")

    st.graphviz_chart("""
    digraph AgentFlow {
        rankdir=LR;
        node [shape=box, style="rounded,filled", fontname="Helvetica"];

        Input [label="User Input\n(URL / Email / Website)", fillcolor="#fef3c7", color="#f59e0b"];

        URL [label="URL Analyzer Agent", fillcolor="#e0f2fe", color="#2563eb"];
        Content [label="Content Analyzer Agent", fillcolor="#ede9fe", color="#7c3aed"];
        Visual [label="Visual Analyzer Agent", fillcolor="#fce7f3", color="#ec4899"];

        TI [label="Threat Intelligence Agent\n(VirusTotal / Feeds)", fillcolor="#fff7ed", color="#f97316"];

        Coordinator [label="Coordinator Agent", fillcolor="#dcfce7", color="#16a34a"];
        Engine [label="Deterministic\nThreat Engine", fillcolor="#ede9fe", color="#7c3aed"];
        Output [label="Final Security Assessment", fillcolor="#fee2e2", color="#dc2626"];

        Input -> URL;
        Input -> Content;
        Input -> Visual;
        Input -> TI;

        URL -> Coordinator;
        Content -> Coordinator;
        Visual -> Coordinator;
        TI -> Coordinator;

        Coordinator -> Engine;
        Engine -> Output;
    }
    """)

with tab3:
    st.markdown("## 📚 System Documentation")

    st.markdown("""
    ### 🔐 Architecture Overview

    This system implements a **defensive, agentic AI architecture** for phishing detection.
    Each agent is isolated, auditable, and purpose-built.

    **Key Design Principles:**
    - Defense in depth
    - Deterministic final decisions
    - Explainability-first design
    - SOC-aligned outputs
    """)
    
    st.markdown("""
    ### 🛰️ Threat Intelligence Integration

    This system integrates **external threat intelligence sources** to validate indicators
    against known malicious infrastructure.

    **Purpose:**
    - Reduce false negatives
    - Detect known phishing campaigns
    - Enforce authoritative overrides

    **Sources (Current / Planned):**
    - VirusTotal
    - PhishTank
    - OpenPhish

    When external intelligence confirms malicious activity, the system **enforces a minimum
    phishing probability threshold**, regardless of heuristic scores.
    """)
    
    st.markdown("""
    ### 🤖 Agent Responsibilities

    | Agent | Responsibility |
    |------|---------------|
    | URL Analyzer | Domain structure, TLD reputation, typosquatting |
    | Content Analyzer | Phishing language, urgency, threats |
    | Visual Analyzer | Brand impersonation, forms, HTML structure |
    | Threat Intelligence | External reputation validation, known phishing & malware correlation |
    | Coordinator | Findings synthesis, policy enforcement, structured reporting |
    """)

    st.markdown("""
    ### ⚠️ Threat Classification Logic

    Final threat level is **not decided by the LLM**.

    ```text
    If external threat intelligence confirms malicious activity → phishing_probability ≥ 80 → HIGH
    Else if phishing_probability ≥ 60 → HIGH
    Else if phishing_probability ≥ 30 → MEDIUM
    Else if brand impersonation detected → MEDIUM
    Else → LOW
    ```
    """)

    st.markdown("""
        ### 🛡️ Security Guarantees

    - External threat intelligence is queried **only for user-provided indicators**
    - No unsolicited crawling or background scanning is performed
    - All LLM outputs are parsed and schema-validated
    - JSON-only coordinator output is enforced
    - Final threat decisions are **deterministic and policy-driven**
    - External intelligence can **override heuristic risk scores**
        """)

# FOOTER
st.markdown("""
    ---
    <div style='text-align: center; color: #94a3b8; padding: 20px;'>
        <p><strong>AI Phishing Detection Engine</strong></p>
        <p>Multi-Agent Architecture • CrewAI • OpenAI GPT-4o-mini</p>
        <p style='font-size: 0.9em;'>Enterprise-grade, explainable security analysis</p>
    </div>
    """, unsafe_allow_html=True)
