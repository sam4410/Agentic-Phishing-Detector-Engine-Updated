# ========================================
# File: agents.py
# ========================================
from crewai import Agent, Task, Crew, Process
from langchain_openai import ChatOpenAI
from tools import URLAnalysisTool, ContentAnalysisTool, VisualAnalysisTool, VirusTotalTool
from config import Config


class PhishingDetectionAgents:
    """Define all agents for phishing detection"""

    def __init__(self):
        # CrewAI's native LLM configuration with OpenAI
        self.llm = ChatOpenAI(
            model=Config.OPENAI_MODEL_NAME,
            temperature=0.3
        )

    def url_analyzer_agent(self):
        return Agent(
            role='URL Security Analyst',
            goal="""
            Analyze the provided URL using the URL Analysis Tool exactly once.

            You MUST:
            - Call the URL Analysis Tool exactly once per input
            - Use the tool output as final and authoritative
            - Report findings verbatim without modification or interpretation
            - Preserve the normalized risk score exactly as returned

            You MUST NOT:
            - Retry the tool under any circumstances
            - Re-run the same analysis
            - Attempt alternative inputs or transformations
            - Infer intent, severity, or legitimacy beyond the tool output
            - Calculate, adjust, or reinterpret risk scores
            - Reference content, visuals, reputation services, or external context
            """,
            backstory="""
            You are a URL and domain security specialist focused exclusively on
            structural and reputational analysis of URLs.

            Your expertise includes detecting phishing indicators such as:
            - Suspicious or abused TLDs
            - Typosquatting and brand impersonation at the domain level
            - Excessive or deceptive subdomains
            - URL obfuscation, entropy, and malformed structures
            - Domain age and registration anomalies

            You do not analyze page content, visual appearance, or social
            engineering tactics. You report only what the URL analysis tool detects.
            """,
            verbose=True,
            allow_delegation=False,
            llm=self.llm,
            tools=[URLAnalysisTool()]
        )

    def content_analyzer_agent(self):
        return Agent(
            role="Content Security Analyst",
            goal="""
            Analyze the provided email or webpage content using the Content Analysis Tool
            exactly once.

            You MUST:
            - Call the Content Analysis Tool exactly once per input
            - Use the tool output as final and authoritative
            - Report findings verbatim without modification or interpretation
            - Preserve the normalized risk score exactly as returned

            You MUST NOT:
            - Retry the tool or re-analyze the same content
            - Attempt to reinterpret, contextualize, or adjust risk scores
            - Infer intent, attacker motivation, or campaign context
            - Declare content malicious or benign beyond the tool output
            - Reference URL structure, page visuals, or external reputation systems
            """,
            backstory="""
            You are a content-focused security analyst specializing in the detection
            of observable social engineering and linguistic patterns.

            Your analysis is strictly limited to textual indicators such as:
            - Urgency and time-pressure language
            - Threatening or coercive phrasing
            - Generic greetings and impersonation cues
            - Linguistic and grammatical anomalies

            You do not assess URL structure, visual design, or external reputation.
            You report only what the Content Analysis Tool explicitly detects.
            """,
            verbose=True,
            allow_delegation=False,
            llm=self.llm,
            tools=[ContentAnalysisTool()]
        )

    def visual_analyzer_agent(self):
        return Agent(
            role="Visual Security Analyst",
            goal="""
            Analyze the visual and structural characteristics of the provided webpage
            using the Visual Analysis Tool exactly once.

            You MUST:
            - Call the Visual Analysis Tool exactly once per input
            - Use the tool output as final and authoritative
            - Report findings verbatim without modification or interpretation
            - Preserve the normalized risk score exactly as returned

            You MUST NOT:
            - Retry the tool or attempt alternative URLs or inputs
            - Infer intent, severity, or legitimacy beyond the tool output
            - Recalculate, reinterpret, or contextualize risk scores
            - Reference URL structure, textual content, or external reputation systems
            """,
            backstory="""
            You are a web security specialist focused exclusively on detecting
            observable visual and structural indicators of phishing pages.

            Your scope includes:
            - Credential-harvesting forms and suspicious form behavior
            - Contextual brand impersonation signals tied to forms
            - Excessive or abnormal external resource usage
            - Hidden inputs, iframes, and JavaScript-based redirects

            You do not analyze textual persuasion, URL structure, or domain reputation.
            You report only what the Visual Analysis Tool explicitly detects.
            """,
            verbose=True,
            allow_delegation=False,
            llm=self.llm,
            tools=[VisualAnalysisTool()]
        )

    def threat_intel_agent(self):
        return Agent(
            role="Threat Intelligence Analyst",
            goal="""
            Retrieve and report external threat intelligence evidence for the provided
            indicator using authorized threat intelligence tools exactly once.

            You MUST:
            - Call the threat intelligence tool exactly once per input
            - Use the tool output as final and authoritative
            - Report evidence verbatim without modification or interpretation
            - Preserve any verdict labels and normalized risk scores exactly as returned
            - Explicitly report when threat intelligence results are pending, unavailable,
              or inconclusive

            You MUST NOT:
            - Retry the same tool or submit alternative indicator forms
            - Infer maliciousness or safety from the absence of detections
            - Recalculate, reinterpret, or contextualize risk scores
            - Declare an indicator benign, safe, or malicious beyond the tool output
            - Reference URL structure, content analysis, or visual indicators
            """,
            backstory="""
            You are a cybersecurity threat intelligence analyst responsible for collecting
            verifiable, third-party intelligence from authoritative sources such as
            VirusTotal.

            Your role is strictly evidentiary:
            - You report what external engines have observed
            - You distinguish between confirmed detections and inconclusive results
            - You do not perform independent analysis, risk scoring, or final classification

            Silence or lack of detections is treated as inconclusive, not as evidence of safety.
            """,
            llm=self.llm,
            tools=[VirusTotalTool()],
            verbose=True,
            allow_delegation=False
        )

    def coordinator_agent(self):
        return Agent(
            role="Security Coordinator",
            goal="""
            Aggregate and synthesize the outputs of all security analysis agents
            and produce a final security assessment in STRICT JSON format only.

            You MUST:
            - Treat all agent outputs as final and authoritative
            - Use only normalized risk scores (0–100) provided by agents
            - Combine scores using fixed, deterministic weighting
            - Derive a final risk score and verdict strictly from numeric thresholds
            - Output ONLY valid JSON conforming exactly to the defined schema
            - Include all available signals, even if inconclusive

            You MUST NOT:
            - Re-run tools or delegate analysis to other agents
            - Reinterpret, adjust, or override agent scores
            - Speculate, explain reasoning, or add narrative text
            - Infer attacker intent or campaign context
            - Output markdown, comments, or non-JSON text
            """,
            backstory="""
            You are a senior security coordination engine responsible for
            aggregating independent security signals into a single, deterministic
            decision.

            You do not perform analysis. You do not investigate indicators.
            You do not reason about intent.

            Your responsibility is limited to:
            - Score fusion
            - Verdict determination
            - Action recommendation based on predefined thresholds

            Your output is consumed by automated systems and must be machine-safe.
            """,
            verbose=True,
            allow_delegation=False,
            llm=self.llm
        )

class PhishingDetectionTasks:
    """Define all tasks for phishing detection"""

    @staticmethod
    def url_analysis_task(agent, input_data):
        return Task(
            description=f"""
            Perform URL security analysis on the following input using the URL Analysis Tool.

            INPUT (analyze exactly as provided):
            {input_data}

            REQUIREMENTS:
            - Call the URL Analysis Tool exactly once
            - Use the tool output as final and authoritative
            - Do not retry, re-run, or transform the input
            - Do not interpret, summarize, or contextualize findings
            - Preserve the normalized risk score (0–100) exactly as returned

            OUTPUT REQUIREMENTS:
            - Return the tool output verbatim
            - Do not add explanations, conclusions, or recommendations
            - Do not reference other analysis domains (content, visuals, reputation)
            """,
            agent=agent,
            expected_output=(
                "Verbatim output from the URL Analysis Tool, including the normalized "
                "risk score and all reported suspicious patterns"
            )
        )

    @staticmethod
    def content_analysis_task(agent, input_data):
        return Task(
            description=f"""
            Perform content-based phishing analysis on the following input using the
            Content Analysis Tool.

            INPUT (analyze exactly as provided):
            {input_data}

            REQUIREMENTS:
            - Call the Content Analysis Tool exactly once
            - Use the tool output as final and authoritative
            - Do not retry, re-run, or transform the input
            - Do not interpret, summarize, or contextualize findings
            - Preserve the normalized risk score (0–100) exactly as returned

            OUTPUT REQUIREMENTS:
            - Return the tool output verbatim
            - Do not add explanations, conclusions, or recommendations
            - Do not reference URL structure, visual appearance, or external reputation
            """,
            agent=agent,
            expected_output=(
                "Verbatim output from the Content Analysis Tool, including the normalized "
                "risk score and all detected linguistic indicators"
            )
        )

    @staticmethod
    def visual_analysis_task(agent, input_data):
        return Task(
            description=f"""
            Perform visual and structural phishing analysis on the following input
            using the Visual Analysis Tool.

            INPUT (analyze exactly as provided):
            {input_data}

            REQUIREMENTS:
            - Call the Visual Analysis Tool exactly once
            - Use the tool output as final and authoritative
            - Do not retry, re-run, or transform the input
            - Do not interpret, summarize, or contextualize findings
            - Preserve the normalized risk score (0–100) exactly as returned

            OUTPUT REQUIREMENTS:
            - Return the tool output verbatim
            - Do not add explanations, conclusions, or recommendations
            - Do not assess visual quality, branding accuracy, or page legitimacy
            - Do not reference URL structure, textual content, or external reputation
            """,
            agent=agent,
            expected_output=(
                "Verbatim output from the Visual Analysis Tool, including the normalized "
                "risk score and all detected visual and structural indicators"
            )
        )

    @staticmethod
    def threat_intel_task(agent, input_data):
        return Task(
            description=f"""
            Retrieve external threat intelligence evidence for the following indicator
            using the Threat Intelligence Tool.

            INPUT (analyze exactly as provided):
            {input_data}

            REQUIREMENTS:
            - Call the threat intelligence tool exactly once
            - Use the tool output as final and authoritative
            - Do not retry, re-run, or transform the indicator
            - Do not infer safety or maliciousness beyond the tool output
            - Explicitly preserve verdict labels, detection counts, and normalized
              risk scores exactly as returned

            OUTPUT REQUIREMENTS:
            - Return the tool output verbatim
            - Explicitly include inconclusive or pending results if reported
            - Do not classify the indicator as clean, safe, or benign
            - Do not reference other analysis domains (URL, content, visual)
            """,
            agent=agent,
            expected_output=(
                "Verbatim threat intelligence evidence from the VirusTotal tool, "
                "including verdict labels, detection statistics, and normalized "
                "risk score if available"
            )
        )

    @staticmethod
    def coordination_task(agent, input_data):
        return Task(
            description=f"""
            Aggregate and synthesize the outputs of all security analysis agents
            into a final security decision.

            INPUT:
            {input_data}

            ENFORCEMENT RULES (MANDATORY):

            1. Source Authority
            - Treat all agent outputs as final and authoritative
            - Do NOT re-run tools or reinterpret findings

            2. Scoring Rules
            - Use ONLY normalized risk scores (0–100) provided by agents
            - Combine scores using fixed, deterministic weighting
            - Do NOT invent probabilities or adjust scores

            3. Threat Intelligence Handling
            - Treat threat intelligence as corroborative evidence only
            - Absence of detections MUST be treated as inconclusive
            - Do NOT declare indicators safe or benign based on threat intelligence

            4. Verdict Rules
            - BLOCK if final_risk_score ≥ 75
            - WARN if final_risk_score is between 40 and 74
            - ALLOW if final_risk_score < 40

            5. Output Rules
            - Output STRICT JSON ONLY
            - No markdown, no explanations, no comments
            - All numbers must be integers
            - All booleans must be true or false
            - Output MUST conform exactly to the schema below

            JSON SCHEMA:
            {{
              "final_risk_score": 0,
              "confidence": 0,
              "verdict": "ALLOW | WARN | BLOCK",
              "signals": {{
                "url": {{ "risk_score": 0 }},
                "content": {{ "risk_score": 0 }},
                "visual": {{ "risk_score": 0 }},
                "threat_intel": {{
                  "risk_score": 0,
                  "verdict": "string"
                }}
              }},
              "top_findings": ["string"],
              "recommended_actions": ["string"]
            }}

            Return ONLY the JSON object.
            """,
            agent=agent,
            expected_output="Strict JSON security decision based on normalized scores"
        )

class PhishingDetectionCrew:
    """Main crew orchestration"""

    def __init__(self):
        self.agents = PhishingDetectionAgents()

    def analyze(self, input_data: str, input_type: str):
        """Run the complete phishing analysis"""

        # Initialize agents
        url_agent = self.agents.url_analyzer_agent()
        content_agent = self.agents.content_analyzer_agent()
        visual_agent = self.agents.visual_analyzer_agent()
        threat_agent = self.agents.threat_intel_agent()
        coordinator = self.agents.coordinator_agent()

        # Create tasks
        tasks = []
        agents_list = []

        if input_type in ['url', 'website']:
            tasks.append(PhishingDetectionTasks.url_analysis_task(url_agent, input_data))
            tasks.append(PhishingDetectionTasks.visual_analysis_task(visual_agent, input_data))
            tasks.append(PhishingDetectionTasks.threat_intel_task(threat_agent, input_data))
            agents_list.extend([url_agent, visual_agent, threat_agent])

        if input_type in ['email', 'content']:
            tasks.append(PhishingDetectionTasks.content_analysis_task(content_agent, input_data))
            agents_list.append(content_agent)

        # Always add coordination task
        tasks.append(PhishingDetectionTasks.coordination_task(coordinator, input_data))
        agents_list.append(coordinator)

        # Create and run crew
        crew = Crew(
            agents=agents_list,
            tasks=tasks,
            process=Process.sequential,
            verbose=True
        )

        result = crew.kickoff()
        return result
