AI Security Validation Platform

Objective

Build a reproducible AI security lab that continuously evaluates and improves the security posture of AI agents.

Core Components

NVIDIA OpenShell — Secure execution environment for AI agents using sandboxing, filesystem, process, network, and tool access policies.
HiddenLayer — Performs adversarial security testing, vulnerability discovery, and validation of AI application defenses.
Nemotron on vLLM — OpenAI-compatible inference endpoint used for reasoning, security analysis, decision making, and policy recommendations.
Security Orchestrator — Coordinates testing, collects results, invokes the LLM, and manages the improvement cycle.

Workflow

Deploy the AI agent inside NVIDIA OpenShell.
Execute automated security assessments using HiddenLayer.
Collect logs, policy violations, and execution traces.
Use Nemotron (via vLLM/OpenAI API) to:
analyze attack outcomes,
identify root causes,
recommend policy improvements,
generate additional security test cases.
Apply validated policy changes.
Re-run HiddenLayer to verify improvements and detect regressions.
Repeat until no new vulnerabilities are identified.

Deployment

All components are containerized and orchestrated with Docker Compose, enabling a reproducible local or cloud-based security testing environment.

High-Level Architecture

                HiddenLayer
                     │
           Security Assessments
                     │
                     ▼
            Security Orchestrator
                     │
      ┌──────────────┴──────────────┐
      │                             │
      ▼                             ▼
 Nemotron (vLLM)          NVIDIA OpenShell
(OpenAI-compatible API)         │
      │                         ▼
      └──────────────► AI Agent/Application

Outcome

A continuously improving AI security platform where HiddenLayer identifies vulnerabilities, OpenShell enforces runtime protections, and Nemotron provides intelligent analysis and recommendations to strengthen the overall security posture.
