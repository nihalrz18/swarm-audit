"""
SwarmOrchestrator — runs the 5-phase multi-agent security audit swarm.
Streams live events to the frontend via WebSocket.
"""
import asyncio
import json
import os
import shutil
import time
from fastapi import WebSocket

from database.connection import execute
from tools.report_generator import generate_pdf_report

from agents.scanner_agent import ScannerAgent
from agents.sast_agent import SASTAgent
from agents.dependency_agent import DependencyAgent
from agents.secrets_agent import SecretsAgent
from agents.api_agent import APIAgent
from agents.attack_chain_agent import AttackChainAgent
from agents.poc_agent import PoCAgent
from agents.severity_agent import SeverityAgent
from agents.patch_agent import PatchAgent
from agents.risk_agent import RiskAgent
from agents.report_agent import ReportAgent


class SwarmOrchestrator:
    def __init__(self, session_id: str, websocket: WebSocket):
        self.session_id = session_id
        self.websocket  = websocket
        self.llm_config = {
            "config_list": [
                {
                    "model":    "llama-3.1-70b-versatile",
                    "api_key":  os.getenv("GROQ_API_KEY"),
                    "base_url": "https://api.groq.com/openai/v1",
                    "api_type": "openai",
                }
            ],
            "temperature": 0.1,
            "max_tokens":  4096,
        }

    # ── WebSocket event helper ─────────────────────────────────────────────────
    async def send_event(
        self,
        agent_name: str,
        agent_type: str,
        status: str,
        message: str,
        data=None,
    ):
        try:
            await self.websocket.send_json(
                {
                    "agent_name": agent_name,
                    "agent_type": agent_type,
                    "status":     status,
                    "message":    message,
                    "data":       data,
                    "timestamp":  time.time(),
                }
            )
        except Exception:
            pass  # Client disconnected — fail silently

    # ── Graceful result unwrap ─────────────────────────────────────────────────
    @staticmethod
    def _safe(result, default):
        return result if not isinstance(result, Exception) else default

    # ── Main orchestration flow ────────────────────────────────────────────────
    async def run(self, github_url: str):
        clone_path = None
        try:
            # ═══════════════════════════════════════════════════════════════
            # PHASE 1: Scanner
            # ═══════════════════════════════════════════════════════════════
            await self.send_event(
                "Scanner", "scanner", "thinking",
                "Cloning repository and mapping file structure…",
            )
            scan_result = await asyncio.wait_for(
                asyncio.to_thread(ScannerAgent(self.llm_config).run, github_url),
                timeout=120,
            )

            if not scan_result.get("scan_complete"):
                err = scan_result.get("error", "Scan failed")
                await self.send_event("Scanner", "scanner", "error", err)
                return

            clone_path = scan_result.get("clone_path")
            await self.send_event(
                "Scanner", "scanner", "done",
                f"Mapped {scan_result['file_count']} files. "
                f"Stack: {', '.join(scan_result['tech_stack'])}",
                scan_result,
            )

            # ═══════════════════════════════════════════════════════════════
            # PHASE 2: Parallel cross-layer scanning
            # ═══════════════════════════════════════════════════════════════
            for name, atype, msg in [
                ("SAST Agent",       "sast",       "Running Semgrep OWASP Top-10…"),
                ("Dependency Agent", "dependency", "Querying OSV.dev CVE database…"),
                ("Secrets Agent",    "secrets",    "Scanning for hardcoded secrets…"),
                ("API Agent",        "api",        "Discovering API endpoints & auth gaps…"),
            ]:
                await self.send_event(name, atype, "working", msg)

            sast_r, dep_r, sec_r, api_r = await asyncio.gather(
                asyncio.wait_for(
                    asyncio.to_thread(SASTAgent(self.llm_config).run, scan_result),
                    timeout=120,
                ),
                asyncio.wait_for(
                    asyncio.to_thread(DependencyAgent(self.llm_config).run, scan_result),
                    timeout=60,
                ),
                asyncio.wait_for(
                    asyncio.to_thread(SecretsAgent(self.llm_config).run, scan_result),
                    timeout=60,
                ),
                asyncio.wait_for(
                    asyncio.to_thread(APIAgent(self.llm_config).run, scan_result),
                    timeout=60,
                ),
                return_exceptions=True,
            )

            sast_r = self._safe(sast_r, {"vulnerabilities": []})
            dep_r  = self._safe(dep_r,  {"vulnerabilities": []})
            sec_r  = self._safe(sec_r,  {"vulnerabilities": []})
            api_r  = self._safe(api_r,  {"vulnerabilities": []})

            await self.send_event("SAST Agent",       "sast",       "done",
                f"Found {len(sast_r['vulnerabilities'])} code vulnerabilities",
                sast_r)
            await self.send_event("Dependency Agent", "dependency", "done",
                f"Found {len(dep_r['vulnerabilities'])} CVE issues",
                dep_r)
            await self.send_event("Secrets Agent",    "secrets",    "done",
                f"Found {len(sec_r['vulnerabilities'])} exposed secrets",
                sec_r)
            await self.send_event("API Agent",        "api",        "done",
                f"Found {len(api_r['vulnerabilities'])} API issues",
                api_r)

            all_vulns = (
                sast_r.get("vulnerabilities", []) +
                dep_r.get("vulnerabilities",  []) +
                sec_r.get("vulnerabilities",  []) +
                api_r.get("vulnerabilities",  [])
            )
            all_findings = {"vulnerabilities": all_vulns, "scan_result": scan_result}

            # Persist raw findings to Neon DB
            for v in all_vulns:
                try:
                    await execute(
                        "INSERT INTO vulnerabilities "
                        "(id, session_id, title, file_path, severity, cvss_score, "
                        "owasp_category, layer) "
                        "VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT DO NOTHING",
                        v.get("id"), self.session_id,
                        v.get("title", "")[:255],
                        v.get("file_path", "")[:500],
                        v.get("severity", "MEDIUM"),
                        float(v.get("cvss_score", 0)),
                        v.get("owasp_category", "")[:255],
                        v.get("layer", "code"),
                    )
                except Exception:
                    pass

            # ═══════════════════════════════════════════════════════════════
            # PHASE 3: Attack Chain Synthesis
            # ═══════════════════════════════════════════════════════════════
            await self.send_event(
                "Attack Chain Agent", "attack_chain", "thinking",
                "Correlating findings across all layers to discover attack chains…",
            )
            chain_result = await asyncio.wait_for(
                asyncio.to_thread(AttackChainAgent(self.llm_config).run, all_findings),
                timeout=90,
            )
            await self.send_event(
                "Attack Chain Agent", "attack_chain", "done",
                f"Discovered {len(chain_result.get('attack_chains', []))} multi-layer attack chains!",
                chain_result,
            )

            # ═══════════════════════════════════════════════════════════════
            # PHASE 4: PoC + Severity + Patch + Risk (parallel)
            # ═══════════════════════════════════════════════════════════════
            for name, atype, msg in [
                ("PoC Agent",      "poc",      "Writing working exploit scripts…"),
                ("Severity Agent", "severity", "Applying CVSS 3.1 scoring…"),
                ("Patch Agent",    "patch",    "Generating context-aware code fixes…"),
                ("Risk Agent",     "risk",     "Calculating business risk in USD…"),
            ]:
                await self.send_event(name, atype, "working", msg)

            poc_r, sev_r, patch_r, risk_r = await asyncio.gather(
                asyncio.wait_for(
                    asyncio.to_thread(PoCAgent(self.llm_config).run, all_findings),
                    timeout=90,
                ),
                asyncio.wait_for(
                    asyncio.to_thread(SeverityAgent(self.llm_config).run, all_findings),
                    timeout=60,
                ),
                asyncio.wait_for(
                    asyncio.to_thread(PatchAgent(self.llm_config).run, all_findings, scan_result),
                    timeout=90,
                ),
                asyncio.wait_for(
                    asyncio.to_thread(RiskAgent(self.llm_config).run, all_findings, chain_result),
                    timeout=60,
                ),
                return_exceptions=True,
            )

            poc_r   = self._safe(poc_r,   {"exploits": []})
            sev_r   = self._safe(sev_r,   {"scored_vulnerabilities": []})
            patch_r = self._safe(patch_r, {"patches": []})
            risk_r  = self._safe(risk_r,  {"total_risk_usd": 0, "roi_ratio": 0})

            await self.send_event("PoC Agent",      "poc",      "done",
                f"Generated {len(poc_r.get('exploits', []))} exploit scripts", poc_r)
            await self.send_event("Severity Agent", "severity", "done",
                f"Scored {len(sev_r.get('scored_vulnerabilities', []))} findings", sev_r)
            await self.send_event("Patch Agent",    "patch",    "done",
                f"Generated {len(patch_r.get('patches', []))} patches", patch_r)
            await self.send_event(
                "Risk Agent", "risk", "done",
                f"Total exposure: ${risk_r.get('total_risk_usd', 0):,.0f} | "
                f"ROI of fixing: {risk_r.get('roi_ratio', 0):,.0f}x",
                risk_r,
            )

            # ═══════════════════════════════════════════════════════════════
            # PHASE 5: Report
            # ═══════════════════════════════════════════════════════════════
            await self.send_event(
                "Report Agent", "report", "thinking",
                "Synthesising full pentest report…",
            )
            report_data = await asyncio.wait_for(
                asyncio.to_thread(
                    ReportAgent(self.llm_config).run,
                    github_url, scan_result, all_findings,
                    chain_result, poc_r, sev_r, patch_r, risk_r,
                ),
                timeout=120,
            )
            generate_pdf_report(self.session_id, report_data)

            # Update Neon DB with final stats
            try:
                await execute(
                    "UPDATE audit_sessions SET "
                    "total_vulnerabilities=$1, critical_count=$2, high_count=$3, "
                    "medium_count=$4, low_count=$5, total_risk_usd=$6, "
                    "tech_stack=$7, file_count=$8, report_path=$9, repo_name=$10 "
                    "WHERE id=$11",
                    len(all_vulns),
                    risk_r.get("critical_count", 0),
                    risk_r.get("high_count",     0),
                    risk_r.get("medium_count",   0),
                    risk_r.get("low_count",      0),
                    float(risk_r.get("total_risk_usd", 0)),
                    json.dumps(scan_result.get("tech_stack", [])),
                    scan_result.get("file_count", 0),
                    f"/tmp/reports/{self.session_id}_report.pdf",
                    scan_result.get("repo_name", ""),
                    self.session_id,
                )
            except Exception:
                pass

            await self.send_event(
                "Report Agent", "report", "done",
                "✅ Audit complete! Pentest report ready for download.",
                {
                    "pdf_ready":      True,
                    "session_id":     self.session_id,
                    "total_risk_usd": risk_r.get("total_risk_usd", 0),
                    "total_vulns":    len(all_vulns),
                },
            )

        except asyncio.TimeoutError:
            await self.send_event(
                "System", "system", "error",
                "Audit timed out. Repository may be too large. Try a smaller repo.",
            )
        except Exception as exc:
            await self.send_event("System", "system", "error", f"Audit failed: {str(exc)}")
            raise
        finally:
            # Cleanup cloned repo to free disk space
            if clone_path and os.path.exists(clone_path):
                try:
                    shutil.rmtree(clone_path, ignore_errors=True)
                except Exception:
                    pass
