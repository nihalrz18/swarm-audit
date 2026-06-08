"""
Run on startup to create tables if they don't exist.
All tables use Neon.tech PostgreSQL — no local DB required.
"""

CREATE_AUDIT_SESSIONS = """
CREATE TABLE IF NOT EXISTS audit_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    github_url TEXT NOT NULL,
    status TEXT DEFAULT 'running',
    repo_name TEXT,
    tech_stack JSONB DEFAULT '[]',
    file_count INTEGER DEFAULT 0,
    total_vulnerabilities INTEGER DEFAULT 0,
    critical_count INTEGER DEFAULT 0,
    high_count INTEGER DEFAULT 0,
    medium_count INTEGER DEFAULT 0,
    low_count INTEGER DEFAULT 0,
    total_risk_usd DECIMAL(15,2) DEFAULT 0,
    report_path TEXT,
    results JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);
"""

CREATE_VULNERABILITIES = """
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id TEXT PRIMARY KEY,
    session_id UUID REFERENCES audit_sessions(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    description TEXT,
    file_path TEXT,
    line_number INTEGER,
    severity TEXT,
    cvss_score DECIMAL(4,1) DEFAULT 0.0,
    cvss_vector TEXT,
    owasp_category TEXT,
    raw_message TEXT,
    code_snippet TEXT,
    proof_of_concept TEXT,
    patch_diff TEXT,
    layer TEXT DEFAULT 'code',
    created_at TIMESTAMPTZ DEFAULT NOW()
);
"""

CREATE_ATTACK_CHAINS = """
CREATE TABLE IF NOT EXISTS attack_chains (
    id TEXT PRIMARY KEY,
    session_id UUID REFERENCES audit_sessions(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    chain_steps JSONB DEFAULT '[]',
    exploit_path TEXT,
    risk_level TEXT,
    cvss_overall DECIMAL(4,1),
    business_impact_usd DECIMAL(15,2),
    fix_sequence JSONB DEFAULT '[]',
    created_at TIMESTAMPTZ DEFAULT NOW()
);
"""

CREATE_PATCHES = """
CREATE TABLE IF NOT EXISTS patches (
    id SERIAL PRIMARY KEY,
    session_id UUID REFERENCES audit_sessions(id) ON DELETE CASCADE,
    vuln_id TEXT,
    file_path TEXT,
    patch_diff TEXT,
    explanation TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
"""


async def run_migrations():
    """Call this on FastAPI startup."""
    from database.connection import execute
    for statement in [
        CREATE_AUDIT_SESSIONS,
        CREATE_VULNERABILITIES,
        CREATE_ATTACK_CHAINS,
        CREATE_PATCHES,
    ]:
        await execute(statement)
    print("✅ Neon.tech migrations complete")
