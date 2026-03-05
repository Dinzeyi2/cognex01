"""
Cognex — Data Access Control for Small Teams (CONTROL PLANE)
MVP supports: PostgreSQL
"""

import asyncio, bcrypt, json, os, re, secrets, time, hashlib
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Optional, Dict, List

import asyncpg
import structlog
from cryptography.fernet import Fernet, InvalidToken
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field
from slowapi import Limiter
from slowapi.util import get_remote_address

log = structlog.get_logger()

# ── Config ────────────────────────────────────────────────────────────────────
DATABASE_URL = os.environ["DATABASE_URL"]
ADMIN_API_KEY = os.environ.get("COGNEX_ADMIN_KEY", "")

COGNEX_FERNET_KEY = os.environ.get("COGNEX_FERNET_KEY", "")
if not COGNEX_FERNET_KEY:
    raise RuntimeError(
        "Missing env var COGNEX_FERNET_KEY. "
        "Generate: python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
    )

FERNET = Fernet(COGNEX_FERNET_KEY.encode() if isinstance(COGNEX_FERNET_KEY, str) else COGNEX_FERNET_KEY)
ALLOW_ORIGINS = os.environ.get("COGNEX_ALLOW_ORIGINS", "http://localhost:3000").split(",")

# ── Sensitive field detection ─────────────────────────────────────────────────
SENSITIVE_PATTERNS = [
    r"\bssn\b", r"social_security", r"password", r"passwd", r"\bsecret\b",
    r"credit_?card", r"card_?number", r"\bcvv\b", r"\bpin\b",
    r"\bemail\b", r"\bphone\b", r"mobile", r"\bdob\b", r"birth",
    r"salary", r"income", r"\btax\b", r"bank_?account", r"routing",
    r"passport", r"license", r"national_?id",
    r"ip_?address", r"location", r"\baddress\b",
    r"token", r"api_?key", r"private_?key",
]

def is_sensitive(column_name: str) -> bool:
    name = column_name.lower()
    return any(re.search(p, name) for p in SENSITIVE_PATTERNS)

# ── Compliance framework definitions ─────────────────────────────────────────
COMPLIANCE_FRAMEWORKS = {
    "hipaa": {
        "name": "HIPAA",
        "description": "Health Insurance Portability and Accountability Act — protects patient health information (PHI).",
        "required_log_retention_days": 2190,
        "auto_block_patterns": [
            r"\bssn\b", r"social_security", r"\bdob\b", r"date_of_birth", r"birth_date",
            r"diagnosis", r"condition", r"medication", r"prescription",
            r"medical_record", r"mrn", r"patient_id", r"\bphone\b", r"mobile",
            r"\bemail\b", r"\baddress\b", r"zip", r"biometric", r"health_plan",
            r"license", r"ip_address",
        ],
        "violation_fields": ["ssn","dob","diagnosis","medical_record","mrn","patient_id","biometric"],
    },
    "gdpr": {
        "name": "GDPR",
        "description": "General Data Protection Regulation — protects EU citizen personal data.",
        "required_log_retention_days": 365,
        "auto_block_patterns": [
            r"\bemail\b", r"\bphone\b", r"\baddress\b",
            r"\bname\b", r"first_name", r"last_name", r"full_name",
            r"ip_address", r"location", r"nationality", r"ethnicity",
            r"political", r"religion", r"sexual", r"biometric", r"genetic",
            r"\bpassword\b", r"national_id", r"passport",
        ],
        "violation_fields": ["email","name","ip_address","location","nationality","biometric"],
    },
    "soc2": {
        "name": "SOC2",
        "description": "Service Organization Control 2 — security, availability, and confidentiality controls.",
        "required_log_retention_days": 365,
        "auto_block_patterns": [
            r"\bpassword\b", r"passwd", r"\bsecret\b",
            r"api_key", r"private_key", r"token", r"credential",
        ],
        "violation_fields": ["password","api_key","private_key","token","secret"],
    },
    "pci": {
        "name": "PCI DSS",
        "description": "Payment Card Industry Data Security Standard — protects cardholder data.",
        "required_log_retention_days": 365,
        "auto_block_patterns": [
            r"card_number", r"credit_card", r"\bpan\b",
            r"\bcvv\b", r"\bcvc\b", r"card_verification",
            r"expir", r"expiry", r"\bpin\b", r"track_data",
            r"cardholder", r"card_holder",
        ],
        "violation_fields": ["card_number","cvv","pan","pin","track_data"],
    },
    "finra": {
        "name": "FINRA",
        "description": "Financial Industry Regulatory Authority — governs broker-dealer data in the US.",
        "required_log_retention_days": 2190,
        "auto_block_patterns": [
            r"account_number", r"brokerage", r"portfolio",
            r"\btrade\b", r"order_id", r"execution",
            r"ssn", r"net_worth", r"income", r"salary",
            r"investment", r"position", r"holding",
        ],
        "violation_fields": ["account_number","ssn","trade","portfolio","net_worth"],
    },
}

SUPPORTED_FRAMEWORKS = list(COMPLIANCE_FRAMEWORKS.keys())

def get_framework_violations(column_name: str) -> list:
    """Return list of compliance frameworks this column name violates."""
    name = column_name.lower()
    return [fw_key for fw_key, fw in COMPLIANCE_FRAMEWORKS.items()
            if any(re.search(p, name) for p in fw["auto_block_patterns"])]

# ── DB pool ───────────────────────────────────────────────────────────────────
pool: asyncpg.Pool = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global pool
    pool = await asyncpg.create_pool(DATABASE_URL, min_size=2, max_size=10)
    await init_db()
    log.info("cognex.started")
    yield
    await pool.close()

async def init_db():
    async with pool.acquire() as conn:
        await conn.execute("""
        CREATE TABLE IF NOT EXISTS tenants (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            api_key TEXT UNIQUE NOT NULL,
            plan TEXT DEFAULT 'free',
            api_call_count INTEGER DEFAULT 0,
            last_seen_at TIMESTAMPTZ,
            created_at TIMESTAMPTZ DEFAULT NOW()
        )""")

        await conn.execute("""
        CREATE TABLE IF NOT EXISTS connections (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL REFERENCES tenants(id),
            name TEXT NOT NULL,
            db_type TEXT NOT NULL,
            host TEXT NOT NULL,
            port INTEGER NOT NULL,
            database_name TEXT NOT NULL,
            username TEXT NOT NULL,
            password_encrypted TEXT NOT NULL,
            ssl_mode TEXT DEFAULT 'prefer',
            status TEXT DEFAULT 'pending',
            last_scanned_at TIMESTAMPTZ,
            created_at TIMESTAMPTZ DEFAULT NOW()
        )""")

        await conn.execute("""
        CREATE TABLE IF NOT EXISTS db_tables (
            id TEXT PRIMARY KEY,
            connection_id TEXT NOT NULL REFERENCES connections(id),
            tenant_id TEXT NOT NULL,
            table_name TEXT NOT NULL,
            row_count BIGINT DEFAULT 0,
            columns JSONB DEFAULT '[]',
            sensitive_columns JSONB DEFAULT '[]',
            created_at TIMESTAMPTZ DEFAULT NOW(),
            UNIQUE(connection_id, table_name)
        )""")

        await conn.execute("""
        CREATE TABLE IF NOT EXISTS access_rules (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            connection_id TEXT NOT NULL,
            name TEXT NOT NULL,
            role TEXT NOT NULL,
            table_name TEXT NOT NULL,
            allowed_operations JSONB DEFAULT '["SELECT"]',
            blocked_columns JSONB DEFAULT '[]',
            max_rows INTEGER DEFAULT 1000,
            conditions JSONB DEFAULT '{}',
            active BOOLEAN DEFAULT true,
            created_at TIMESTAMPTZ DEFAULT NOW()
        )""")

        await conn.execute("""
        CREATE TABLE IF NOT EXISTS query_logs (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            connection_id TEXT NOT NULL,
            role TEXT,
            user_identifier TEXT,
            table_name TEXT,
            operation TEXT,
            query_hash TEXT,
            columns_accessed JSONB DEFAULT '[]',
            compliance_blocked BOOLEAN DEFAULT false,
            compliance_frameworks JSONB DEFAULT '[]',
            rows_returned INTEGER DEFAULT 0,
            blocked BOOLEAN DEFAULT false,
            block_reason TEXT,
            duration_ms INTEGER DEFAULT 0,
            created_at TIMESTAMPTZ DEFAULT NOW()
        )""")

        await conn.execute("""
        CREATE TABLE IF NOT EXISTS anomaly_alerts (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            connection_id TEXT NOT NULL,
            alert_type TEXT NOT NULL,
            severity TEXT DEFAULT 'medium',
            message TEXT NOT NULL,
            metadata JSONB DEFAULT '{}',
            resolved BOOLEAN DEFAULT false,
            created_at TIMESTAMPTZ DEFAULT NOW()
        )""")

        await conn.execute("CREATE INDEX IF NOT EXISTS ql_tenant_idx ON query_logs(tenant_id, created_at DESC)")
        await conn.execute("CREATE INDEX IF NOT EXISTS ql_conn_idx ON query_logs(connection_id, created_at DESC)")
        await conn.execute("CREATE INDEX IF NOT EXISTS alert_tenant_idx ON anomaly_alerts(tenant_id, resolved)")

        # Compliance settings per connection
        await conn.execute("""
        CREATE TABLE IF NOT EXISTS compliance_settings (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            connection_id TEXT NOT NULL REFERENCES connections(id),
            framework TEXT NOT NULL,
            enabled BOOLEAN DEFAULT true,
            auto_block BOOLEAN DEFAULT true,
            created_at TIMESTAMPTZ DEFAULT NOW(),
            UNIQUE(connection_id, framework)
        )""")

        await conn.execute("CREATE INDEX IF NOT EXISTS cs_conn_idx ON compliance_settings(connection_id, enabled)")
        log.info("cognex.db.initialized")

# ── App setup ─────────────────────────────────────────────────────────────────
def forwarded_ip(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return get_remote_address(request)

limiter = Limiter(key_func=forwarded_ip)
app = FastAPI(title="Cognex API", version="1.1.0", lifespan=lifespan)
app.state.limiter = limiter

app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in ALLOW_ORIGINS if o.strip()],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Auth dependency ───────────────────────────────────────────────────────────
async def get_tenant(
    request: Request,
    x_api_key: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None),
):
    key = x_api_key
    if not key and authorization and authorization.startswith("Bearer "):
        key = authorization[7:]
    if not key:
        raise HTTPException(401, "API key required — set x-api-key header")
    if key == ADMIN_API_KEY and ADMIN_API_KEY:
        return {"id": "__admin__", "plan": "enterprise", "email": "admin"}
    async with pool.acquire() as conn:
        tenant = await conn.fetchrow("SELECT * FROM tenants WHERE api_key=$1", key)
        if not tenant:
            raise HTTPException(401, "Invalid API key")
        await conn.execute(
            "UPDATE tenants SET api_call_count=COALESCE(api_call_count,0)+1, last_seen_at=NOW() WHERE id=$1",
            tenant["id"])
    return dict(tenant)

# ── Pydantic models ───────────────────────────────────────────────────────────
class SignupBody(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    email: EmailStr
    password: str = Field(min_length=8, max_length=200)

class LoginBody(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=200)

class ConnectBody(BaseModel):
    name: str
    db_type: str
    host: str
    port: int
    database_name: str
    username: str
    password: str
    ssl_mode: Optional[str] = "prefer"
    # BigQuery extras
    project_id: Optional[str] = None        # GCP project
    credentials_json: Optional[str] = None  # service account JSON string
    # Snowflake extras
    account: Optional[str] = None           # e.g. xy12345.us-east-1
    warehouse: Optional[str] = None         # e.g. COMPUTE_WH
    schema: Optional[str] = None            # e.g. PUBLIC
    # MongoDB extras
    auth_source: Optional[str] = None       # e.g. admin

class AccessRuleBody(BaseModel):
    name: str
    role: str
    table_name: str
    allowed_operations: List[str] = ["SELECT"]
    blocked_columns: List[str] = []
    max_rows: int = 1000
    conditions: Dict[str, Any] = {}

class QueryCheckBody(BaseModel):
    connection_id: str
    role: str
    user_identifier: str
    table_name: str
    operation: str
    columns: Optional[List[str]] = None
    query: Optional[str] = None

class LogResultBody(BaseModel):
    log_id: str
    rows_returned: int = Field(ge=0, le=10_000_000)

# ── Helpers ───────────────────────────────────────────────────────────────────
def make_id(prefix="") -> str:
    return f"{prefix}{secrets.token_hex(8)}"

def encrypt_password(pw: str) -> str:
    return FERNET.encrypt(pw.encode()).decode()

def decrypt_password(encrypted: str) -> str:
    try:
        return FERNET.decrypt(encrypted.encode()).decode()
    except InvalidToken:
        raise HTTPException(500, "Cannot decrypt stored database password.")

def hash_query(query: Optional[str], meta: Dict[str, Any]) -> str:
    payload = query if query else json.dumps(meta, sort_keys=True, default=str)
    return hashlib.sha256(payload.encode()).hexdigest()

async def _create_alert(conn, tenant_id, connection_id, alert_type, severity, message, metadata):
    await conn.execute("""
        INSERT INTO anomaly_alerts (id, tenant_id, connection_id, alert_type, severity, message, metadata)
        VALUES ($1,$2,$3,$4,$5,$6,$7)
    """, make_id("alt_"), tenant_id, connection_id, alert_type, severity, message, json.dumps(metadata))

async def check_anomalies_for_log(log_id: str, tenant_id: str):
    """Read the finished log row and fire alerts if needed."""
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT * FROM query_logs WHERE id=$1 AND tenant_id=$2", log_id, tenant_id)
        if not row:
            return

        cid   = row["connection_id"]
        role  = row["role"] or "unknown"
        rows  = int(row["rows_returned"] or 0)
        hour  = datetime.now(timezone.utc).hour

        if rows > 5000:
            await _create_alert(conn, tenant_id, cid, "high_row_count", "high",
                f"Role '{role}' returned {rows} rows in a single query",
                {"role": role, "rows": rows, "log_id": log_id})

        if hour < 5:
            await _create_alert(conn, tenant_id, cid, "unusual_time", "medium",
                f"Role '{role}' accessed database at {hour:02d}:00 UTC (outside business hours)",
                {"role": role, "hour": hour, "log_id": log_id})

        count = int(await conn.fetchval("""
            SELECT COUNT(*) FROM query_logs
            WHERE tenant_id=$1 AND role=$2 AND created_at > NOW() - INTERVAL '1 minute'
        """, tenant_id, role) or 0)

        if count > 100:
            await _create_alert(conn, tenant_id, cid, "rate_spike", "high",
                f"Role '{role}' made {count} queries in the last minute — possible scraping",
                {"role": role, "count": count})

# ── Postgres scanner ──────────────────────────────────────────────────────────
# ── Database type aliases ─────────────────────────────────────────────────────
# Maps every accepted db_type string → canonical internal type
DB_TYPE_MAP = {
    # Postgres family (all use asyncpg / Postgres wire protocol)
    "postgres":   "postgres",
    "postgresql": "postgres",
    "supabase":   "postgres",   # Supabase = managed Postgres
    "neon":       "postgres",   # Neon = serverless Postgres
    "redshift":   "postgres",   # Redshift speaks Postgres wire protocol
    "cockroachdb":"postgres",   # CockroachDB = Postgres-compatible
    "timescaledb":"postgres",   # TimescaleDB = Postgres extension
    "alloydb":    "postgres",   # Google AlloyDB = Postgres-compatible

    # MySQL family (all use aiomysql)
    "mysql":       "mysql",
    "planetscale": "mysql",     # PlanetScale = MySQL-compatible
    "tidb":        "mysql",     # TiDB = MySQL-compatible
    "aurora_mysql":"mysql",     # AWS Aurora MySQL

    # MongoDB family (all use motor)
    "mongodb":      "mongodb",
    "mongo":        "mongodb",
    "atlas":        "mongodb",  # MongoDB Atlas = hosted MongoDB
    "documentdb":   "mongodb",  # AWS DocumentDB = MongoDB-compatible

    # BigQuery (uses google-cloud-bigquery — separate scanner)
    "bigquery": "bigquery",

    # Snowflake (uses snowflake-connector-python — separate scanner)
    "snowflake": "snowflake",
}

SUPPORTED_DB_TYPES = sorted(DB_TYPE_MAP.keys())


async def scan_postgres(cfg: dict) -> list:
    """
    Handles: postgres, supabase, neon, redshift, cockroachdb, timescaledb, alloydb.
    All speak the Postgres wire protocol — same driver, same queries.
    """
    try:
        ssl = cfg.get("ssl_mode", "prefer")
        # Redshift requires ssl=True
        if cfg.get("db_type", "").lower() == "redshift":
            ssl = "require"

        dsn = (f"postgresql://{cfg['username']}:{cfg['password']}"
               f"@{cfg['host']}:{cfg['port']}/{cfg['database_name']}"
               f"?sslmode={ssl}")
        ext = await asyncpg.connect(dsn, timeout=15)

        # Use pg_class estimates — no COUNT(*), no table scan
        table_rows = await ext.fetch("""
            SELECT c.relname AS table_name, COALESCE(c.reltuples::BIGINT, 0) AS est_rows
            FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = 'public' AND c.relkind = 'r'
            ORDER BY c.relname
        """)
        tables = []
        for tr in table_rows:
            tname = tr["table_name"]
            cols = await ext.fetch("""
                SELECT column_name, data_type, is_nullable
                FROM information_schema.columns
                WHERE table_schema='public' AND table_name=$1
                ORDER BY ordinal_position
            """, tname)
            columns = [{"name": c["column_name"], "type": c["data_type"],
                        "nullable": c["is_nullable"] == "YES",
                        "sensitive": is_sensitive(c["column_name"])} for c in cols]
            tables.append({
                "table_name": tname,
                "row_count": int(tr["est_rows"] or 0),
                "columns": columns,
                "sensitive_columns": [c["name"] for c in columns if c["sensitive"]],
            })
        await ext.close()
        return tables
    except Exception as e:
        raise HTTPException(400, f"Cannot connect to Postgres-compatible database: {e}")


async def scan_mysql(cfg: dict) -> list:
    """
    Handles: mysql, planetscale, tidb, aurora_mysql.
    All speak the MySQL wire protocol.
    """
    try:
        import aiomysql
        # PlanetScale requires SSL
        ssl_ctx = None
        if cfg.get("db_type", "").lower() == "planetscale":
            import ssl as ssl_lib
            ssl_ctx = ssl_lib.create_default_context()

        conn = await aiomysql.connect(
            host=cfg["host"], port=int(cfg["port"]),
            user=cfg["username"], password=cfg["password"],
            db=cfg["database_name"], connect_timeout=10,
            autocommit=True, ssl=ssl_ctx,
        )
        cursor = await conn.cursor(aiomysql.DictCursor)
        await cursor.execute("""
            SELECT TABLE_NAME, COALESCE(TABLE_ROWS, 0) AS est_rows
            FROM information_schema.TABLES
            WHERE TABLE_SCHEMA = %s AND TABLE_TYPE = 'BASE TABLE'
            ORDER BY TABLE_NAME
        """, (cfg["database_name"],))
        table_rows = await cursor.fetchall()

        tables = []
        for tr in table_rows:
            tname = tr["TABLE_NAME"]
            await cursor.execute("""
                SELECT COLUMN_NAME, DATA_TYPE, IS_NULLABLE
                FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s
                ORDER BY ORDINAL_POSITION
            """, (cfg["database_name"], tname))
            cols = await cursor.fetchall()
            columns = [{"name": c["COLUMN_NAME"], "type": c["DATA_TYPE"],
                        "nullable": c["IS_NULLABLE"] == "YES",
                        "sensitive": is_sensitive(c["COLUMN_NAME"])} for c in cols]
            tables.append({
                "table_name": tname,
                "row_count": int(tr["est_rows"] or 0),
                "columns": columns,
                "sensitive_columns": [c["name"] for c in columns if c["sensitive"]],
            })
        conn.close()
        return tables
    except Exception as e:
        raise HTTPException(400, f"Cannot connect to MySQL-compatible database: {e}")


async def scan_mongodb(cfg: dict) -> list:
    """
    Handles: mongodb, atlas, documentdb.
    Uses motor (async MongoDB driver).
    """
    try:
        from motor.motor_asyncio import AsyncIOMotorClient

        # Atlas uses SRV connection string
        if cfg.get("db_type", "").lower() == "atlas" or cfg.get("host", "").endswith(".mongodb.net"):
            uri = f"mongodb+srv://{cfg['username']}:{cfg['password']}@{cfg['host']}/{cfg['database_name']}?retryWrites=true&w=majority"
        else:
            uri = (f"mongodb://{cfg['username']}:{cfg['password']}"
                   f"@{cfg['host']}:{cfg['port']}/{cfg['database_name']}"
                   f"?authSource={cfg.get('auth_source', 'admin')}")

        client = AsyncIOMotorClient(uri, serverSelectionTimeoutMS=8000)
        db = client[cfg["database_name"]]
        collection_names = await db.list_collection_names()

        tables = []
        for cname in collection_names:
            col = db[cname]
            count = await col.estimated_document_count()
            sample = await col.find_one({})
            columns = []
            if sample:
                for field, val in sample.items():
                    if field == "_id":
                        continue
                    columns.append({"name": field, "type": type(val).__name__,
                                    "nullable": True, "sensitive": is_sensitive(field)})
            tables.append({
                "table_name": cname,
                "row_count": int(count),
                "columns": columns,
                "sensitive_columns": [c["name"] for c in columns if c["sensitive"]],
            })
        client.close()
        return tables
    except Exception as e:
        raise HTTPException(400, f"Cannot connect to MongoDB-compatible database: {e}")


async def scan_bigquery(cfg: dict) -> list:
    """
    Handles: BigQuery (Google Cloud).
    Requires: pip install google-cloud-bigquery
    cfg extras: project_id, credentials_json (service account JSON as string)
    """
    try:
        import json as _json
        from google.cloud import bigquery
        from google.oauth2 import service_account

        creds_raw = cfg.get("credentials_json") or cfg.get("password")
        creds_dict = _json.loads(creds_raw) if isinstance(creds_raw, str) else creds_raw
        credentials = service_account.Credentials.from_service_account_info(
            creds_dict, scopes=["https://www.googleapis.com/auth/bigquery.readonly"])

        project_id = cfg.get("project_id") or cfg.get("database_name")
        client = bigquery.Client(project=project_id, credentials=credentials)
        dataset_id = cfg.get("schema") or cfg.get("database_name")

        tables = []
        for tbl in client.list_tables(dataset_id):
            tbl_ref = client.get_table(tbl)
            columns = [{"name": f.name, "type": f.field_type,
                        "nullable": f.mode != "REQUIRED",
                        "sensitive": is_sensitive(f.name)} for f in tbl_ref.schema]
            tables.append({
                "table_name": tbl.table_id,
                "row_count": int(tbl_ref.num_rows or 0),
                "columns": columns,
                "sensitive_columns": [c["name"] for c in columns if c["sensitive"]],
            })
        return tables
    except ImportError:
        raise HTTPException(400, "BigQuery requires google-cloud-bigquery. Contact support to enable.")
    except Exception as e:
        raise HTTPException(400, f"Cannot connect to BigQuery: {e}")


async def scan_snowflake(cfg: dict) -> list:
    """
    Handles: Snowflake.
    Requires: pip install snowflake-connector-python
    cfg extras: account (e.g. xy12345.us-east-1), warehouse, schema
    """
    try:
        import snowflake.connector
        conn = snowflake.connector.connect(
            user=cfg["username"],
            password=cfg["password"],
            account=cfg.get("account") or cfg["host"],
            database=cfg["database_name"],
            warehouse=cfg.get("warehouse", "COMPUTE_WH"),
            schema=cfg.get("schema", "PUBLIC"),
            login_timeout=15,
        )
        cursor = conn.cursor(snowflake.connector.DictCursor)
        cursor.execute("SHOW TABLES")
        table_rows = cursor.fetchall()

        tables = []
        for tr in table_rows:
            tname = tr.get("name") or tr.get("TABLE_NAME", "")
            cursor.execute(f'DESCRIBE TABLE "{tname}"')
            cols = cursor.fetchall()
            columns = [{"name": c.get("name", ""), "type": c.get("type", ""),
                        "nullable": c.get("null?", "Y") == "Y",
                        "sensitive": is_sensitive(c.get("name", ""))} for c in cols]
            # Snowflake row count from SHOW TABLES
            row_count = int(tr.get("rows", 0) or 0)
            tables.append({
                "table_name": tname,
                "row_count": row_count,
                "columns": columns,
                "sensitive_columns": [c["name"] for c in columns if c["sensitive"]],
            })
        conn.close()
        return tables
    except ImportError:
        raise HTTPException(400, "Snowflake requires snowflake-connector-python. Contact support to enable.")
    except Exception as e:
        raise HTTPException(400, f"Cannot connect to Snowflake: {e}")


async def scan_database(cfg: dict) -> list:
    raw_type = cfg["db_type"].lower().strip()
    canonical = DB_TYPE_MAP.get(raw_type)
    if not canonical:
        raise HTTPException(
            400,
            f"Unsupported db_type '{raw_type}'. "
            f"Supported: {', '.join(SUPPORTED_DB_TYPES)}"
        )
    if canonical == "postgres":   return await scan_postgres(cfg)
    if canonical == "mysql":      return await scan_mysql(cfg)
    if canonical == "mongodb":    return await scan_mongodb(cfg)
    if canonical == "bigquery":   return await scan_bigquery(cfg)
    if canonical == "snowflake":  return await scan_snowflake(cfg)
    raise HTTPException(400, f"Scanner not implemented for '{canonical}'")

# ══════════════════════════════════════════════════════════════════════════════
# ROUTES
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/health")
async def health():
    return {"status": "ok", "service": "cognex", "version": "1.0.1"}

# ── Auth ──────────────────────────────────────────────────────────────────────
@app.post("/auth/signup")
async def signup(body: SignupBody):
    pw_hash = bcrypt.hashpw(body.password.encode(), bcrypt.gensalt()).decode()
    tenant_id, api_key = make_id("ten_"), f"cx-{secrets.token_hex(32)}"
    try:
        async with pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO tenants (id, name, email, password_hash, api_key) VALUES ($1,$2,$3,$4,$5)",
                tenant_id, body.name, body.email, pw_hash, api_key)
    except asyncpg.UniqueViolationError:
        raise HTTPException(400, "Email already registered")
    return {"tenant_id": tenant_id, "api_key": api_key,
            "message": "Save your API key — it won't be shown again"}

@app.post("/auth/login")
async def login(body: LoginBody):
    async with pool.acquire() as conn:
        tenant = await conn.fetchrow("SELECT * FROM tenants WHERE email=$1", body.email)
    if not tenant or not bcrypt.checkpw(body.password.encode(), tenant["password_hash"].encode()):
        raise HTTPException(401, "Invalid credentials")
    return {"api_key": tenant["api_key"], "tenant_id": tenant["id"], "name": tenant["name"]}

@app.get("/auth/me")
async def me(tenant=Depends(get_tenant)):
    return {k: v for k, v in tenant.items() if k not in ("password_hash", "api_key")}

# ── Connections ───────────────────────────────────────────────────────────────
@app.post("/connections")
async def create_connection(body: ConnectBody, tenant=Depends(get_tenant)):
    cfg = {"db_type": body.db_type, "host": body.host, "port": body.port,
           "database_name": body.database_name, "username": body.username,
           "password": body.password, "ssl_mode": body.ssl_mode,
           # Enterprise extras
           "project_id": body.project_id, "credentials_json": body.credentials_json,
           "account": body.account, "warehouse": body.warehouse,
           "schema": body.schema, "auth_source": body.auth_source}
    tables = await scan_database(cfg)
    conn_id = make_id("conn_")

    async with pool.acquire() as conn:
        await conn.execute("""
            INSERT INTO connections (id, tenant_id, name, db_type, host, port,
                database_name, username, password_encrypted, ssl_mode, status, last_scanned_at)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'connected',NOW())
        """, conn_id, tenant["id"], body.name, body.db_type, body.host, body.port,
            body.database_name, body.username, encrypt_password(body.password), body.ssl_mode)

        for t in tables:
            await conn.execute("""
                INSERT INTO db_tables (id, connection_id, tenant_id, table_name,
                    row_count, columns, sensitive_columns)
                VALUES ($1,$2,$3,$4,$5,$6,$7)
                ON CONFLICT (connection_id, table_name) DO UPDATE
                SET row_count=$5, columns=$6, sensitive_columns=$7
            """, make_id("tbl_"), conn_id, tenant["id"], t["table_name"],
                t["row_count"], json.dumps(t["columns"]), json.dumps(t["sensitive_columns"]))

    return {"connection_id": conn_id, "status": "connected", "tables_found": len(tables),
            "tables": [{"name": t["table_name"], "rows": t["row_count"],
                        "sensitive_columns": t["sensitive_columns"]} for t in tables]}

@app.get("/connections")
async def list_connections(tenant=Depends(get_tenant)):
    async with pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT id, name, db_type, host, database_name, status, last_scanned_at, created_at
            FROM connections WHERE tenant_id=$1 ORDER BY created_at DESC
        """, tenant["id"])
    return [dict(r) for r in rows]

@app.post("/connections/{conn_id}/scan")
async def rescan_connection(conn_id: str, tenant=Depends(get_tenant)):
    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT * FROM connections WHERE id=$1 AND tenant_id=$2",
                                  conn_id, tenant["id"])
    if not row:
        raise HTTPException(404, "Connection not found")

    cfg = {"db_type": row["db_type"], "host": row["host"], "port": row["port"],
           "database_name": row["database_name"], "username": row["username"],
           "password": decrypt_password(row["password_encrypted"])}
    tables = await scan_database(cfg)

    async with pool.acquire() as conn:
        for t in tables:
            await conn.execute("""
                INSERT INTO db_tables (id, connection_id, tenant_id, table_name,
                    row_count, columns, sensitive_columns)
                VALUES ($1,$2,$3,$4,$5,$6,$7)
                ON CONFLICT (connection_id, table_name) DO UPDATE
                SET row_count=$5, columns=$6, sensitive_columns=$7
            """, make_id("tbl_"), conn_id, tenant["id"], t["table_name"],
                t["row_count"], json.dumps(t["columns"]), json.dumps(t["sensitive_columns"]))
        await conn.execute("UPDATE connections SET last_scanned_at=NOW() WHERE id=$1", conn_id)

    return {"tables_found": len(tables), "tables": tables}

@app.get("/connections/{conn_id}/tables")
async def get_tables(conn_id: str, tenant=Depends(get_tenant)):
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT * FROM db_tables WHERE connection_id=$1 AND tenant_id=$2 ORDER BY table_name",
            conn_id, tenant["id"])
    return [dict(r) for r in rows]

# ── Access Rules ──────────────────────────────────────────────────────────────
@app.post("/connections/{conn_id}/rules")
async def create_rule(conn_id: str, body: AccessRuleBody, tenant=Depends(get_tenant)):
    async with pool.acquire() as conn:
        if not await conn.fetchval("SELECT id FROM connections WHERE id=$1 AND tenant_id=$2",
                                   conn_id, tenant["id"]):
            raise HTTPException(404, "Connection not found")
        rule_id = make_id("rule_")
        await conn.execute("""
            INSERT INTO access_rules (id, tenant_id, connection_id, name, role,
                table_name, allowed_operations, blocked_columns, max_rows, conditions)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
        """, rule_id, tenant["id"], conn_id, body.name, body.role, body.table_name,
            json.dumps(body.allowed_operations), json.dumps(body.blocked_columns),
            body.max_rows, json.dumps(body.conditions))
    return {"rule_id": rule_id,
            "message": f"Rule '{body.name}' — {body.role} can {body.allowed_operations} on {body.table_name}"}

@app.get("/connections/{conn_id}/rules")
async def list_rules(conn_id: str, tenant=Depends(get_tenant)):
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT * FROM access_rules WHERE connection_id=$1 AND tenant_id=$2 ORDER BY created_at DESC",
            conn_id, tenant["id"])
    return [dict(r) for r in rows]

@app.delete("/connections/{conn_id}/rules/{rule_id}")
async def delete_rule(conn_id: str, rule_id: str, tenant=Depends(get_tenant)):
    async with pool.acquire() as conn:
        await conn.execute("UPDATE access_rules SET active=false WHERE id=$1 AND tenant_id=$2",
                           rule_id, tenant["id"])
    return {"message": "Rule deactivated"}

# ── Query Check (core endpoint) ───────────────────────────────────────────────
@app.post("/check")
@limiter.limit("300/minute")
async def check_query(body: QueryCheckBody, request: Request, tenant=Depends(get_tenant)):
    start  = time.monotonic()
    log_id = make_id("log_")
    op     = body.operation.upper()
    qhash  = hash_query(body.query, {
        "connection_id": body.connection_id, "role": body.role,
        "table_name": body.table_name, "operation": op, "columns": body.columns or []})

    async with pool.acquire() as conn:
        rules = await conn.fetch("""
            SELECT * FROM access_rules
            WHERE connection_id=$1 AND tenant_id=$2 AND table_name=$3
              AND active=true AND (role=$4 OR role='*')
            ORDER BY created_at DESC
        """, body.connection_id, tenant["id"], body.table_name, body.role)

    async def _log_blocked(reason: str) -> int:
        ms = int((time.monotonic() - start) * 1000)
        async with pool.acquire() as c:
            await c.execute("""
                INSERT INTO query_logs (id, tenant_id, connection_id, role, user_identifier,
                    table_name, operation, query_hash, rows_returned, blocked, block_reason, duration_ms)
                VALUES ($1,$2,$3,$4,$5,$6,$7,$8,0,true,$9,$10)
            """, log_id, tenant["id"], body.connection_id, body.role, body.user_identifier,
                body.table_name, op, qhash, reason, ms)
        return ms

    # Deny by default — no rule found
    if not rules:
        await _log_blocked("No access rule found for this role — deny by default")
        return JSONResponse(status_code=403, content={
            "allowed": False,
            "reason": f"No access rule for role '{body.role}' on table '{body.table_name}' — deny-by-default",
            "log_id": log_id})

    rule         = dict(rules[0])
    allowed_ops  = [str(o).upper() for o in (rule["allowed_operations"] or ["SELECT"])]
    blocked_cols = rule["blocked_columns"] or []
    max_rows     = int(rule["max_rows"] or 1000)

    # Operation not allowed
    if op not in allowed_ops and "*" not in allowed_ops:
        await _log_blocked(f"Operation '{op}' not allowed — allowed: {allowed_ops}")
        return JSONResponse(status_code=403, content={
            "allowed": False,
            "reason": f"Operation '{op}' not allowed for role '{body.role}' — allowed: {allowed_ops}",
            "log_id": log_id})

    # ── Compliance enforcement ────────────────────────────────────────────────
    # Load active compliance frameworks for this connection
    async with pool.acquire() as conn:
        active_frameworks = await conn.fetch("""
            SELECT framework FROM compliance_settings
            WHERE connection_id=$1 AND enabled=true AND auto_block=true
        """, body.connection_id)

    active_fw_keys = [r["framework"] for r in active_frameworks]
    compliance_blocked_cols = set()

    if active_fw_keys and body.columns:
        for fw_key in active_fw_keys:
            fw = COMPLIANCE_FRAMEWORKS.get(fw_key, {})
            for col in body.columns:
                if any(re.search(p, col.lower()) for p in fw.get("auto_block_patterns", [])):
                    compliance_blocked_cols.add(col)

    # Merge rule-level + compliance-level blocked columns
    all_blocked = set(blocked_cols) | compliance_blocked_cols

    # Compute safe columns
    safe_columns, removed = None, []
    if body.columns:
        safe_columns = [c for c in body.columns if c not in all_blocked]
        removed      = [c for c in body.columns if c in all_blocked]

    # If compliance blocked ALL requested columns — hard deny
    if body.columns and compliance_blocked_cols and not safe_columns:
        fw_names = [COMPLIANCE_FRAMEWORKS[k]["name"] for k in active_fw_keys if k in COMPLIANCE_FRAMEWORKS]
        reason = f"All requested columns are blocked by compliance frameworks: {', '.join(fw_names)}"
        await _log_blocked(reason)
        return JSONResponse(status_code=403, content={
            "allowed": False,
            "reason": reason,
            "compliance_frameworks": active_fw_keys,
            "blocked_columns": list(compliance_blocked_cols),
            "log_id": log_id,
        })

    ms = int((time.monotonic() - start) * 1000)
    cols_accessed = body.columns or []

    async with pool.acquire() as conn:
        await conn.execute("""
            INSERT INTO query_logs (id, tenant_id, connection_id, role, user_identifier,
                table_name, operation, query_hash, columns_accessed,
                compliance_blocked, compliance_frameworks,
                rows_returned, blocked, duration_ms)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,0,false,$12)
        """, log_id, tenant["id"], body.connection_id, body.role, body.user_identifier,
            body.table_name, op, qhash,
            json.dumps(cols_accessed),
            len(compliance_blocked_cols) > 0,
            json.dumps(active_fw_keys),
            ms)

    return {"allowed": True, "rule_id": rule["id"], "rule_name": rule["name"],
            "safe_columns": safe_columns,
            "blocked_columns": list(all_blocked),
            "removed_columns": removed,
            "compliance_blocked_columns": list(compliance_blocked_cols),
            "active_compliance_frameworks": active_fw_keys,
            "max_rows": max_rows,
            "conditions": rule["conditions"] or {}, "duration_ms": ms,
            "log_id": log_id, "query_hash": qhash}

@app.post("/log-result")
async def log_query_result(body: LogResultBody, tenant=Depends(get_tenant)):
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE query_logs SET rows_returned=$1 WHERE id=$2 AND tenant_id=$3",
            body.rows_returned, body.log_id, tenant["id"])
    asyncio.create_task(check_anomalies_for_log(body.log_id, tenant["id"]))
    return {"updated": True}

# ── Audit ─────────────────────────────────────────────────────────────────────
@app.get("/audit")
async def get_audit(connection_id: Optional[str] = None, role: Optional[str] = None,
                    blocked_only: bool = False, limit: int = 50, tenant=Depends(get_tenant)):
    conds, params, i = ["tenant_id=$1"], [tenant["id"]], 2
    if connection_id:
        conds.append(f"connection_id=${i}"); params.append(connection_id); i += 1
    if role:
        conds.append(f"role=${i}"); params.append(role); i += 1
    if blocked_only:
        conds.append("blocked=true")
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            f"SELECT * FROM query_logs WHERE {' AND '.join(conds)} ORDER BY created_at DESC LIMIT {int(limit)}",
            *params)
    return [dict(r) for r in rows]

@app.get("/audit/stats")
async def audit_stats(tenant=Depends(get_tenant)):
    async with pool.acquire() as conn:
        total   = int(await conn.fetchval("SELECT COUNT(*) FROM query_logs WHERE tenant_id=$1", tenant["id"]) or 0)
        blocked = int(await conn.fetchval("SELECT COUNT(*) FROM query_logs WHERE tenant_id=$1 AND blocked=true", tenant["id"]) or 0)
        by_role  = await conn.fetch("""
            SELECT role, COUNT(*) as count,
                   SUM(CASE WHEN blocked THEN 1 ELSE 0 END) as blocked_count
            FROM query_logs WHERE tenant_id=$1 GROUP BY role ORDER BY count DESC
        """, tenant["id"])
        by_table = await conn.fetch("""
            SELECT table_name, COUNT(*) as count FROM query_logs
            WHERE tenant_id=$1 GROUP BY table_name ORDER BY count DESC LIMIT 10
        """, tenant["id"])
    return {"total_queries": total, "blocked_queries": blocked,
            "allow_rate": round((total - blocked) / max(total, 1) * 100, 1),
            "by_role": [dict(r) for r in by_role], "by_table": [dict(r) for r in by_table]}

# ── Alerts ────────────────────────────────────────────────────────────────────
@app.get("/alerts")
async def get_alerts(resolved: bool = False, tenant=Depends(get_tenant)):
    async with pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT * FROM anomaly_alerts WHERE tenant_id=$1 AND resolved=$2
            ORDER BY created_at DESC LIMIT 50
        """, tenant["id"], resolved)
    return [dict(r) for r in rows]

@app.post("/alerts/{alert_id}/resolve")
async def resolve_alert(alert_id: str, tenant=Depends(get_tenant)):
    async with pool.acquire() as conn:
        await conn.execute("UPDATE anomaly_alerts SET resolved=true WHERE id=$1 AND tenant_id=$2",
                           alert_id, tenant["id"])
    return {"resolved": True}

# ── Compliance ───────────────────────────────────────────────────────────────
@app.get("/compliance/frameworks")
async def list_frameworks():
    """List all supported compliance frameworks and what they protect."""
    return {
        fw_key: {
            "name": fw["name"],
            "description": fw["description"],
            "required_log_retention_days": fw["required_log_retention_days"],
            "violation_fields": fw["violation_fields"],
        }
        for fw_key, fw in COMPLIANCE_FRAMEWORKS.items()
    }

@app.post("/connections/{conn_id}/compliance/{framework}")
async def enable_compliance(conn_id: str, framework: str, tenant=Depends(get_tenant)):
    """Enable a compliance framework on a connection. Auto-detects violating columns."""
    if framework not in COMPLIANCE_FRAMEWORKS:
        raise HTTPException(400, f"Unknown framework '{framework}'. Supported: {SUPPORTED_FRAMEWORKS}")

    async with pool.acquire() as conn:
        if not await conn.fetchval("SELECT id FROM connections WHERE id=$1 AND tenant_id=$2",
                                   conn_id, tenant["id"]):
            raise HTTPException(404, "Connection not found")

        # Upsert compliance setting
        cs_id = make_id("cs_")
        await conn.execute("""
            INSERT INTO compliance_settings (id, tenant_id, connection_id, framework, enabled, auto_block)
            VALUES ($1,$2,$3,$4,true,true)
            ON CONFLICT (connection_id, framework) DO UPDATE SET enabled=true
        """, cs_id, tenant["id"], conn_id, framework)

        # Scan tables for violating columns
        tables = await conn.fetch(
            "SELECT table_name, columns FROM db_tables WHERE connection_id=$1 AND tenant_id=$2",
            conn_id, tenant["id"])

    fw = COMPLIANCE_FRAMEWORKS[framework]
    violations = []
    for tbl in tables:
        cols = tbl["columns"] if isinstance(tbl["columns"], list) else json.loads(tbl["columns"])
        violating = [c["name"] for c in cols
                     if any(re.search(p, c["name"].lower()) for p in fw["auto_block_patterns"])]
        if violating:
            violations.append({"table": tbl["table_name"], "columns": violating})

    return {
        "framework": framework,
        "name": fw["name"],
        "enabled": True,
        "connection_id": conn_id,
        "violations_detected": violations,
        "total_violating_tables": len(violations),
        "message": f"{fw['name']} enabled. Found {len(violations)} tables with regulated fields. Review and update your access rules to block these columns.",
        "retention_required_days": fw["required_log_retention_days"],
    }

@app.get("/connections/{conn_id}/compliance")
async def get_compliance_status(conn_id: str, tenant=Depends(get_tenant)):
    """Get compliance status for a connection — which frameworks are enabled and any violations."""
    async with pool.acquire() as conn:
        if not await conn.fetchval("SELECT id FROM connections WHERE id=$1 AND tenant_id=$2",
                                   conn_id, tenant["id"]):
            raise HTTPException(404, "Connection not found")
        settings = await conn.fetch(
            "SELECT * FROM compliance_settings WHERE connection_id=$1 AND enabled=true",
            conn_id)
        tables = await conn.fetch(
            "SELECT table_name, columns FROM db_tables WHERE connection_id=$1 AND tenant_id=$2",
            conn_id, tenant["id"])

    result = {}
    for s in settings:
        fw_key = s["framework"]
        fw = COMPLIANCE_FRAMEWORKS.get(fw_key, {})
        violations = []
        for tbl in tables:
            cols = tbl["columns"] if isinstance(tbl["columns"], list) else json.loads(tbl["columns"])
            violating = [c["name"] for c in cols
                         if any(re.search(p, c["name"].lower()) for p in fw.get("auto_block_patterns", []))]
            if violating:
                violations.append({"table": tbl["table_name"], "columns": violating})
        result[fw_key] = {
            "name": fw.get("name", fw_key),
            "enabled": True,
            "violations": violations,
            "compliant": len(violations) == 0,
        }

    return {"connection_id": conn_id, "frameworks": result,
            "overall_compliant": all(v["compliant"] for v in result.values())}

@app.delete("/connections/{conn_id}/compliance/{framework}")
async def disable_compliance(conn_id: str, framework: str, tenant=Depends(get_tenant)):
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE compliance_settings SET enabled=false WHERE connection_id=$1 AND framework=$2 AND tenant_id=$3",
            conn_id, framework, tenant["id"])
    return {"framework": framework, "enabled": False}

@app.get("/connections/{conn_id}/compliance/report/{framework}")
async def compliance_report(conn_id: str, framework: str,
                             days: int = 30, tenant=Depends(get_tenant)):
    """
    Generate a compliance audit report for a framework.
    Returns structured data — your frontend renders it as PDF/CSV.
    """
    if framework not in COMPLIANCE_FRAMEWORKS:
        raise HTTPException(400, f"Unknown framework '{framework}'")

    fw = COMPLIANCE_FRAMEWORKS[framework]
    async with pool.acquire() as conn:
        if not await conn.fetchval("SELECT id FROM connections WHERE id=$1 AND tenant_id=$2",
                                   conn_id, tenant["id"]):
            raise HTTPException(404, "Connection not found")

        # All queries in period
        logs = await conn.fetch("""
            SELECT * FROM query_logs
            WHERE tenant_id=$1 AND connection_id=$2
              AND created_at > NOW() - ($3 || ' days')::INTERVAL
            ORDER BY created_at DESC
        """, tenant["id"], conn_id, str(days))

        # Blocked queries
        blocked_logs = [l for l in logs if l["blocked"]]

        # Alerts in period
        alerts = await conn.fetch("""
            SELECT * FROM anomaly_alerts
            WHERE tenant_id=$1 AND connection_id=$2
              AND created_at > NOW() - ($3 || ' days')::INTERVAL
            ORDER BY created_at DESC
        """, tenant["id"], conn_id, str(days))

        # Violation queries — logs touching regulated columns
        fw_patterns = fw["auto_block_patterns"]
        # Match against actual columns_accessed in the log (not table name)
        violation_logs = []
        for l in logs:
            cols = l["columns_accessed"] if isinstance(l["columns_accessed"], list)                    else (json.loads(l["columns_accessed"]) if l["columns_accessed"] else [])
            if any(any(re.search(p, c.lower()) for p in fw_patterns) for c in cols):
                violation_logs.append(l)

        # Unique roles that accessed data
        roles = list(set(l["role"] for l in logs if l["role"]))
        users = list(set(l["user_identifier"] for l in logs if l["user_identifier"]))

    return {
        "report": {
            "framework": framework,
            "framework_name": fw["name"],
            "connection_id": conn_id,
            "period_days": days,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "tenant_id": tenant["id"],
        },
        "summary": {
            "total_queries": len(logs),
            "blocked_queries": len(blocked_logs),
            "violation_queries": len(violation_logs),
            "anomaly_alerts": len(alerts),
            "unique_roles": roles,
            "unique_users": users,
            "compliant": len(violation_logs) == 0 and len(alerts) == 0,
        },
        "violations": [
            {"time": str(l["created_at"]), "role": l["role"],
             "user": l["user_identifier"], "table": l["table_name"],
             "operation": l["operation"], "blocked": l["blocked"],
             "reason": l["block_reason"]}
            for l in violation_logs[:100]
        ],
        "anomalies": [
            {"time": str(a["created_at"]), "type": a["alert_type"],
             "severity": a["severity"], "message": a["message"]}
            for a in alerts
        ],
        "retention_requirement": f"{fw['required_log_retention_days']} days ({fw['required_log_retention_days']//365} years)",
        "note": f"This report covers {days} days. {fw['name']} requires {fw['required_log_retention_days']} days of log retention.",
    }

@app.get("/connections/{conn_id}/compliance/scan/{framework}")
async def scan_for_violations(conn_id: str, framework: str, tenant=Depends(get_tenant)):
    """Scan all tables and return every column that violates this framework."""
    if framework not in COMPLIANCE_FRAMEWORKS:
        raise HTTPException(400, f"Unknown framework '{framework}'")
    fw = COMPLIANCE_FRAMEWORKS[framework]

    async with pool.acquire() as conn:
        tables = await conn.fetch(
            "SELECT table_name, columns FROM db_tables WHERE connection_id=$1 AND tenant_id=$2",
            conn_id, tenant["id"])

    violations = []
    for tbl in tables:
        cols = tbl["columns"] if isinstance(tbl["columns"], list) else json.loads(tbl["columns"])
        for c in cols:
            matching = [p for p in fw["auto_block_patterns"]
                        if re.search(p, c["name"].lower())]
            if matching:
                violations.append({
                    "table": tbl["table_name"],
                    "column": c["name"],
                    "column_type": c.get("type", "unknown"),
                    "matched_patterns": matching,
                    "recommendation": f"Add '{c['name']}' to blocked_columns in your access rule for table '{tbl['table_name']}'"
                })

    return {
        "framework": framework,
        "name": fw["name"],
        "total_violations": len(violations),
        "violations": violations,
        "compliant": len(violations) == 0,
    }

# ── Admin ─────────────────────────────────────────────────────────────────────
@app.get("/admin/tenants")
async def admin_tenants(x_api_key: str = Header(...)):
    if x_api_key != ADMIN_API_KEY:
        raise HTTPException(401, "Admin only")
    async with pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT t.id, t.name, t.email, t.plan, t.created_at,
                   COALESCE(t.api_call_count,0) as api_call_count, t.last_seen_at,
                   COUNT(DISTINCT c.id) as connection_count,
                   COUNT(DISTINCT ql.id) as query_count
            FROM tenants t
            LEFT JOIN connections c ON c.tenant_id=t.id
            LEFT JOIN query_logs ql ON ql.tenant_id=t.id
            GROUP BY t.id ORDER BY t.created_at DESC
        """)
    return [dict(r) for r in rows]
