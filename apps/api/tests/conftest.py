from __future__ import annotations

pytest_plugins = ["tests.neo4j_fixtures"]

import asyncio
import sys
from pathlib import Path
from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import adbygod_api.config as config
import adbygod_api.database as database
import adbygod_api.main as main
import adbygod_api.models as models
from adbygod_api.routes import auth as auth_routes
from adbygod_api.routes import collection as collection_routes
from adbygod_api.routes import import_data as import_routes
from adbygod_api.routes import ingest as ingest_routes


class TestDataFactory:
    def __init__(self, session_maker: async_sessionmaker[AsyncSession]):
        self.session_maker = session_maker

    def run(self, coro):
        return asyncio.run(coro)

    async def create_user(
        self,
        username: str,
        email: str,
        password: str = "password123!",
        *,
        is_superadmin: bool = False,
        is_active: bool = True,
    ) -> models.PlatformUser:
        async with self.session_maker() as db:
            user = models.PlatformUser(
                username=username,
                email=email,
                hashed_password=auth_routes.pwd_context.hash(password),
                is_superadmin=is_superadmin,
                is_active=is_active,
            )
            db.add(user)
            await db.commit()
            await db.refresh(user)
            return user

    async def create_workspace(self, name: str) -> models.Workspace:
        async with self.session_maker() as db:
            workspace = models.Workspace(name=name)
            db.add(workspace)
            await db.commit()
            await db.refresh(workspace)
            return workspace

    async def add_workspace_user(self, workspace_id: UUID, user_id: UUID, role: str = "analyst") -> models.WorkspaceUser:
        async with self.session_maker() as db:
            workspace_user = models.WorkspaceUser(workspace_id=workspace_id, user_id=user_id, role=role)
            db.add(workspace_user)
            await db.commit()
            await db.refresh(workspace_user)
            return workspace_user

    async def create_assessment(
        self,
        name: str,
        domain: str,
        *,
        workspace_id: UUID | None,
        created_by: UUID | None = None,
        status: models.AssessmentStatus = models.AssessmentStatus.PENDING,
        exposure_score: float = 0.0,
    ) -> models.Assessment:
        async with self.session_maker() as db:
            assessment = models.Assessment(
                name=name,
                domain=domain,
                workspace_id=workspace_id,
                created_by=created_by,
                status=status,
                exposure_score=exposure_score,
                modules_run=[],
                stats={},
            )
            db.add(assessment)
            await db.commit()
            await db.refresh(assessment)
            return assessment

    async def create_entity(
        self,
        assessment_id: UUID,
        *,
        entity_type: models.EntityType,
        sam_account_name: str,
        tier: int | None = None,
        is_crown_jewel: bool = False,
    ) -> models.Entity:
        async with self.session_maker() as db:
            entity = models.Entity(
                assessment_id=assessment_id,
                entity_type=entity_type,
                sam_account_name=sam_account_name,
                display_name=sam_account_name,
                is_enabled=True,
                is_admin_count=tier == 0,
                is_sensitive=False,
                is_protected_user=False,
                tier=tier,
                is_crown_jewel=is_crown_jewel,
                business_tags=[],
                attributes={},
            )
            db.add(entity)
            await db.commit()
            await db.refresh(entity)
            return entity

    async def create_edge(
        self,
        assessment_id: UUID,
        source_id: UUID,
        target_id: UUID,
        *,
        edge_type: models.EdgeType = models.EdgeType.MEMBER_OF,
        risk_weight: float = 0.9,
    ) -> models.GraphEdge:
        async with self.session_maker() as db:
            edge = models.GraphEdge(
                assessment_id=assessment_id,
                source_id=source_id,
                target_id=target_id,
                edge_type=edge_type,
                risk_weight=risk_weight,
                attributes={},
            )
            db.add(edge)
            await db.commit()
            await db.refresh(edge)
            return edge

    async def create_finding(
        self,
        assessment_id: UUID,
        *,
        title: str,
        module: str = "Kerberos",
        severity: models.SeverityLevel = models.SeverityLevel.HIGH,
        composite_score: float = 75.0,
    ) -> models.Finding:
        async with self.session_maker() as db:
            finding = models.Finding(
                assessment_id=assessment_id,
                finding_type=title.upper().replace(" ", "_"),
                module=module,
                title=title,
                severity=severity,
                confidence=1.0,
                composite_score=composite_score,
                affected_count=1,
                affected_objects=[],
                causal_chain=[],
                remediation_steps=[],
                references=[],
                status=models.FindingStatus.OPEN,
            )
            db.add(finding)
            await db.commit()
            await db.refresh(finding)
            return finding

    async def get_assessment(self, assessment_id: UUID) -> models.Assessment | None:
        async with self.session_maker() as db:
            return await db.get(models.Assessment, assessment_id)

    async def get_findings(self, assessment_id: UUID) -> list[models.Finding]:
        async with self.session_maker() as db:
            result = await db.execute(
                select(models.Finding).where(models.Finding.assessment_id == assessment_id)
            )
            return result.scalars().all()


@pytest.fixture()
def test_app(tmp_path, monkeypatch):
    config.settings.SECRET_KEY = "test-secret-key-with-sufficient-length-1234567890"
    config.settings.DEBUG = True
    config.settings.AUTH_COOKIE_SECURE = False
    config.settings.ALLOW_DEV_BOOTSTRAP = False
    config.settings.STRICT_COOKIE_ORIGIN_CHECK = True
    config.settings.LOGIN_RATE_LIMIT_ATTEMPTS = 5
    config.settings.LOGIN_RATE_LIMIT_WINDOW_SECONDS = 300
    config.settings.ENABLE_COMMAND_EXECUTION = False
    config.settings.ENABLE_CHAIN_BUILDER = True
    config.settings.COMMAND_EXECUTION_ALLOWLIST = ""
    config.settings.ENABLE_PUBLIC_ASSESSMENT_SUMMARY = False
    auth_routes.settings.SECRET_KEY = config.settings.SECRET_KEY
    auth_routes.settings.DEBUG = True
    auth_routes.settings.AUTH_COOKIE_SECURE = False
    auth_routes.settings.ALLOW_DEV_BOOTSTRAP = False
    auth_routes.settings.STRICT_COOKIE_ORIGIN_CHECK = True
    auth_routes.settings.LOGIN_RATE_LIMIT_ATTEMPTS = 5
    auth_routes.settings.LOGIN_RATE_LIMIT_WINDOW_SECONDS = 300
    auth_routes._LOGIN_ATTEMPTS.clear()

    db_path = tmp_path / "test.db"
    engine = create_async_engine(f"sqlite+aiosqlite:///{db_path}", future=True)
    session_maker = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async def _setup():
        async with engine.begin() as conn:
            await conn.run_sync(models.Base.metadata.create_all)

    asyncio.run(_setup())

    async def override_get_db():
        async with session_maker() as session:
            yield session

    monkeypatch.setattr(database, "AsyncSessionLocal", session_maker)
    monkeypatch.setattr(ingest_routes, "AsyncSessionLocal", session_maker, raising=False)
    monkeypatch.setattr(import_routes, "AsyncSessionLocal", session_maker, raising=False)
    monkeypatch.setattr(collection_routes, "AsyncSessionLocal", session_maker, raising=False)
    monkeypatch.setattr(auth_routes, "AsyncSessionLocal", session_maker, raising=False)
    monkeypatch.setattr(main, "AsyncSessionLocal", session_maker, raising=False)

    main.app.dependency_overrides[database.get_db] = override_get_db
    client = TestClient(main.app)
    factory = TestDataFactory(session_maker)

    def make_headers(user: models.PlatformUser) -> dict[str, str]:
        token = auth_routes._create_access_token(user)
        return {"Authorization": f"Bearer {token}"}

    yield {
        "client": client,
        "db": factory,
        "headers_for": make_headers,
        "session_maker": session_maker,
    }

    main.app.dependency_overrides.clear()
    auth_routes._LOGIN_ATTEMPTS.clear()
    client.close()
    asyncio.run(engine.dispose())
