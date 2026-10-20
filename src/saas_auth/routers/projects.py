"""Demo tenant-scoped resource. Every query filters on ctx.org.id; ids alone never grant access."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Project
from ..rbac import TenantContext, require
from ..schemas import MessageOut, ProjectCreate, ProjectOut, ProjectUpdate

router = APIRouter(prefix="/v1/orgs/{org_id}/projects", tags=["projects"])


def _get_project(db: Session, org_id: str, project_id: str) -> Project:
    project = db.scalar(select(Project).where(Project.id == project_id, Project.org_id == org_id))
    if project is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Project not found")
    return project


@router.post("", response_model=ProjectOut, status_code=status.HTTP_201_CREATED)
def create_project(
    payload: ProjectCreate,
    ctx: TenantContext = Depends(require("projects:create")),
    db: Session = Depends(get_db),
) -> Project:
    project = Project(
        org_id=ctx.org.id,
        name=payload.name.strip(),
        description=payload.description,
        created_by=ctx.actor_id,
    )
    db.add(project)
    db.commit()
    return project


@router.get("", response_model=list[ProjectOut])
def list_projects(
    ctx: TenantContext = Depends(require("projects:read")),
    db: Session = Depends(get_db),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> list[Project]:
    return list(
        db.scalars(
            select(Project)
            .where(Project.org_id == ctx.org.id)
            .order_by(Project.created_at)
            .limit(limit)
            .offset(offset)
        )
    )


@router.get("/{project_id}", response_model=ProjectOut)
def get_project(
    project_id: str,
    ctx: TenantContext = Depends(require("projects:read")),
    db: Session = Depends(get_db),
) -> Project:
    return _get_project(db, ctx.org.id, project_id)


@router.patch("/{project_id}", response_model=ProjectOut)
def update_project(
    project_id: str,
    payload: ProjectUpdate,
    ctx: TenantContext = Depends(require("projects:update")),
    db: Session = Depends(get_db),
) -> Project:
    project = _get_project(db, ctx.org.id, project_id)
    if payload.name is not None:
        project.name = payload.name.strip()
    if payload.description is not None:
        project.description = payload.description
    db.commit()
    return project


@router.delete("/{project_id}", response_model=MessageOut)
def delete_project(
    project_id: str,
    ctx: TenantContext = Depends(require("projects:delete")),
    db: Session = Depends(get_db),
) -> MessageOut:
    project = _get_project(db, ctx.org.id, project_id)
    db.delete(project)
    db.commit()
    return MessageOut(message="Project deleted")
