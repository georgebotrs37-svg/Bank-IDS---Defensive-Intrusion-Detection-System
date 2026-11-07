import uuid
from datetime import datetime
from typing import List, Optional, Dict, Any
from sqlalchemy.orm import Session
from backend.models import (
    Incident, IncidentTimeline, IncidentNote, Alert,
    IncidentStatusEnum, EscalationLevelEnum, SeverityEnum
)


class IncidentManager:
    """
    Manages Security Incidents, Investigation Workflows, Analyst Notes,
    Audit Timelines, and Tier Escalations (L1 -> L2 -> L3) for MR.X BANK SOC SENTINEL.
    """
    def __init__(self, db: Session):
        self.db = db

    def create_incident(
        self,
        title: str,
        description: str,
        severity: str = SeverityEnum.HIGH.value,
        assigned_to: str = "Alex Rivera (L1 SOC Analyst)",
        escalation_level: str = EscalationLevelEnum.L1_TRIAGE.value,
        alert_ids: Optional[List[int]] = None,
        creator: str = "Alex Rivera (L1 SOC Analyst)"
    ) -> Incident:
        incident_uuid = f"INC-{datetime.utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"

        incident = Incident(
            incident_uuid=incident_uuid,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
            title=title,
            description=description,
            severity=severity,
            status=IncidentStatusEnum.OPEN.value,
            escalation_level=escalation_level,
            assigned_to=assigned_to
        )
        self.db.add(incident)
        self.db.flush()

        # Link requested alerts to this incident
        linked_alert_uuids = []
        if alert_ids:
            alerts = self.db.query(Alert).filter(Alert.id.in_(alert_ids)).all()
            for alert in alerts:
                alert.incident_id = incident.id
                alert.status = "INVESTIGATING"
                linked_alert_uuids.append(alert.alert_uuid)

        # Create initial audit timeline event
        timeline_entry = IncidentTimeline(
            incident_id=incident.id,
            timestamp=datetime.utcnow(),
            actor=creator,
            action="INCIDENT_CREATED",
            details=f"Incident {incident_uuid} formally opened with severity {severity}. Linked {len(linked_alert_uuids)} alert(s): {', '.join(linked_alert_uuids) if linked_alert_uuids else 'None'}."
        )
        self.db.add(timeline_entry)
        self.db.commit()
        self.db.refresh(incident)
        return incident

    def update_status(
        self,
        incident_id: int,
        new_status: str,
        analyst_name: str,
        notes: Optional[str] = None
    ) -> Incident:
        incident = self.db.query(Incident).filter(Incident.id == incident_id).first()
        if not incident:
            raise ValueError(f"Incident with ID {incident_id} not found.")

        old_status = incident.status
        incident.status = new_status
        incident.updated_at = datetime.utcnow()

        timeline_event = IncidentTimeline(
            incident_id=incident.id,
            timestamp=datetime.utcnow(),
            actor=analyst_name,
            action="STATUS_CHANGED",
            details=f"Status transitioned from [{old_status}] to [{new_status}]. Note: {notes or 'No specific note provided.'}"
        )
        self.db.add(timeline_event)

        if notes:
            note_obj = IncidentNote(
                incident_id=incident.id,
                timestamp=datetime.utcnow(),
                analyst_name=analyst_name,
                content=notes
            )
            self.db.add(note_obj)

        self.db.commit()
        self.db.refresh(incident)
        return incident

    def escalate(
        self,
        incident_id: int,
        target_level: str,
        assigned_to: str,
        analyst_name: str,
        reason: str
    ) -> Incident:
        incident = self.db.query(Incident).filter(Incident.id == incident_id).first()
        if not incident:
            raise ValueError(f"Incident with ID {incident_id} not found.")

        old_level = incident.escalation_level
        incident.escalation_level = target_level
        incident.assigned_to = assigned_to
        incident.updated_at = datetime.utcnow()

        timeline_event = IncidentTimeline(
            incident_id=incident.id,
            timestamp=datetime.utcnow(),
            actor=analyst_name,
            action="INCIDENT_ESCALATED",
            details=f"Escalated from [{old_level}] to [{target_level}] and reassigned to [{assigned_to}]. Justification: {reason}"
        )
        self.db.add(timeline_event)
        self.db.commit()
        self.db.refresh(incident)
        return incident

    def add_note(self, incident_id: int, analyst_name: str, content: str) -> IncidentNote:
        incident = self.db.query(Incident).filter(Incident.id == incident_id).first()
        if not incident:
            raise ValueError(f"Incident with ID {incident_id} not found.")

        note = IncidentNote(
            incident_id=incident.id,
            timestamp=datetime.utcnow(),
            analyst_name=analyst_name,
            content=content
        )
        self.db.add(note)

        timeline_event = IncidentTimeline(
            incident_id=incident.id,
            timestamp=datetime.utcnow(),
            actor=analyst_name,
            action="NOTE_ADDED",
            details=f"Analyst note added: '{content[:80]}...'"
        )
        self.db.add(timeline_event)
        self.db.commit()
        self.db.refresh(note)
        return note

    def execute_containment_action(
        self,
        incident_id: int,
        action_name: str,
        details: str,
        analyst_name: str
    ) -> Incident:
        incident = self.db.query(Incident).filter(Incident.id == incident_id).first()
        if not incident:
            raise ValueError(f"Incident with ID {incident_id} not found.")

        existing_actions = incident.containment_actions or ""
        timestamp_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        updated_actions = f"{existing_actions}\n[{timestamp_str}] ({action_name}) - {details} (By: {analyst_name})".strip()
        incident.containment_actions = updated_actions
        incident.updated_at = datetime.utcnow()

        timeline_event = IncidentTimeline(
            incident_id=incident.id,
            timestamp=datetime.utcnow(),
            actor=analyst_name,
            action="CONTAINMENT_EXECUTED",
            details=f"Defensive containment applied: [{action_name}] - {details}"
        )
        self.db.add(timeline_event)
        self.db.commit()
        self.db.refresh(incident)
        return incident

