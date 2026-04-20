"""
analysis/entity_relationship_mapper.py
Entity Relationship Mapping — Intelligent cross-referencing

Creates relationship graphs:
- Person ↔ Company (founder, CEO, employee, investor)
- Company ↔ Domain
- Person ↔ Social Media Accounts
- Company ↔ Team Members
- Domain ↔ IP/Infrastructure
"""

import logging
from typing import List, Dict, Any, Set
from collections import defaultdict

logger = logging.getLogger(__name__)


class EntityRelationship:
    """Represents a single relationship between entities."""
    
    def __init__(self, entity_a: str, relationship_type: str, entity_b: str, confidence: float, source: str):
        self.entity_a = entity_a
        self.relationship_type = relationship_type  # e.g., "founder_of", "ceo_of", "owns_domain"
        self.entity_b = entity_b
        self.confidence = confidence  # 0-100
        self.source = source
    
    def __repr__(self):
        return f"{self.entity_a} --[{self.relationship_type} ({self.confidence}%)]→ {self.entity_b}"


class EntityRelationshipMapper:
    """
    Builds intelligent relationship graphs from findings.
    Maps person ↔ organizations ↔ domains ↔ infrastructure.
    """
    
    def __init__(self, target_entity: str, entity_type: str):
        self.target_entity = target_entity
        self.entity_type = entity_type
        self.relationships: List[EntityRelationship] = []
        self.entities: Set[str] = {target_entity}  # All discovered entities
    
    def build_graph(self, findings: List[Dict]) -> Dict[str, Any]:
        """
        Process findings and extract relationships.
        
        Returns:
        {
            "entities": set of all discovered entities,
            "relationships": list of EntityRelationship objects,
            "clusters": { primary_entity: [related_entities] },
            "confidence_scores": { entity: avg_confidence },
        }
        """
        logger.info("🔗 Building entity relationship graph for: %s", self.target_entity)
        
        # Extract relationships from findings
        for finding in findings:
            self._extract_relationships_from_finding(finding)
        
        # Build confidence map
        confidence_map = self._calculate_confidence_scores()
        
        # Build entity clusters
        clusters = self._build_clusters()
        
        logger.info("✓ Graph complete: %d entities, %d relationships", 
                   len(self.entities), len(self.relationships))
        
        return {
            "target_entity": self.target_entity,
            "entities": self.entities,
            "relationships": self.relationships,
            "clusters": clusters,
            "confidence_scores": confidence_map,
        }
    
    def _extract_relationships_from_finding(self, finding: Dict):
        """
        Parse findings to extract structured relationships.
        Examines title, value, adapter type, and confidence.
        """
        title = finding.get("title", "").lower()
        value = finding.get("value", {})
        adapter = finding.get("adapter", "")
        confidence = finding.get("confidence_score", 50)
        
        # Person Verification findings
        if adapter == "person_verification":
            if "linkedin" in title and value.get("found"):
                company = value.get("company", "")
                if company:
                    self._add_relationship(
                        self.target_entity, "employed_at", company, 
                        confidence=80, source="LinkedIn"
                    )
            
            if "crunchbase" in title:
                for affiliation in value.get("affiliations", []):
                    role = affiliation.get("role", "")
                    company = affiliation.get("company", "")
                    if company:
                        rel_type = self._infer_relationship_type(role)
                        self._add_relationship(
                            self.target_entity, rel_type, company,
                            confidence=85, source="Crunchbase"
                        )
        
        # Company Discovery findings
        elif adapter == "company_discovery":
            if "company affiliation" in title:
                company = value.get("company_name", "")
                if company and company != "(Check LinkedIn profile for company information)":
                    self._add_relationship(
                        self.target_entity, "affiliated_with", company,
                        confidence=80, source="LinkedIn Company Discovery"
                    )
        
        # Website Verification findings
        elif adapter == "website_verification":
            if "domain verified" in title:
                domain = value.get("domain", "")
                if value.get("match_confidence", 0) > 60:
                    self._add_relationship(
                        self.target_entity, "owns_domain", domain,
                        confidence=value.get("match_confidence", 70),
                        source="WHOIS"
                    )
            
            if "dns configuration" in title:
                domain = value.get("domain", "")
                registrant = value.get("registrant_org", "")
                if registrant:
                    self._add_relationship(
                        domain, "registered_to", registrant,
                        confidence=75, source="WHOIS/DNS"
                    )
        
        # Google Dorking findings
        elif adapter == "google_dork":
            url = value.get("url", "")
            if url:
                domain = self._extract_domain(url)
                if domain and domain != self.target_entity:
                    self._add_relationship(
                        self.target_entity, "mentioned_on", domain,
                        confidence=40, source="Google Dork"
                    )
        
        # GitHub findings
        elif adapter == "github":
            if value.get("org_name"):
                org = value.get("org_name")
                self._add_relationship(
                    self.target_entity, "github_org_owner", org,
                    confidence=90, source="GitHub"
                )
            if value.get("repos"):
                for repo in value.get("repos", []):
                    self._add_relationship(
                        self.target_entity, "created_repo", repo,
                        confidence=85, source="GitHub"
                    )
        
        # Company Intel findings
        elif adapter == "company_intel":
            if value.get("founders"):
                for founder in value.get("founders", []):
                    self._add_relationship(
                        founder, "founder_of", self.target_entity,
                        confidence=90, source="Company Registry"
                    )
    
    def _add_relationship(self, entity_a: str, rel_type: str, entity_b: str, 
                         confidence: float, source: str):
        """Add a relationship and update entity set."""
        rel = EntityRelationship(entity_a, rel_type, entity_b, confidence, source)
        self.relationships.append(rel)
        
        # Add entities to set
        self.entities.add(entity_a)
        self.entities.add(entity_b)
        
        logger.debug("  Added relationship: %s", rel)
    
    def _infer_relationship_type(self, role: str) -> str:
        """Infer relationship type from job role."""
        role_lower = role.lower()
        
        if "founder" in role_lower or "co-founder" in role_lower or "co founder" in role_lower:
            return "founder_of"
        elif "ceo" in role_lower or "chief executive" in role_lower:
            return "ceo_of"
        elif "cto" in role_lower or "chief technology" in role_lower:
            return "cto_of"
        elif "cfo" in role_lower or "chief financial" in role_lower:
            return "cfo_of"
        elif "president" in role_lower:
            return "president_of"
        elif "board" in role_lower or "director" in role_lower:
            return "board_member_of"
        elif "investor" in role_lower or "venture partner" in role_lower or "vc" in role_lower:
            return "investor_in"
        elif "employee" in role_lower or "staff" in role_lower:
            return "employed_at"
        elif "contractor" in role_lower or "consultant" in role_lower:
            return "consultant_at"
        else:
            return "affiliated_with"
    
    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL."""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            domain = parsed.netloc or parsed.path
            return domain.split("/")[0]  # Remove path
        except:
            return url
    
    def _calculate_confidence_scores(self) -> Dict[str, float]:
        """Calculate average confidence for each entity based on relationships."""
        confidence_map = defaultdict(list)
        
        for rel in self.relationships:
            confidence_map[rel.entity_a].append(rel.confidence)
            confidence_map[rel.entity_b].append(rel.confidence)
        
        # Calculate averages
        return {
            entity: sum(scores) / len(scores) 
            for entity, scores in confidence_map.items()
        }
    
    def _build_clusters(self) -> Dict[str, List[str]]:
        """
        Group related entities into clusters.
        Primary cluster: all entities directly related to target.
        Secondary clusters: entities related to primary entities.
        """
        clusters = {self.target_entity: []}
        
        # Primary cluster: directly related to target
        for rel in self.relationships:
            if rel.entity_a == self.target_entity:
                clusters[self.target_entity].append(rel.entity_b)
            elif rel.entity_b == self.target_entity:
                clusters[self.target_entity].append(rel.entity_a)
        
        # Secondary clusters: related to primary entities
        for entity in list(clusters[self.target_entity]):
            related = []
            for rel in self.relationships:
                if rel.entity_a == entity and rel.entity_b != self.target_entity:
                    related.append(rel.entity_b)
                elif rel.entity_b == entity and rel.entity_a != self.target_entity:
                    related.append(rel.entity_a)
            if related:
                clusters[entity] = related
        
        return clusters
    
    def get_summary(self) -> str:
        """Generate human-readable summary of relationships."""
        lines = [
            f"\n📊 ENTITY RELATIONSHIP ANALYSIS: {self.target_entity}",
            f"Total Entities Discovered: {len(self.entities)}",
            f"Total Relationships: {len(self.relationships)}",
            "\n🔗 RELATIONSHIPS:",
        ]
        
        # Group by relationship type
        by_type = defaultdict(list)
        for rel in self.relationships:
            by_type[rel.relationship_type].append(rel)
        
        for rel_type, rels in sorted(by_type.items()):
            lines.append(f"\n  {rel_type.upper().replace('_', ' ')}:")
            for rel in sorted(rels, key=lambda r: r.confidence, reverse=True):
                lines.append(f"    • {rel.entity_a} → {rel.entity_b} ({rel.confidence}%)")
        
        return "\n".join(lines)
