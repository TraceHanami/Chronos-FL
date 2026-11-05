"""
Research Module: Neo4j Graph Database Driver.

Exports evidence causality graph nodes and edges to Neo4j graph database.
"""

from __future__ import annotations
from typing import Dict, Any, List, Optional
from chronos.shared.logging import get_logger
from chronos.config.settings import get_settings

logger = get_logger("chronos.graph.neo4j")


class Neo4jGraphExporter:
    """Exports forensic causality multigraph to Neo4j database."""

    def __init__(self):
        settings = get_settings()
        self.uri = getattr(settings, "NEO4J_URI", "bolt://localhost:7687")
        self.user = getattr(settings, "NEO4J_USER", "neo4j")
        self.password = getattr(settings, "NEO4J_PASSWORD", "chronos_secret")
        self.driver = None

        try:
            from neo4j import GraphDatabase
            self.driver = GraphDatabase.driver(self.uri, auth=(self.user, self.password))
        except Exception as e:
            logger.info(f"Neo4j driver not connected (running in local NetworkX mode): {e}")

    def export_graph(self, graph_dict: Dict[str, Any]) -> bool:
        if not self.driver:
            return False

        nodes = graph_dict.get("nodes", [])
        edges = graph_dict.get("edges", [])

        try:
            with self.driver.session() as session:
                for node in nodes:
                    n_type = node.get("type", "Entity")
                    label = node.get("label", node.get("id"))
                    session.run(
                        f"MERGE (n:{n_type} {{id: $id}}) SET n.label = $label, n.risk = $risk",
                        id=node.get("id"),
                        label=label,
                        risk=node.get("risk", 0.0),
                    )

                for edge in edges:
                    rel = edge.get("relation", "CONNECTED_TO").upper().replace("-", "_")
                    session.run(
                        f"MATCH (src {{id: $src_id}}), (tgt {{id: $tgt_id}}) "
                        f"MERGE (src)-[r:{rel}]->(tgt)",
                        src_id=edge.get("source"),
                        tgt_id=edge.get("target"),
                    )
            logger.info(f"Exported {len(nodes)} nodes and {len(edges)} edges to Neo4j.")
            return True
        except Exception as e:
            logger.warning(f"Neo4j export exception: {e}")
            return False

    def close(self):
        if self.driver:
            self.driver.close()
