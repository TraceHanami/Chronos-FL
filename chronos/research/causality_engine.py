from __future__ import annotations
from typing import Dict, Any, List, Optional
import networkx as nx
from chronos.shared.models import Event, EventType
from chronos.graph.neo4j_driver import Neo4jGraphExporter


class CausalityEngine:
    def __init__(self, host_id: str = "victim_host_01"):
        self.host_id = host_id
        self.g = nx.MultiDiGraph()
        self.neo4j_exporter = Neo4jGraphExporter()

    def ingest_event(self, evt: Event) -> None:
        user_node = f"user:{evt.user}"
        proc_node = f"proc:{evt.pid}:{evt.comm}"
        evt_node = f"evidence:{evt.event_id}"

        if not self.g.has_node(user_node):
            self.g.add_node(user_node, type="User", label=evt.user, uid=evt.uid, risk=0.0)

        if not self.g.has_node(proc_node):
            self.g.add_node(
                proc_node,
                type="Process",
                pid=evt.pid,
                ppid=evt.ppid,
                comm=evt.comm,
                cmdline=evt.cmdline,
                label=f"{evt.comm} (PID: {evt.pid})",
                risk=0.0,
            )

        if not self.g.has_node(evt_node):
            self.g.add_node(
                evt_node,
                type="Evidence",
                event_id=evt.event_id,
                event_type=evt.event_type,
                label=f"Evt:{evt.event_type}:{evt.event_id[:6]}",
                hash=evt.evidence_hash or "",
            )

        if not self.g.has_edge(user_node, proc_node):
            self.g.add_edge(user_node, proc_node, relation="authenticated")

        for node, data in self.g.nodes(data=True):
            if data.get("type") == "Process" and data.get("pid") == evt.ppid and node != proc_node:
                if not self.g.has_edge(node, proc_node):
                    self.g.add_edge(node, proc_node, relation="spawned")

        self.g.add_edge(proc_node, evt_node, relation="executed")

        if evt.target_path:
            file_node = f"file:{evt.target_path}"
            if not self.g.has_node(file_node):
                self.g.add_node(file_node, type="File", path=evt.target_path, label=evt.target_path, risk=0.0)

            rel = "modified"
            e_type = str(evt.event_type).lower()
            if any(k in e_type for k in ["file_create", "create"]):
                rel = "created"
            elif any(k in e_type for k in ["file_delete", "delete", "unlink"]):
                rel = "deleted"
            elif any(k in e_type for k in ["modify", "write"]):
                rel = "modified"

            self.g.add_edge(proc_node, file_node, relation=rel)

        if evt.target_ip:
            net_node = f"net:{evt.target_ip}:{evt.target_port or 0}"
            if not self.g.has_node(net_node):
                self.g.add_node(
                    net_node,
                    type="IP",
                    ip=evt.target_ip,
                    port=evt.target_port,
                    label=f"{evt.target_ip}:{evt.target_port or '*'}",
                    risk=0.0,
                )

            rel = "connected_to"
            e_type = str(evt.event_type).lower()
            if "bind" in e_type:
                rel = "bound_to"

            self.g.add_edge(proc_node, net_node, relation=rel)

        if "service" in evt.comm or "systemd" in evt.comm or "service" in str(evt.event_type):
            svc_node = f"service:{evt.comm}"
            if not self.g.has_node(svc_node):
                self.g.add_node(svc_node, type="Service", label=evt.comm)
            rel = "started" if "start" in str(evt.event_type) else "stopped"
            self.g.add_edge(proc_node, svc_node, relation=rel)

        if evt.metadata and evt.metadata.get("container_id"):
            c_id = evt.metadata["container_id"]
            cnt_node = f"container:{c_id}"
            if not self.g.has_node(cnt_node):
                self.g.add_node(cnt_node, type="Container", container_id=c_id, label=f"Container:{c_id[:8]}")
            self.g.add_edge(cnt_node, proc_node, relation="spawned")

    def ingest_events(self, events: List[Event]) -> None:
        for evt in events:
            self.ingest_event(evt)

    def export_to_neo4j(self) -> bool:
        return self.neo4j_exporter.export_graph(self.to_dict())

    def get_causality_chain(self, target_pid: int) -> List[str]:
        target_node = None
        for node, data in self.g.nodes(data=True):
            if data.get("type") == "Process" and data.get("pid") == target_pid:
                target_node = node
                break

        if not target_node:
            return []

        paths = []
        for user_node in [n for n, d in self.g.nodes(data=True) if d.get("type") == "User"]:
            try:
                path = nx.shortest_path(self.g, source=user_node, target=target_node)
                paths.append(path)
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                continue

        if not paths:
            return [target_node]

        longest_path = max(paths, key=len)
        return [self.g.nodes[node].get("label", node) for node in longest_path]

    def render_ascii_graph(self) -> str:
        lines = [
            "Forensic Evidence Causality Graph:",
            "=========================================================================="
        ]

        for u_node, u_data in self.g.nodes(data=True):
            if u_data.get("type") == "User":
                lines.append(f"User [{u_data.get('label')}]")
                for _, child, edata in self.g.out_edges(u_node, data=True):
                    c_data = self.g.nodes[child]
                    lines.append(f"  └── ({edata.get('relation', 'authenticated')}) ──► {c_data.get('label')}")
                    for _, sub_child, sub_edata in self.g.out_edges(child, data=True):
                        s_data = self.g.nodes[sub_child]
                        lines.append(f"        └── ({sub_edata.get('relation', 'accessed')}) ──► {s_data.get('label')}")

        lines.append("==========================================================================")
        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        nodes = [{"id": n, **d} for n, d in self.g.nodes(data=True)]
        edges = [{"source": u, "target": v, "key": k, **d} for u, v, k, d in self.g.edges(keys=True, data=True)]
        return {"nodes": nodes, "edges": edges}
