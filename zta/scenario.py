from typing import Optional

from core.base_scenario import BaseScenario
from core.infrastructure import Location
from .link import ZTALink
from .zta_node import ZTANode


class ZTAScenario(BaseScenario):
    """
    Scenario that instantiates ZTA-aware nodes (ZTANode) from JSON.

    Supported NodeType values in config:
    - "ZTANode": standard ZTANode
    - "MaliciousNode": ZTANode with a malicious_type set (1 by default)
    """

    def init_infrastructure_nodes(self):
        for node_info in self.json_nodes:
            ntype = node_info.get("NodeType", "ZTANode")

            location: Optional[Location]
            if 'LocX' in node_info and 'LocY' in node_info:
                location = Location(node_info['LocX'], node_info['LocY'])
            else:
                location = None

            node = ZTANode(
                node_id=node_info['NodeId'],
                name=node_info['NodeName'],
                max_cpu_freq=node_info['MaxCpuFreq'],
                max_buffer_size=node_info['MaxBufferSize'],
                location=location,
                idle_energy_coef=node_info['IdleEnergyCoef'],
                exe_energy_coef=node_info['ExeEnergyCoef'],
                window_size=node_info.get('TrustWindow', 5),
            )
            if ntype == "MaliciousNode":
                node.set_malicious_type(node_info.get('MalType', 1))

            self.infrastructure.add_node(node)
            self.node_id2name[node_info['NodeId']] = node_info['NodeName']

    def status(self, node_name=None, link_args=None):
        return

    def init_infrastructure_links(self):
        """Initialize links using ZTALink to support ZTA overheads."""
        nodes = self.infrastructure.get_nodes()
        for edge_info in self.json_edges:
            src_node_id, dst_node_id = edge_info['SrcNodeID'], edge_info['DstNodeID']
            src, dst = nodes[self.node_id2name[src_node_id]], nodes[self.node_id2name[dst_node_id]]

            # Compute base latency using BaseScenario logic
            base_latency = 0
            if 'BaseLatency' in edge_info:
                base_latency = edge_info['BaseLatency']
            else:
                if src.location and dst.location:
                    distance = src.distance(dst) * 2
                    base_latency = round(distance * (1 / self.signal_speed + self.hops_delay), 3)

            enc_ov = edge_info.get('EncryptionOverhead', 0.0)
            auth_lat = edge_info.get('AuthLatency', 0.0)

            def make_link(a, b, bw):
                return ZTALink(a, b, max_bandwidth=bw, base_latency=base_latency,
                               encryption_overhead=enc_ov, auth_latency=auth_lat)

            if edge_info['EdgeType'] == 'SingleLink':
                link = make_link(src, dst, edge_info['Bandwidth'])
                self.infrastructure.add_link(link)
            else:
                bw = edge_info['Bandwidth']
                bw_ab = bw[0] if isinstance(bw, list) else bw
                bw_ba = bw[1] if isinstance(bw, list) else bw
                self.infrastructure.add_link(make_link(src, dst, bw_ab))
                self.infrastructure.add_link(make_link(dst, src, bw_ba))
