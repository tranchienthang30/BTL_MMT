####################################################
# LSrouter.py
# Name: Tran Chien Thang
# HUID: 23021725
#####################################################

import sys
import json
import heapq
from router import Router
from packet import Packet

INFINITY = sys.maxsize

class LSrouter(Router):
    def __init__(self, addr, heartbeat_time):
        Router.__init__(self, addr)
        self.heartbeat_time = heartbeat_time
        self.last_time = 0
        self.sequence_number = 0
        # LSDB: {router_addr: (sequence_num, {neighbor_addr: cost})}
        self.link_state_db = {self.addr: (self.sequence_number, {})}
        self.forwarding_table = {self.addr: (None, 0)}
        self.link_costs = {}  # {port: cost}
        self.neighbor_endpoints = {}  # {port: endpoint_addr}
        # print(f"[{self.addr}] LSrouter Initialized. LSDB: {self.link_state_db}")


    def handle_new_link(self, port, endpoint, cost):
        # print(f"[{self.addr}] LS: NEW_LINK - Port {port} to {endpoint}, Cost {cost}")
        self.link_costs[port] = cost
        self.neighbor_endpoints[port] = endpoint
        self._broadcast_lsp("new_link")


    def handle_remove_link(self, port):
        # print(f"[{self.addr}] LS: REMOVE_LINK - Port {port}")
        if port in self.link_costs: del self.link_costs[port]
        if port in self.neighbor_endpoints: del self.neighbor_endpoints[port]
        self._broadcast_lsp("remove_link")


    def handle_packet(self, port, packet):
        if packet.is_traceroute:
            if packet.dst_addr == self.addr: return
            if packet.dst_addr in self.forwarding_table:
                out_port, _ = self.forwarding_table[packet.dst_addr]
                if out_port is not None: self.send(out_port, packet)
            return

        elif packet.is_routing: # Gói LSP
            content_str = packet.content
            if not content_str:
                # print(f"[{self.addr}] LS: Received ROUTING packet with EMPTY content from {packet.src_addr} on port {port}")
                return

            try:
                lsp_data = json.loads(content_str)
                if not (isinstance(lsp_data, dict) and 'src' in lsp_data and
                        'seq' in lsp_data and 'neighbors' in lsp_data and
                        isinstance(lsp_data['neighbors'], dict)):
                    # print(f"[{self.addr}] LS: Invalid LSP format from {packet.src_addr}. Data: {lsp_data}")
                    return
            except json.JSONDecodeError as e:
                # print(f"[{self.addr}] LS: Failed to decode LSP JSON from {packet.src_addr}. Error: {e}. Content: '{content_str}'")
                return

            lsp_src = lsp_data['src']
            lsp_seq = lsp_data['seq']
            lsp_neighbors = lsp_data['neighbors']

            if lsp_src == self.addr:
                return

            current_seq, _ = self.link_state_db.get(lsp_src, (-1, {}))

            if lsp_seq <= current_seq:
                return

            # print(f"[{self.addr}] LS: ACCEPTED new LSP from {lsp_src} (Seq {lsp_seq}). Neighbors: {lsp_neighbors}. OLD_SEQ: {current_seq}")
            self.link_state_db[lsp_src] = (lsp_seq, lsp_neighbors)
            # print(f"[{self.addr}] LS: Updated LSDB for {lsp_src}. LSDB is now: {self.link_state_db}")

            self._run_dijkstra(f"lsp_received_from_{lsp_src}")

            pkt_to_flood = Packet(Packet.ROUTING, self.addr, None, content=content_str)
            for out_port_flood in self.link_costs:
                if out_port_flood != port:
                    # print(f"[{self.addr}] LS: FLOODING LSP (orig_src: {lsp_src}, seq: {lsp_seq}) out own_port {out_port_flood} to neighbor {self.neighbor_endpoints.get(out_port_flood)}")
                    self.send(out_port_flood, pkt_to_flood)


    def handle_time(self, time_ms):
        if time_ms - self.last_time >= self.heartbeat_time:
            self.last_time = time_ms
            self._broadcast_lsp("heartbeat")


    def _build_own_lsp_neighbors_dict(self):
        own_neighbors = {}
        for port, endpoint_addr in self.neighbor_endpoints.items():
            cost = self.link_costs.get(port)
            if cost is not None and cost < INFINITY:
                if endpoint_addr not in own_neighbors or cost < own_neighbors[endpoint_addr]:
                    own_neighbors[endpoint_addr] = cost
        return own_neighbors


    def _broadcast_lsp(self, reason="unknown"):
        self.sequence_number += 1
        own_lsp_neighbors = self._build_own_lsp_neighbors_dict()

        lsp_content_dict = {
            "src": self.addr,
            "seq": self.sequence_number,
            "neighbors": own_lsp_neighbors
        }
        # print(f"[{self.addr}] LS: BROADCASTING own LSP (Seq {self.sequence_number}) due to '{reason}'. Neighbors: {own_lsp_neighbors}")

        self.link_state_db[self.addr] = (self.sequence_number, own_lsp_neighbors)
        # print(f"[{self.addr}] LS: Updated own entry in LSDB. Current LSDB: {self.link_state_db}")
        
        self._run_dijkstra(f"own_lsp_broadcast_seq_{self.sequence_number}")

        try:
            content_str = json.dumps(lsp_content_dict)
        except TypeError as e:
            # print(f"[{self.addr}] LS: ERROR serializing own LSP to JSON: {e}. Dict: {lsp_content_dict}")
            return

        pkt = Packet(Packet.ROUTING, self.addr, None, content=content_str)
        # if not self.link_costs:
             # print(f"[{self.addr}] LS: No active links to broadcast LSP to.")

        for port_to_send in self.link_costs:
            # print(f"[{self.addr}] LS: Sending own LSP (Seq {self.sequence_number}) out port {port_to_send} to neighbor {self.neighbor_endpoints.get(port_to_send)}")
            self.send(port_to_send, pkt)


    def _run_dijkstra(self, reason="unknown"):
        # print(f"[{self.addr}] LS: RUNNING DIJKSTRA due to '{reason}'. LSDB for Dijkstra: {self.link_state_db}")
        dist = {}
        prev = {}
        pq = []

        # Khởi tạo dist cho tất cả các nút có thể biết được (từ keys của LSDB và neighbors trong values của LSDB)
        all_reachable_nodes = set()
        all_reachable_nodes.add(self.addr)
        for router_addr_in_lsdb, (_, neighbors_dict_in_lsdb) in self.link_state_db.items():
            all_reachable_nodes.add(router_addr_in_lsdb)
            all_reachable_nodes.update(neighbors_dict_in_lsdb.keys())
        
        # print(f"[{self.addr}] LS Dijkstra: All potentially reachable nodes for init: {all_reachable_nodes}")

        for node in all_reachable_nodes:
            dist[node] = INFINITY
            prev[node] = None
        
        dist[self.addr] = 0
        heapq.heappush(pq, (0, self.addr))
        # print(f"[{self.addr}] LS Dijkstra: Initializing. PQ: {pq}. Dist[{self.addr}]: {dist[self.addr]}")

        processed_nodes = set()

        while pq:
            d, u = heapq.heappop(pq)

            if u in processed_nodes:
                continue
            processed_nodes.add(u)
            # print(f"[{self.addr}] LS Dijkstra: Processing node {u} with cost {d}")

            # Lấy thông tin hàng xóm của u TỪ LSDB. Nếu u không có trong LSDB, nó không thể mở rộng.
            if u not in self.link_state_db:
                # print(f"[{self.addr}] LS Dijkstra: Node {u} not in self.link_state_db, cannot expand its neighbors.")
                continue
            
            _, u_lsp_neighbors_dict = self.link_state_db[u]
            # print(f"[{self.addr}] LS Dijkstra: Neighbors of {u} from its LSP: {u_lsp_neighbors_dict}")

            for v_neighbor_addr, cost_uv in u_lsp_neighbors_dict.items():
                # Hàng xóm v phải là một nút đã được khởi tạo trong dist
                if v_neighbor_addr not in dist:
                    # print(f"[{self.addr}] LS Dijkstra WARNING: Neighbor {v_neighbor_addr} of {u} was not in initial reachable set. Skipping relax.")
                    continue

                if v_neighbor_addr not in processed_nodes:
                    new_dist_to_v = d + cost_uv
                    if new_dist_to_v < dist[v_neighbor_addr]:
                        dist[v_neighbor_addr] = new_dist_to_v
                        prev[v_neighbor_addr] = u
                        heapq.heappush(pq, (new_dist_to_v, v_neighbor_addr))
                        # print(f"[{self.addr}] LS Dijkstra: Relaxed {u}->{v_neighbor_addr}. New dist[{v_neighbor_addr}] = {new_dist_to_v}. Prev[{v_neighbor_addr}] = {u}")
        
        # print(f"[{self.addr}] LS Dijkstra: Final dist: {dist}")
        # print(f"[{self.addr}] LS Dijkstra: Final prev: {prev}")

        new_ft = {self.addr: (None, 0)}
        my_direct_neighbor_addr_to_port = {addr: p for p, addr in self.neighbor_endpoints.items() if p in self.link_costs}
        # print(f"[{self.addr}] LS Dijkstra: My direct neighbor_to_port map for FT: {my_direct_neighbor_addr_to_port}")

        for dest_node in all_reachable_nodes:
            if dest_node == self.addr or dist.get(dest_node, INFINITY) == INFINITY:
                continue

            path_curr = dest_node
            first_hop_on_path = None
            
            # print(f"[{self.addr}] LS Dijkstra: Tracing path from {self.addr} to {dest_node}")
            while prev.get(path_curr) is not None:
                if prev[path_curr] == self.addr:
                    first_hop_on_path = path_curr
                    break
                path_curr = prev[path_curr]
                if path_curr == self.addr : # Đã quay về gốc mà không qua hàng xóm trực tiếp
                    break # Dừng nếu prev[path_curr] không phải là self.addr
            
            # print(f"[{self.addr}] LS Dijkstra: For dest {dest_node}, first_hop_on_path: {first_hop_on_path}")

            if first_hop_on_path:
                outgoing_port = my_direct_neighbor_addr_to_port.get(first_hop_on_path)
                if outgoing_port is not None:
                    new_ft[dest_node] = (outgoing_port, dist[dest_node])
                    # print(f"[{self.addr}] LS Dijkstra: FT ADDED: Dest={dest_node}, NextHop={first_hop_on_path}, OutPort={outgoing_port}, Cost={dist[dest_node]}")
                # else:
                    # print(f"[{self.addr}] LS Dijkstra ERROR: No DIRECT outgoing port found for first_hop '{first_hop_on_path}' to reach '{dest_node}'. My direct neighbors: {my_direct_neighbor_addr_to_port}")
            # else:
                # print(f"[{self.addr}] LS Dijkstra: No valid first_hop found from {self.addr} for dest '{dest_node}'. Dist: {dist.get(dest_node)}")
        
        # print(f"[{self.addr}] LS: Dijkstra computed FT: {new_ft}")
        if new_ft != self.forwarding_table:
            # print(f"[{self.addr}] LS: Forwarding table UPDATED.")
            self.forwarding_table = new_ft
        # else:
            # print(f"[{self.addr}] LS: Forwarding table UNCHANGED after Dijkstra.")


    def __repr__(self):
        # return f"LSrouter(addr={self.addr}, seq={self.sequence_number}, FT_size={len(self.forwarding_table)}, LSDB_size={len(self.link_state_db)})"
        return f"LSrouter(addr={self.addr}, FT={self.forwarding_table})" # Hiển thị FT để dễ debug
        # return f"LSrouter(addr={self.addr})"