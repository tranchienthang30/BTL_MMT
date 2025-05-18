####################################################
# DVrouter.py
# Name: Tran Chien Thang
# HUID: 23021725
#####################################################

import sys
import json # <<< QUAN TRỌNG: Đã import json
from router import Router
from packet import Packet

# Sử dụng giá trị lớn nhất có thể của hệ thống làm vô cực
INFINITY = sys.maxsize

class DVrouter(Router):
    """Distance Vector Router implementation."""

    def __init__(self, addr, heartbeat_time):
        """Initialize the router."""
        Router.__init__(self, addr) # Gọi __init__ của lớp cha
        self.heartbeat_time = heartbeat_time
        self.last_time = 0

        # --- Cấu trúc dữ liệu ---
        # Chi phí đến hàng xóm trực tiếp: {port: cost}
        self.link_costs = {}
        # Địa chỉ của hàng xóm ở đầu kia liên kết: {port: endpoint_addr}
        self.neighbor_endpoints = {}
        # Vector khoảng cách gần nhất nhận được từ hàng xóm: {port: {destination: cost}}
        self.neighbor_vectors = {}
        # Vector khoảng cách của chính router này: {destination: cost}
        self.distance_vector = {self.addr: 0} # Khoảng cách đến chính mình luôn là 0
        # Bảng chuyển tiếp: {destination: (port, cost)}
        self.forwarding_table = {self.addr: (None, 0)} # Route đến chính mình

    def handle_new_link(self, port, endpoint, cost):
        """Xử lý khi có một liên kết mới được thiết lập."""
        # print(f"[{self.addr}] New link port {port} to {endpoint} cost {cost}")
        self.link_costs[port] = cost
        self.neighbor_endpoints[port] = endpoint
        # Khởi tạo vector trống cho hàng xóm mới, chờ nhận thông tin
        self.neighbor_vectors[port] = {}
        # Tính toán lại và gửi cập nhật nếu cần
        self.recompute_routes()

    def handle_remove_link(self, port):
        """Xử lý khi một liên kết bị gỡ bỏ."""
        # print(f"[{self.addr}] Remove link port {port}")
        # Xóa thông tin liên quan đến liên kết/port này
        if port in self.link_costs: del self.link_costs[port]
        if port in self.neighbor_endpoints: del self.neighbor_endpoints[port]
        if port in self.neighbor_vectors: del self.neighbor_vectors[port]
        # Tính toán lại và gửi cập nhật nếu cần
        self.recompute_routes()

    def handle_packet(self, port, packet):
        """Xử lý một gói tin đến."""
        # print(f"[{self.addr}] Rcv packet port {port} from {packet.src_addr} type {packet.kind}")

        if packet.is_traceroute:
            # Xử lý gói traceroute: chuyển tiếp nếu biết đường và không phải đích
            if packet.dst_addr == self.addr:
                pass # Đã đến đích
            elif packet.dst_addr in self.forwarding_table:
                out_port, _ = self.forwarding_table[packet.dst_addr]
                if out_port is not None:
                    # print(f"[{self.addr}] Fwd traceroute for {packet.dst_addr} via port {out_port}")
                    self.send(out_port, packet)
            return # Kết thúc xử lý traceroute

        elif packet.is_routing:
            # Xử lý gói ROUTING (chứa distance vector)
            neighbor_addr = packet.src_addr
            # Bỏ qua nếu nhận từ port không còn tồn tại (gói tin cũ)
            if port not in self.link_costs:
                # print(f"[{self.addr}] Rcv ROUTING on inactive port {port}. Ignoring.")
                return

            # Lấy nội dung dạng chuỗi từ gói tin
            content_str = packet.content
            if not content_str: # Bỏ qua nếu không có nội dung
                 # print(f"[{self.addr}] Rcv ROUTING with empty content from {neighbor_addr}. Ignoring.")
                 return

            # <<< QUAN TRỌNG: Giải mã JSON từ chuỗi content >>>
            try:
                received_vector = json.loads(content_str)
                # Đảm bảo kết quả giải mã là một dictionary
                if not isinstance(received_vector, dict):
                    # print(f"[{self.addr}] Warning: Decoded JSON content is not a dict from {neighbor_addr}. Type: {type(received_vector)}")
                    return
            except json.JSONDecodeError:
                # print(f"[{self.addr}] Warning: Failed to decode JSON content from {neighbor_addr}. Content: '{content_str}'")
                return # Bỏ qua gói tin không thể giải mã JSON
            # <<< KẾT THÚC GIẢI MÃ JSON >>>

            # Lưu trữ vector distance của hàng xóm
            self.neighbor_vectors[port] = received_vector
            # print(f"[{self.addr}] Stored vector from {neighbor_addr} (port {port}): {received_vector}")

            # Tính toán lại route dựa trên thông tin mới
            self.recompute_routes()

    def recompute_routes(self):
        """
        Tính toán lại toàn bộ distance_vector và forwarding_table
        dựa trên link_costs và neighbor_vectors hiện tại.
        """
        new_dv = {self.addr: 0} # Bắt đầu với route đến chính mình
        new_ft = {self.addr: (None, 0)}

        # Thu thập tất cả các đích có thể biết (từ hàng xóm và vector của hàng xóm)
        all_possible_destinations = set()
        for neighbor_vec in self.neighbor_vectors.values():
            all_possible_destinations.update(neighbor_vec.keys())
        all_possible_destinations.update(self.neighbor_endpoints.values())
        if self.addr in all_possible_destinations:
            all_possible_destinations.remove(self.addr) # Không cần tính route đến chính mình qua người khác

        # Áp dụng Bellman-Ford để tìm đường đi ngắn nhất cho từng đích
        for dst in all_possible_destinations:
            min_cost_to_dst = INFINITY
            best_port_to_dst = None

            # 1. Kiểm tra đường đi trực tiếp (nếu đích là hàng xóm)
            for port, neighbor_addr in self.neighbor_endpoints.items():
                if neighbor_addr == dst:
                    direct_cost = self.link_costs.get(port, INFINITY)
                    if direct_cost < min_cost_to_dst:
                        min_cost_to_dst = direct_cost
                        best_port_to_dst = port
                    # Không cần break, có thể có nhiều link đến cùng 1 hàng xóm (ít gặp)
                    # Nhưng thường chỉ có 1 link trực tiếp

            # 2. Kiểm tra đường đi qua các hàng xóm khác
            for neighbor_port, neighbor_vector in self.neighbor_vectors.items():
                cost_to_neighbor = self.link_costs.get(neighbor_port, INFINITY)
                if cost_to_neighbor == INFINITY: continue # Link đến hàng xóm này đã mất

                # Chi phí từ hàng xóm đó đến đích dst (theo vector hàng xóm gửi)
                cost_via_neighbor = neighbor_vector.get(dst, INFINITY)

                # Tính tổng chi phí: self -> neighbor -> dst
                total_cost = INFINITY
                if cost_via_neighbor != INFINITY: # Chỉ tính nếu hàng xóm biết đường đến dst
                    total_cost = cost_to_neighbor + cost_via_neighbor

                # Cập nhật nếu tìm được đường tốt hơn
                if total_cost < min_cost_to_dst:
                    min_cost_to_dst = total_cost
                    best_port_to_dst = neighbor_port

            # Lưu kết quả tốt nhất tìm được cho đích dst
            if best_port_to_dst is not None and min_cost_to_dst < INFINITY:
                 new_dv[dst] = min_cost_to_dst
                 new_ft[dst] = (best_port_to_dst, min_cost_to_dst)

        # So sánh bảng mới với bảng cũ để xem có thay đổi không
        if new_dv != self.distance_vector or new_ft != self.forwarding_table:
            # print(f"[{self.addr}] Routes changed after recompute.") # Debug
            self.distance_vector = new_dv
            self.forwarding_table = new_ft
            # Nếu có thay đổi, gửi vector mới của mình cho hàng xóm
            self.send_vector()
            return True # Có thay đổi
        return False # Không có thay đổi

    def handle_time(self, time_ms):
        """Xử lý sự kiện thời gian (heartbeat)."""
        # Gửi định kỳ để đảm bảo thông tin được cập nhật và xử lý link down tiềm ẩn
        if time_ms - self.last_time >= self.heartbeat_time:
            self.last_time = time_ms
            # print(f"[{self.addr}] Heartbeat triggered. Sending vector.") # Debug
            self.send_vector()

    def send_vector(self):
        """Gửi distance vector tới tất cả các hàng xóm (Split Horizon w/ Poisoned Reverse)."""
        # print(f"[{self.addr}] Preparing to send vectors. Current DV: {self.distance_vector}") # Debug
        for port, link_cost in self.link_costs.items():
            dv_to_send = {}
            # Xây dựng vector riêng cho hàng xóm này
            for dst, cost in self.distance_vector.items():
                if dst == self.addr:
                     continue # Không gửi route đến chính mình

                # Lấy thông tin route hiện tại để quyết định poisoned reverse
                route_port, route_cost = self.forwarding_table.get(dst, (None, INFINITY))

                # Poisoned Reverse logic:
                if route_port == port:
                    # Nếu đường đi tốt nhất đến dst là qua chính hàng xóm (port) này,
                    # báo cho hàng xóm đó biết chi phí là vô cực (poison).
                    dv_to_send[dst] = INFINITY
                    # print(f"[{self.addr}] Poisoning route to {dst} for port {port}") # Debug
                else:
                    # Ngược lại, báo chi phí thực tế (có thể là INFINITY nếu không có đường).
                    dv_to_send[dst] = route_cost # Gửi chi phí thực tế trong DV của mình

            # <<< QUAN TRỌNG: Chuyển đổi dictionary thành chuỗi JSON >>>
            try:
                content_str = json.dumps(dv_to_send)
            except TypeError as e:
                 # print(f"[{self.addr}] ERROR: Failed to serialize DV to JSON: {e}. DV: {dv_to_send}")
                 continue # Không gửi nếu không serialize được
            # <<< KẾT THÚC CHUYỂN ĐỔI JSON >>>

            # Tạo gói tin với content là chuỗi JSON
            pkt = Packet(Packet.ROUTING, self.addr, None, content=content_str)

            # print(f"[{self.addr}] Sending vector to port {port}: {content_str}") # Debug
            self.send(port, pkt) # Gửi gói tin

    def __repr__(self):
        """Representation for debugging."""
        # Có thể tùy chỉnh để hiển thị nhiều thông tin hơn nếu cần
        # Ví dụ: return f"DVrouter(addr={self.addr}, FT={self.forwarding_table})"
        return f"DVrouter(addr={self.addr})"