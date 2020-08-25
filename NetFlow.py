import logging
from math import sqrt
from pprint import pprint


class NetFlow:
    PROTOCOL_TCP = "tcp"
    PROTOCOL_UDP = "udp"
    PROTOCOL_ICMP = "icmp"

    def __init__(self, pkts, proto):
        self.src_ip = None
        self.src_port = None
        self.dst_ip = None
        self.dst_port = None
        self.proto = proto

        self.flow = {
            "all": {
                "id": "",
                "ip_src": "",
                "ip_dst": "",
                "port_src": "",
                "port_dst": "",
                "proto": proto,
                "pkt_len": 0,
                "pkt_size": 0,
                "pkt_min": -1,
                "pkt_max": -1,
                "pkt_mean": 0.0,
                "pkt_std": 0.0,
            },
            "fwd": {
                "id": "",
                "pkt_len": 0,
                "pkt_size": 0,
                "pkt_min": -1,
                "pkt_max": -1,
                "pkt_mean": 0.0,
                "pkt_std": 0.0,
                "pkt_ss": 0
            },
            "bwd": {
                "id": "",
                "pkt_len": 0,
                "pkt_size": 0,
                "pkt_min": -1,
                "pkt_max": -1,
                "pkt_mean": 0.0,
                "pkt_std": 0.0,
                "pkt_ss": 0
            }
        }

        self.iat_len = 0
        self.iat_size = 0
        self.iat_min = -1
        self.iat_max = -1
        self.iat_mean = 0
        self.iat_std = 0
        self.iat_ss = 0

        self.fwd_iat_len = 0
        self.fwd_iat_size = 0
        self.fwd_iat_min = -1
        self.fwd_iat_max = -1
        self.fwd_iat_mean = 0
        self.fwd_iat_std = 0
        self.fwd_iat_ss = 0
        self.fwd_iat_ts = -1

        self.bwd_iat_len = 0
        self.bwd_iat_size = 0
        self.bwd_iat_min = -1
        self.bwd_iat_max = -1
        self.bwd_iat_mean = 0
        self.bwd_iat_std = 0
        self.bwd_iat_ss = 0
        self.bwd_iat_ts = -1

        self.flag_fin = 0
        self.flag_syn = 0
        self.flag_rst = 0
        self.flag_psh = 0
        self.flag_ack = 0
        self.flag_urg = 0
        self.flag_ece = 0
        self.flag_cwr = 0

        self.fwd_flag_psh = 0
        self.fwd_flag_urg = 0

        self.bwd_flag_psh = 0
        self.bwd_flag_urg = 0

        self.fwd_hdr_len = 0
        self.bwd_hdr_len = 0

        self.dp_ratio = 0

        self.fwd_win_size = 0
        self.bwd_win_size = 0

        self.set_flow(pkts)

    def set_flow(self, pkts):
        try:  # First Packet
            pkt = pkts.next()
            self.set_flow_id(pkt)

            if self.proto == NetFlow.PROTOCOL_TCP:
                src_port = pkt.tcp.srcport
                dst_port = pkt.tcp.dstport
                size = int(pkt.tcp.len)
                self.upd_fwd_psh_urg(pkt.tcp)
                self.upd_flags(pkt.tcp)
                self.upd_fwd_window_size(pkt.tcp)
                self.upd_fwd_hdr_len(int(pkt.tcp.hdr_len))
            elif self.proto == NetFlow.PROTOCOL_UDP:
                src_port = pkt.udp.srcport
                dst_port = pkt.udp.dstport
                size = 0
            else:
                src_port = 0
                dst_port = 0
                size = 0

            self.set_src_ip_port(pkt.ip.src, src_port)
            self.set_dst_ip_port(pkt.ip.dst, dst_port)

            self.set_len_size_min_max_ss("fwd", "pkt", size)
            self.upd_fwd_iat(0.0, 0.0)

        except StopIteration:
            pass

        while True:
            try:  # Rest Packets
                pkt = pkts.next()
                id = self.get_pkt_id(pkt)
                path = self.get_pkt_path(id)

                if self.proto == NetFlow.PROTOCOL_TCP:
                    size = int(pkt.tcp.len)
                    iat = float(pkt.tcp.time_delta)
                    iat_ts = float(pkt.tcp.time_relative)
                    tcp = pkt.tcp
                    self.upd_flags(pkt.tcp)
                elif self.proto == NetFlow.PROTOCOL_UDP:
                    size = int(pkt.udp.len)
                    iat = 0
                    iat_ts = 0
                    tcp = None
                else:
                    size = 0
                    iat = 0
                    iat_ts = 0
                    tcp = None

                self.set_len_size_min_max_ss(path, "pkt", size)
                self.upd_iat(iat)

                if self.flow["fwd"]["id"] == id:

                    self.upd_fwd_iat(iat_ts - self.fwd_iat_ts, iat_ts)
                    self.upd_fwd_psh_urg(tcp)
                    self.upd_fwd_window_size(tcp)
                    self.upd_fwd_hdr_len(int(pkt.tcp.hdr_len))
                else:
                    self.upd_bwd_iat(iat_ts - self.bwd_iat_ts, iat_ts)
                    self.upd_bwd_psh_urg(tcp)
                    self.upd_bwd_window_size(tcp)
                    self.upd_bwd_hdr_len(int(pkt.tcp.hdr_len))
            except StopIteration:
                break

        self.set_mean_std("fwd", "pkt")
        self.set_mean_std("bwd", "pkt")
        self.set_all_len_size_min_max_mean_std()

        self.set_iat_mean_std()
        self.set_down_up_ratio()

        pprint(self.flow)



    def upd_iat(self, iat):
        self.iat_len += 1
        iat *= 10**6
        self.iat_size += iat
        self.iat_ss += iat * iat

        if self.iat_min == -1:
            self.iat_min = iat
        else:
            self.iat_min = min(self.iat_min, iat)
        if self.iat_max == -1:
            self.iat_max = iat
        else:
            self.iat_max = max(self.iat_max, iat)

    def upd_fwd_iat(self, iat, ts):
        if self.fwd_iat_ts == -1:
            self.fwd_iat_ts = ts
            return

        self.fwd_iat_ts = ts
        self.fwd_iat_len += 1
        iat *= 10**6
        self.fwd_iat_size += iat
        self.fwd_iat_ss += iat * iat

        if self.fwd_iat_min == -1:
            self.fwd_iat_min = iat
        else:
            self.fwd_iat_min = min(self.fwd_iat_min, iat)
        if self.fwd_iat_max == -1:
            self.fwd_iat_max = iat
        else:
            self.fwd_iat_max = max(self.fwd_iat_max, iat)

    def upd_bwd_iat(self, iat, ts):
        if self.bwd_iat_ts == -1:
            self.bwd_iat_ts = ts
            return

        self.bwd_iat_ts = ts
        self.bwd_iat_len += 1
        iat *= 10**6
        self.bwd_iat_size += iat
        self.bwd_iat_ss += iat * iat

        if self.bwd_iat_min == -1:
            self.bwd_iat_min = iat
        else:
            self.bwd_iat_min = min(self.bwd_iat_min, iat)
        if self.bwd_iat_max == -1:
            self.bwd_iat_max = iat
        else:
            self.bwd_iat_max = max(self.bwd_iat_max, iat)

    def upd_fwd_psh_urg(self, tcp):
        if tcp is not None:
            self.fwd_flag_psh += int(tcp.flags_push)
            self.fwd_flag_urg += int(tcp.flags_urg)

    def upd_bwd_psh_urg(self, tcp):
        if tcp is not None:
            self.bwd_flag_psh += int(tcp.flags_push)
            self.bwd_flag_urg += int(tcp.flags_urg)

    def upd_flags(self, tcp):
        self.flag_fin += int(tcp.flags_fin)
        self.flag_syn += int(tcp.flags_syn)
        self.flag_rst += int(tcp.flags_reset)
        self.flag_psh += int(tcp.flags_push)
        self.flag_ack += int(tcp.flags_ack)
        self.flag_urg += int(tcp.flags_urg)
        self.flag_ece += int(tcp.flags_ecn)
        self.flag_cwr += int(tcp.flags_cwr)

    def upd_fwd_hdr_len(self, length):
        self.fwd_hdr_len += length

    def upd_bwd_hdr_len(self, length):
        self.bwd_hdr_len += length

    def upd_fwd_window_size(self, tcp):
        if tcp is not None:
            self.fwd_win_size += int(tcp.window_size)

    def upd_bwd_window_size(self, tcp):
        if tcp is not None:
            self.bwd_win_size += int(tcp.window_size)

    def set_src_ip_port(self, ip, port):
        self.src_ip = ip
        self.src_port = port

    def set_dst_ip_port(self, ip, port):
        self.dst_ip = ip
        self.dst_port = port

    def set_iat_mean_std(self):
        self.iat_mean = float(self.iat_size) / self.iat_len
        self.iat_std = self.get_std(self.iat_len, self.iat_ss, self.iat_mean)

        self.fwd_iat_mean = float(self.fwd_iat_size) / self.fwd_iat_len
        self.fwd_iat_std = self.get_std(self.fwd_iat_len, self.fwd_iat_ss, self.fwd_iat_mean)

        self.bwd_iat_mean = float(self.bwd_iat_size) / self.bwd_iat_len
        self.bwd_iat_std = self.get_std(self.bwd_iat_len, self.bwd_iat_ss, self.bwd_iat_mean)

    def set_down_up_ratio(self):
        if self.flow["fwd"]["pkt_len"] > 0:
            self.dp_ratio = float(self.flow["bwd"]["pkt_len"]) / self.flow["fwd"]["pkt_len"]



    def get_pkt_id(self, pkt):
        return "{} {}:{} > {}:{}".format(self.proto.upper(), pkt.ip.src, pkt[self.proto].srcport,
                                         pkt.ip.dst, pkt[self.proto].dstport)

    def get_pkt_path(self, id):
        if self.flow["fwd"]["id"] == id:
            return "fwd"
        else:
            return "bwd"

    def get_std(self, n, ss, mean):
        return sqrt((ss / float(n - 1)) - (n / float(n - 1)) * (mean * mean))

    def set_flow_id(self, pkt):
        self.flow["fwd"]["id"] = "{} {}:{} > {}:{}".format(self.proto.upper(), pkt.ip.src, pkt[self.proto].srcport,
                                                           pkt.ip.dst, pkt[self.proto].dstport)
        self.flow["bwd"]["id"] = "{} {}:{} > {}:{}".format(self.proto.upper(), pkt.ip.dst, pkt[self.proto].dstport,
                                                           pkt.ip.src, pkt[self.proto].srcport)
        self.flow["all"]["id"] = "{} {}:{} <> {}:{}".format(self.proto.upper(), pkt.ip.src, pkt[self.proto].srcport,
                                                            pkt.ip.dst, pkt[self.proto].dstport)

    def set_len_size_min_max_ss(self, path, cat, size):
        self.flow[path][cat + "_len"] += 1
        self.flow[path][cat + "_size"] += size
        self.flow[path][cat + "_ss"] += size * size

        if self.flow[path][cat + "_min"] == -1:
            self.flow[path][cat + "_min"] = size
        else:
            self.flow[path][cat + "_min"] = min(self.flow[path][cat + "_min"], size)

        if self.flow[path][cat + "_max"] == -1:
            self.flow[path][cat + "_max"] = size
        else:
            self.flow[path][cat + "_max"] = max(self.flow[path][cat + "_max"], size)

    def set_mean_std(self, path, cat):
        self.flow[path][cat + "_mean"] = float(self.flow[path][cat + "_size"]) / self.flow[path][cat + "_len"]
        self.flow[path][cat + "_std"] = self.get_std(self.flow[path][cat + "_len"],
                                                     self.flow[path][cat + "_ss"],
                                                     self.flow[path][cat + "_mean"])

    def set_all_len_size_min_max_mean_std(self):
        self.flow["all"]["pkt_len"] = self.flow["fwd"]["pkt_len"] + self.flow["bwd"]["pkt_len"]
        self.flow["all"]["pkt_size"] = self.flow["fwd"]["pkt_size"] + self.flow["bwd"]["pkt_size"]
        self.flow["all"]["pkt_min"] = min(self.flow["fwd"]["pkt_min"], self.flow["bwd"]["pkt_min"])
        self.flow["all"]["pkt_max"] = max(self.flow["fwd"]["pkt_max"], self.flow["bwd"]["pkt_max"])
        self.flow["all"]["pkt_mean"] = float(self.flow["all"]["pkt_size"]) / self.flow["all"]["pkt_len"]
        self.flow["all"]["pkt_std"] = self.get_std(self.flow["all"]["pkt_len"],
                                                   self.flow["fwd"]["pkt_ss"] + self.flow["bwd"]["pkt_ss"],
                                                   self.flow["all"]["pkt_mean"])