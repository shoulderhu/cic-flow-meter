import logging
from math import sqrt
from pprint import pprint


class NetFlow:
    PROTOCOL_TCP = "tcp"
    PROTOCOL_UDP = "udp"
    PROTOCOL_ICMP = "icmp"

    def __init__(self, pkts, proto):
        self.flow = {
            "all": {
                "id": "",
                "ip_src": "",
                "ip_dst": "",
                "port_src": "",
                "port_dst": "",
                "proto": proto,
                "timestamp": "",
                "duration": 0.0,
                "len_per_sec": 0.0,
                "size_per_sec": 0.0,
                "pkt_len": 0,
                "pkt_size": 0,
                "pkt_min": -1,
                "pkt_max": -1,
                "pkt_mean": 0.0,
                "pkt_std": 0.0,
                "iat_len": 0,
                "iat_size": 0,
                "iat_min": -1,
                "iat_max": -1,
                "iat_mean": 0,
                "iat_std": 0,
                "iat_ss": 0,
                "flg_fin": 0,
                "flg_syn": 0,
                "flg_rst": 0,
                "flg_psh": 0,
                "flg_ack": 0,
                "flg_urg": 0,
                "flg_ece": 0,
                "flg_cwr": 0,
                "dp_ratio": 0
            },
            "fwd": {
                "id": "",
                "len_per_sec": 0.0,
                "size_per_sec": 0.0,
                "pkt_len": 0,
                "pkt_size": 0,
                "pkt_min": -1,
                "pkt_max": -1,
                "pkt_mean": 0.0,
                "pkt_std": 0.0,
                "pkt_ss": 0,
                "pkt_len_pay": 0,
                "iat_len": 0,
                "iat_size": 0,
                "iat_min": -1,
                "iat_max": -1,
                "iat_mean": 0,
                "iat_std": 0,
                "iat_ss": 0,
                "iat_ts": -1,
                "flg_psh": 0,
                "flg_urg": 0,
                "hdr_size": 0,
                "hdr_min": -1,
                "win_size": 0
            },
            "bwd": {
                "id": "",
                "len_per_sec": 0.0,
                "size_per_sec": 0.0,
                "pkt_len": 0,
                "pkt_size": 0,
                "pkt_min": -1,
                "pkt_max": -1,
                "pkt_mean": 0.0,
                "pkt_std": 0.0,
                "pkt_ss": 0,
                "pkt_len_pay": 0,
                "iat_len": 0,
                "iat_size": 0,
                "iat_min": -1,
                "iat_max": -1,
                "iat_mean": 0,
                "iat_std": 0,
                "iat_ss": 0,
                "iat_ts": -1,
                "flg_psh": 0,
                "flg_urg": 0,
                "hdr_size": 0,
                "hdr_min": -1,
                "win_size": 0
            }
        }

        self.set_flow(pkts)

    def set_flow(self, pkts):
        iat_ts = 0

        try:  # First Packet
            pkt = pkts.next()
            self.set_flow_id(pkt)
            self.set_flow_ip_port(pkt)
            self.set_flow_timestamp(pkt)

            if self.flow["all"]["proto"] == NetFlow.PROTOCOL_TCP:
                tl = pkt.tcp
                size = int(tl.len)
                hdr_size = int(tl.hdr_len)
            elif self.flow["all"]["proto"] == NetFlow.PROTOCOL_UDP:
                tl = None
                size = 0
                hdr_size = 0
            else:
                tl = None
                size = 0
                hdr_size = 0

            self.upd_flow_pkt("fwd", size)
            self.upd_flow_iat("fwd", 0.0, 0.0)

            self.upd_flow_flg("all", tl)
            self.upd_flow_flg("fwd", tl)
            self.upd_flow_win_size("fwd", tl)

            self.upd_flow_hdr("fwd", hdr_size)
        except StopIteration:
            pass

        while True:
            try:  # Rest Packets
                pkt = pkts.next()
                id = self.get_pkt_id(pkt)
                path = self.get_pkt_path(id)

                if self.flow["all"]["proto"] == NetFlow.PROTOCOL_TCP:
                    tl = pkt.tcp
                    size = int(tl.len)
                    iat = float(tl.time_delta)
                    iat_ts = float(tl.time_relative)
                    hdr_size = int(tl.hdr_len)
                elif self.flow["all"]["proto"] == NetFlow.PROTOCOL_UDP:
                    tl = None
                    size = int(pkt.udp.len)
                    iat = 0
                    iat_ts = 0
                    hdr_size = 0
                else:
                    tl = None
                    size = 0
                    iat = 0
                    iat_ts = 0
                    hdr_size = 0

                self.upd_flow_pkt(path, size)

                self.upd_flow_iat("all", iat)
                self.upd_flow_iat(path, iat_ts - self.flow[path]["iat_ts"], iat_ts)

                self.upd_flow_flg("all", tl)
                self.upd_flow_flg(path, tl)
                self.upd_flow_win_size(path, tl)

                self.upd_flow_hdr(path, hdr_size)
            except StopIteration:
                break

        self.set_flow_pkt()
        self.set_flow_iat()

        self.set_flow_duration(iat_ts)
        self.set_flow_speed(iat_ts)

        self.set_flow_dp_ratio()

        pprint(self.flow)

    def get_pkt_id(self, pkt):
        proto = self.flow["all"]["proto"]
        return "{} {}:{} > {}:{}".format(proto.upper(),
                                         pkt.ip.src, pkt[proto].srcport,
                                         pkt.ip.dst, pkt[proto].dstport)

    def get_pkt_path(self, id):
        if self.flow["fwd"]["id"] == id:
            return "fwd"
        elif self.flow["bwd"]["id"] == id:
            return "bwd"
        else:
            return ""

    def get_std(self, n, ss, mean):
        return sqrt((ss / float(n - 1)) - (n / float(n - 1)) * (mean * mean))

    def set_flow_id(self, pkt):
        proto = self.flow["all"]["proto"]
        self.flow["fwd"]["id"] = "{} {}:{} > {}:{}".format(proto.upper(),
                                                           pkt.ip.src, pkt[proto].srcport,
                                                           pkt.ip.dst, pkt[proto].dstport)
        self.flow["bwd"]["id"] = "{} {}:{} > {}:{}".format(proto.upper(),
                                                           pkt.ip.dst, pkt[proto].dstport,
                                                           pkt.ip.src, pkt[proto].srcport)
        self.flow["all"]["id"] = "{} {}:{} <> {}:{}".format(proto.upper(),
                                                            pkt.ip.src, pkt[proto].srcport,
                                                            pkt.ip.dst, pkt[proto].dstport)

    def set_flow_ip_port(self, pkt):
        proto = self.flow["all"]["proto"]
        self.flow["all"]["ip_src"] = pkt.ip.src
        self.flow["all"]["ip_dst"] = pkt.ip.dst
        self.flow["all"]["port_src"] = pkt[proto].srcport
        self.flow["all"]["port_dst"] = pkt[proto].dstport

    def set_flow_timestamp(self, pkt):
        self.flow["all"]["timestamp"] = str(pkt.sniff_time)

    def set_flow_duration(self, ts):
        self.flow["all"]["duration"] = ts * 10**6

    def set_flow_len_size_per_sec(self, path, duration):
        self.flow[path]["len_per_sec"] = float(self.flow[path]["pkt_len"]) / duration
        self.flow[path]["size_per_sec"] = float(self.flow[path]["pkt_size"]) / duration

    def set_flow_len_size_min_max_ss(self, path, cat, size):
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

    def set_flow_mean_std(self, path, cat):
        self.flow[path][cat + "_mean"] = float(self.flow[path][cat + "_size"]) / self.flow[path][cat + "_len"]
        self.flow[path][cat + "_std"] = self.get_std(self.flow[path][cat + "_len"],
                                                     self.flow[path][cat + "_ss"],
                                                     self.flow[path][cat + "_mean"])

    def set_flow_len_size_min_max_mean_std(self, cat=None):
        self.flow["all"]["pkt_len"] = self.flow["fwd"]["pkt_len"] + self.flow["bwd"]["pkt_len"]
        self.flow["all"]["pkt_size"] = self.flow["fwd"]["pkt_size"] + self.flow["bwd"]["pkt_size"]
        self.flow["all"]["pkt_min"] = min(self.flow["fwd"]["pkt_min"], self.flow["bwd"]["pkt_min"])
        self.flow["all"]["pkt_max"] = max(self.flow["fwd"]["pkt_max"], self.flow["bwd"]["pkt_max"])
        self.flow["all"]["pkt_mean"] = float(self.flow["all"]["pkt_size"]) / self.flow["all"]["pkt_len"]
        self.flow["all"]["pkt_std"] = self.get_std(self.flow["all"]["pkt_len"],
                                                   self.flow["fwd"]["pkt_ss"] + self.flow["bwd"]["pkt_ss"],
                                                   self.flow["all"]["pkt_mean"])

    def upd_flow_pkt(self, path, size):
        self.set_flow_len_size_min_max_ss(path, "pkt", size)
        if size > 0:
            self.flow[path]["pkt_len_pay"] += 1

    def set_flow_pkt(self):
        self.set_flow_mean_std("fwd", "pkt")
        self.set_flow_mean_std("bwd", "pkt")
        self.set_flow_len_size_min_max_mean_std()

    def upd_flow_iat(self, path, iat, ts=None):
        if ts is None:
            self.set_flow_len_size_min_max_ss(path, "iat", iat * 10**6)
        else:
            if self.flow[path]["iat_ts"] != -1:
                self.flow[path]["iat_ts"] = ts
                self.set_flow_len_size_min_max_ss(path, "iat", iat * 10**6)
            else:
                self.flow[path]["iat_ts"] = ts

    def set_flow_iat(self):
        self.set_flow_mean_std("all", "iat")
        self.set_flow_mean_std("fwd", "iat")
        self.set_flow_mean_std("bwd", "iat")

    def upd_flow_flg(self, path, tcp):
        if tcp is not None:
            if path == "all":
                self.flow[path]["flg_fin"] += int(tcp.flags_fin)
                self.flow[path]["flg_syn"] += int(tcp.flags_syn)
                self.flow[path]["flg_rst"] += int(tcp.flags_reset)
                self.flow[path]["flg_psh"] += int(tcp.flags_push)
                self.flow[path]["flg_ack"] += int(tcp.flags_ack)
                self.flow[path]["flg_urg"] += int(tcp.flags_urg)
                self.flow[path]["flg_ece"] += int(tcp.flags_ecn)
                self.flow[path]["flg_cwr"] += int(tcp.flags_cwr)
            else:
                self.flow[path]["flg_psh"] += int(tcp.flags_push)
                self.flow[path]["flg_urg"] += int(tcp.flags_urg)

    def upd_flow_hdr(self, path, length):
        self.flow[path]["hdr_size"] += length
        if self.flow[path]["hdr_min"] == -1:
            self.flow[path]["hdr_min"] = length
        else:
            self.flow[path]["hdr_min"] = min(self.flow[path]["hdr_min"], length)

    def set_flow_speed(self, duration):
        self.set_flow_len_size_per_sec("all", duration)
        self.set_flow_len_size_per_sec("fwd", duration)
        self.set_flow_len_size_per_sec("bwd", duration)

    def set_flow_dp_ratio(self):
        if self.flow["fwd"]["pkt_len"] > 0:
            self.flow["all"]["dp_ratio"] = float(self.flow["bwd"]["pkt_len"]) / self.flow["fwd"]["pkt_len"]

    def upd_flow_win_size(self, path, tcp):
        if tcp is not None:
            self.flow[path]["win_size"] += int(tcp.window_size)