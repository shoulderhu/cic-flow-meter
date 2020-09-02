import pandas as pd
from datetime import datetime
from math import sqrt


from feature import Feature


class TCPFlow:
    def __init__(self, id, ts, tcp):
        self.id = id
        self.timestamp = ts
        self.duration = 0
        self.dp_ratio = 0

        self.flow = {
            "all": {
                "len_per_sec": 0.0,
                "size_per_sec": 0.0,
                "pkt_len": 0,
                "pkt_size": 0,
                # "pkt_min": -1,
                # "pkt_max": -1,
                "pkt_mean": 0.0,
                "pkt_std": 0.0,
                "iat_len": 0,
                "iat_size": 0,
                # "iat_min": -1,
                # "iat_max": -1,
                "iat_mean": 0,
                "iat_std": 0,
                "iat_ss": 0,
                "iat_ts": ts,
                "flg_fin": 0,
                "flg_syn": 0,
                "flg_rst": 0,
                "flg_psh": 0,
                "flg_ack": 0,
                "flg_urg": 0,
                "flg_ece": 0,
                "flg_cwr": 0,
            },
            "fwd": {
                "len_per_sec": 0.0,
                "size_per_sec": 0.0,
                "pkt_len": 0,
                "pkt_size": 0,
                # "pkt_min": -1,
                # "pkt_max": -1,
                "pkt_mean": 0.0,
                "pkt_std": 0.0,
                "pkt_ss": 0,
                "pkt_len_pay": 0,
                "iat_len": 0,
                "iat_size": 0,
                "iat_ss": 0,
                # "iat_min": -1,
                # "iat_max": -1,
                "iat_mean": 0,
                "iat_std": 0,
                # "iat_ts": -1,
                "flg_psh": 0,
                "flg_urg": 0,
                "hdr_size": 0,
                "win_size": 0
            },
            "bwd": {
                "len_per_sec": 0.0,
                "size_per_sec": 0.0,
                "pkt_len": 0,
                "pkt_size": 0,
                # "pkt_min": -1,
                # "pkt_max": -1,
                "pkt_mean": 0.0,
                "pkt_std": 0.0,
                "pkt_ss": 0,
                "pkt_len_pay": 0,
                "iat_len": 0,
                "iat_size": 0,
                # "iat_min": -1,
                # "iat_max": -1,
                "iat_mean": 0,
                "iat_std": 0,
                "iat_ss": 0,
                # "iat_ts": -1,
                "flg_psh": 0,
                "flg_urg": 0,
                "hdr_size": 0,
                "win_size": 0
            }
        }

        self.init(ts, tcp)

    def init(self, ts, tcp):
        path = self.get_pkt_path(tcp.sport, tcp.dport)

        self.upd_flow_pkt(path, len(tcp.data))
        self.upd_flow_iat(path, ts)

        self.upd_flow_flg("all", tcp.flags)
        self.upd_flow_flg(path, tcp.flags)

        self.upd_flow_win_size(path, tcp.win)
        self.upd_flow_hdr(path, len(tcp) - len(tcp.data))

    def upd_flow(self, ts, tcp):
        path = self.get_pkt_path(tcp.sport, tcp.dport)

        self.set_flow_duration(ts)
        self.upd_flow_pkt(path, len(tcp.data))

        self.upd_flow_iat("all", ts)
        self.upd_flow_iat(path, ts)

        self.upd_flow_flg("all", tcp.flags)
        self.upd_flow_flg(path, tcp.flags)
        self.upd_flow_win_size(path, tcp.win)
        self.upd_flow_hdr(path, len(tcp) - len(tcp.data))

    def get_pkt_path(self, sport, dport):
        if sport < dport:
            return "bwd"
        else:
            return "fwd"

    def get_std(self, n, ss, mean):
        if n == 1:
            return 0
        else:
            return sqrt((ss / float(n - 1)) - (n / float(n - 1)) * (mean * mean))

    def set_flow_duration(self, ts):
        self.duration = (ts - self.timestamp)  # * 10**6

    def set_flow_len_size_per_sec(self, path):
        if self.duration > 0:
            self.flow[path]["len_per_sec"] = float(self.flow[path]["pkt_len"]) / self.duration
            self.flow[path]["size_per_sec"] = float(self.flow[path]["pkt_size"]) / self.duration

    def set_flow_len_size_min_max_ss(self, path, cat, size):
        self.flow[path][cat + "_len"] += 1
        self.flow[path][cat + "_size"] += size
        self.flow[path][cat + "_ss"] += size * size

        if cat + "_min" not in self.flow[path].keys():
            self.flow[path][cat + "_min"] = size
        else:
            self.flow[path][cat + "_min"] = min(self.flow[path][cat + "_min"], size)

        if cat + "_max" not in self.flow[path].keys():
            self.flow[path][cat + "_max"] = size
        else:
            self.flow[path][cat + "_max"] = max(self.flow[path][cat + "_max"], size)

    def set_flow_mean_std(self, path, cat):
        if self.flow[path][cat + "_len"] != 0:
            self.flow[path][cat + "_mean"] = float(self.flow[path][cat + "_size"]) / self.flow[path][cat + "_len"]
            self.flow[path][cat + "_std"] = self.get_std(self.flow[path][cat + "_len"],
                                                         self.flow[path][cat + "_ss"],
                                                         self.flow[path][cat + "_mean"])

    def set_flow_len_size_min_max_mean_std(self, cat=None):
        self.flow["all"]["pkt_len"] = self.flow["fwd"]["pkt_len"] + self.flow["bwd"]["pkt_len"]
        self.flow["all"]["pkt_size"] = self.flow["fwd"]["pkt_size"] + self.flow["bwd"]["pkt_size"]

        for i in ["min", "max"]:
            if "pkt_" + i not in self.flow["fwd"] and "pkt_" + i not in self.flow["bwd"]:
                self.flow["all"]["pkt_" + i] = 0
            elif "pkt" + i in self.flow["fwd"]:
                self.flow["all"]["pkt_" + i] = self.flow["fwd"].get("pkt_" + i, 0)
            else:
                self.flow["all"]["pkt_" + i] = self.flow["bwd"].get("pkt_" + i, 0)

        if self.flow["all"]["pkt_len"] != 0:
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

    def upd_flow_iat(self, path, ts):
        if "iat_ts" in self.flow[path]:
            iat = ts - self.flow[path]["iat_ts"]
            self.flow[path]["iat_ts"] = ts
            self.set_flow_len_size_min_max_ss(path, "iat", iat * 10 ** 6)
        else:
            self.flow[path]["iat_ts"] = ts

    def set_flow_iat(self):
        self.set_flow_mean_std("all", "iat")
        self.set_flow_mean_std("fwd", "iat")
        self.set_flow_mean_std("bwd", "iat")

    def upd_flow_flg(self, path, flags):
        if path == "all":
            self.flow[path]["flg_fin"] += flags & 1
            self.flow[path]["flg_syn"] += (flags >> 1) & 1
            self.flow[path]["flg_rst"] += (flags >> 2) & 1
            self.flow[path]["flg_psh"] += (flags >> 3) & 1
            self.flow[path]["flg_ack"] += (flags >> 4) & 1
            self.flow[path]["flg_urg"] += (flags >> 5) & 1
            self.flow[path]["flg_ece"] += (flags >> 6) & 1
            self.flow[path]["flg_cwr"] += (flags >> 7) & 1
        else:
            self.flow[path]["flg_psh"] += (flags >> 3) & 1
            self.flow[path]["flg_urg"] += (flags >> 5) & 1

    def upd_flow_hdr(self, path, length):
        self.flow[path]["hdr_size"] += length

    def set_flow_speed(self):
        self.set_flow_len_size_per_sec("all")
        self.set_flow_len_size_per_sec("fwd")
        self.set_flow_len_size_per_sec("bwd")

    def set_flow_dp_ratio(self):
        if self.flow["fwd"]["pkt_len"] > 0:
            self.dp_ratio = float(self.flow["bwd"]["pkt_len"]) / self.flow["fwd"]["pkt_len"]

    def upd_flow_win_size(self, path, win):
        self.flow[path]["win_size"] += win

    def to_list(self, source, label=None):
        if label is None:
            label = "NeedManualLabel"

        self.set_flow_pkt()
        self.set_flow_iat()

        self.set_flow_speed()
        self.set_flow_dp_ratio()

        return [self.id,
                datetime.fromtimestamp(self.timestamp),
                self.duration * 10**6,
                self.flow["all"]["pkt_len"],
                self.flow["all"]["pkt_size"],
                self.flow["all"].get("pkt_min", 0),
                self.flow["all"].get("pkt_max", 0),
                self.flow["all"]["pkt_mean"],
                self.flow["all"]["pkt_std"],
                self.flow["fwd"]["pkt_len"],
                self.flow["fwd"]["pkt_size"],
                self.flow["fwd"].get("pkt_min", 0),
                self.flow["fwd"].get("pkt_max", 0),
                self.flow["fwd"]["pkt_mean"],
                self.flow["fwd"]["pkt_std"],
                self.flow["bwd"]["pkt_len"],
                self.flow["bwd"]["pkt_size"],
                self.flow["bwd"].get("pkt_min", 0),
                self.flow["bwd"].get("pkt_max", 0),
                self.flow["bwd"]["pkt_mean"],
                self.flow["bwd"]["pkt_std"],
                self.flow["all"]["len_per_sec"],
                self.flow["all"]["size_per_sec"],
                self.flow["fwd"]["len_per_sec"],
                self.flow["fwd"]["size_per_sec"],
                self.flow["bwd"]["len_per_sec"],
                self.flow["bwd"]["size_per_sec"],
                self.flow["all"]["iat_size"],
                self.flow["all"].get("iat_min", 0),
                self.flow["all"].get("iat_max", 0),
                self.flow["all"]["iat_mean"],
                self.flow["all"]["iat_std"],
                self.flow["fwd"]["iat_size"],
                self.flow["fwd"].get("iat_min", 0),
                self.flow["fwd"].get("iat_max", 0),
                self.flow["fwd"]["iat_mean"],
                self.flow["fwd"]["iat_std"],
                self.flow["bwd"]["iat_size"],
                self.flow["bwd"].get("iat_min", 0),
                self.flow["bwd"].get("iat_max", 0),
                self.flow["bwd"]["iat_mean"],
                self.flow["bwd"]["iat_std"],
                self.flow["fwd"]["flg_psh"],
                self.flow["fwd"]["flg_urg"],
                self.flow["bwd"]["flg_psh"],
                self.flow["bwd"]["flg_urg"],
                self.flow["all"]["flg_fin"],
                self.flow["all"]["flg_syn"],
                self.flow["all"]["flg_rst"],
                self.flow["all"]["flg_psh"],
                self.flow["all"]["flg_ack"],
                self.flow["all"]["flg_urg"],
                self.flow["all"]["flg_ece"],
                self.flow["all"]["flg_cwr"],
                self.flow["fwd"]["hdr_size"],
                self.flow["bwd"]["hdr_size"],
                self.dp_ratio,
                self.flow["fwd"]["win_size"],
                self.flow["bwd"]["win_size"],
                self.flow["fwd"]["pkt_len_pay"],
                source,
                label]