import logging
from math import sqrt


class NetFlow:
    PROTOCOL_TCP  = 6
    PROTOCOL_UDP  = 17
    PROTOCOL_ICMP = 1

    def __init__(self, pkts, proto):
        self.src_ip = None
        self.src_port = None
        self.dst_ip = None
        self.dst_port = None
        self.proto = proto

        self.fwd_id = None
        self.bwd_id = None

        self.iat = 0
        self.iat_min = -1
        self.iat_max = -1
        self.iat_mean = 0
        self.iat_std = 0

        self.fwd_len = 0
        self.fwd_size = 0
        self.fwd_size_min = -1
        self.fwd_size_max = -1
        self.fwd_size_mean = 0
        self.fwd_size_std = 0
        self.fwd_size_ss = 0

        self.fwd_iat = 0
        self.fwd_iat_min = -1
        self.fwd_iat_max = -1
        self.fwd_iat_mean = 0
        self.fwd_iat_std = 0
        self.fwd_iat_ss = 0

        self.bwd_len = 0
        self.bwd_size = 0
        self.bwd_size_min = -1
        self.bwd_size_max = -1
        self.bwd_size_mean = 0
        self.bwd_size_std = 0
        self.bwd_size_ss = 0

        self.bwd_iat = 0
        self.bwd_iat_min = -1
        self.bwd_iat_max = -1
        self.bwd_iat_mean = 0
        self.bwd_iat_std = 0
        self.bwd_iat_ss = 0

        self.init()
        self.set_flow(pkts)

    def init(self):
        pass

    def set_flow(self, pkts):
        try:
            pkt = pkts.next()
            self.fwd_id = self.get_fwd_id(pkt)
            self.bwd_id = self.get_bwd_id(pkt)

            if self.proto == NetFlow.PROTOCOL_TCP:
                src_port = pkt.tcp.srcport
                dst_port = pkt.tcp.dstport
                size = int(pkt.tcp.len)
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
            self.upd_fwd_len_size(size)

        except StopIteration:
            pass

        while True:
            try:
                pkt = pkts.next()
                fwd_id = self.get_fwd_id(pkt)

                if self.proto == NetFlow.PROTOCOL_TCP:
                    size = int(pkt.tcp.len)
                    iat = float(pkt.tcp.time_delta)
                elif self.proto == NetFlow.PROTOCOL_UDP:
                    size = int(pkt.udp.len)
                    iat = 0
                else:
                    size = 0
                    iat = 0
                    logging.error("size variable")

                # self.iat += iat
                # if self.iat_min == -1:
                #     self.iat_min = iat
                # else:
                #     self.iat_min = min(self.iat_min, )

                if self.fwd_id == fwd_id:
                    self.upd_fwd_len_size(size)
                else:
                    self.upd_bwd_len_size(size)

            except StopIteration:
                break

        self.set_fwd_mean_std()
        self.set_bwd_mean_std()



        # print(self.src_ip, self.src_port)
        # print(self.dst_ip, self.dst_port)
        # print(self.proto)
        #
        # print(self.fwd_id, self.bwd_id)
        #
        # print(self.fwd_len, self.fwd_size)
        # print(self.bwd_len, self.bwd_size)
        #
        # print(self.fwd_size_max, self.fwd_size_min, self.fwd_size_mean, self.fwd_size_std)
        # print(self.bwd_size_max, self.bwd_size_min, self.bwd_size_mean, self.bwd_size_std)

    def upd_fwd_len_size(self, size):
        self.fwd_len += 1
        self.fwd_size += size
        self.fwd_size_ss += size * size

        if self.fwd_size_min == -1:
            self.fwd_size_min = size
        else:
            self.fwd_size_min = min(self.fwd_size_min, size)

        if self.fwd_size_max == -1:
            self.fwd_size_max = size
        else:
            self.fwd_size_max = max(self.fwd_size_max, size)

    def upd_bwd_len_size(self, size):
        self.bwd_len += 1
        self.bwd_size += size
        self.bwd_size_ss += size * size

        if self.bwd_size_min == -1:
            self.bwd_size_min = size
        else:
            self.bwd_size_min = min(self.bwd_size_min, size)
        if self.bwd_size_max == -1:
            self.bwd_size_max = size
        else:
            self.bwd_size_max = max(self.bwd_size_max, size)

    def set_src_ip_port(self, ip, port):
        self.src_ip = ip
        self.src_port = port

    def set_dst_ip_port(self, ip, port):
        self.dst_ip = ip
        self.dst_port = port

    def set_fwd_mean_std(self):
        self.fwd_size_mean = float(self.fwd_size) / self.fwd_len
        self.fwd_size_std = self.get_std(self.fwd_len, self.fwd_size_ss, self.fwd_size_mean)

    def set_bwd_mean_std(self):
        self.bwd_size_mean = float(self.bwd_size) / self.bwd_len
        self.bwd_size_std = self.get_std(self.bwd_len, self.bwd_size_ss, self.bwd_size_mean)

    def get_fwd_id(self, pkt):
        if self.proto == NetFlow.PROTOCOL_TCP:
            return "TCP {}:{} > {}:{}".format(pkt.ip.src, pkt.tcp.srcport, pkt.ip.dst, pkt.tcp.dstport)
        elif self.proto == NetFlow.PROTOCOL_UDP:
            return "UDP {}:{} > {}:{}".format(pkt.ip.src, pkt.udp.srcport, pkt.ip.dst, pkt.udp.dstport)
        elif self.proto == NetFlow.PROTOCOL_ICMP:
            pass

    def get_bwd_id(self, pkt):
        if self.proto == NetFlow.PROTOCOL_TCP:
            return "TCP {}:{} > {}:{}".format(pkt.ip.dst, pkt.tcp.dstport, pkt.ip.src, pkt.tcp.srcport)
        elif self.proto == NetFlow.PROTOCOL_UDP:
            return "UDP {}:{} > {}:{}".format(pkt.ip.dst, pkt.udp.dstport, pkt.ip.src, pkt.udp.srcport)
        elif self.proto == NetFlow.PROTOCOL_ICMP:
            pass

    def get_std(self, n, ss, mean):
        return sqrt((ss / float(n - 1)) - (n / float(n - 1)) * (mean * mean))

    def get_flow(self):
        pass