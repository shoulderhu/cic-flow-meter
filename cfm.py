import click
import csv
import json
import logging
import magic
import os

from concurrent.futures import ProcessPoolExecutor, wait, FIRST_COMPLETED
from pyfiglet import Figlet

import dpkt
from dpkt.ethernet import Ethernet, ETH_TYPE_IP, ETH_TYPE_IP6
from dpkt.ip import IP_PROTO_TCP, IP_PROTO_UDP
from socket import inet_ntop, AF_INET, AF_INET6

from tcpflow import TCPFlow
from feature import Feature

PCAP   = "application/vnd.tcpdump.pcap"
PCAPNG = "application/octet-stream"


@click.command()
@click.option("-c", "--config", "conf",
              help="",
              default="config.json", show_default=True)
@click.option("-j", "--jobs", "jobs",
              help="Number of jobs to run simultaneously",
              default=4, show_default=True)
def main(conf, jobs):
    """ CIC Flow Meter """

    # Check config file exists
    logging.debug("Config: %s", conf)
    if not os.path.isfile(conf):
        click_fail("The config file does not exist!")

    # Read configuration file
    with open(conf, "r") as f:
        config = json.load(f)

    # Check read dir exists
    logging.debug("Input Directory: %s", config["read-dir"])
    if not os.path.isdir(config["read-dir"]):
        click_fail("The read dir does not exist!")

    # Create wite dir
    os.makedirs(config["write-dir"], exist_ok=True)

    # Check write dir exists
    logging.debug("Output Directory: %s", config["write-dir"])
    if not os.path.isdir(config["write-dir"]):
        click_fail("The write dir does not exist!")

    # Threading
    not_done = []
    with ProcessPoolExecutor(max_workers=jobs) as executor:
        # Read pcap files
        for key, val in config["pcap"].items():
            # Check 'enable' (default: False)
            if "enable" in val and not val["enable"]:
                continue

            # Check 'proto'
            if "proto" not in val or val["proto"] not in ["tcp", "udp"]:
                val["proto"] = "tcp || udp"

            # Check 'index'
            if "index" not in val:
                val["index"] = {}

            # Check 'tcp/udp index'
            for tl in ["tcp", "udp"]:
                if tl not in val["index"]:
                    val["index"][tl] = None
                else:
                    if "txt" in val["index"][tl]:
                        with open(os.path.join(config["read-dir"], val["index"][tl]), "r") as txt:
                            val["index"][tl] = get_index_from_str(txt.read())
                    else:
                        val["index"][tl] = get_index_from_str(val["index"][tl])

            # Check 'label'
            if "label" not in val:
                val["label"] = None

            print(key)

            # Submit jobs
            not_done.append(executor.submit(worker,
                                            os.path.join(config["read-dir"], key),
                                            val["proto"],
                                            val["index"],
                                            val["label"],
                                            os.path.join(config["write-dir"], val["output"])))

        while not_done:
            done, not_done = wait(not_done, return_when=FIRST_COMPLETED)
            print("{} done".format(done.pop().result()))
            # Debug
            # worker(os.path.join(config["read-dir"], key),
            #        val["proto"],
            #        val["index"],
            #        val["label"],
            #        os.path.join(config["write-dir"], val["output"]))


def click_fail(msg):
    with click.Context(main) as context:
        context.fail(msg)


def get_index_from_str(string):
    return sum(((list(range(*[int(b) + c
                              for c, b in enumerate(a.split('-'))]))
                 if '-' in a else [int(a)]) for a in string.split(',')), [])


def get_pkt_id(src, sport, dst, dport, proto=IP_PROTO_TCP, v=4):
    if sport < dport:
        src, sport, dst, dport = dst, dport, src, sport

    if proto == IP_PROTO_TCP:
        p = "TCP"
    elif proto == IP_PROTO_UDP:
        p = "UDP"
    else:
        raise ValueError("Argument proto must be TCP or UDP")

    if v == 4:
        sep = ":"
        src = inet_ntop(AF_INET, src)
        dst = inet_ntop(AF_INET, dst)
    elif v == 6:
        sep = "."
        src = inet_ntop(AF_INET6, src)
        dst = inet_ntop(AF_INET6, dst)
    else:
        raise ValueError("Argument v must be AF_INET or AF_INET6")

    return "{} {}{}{} <> {}{}{}".format(p,
                                        src, sep, sport,
                                        dst, sep, dport)


def worker(pcap, filter, index, label, out):
    f = open(pcap, "rb")
    mime = magic.from_file(pcap, mime=True)

    if mime == PCAP:
        pkts = dpkt.pcap.Reader(f)
    elif mime == PCAPNG:
        pkts = dpkt.pcapng.Reader(f)
    else:
        raise ValueError("Argument pcap must be pcap or pcapng")

    id_to_index = {
        IP_PROTO_TCP: {},
        IP_PROTO_UDP: {}
    }
    flows = {
        IP_PROTO_TCP: {},
        IP_PROTO_UDP: {}
    }
    data = [Feature.col]
    length = 0

    for i, (ts, buf) in enumerate(pkts):
        eth = Ethernet(buf)
        if eth.type != ETH_TYPE_IP:
            continue

        ip = eth.data
        if ip.p == IP_PROTO_TCP:  # Handle TCP
            tcp = ip.data

            # Create new id to index mapping
            id = get_pkt_id(ip.src, tcp.sport, ip.dst, tcp.dport, ip.p, ip.v)
            if id not in id_to_index[ip.p]:
                id_to_index[ip.p][id] = length
                length += 1

            # Check requirement
            # if index["tcp"] is not None and idx not in index["tcp"]:
            #     continue

            # Create new flow
            idx = id_to_index[ip.p][id]
            if idx not in flows[ip.p]:
                flows[ip.p][idx] = TCPFlow(id, ts, tcp, i)
            else:
                if tcp.flags == 2:  # [TCP Port numbers reused]
                    if index["tcp"] is None or idx in index["tcp"]:
                        source = "{}-{}-{}".format(pcap, ip.p, idx)
                        data.append(flows[ip.p][idx].to_list(source, label))
                    flows[ip.p].pop(idx, None)
                    id_to_index[ip.p][id] = length
                    flows[ip.p][length] = TCPFlow(id, ts, tcp, i)
                    length += 1
                else:
                    flows[ip.p][idx].upd_flow(ts, tcp, i)
        elif ip.p == IP_PROTO_UDP:  # Handle UDP
            udp = ip.data
            # TODO

    f.close()
    print("{} prepare to write".format(pcap))

    for p in [IP_PROTO_TCP, IP_PROTO_UDP]:
        for idx, flow in flows[p].items():
            if index["tcp"] is None or idx in index["tcp"]:
                source = "{}-{}-{}".format(pcap, p, idx)
                data.append(flow.to_list(source, label))

    with open(out, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerows(data)
        print("{}: {} lines".format(pcap, len(data) - 1))

    return out


if __name__ == "__main__":
    # Figlet
    f = Figlet(font="standard")
    print(f.renderText("CICFlowMeter"))

    # logging
    logging.getLogger().setLevel(logging.ERROR)

    # Click CLI
    main()
