import click
import json
import logging
import nest_asyncio
import os

from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from pyfiglet import Figlet
from pyshark import FileCapture

from netflow import NetFlow
from feature import feature


@click.command()
@click.option("-r", "--read-dir", "rd",
              help="Read packet data from DIR.",
              default="pcap", show_default=True)
@click.option("-w", "--write-dir", "wd",
              help="Write csv to DIR.",
              default="csv", show_default=True)
@click.option("-c", "--config", "conf",
              help="",
              default="config.json", show_default=True)
@click.option("-j", "--jobs", "jobs",
              help="Number of jobs to run simultaneously",
              default=4, show_default=True)
@click.option("--flow-timeout", "flow_timeout",
              help="Flow Timeout.",
              default=120000000, show_default=True)
@click.option("--activity-timeout", "activity_timeout",
              help="Activity Timeout.",
              default=5000000, show_default=True)
def main(rd, wd, conf, jobs, flow_timeout, activity_timeout):
    """ CIC Flow Meter """

    # rd check
    if not os.path.isdir(rd):
        click_fail("The read dir does not exist!")

    # wr check
    os.makedirs(wd, exist_ok=True)
    if not os.path.isdir(wd):
        click_fail("The write dir does not exist!")

    logging.debug("Infile: %s", rd)
    logging.debug("Outfile: %s", wd)

    # Read configuration file
    with open(conf, "r") as f:
        config = json.load(f)

    for key, val in config.items():
        # Check 'enable'
        if "enable" in val and not val["enable"]:
            continue

        # Check 'proto'
        if "proto" not in val:
            val["proto"] = "all"

        # Handle 'tcp', 'udp'
        for proto in ["tcp", "udp"]:
            if val["proto"] == proto or val["proto"] == "all":
                # Check 'tcp_index', 'udp_index'
                if proto + "_index" not in val:
                    index = get_index_from_pcap(os.path.join(rd, key), proto)
                else:
                    index = get_index_from_str(val["tcp_index"])

                # Check 'label'
                if "label" not in val:
                    val["label"] = None

                not_done = []

                # Calculate features from TCP or UDP stream
                with ThreadPoolExecutor(max_workers=jobs) as executor:
                    for i in index:
                        not_done.append(executor.submit(worker, os.path.join(rd, key), proto, i, val["label"]))

                    while not_done:
                        done, not_done = wait(not_done, return_when=FIRST_COMPLETED)
                        feature.append(done.pop().result())

                feature.export(os.path.join(wd, "out.csv"))


def click_fail(msg):
    with click.Context(main) as context:
        context.fail(msg)


def get_index_from_str(string):
    return sum(((list(range(*[int(b) + c
                              for c, b in enumerate(a.split('-'))]))
                 if '-' in a else [int(a)]) for a in string.split(',')), [])


def get_index_from_pcap(pcap, proto):
    pkts = FileCapture(pcap, display_filter=proto, keep_packets=False)
    count = -1
    for pkt in pkts:
        count = max(int(pkt[proto].stream), count)
    return range(count + 1)


def worker(pcap, proto, idx, label=None):
    filter = "{}.stream eq {}".format(proto, idx)
    pkts = FileCapture(pcap, display_filter=filter, keep_packets=False)
    flow = NetFlow(pkts, proto)
    source = "{}-{}-{}".format(pcap, proto, idx)
    return flow.to_df(source, label)


if __name__ == "__main__":
    # Figlet
    f = Figlet(font="standard")
    print(f.renderText("CICFlowMeter"))

    # logging
    logging.getLogger().setLevel(logging.ERROR)

    # RuntimeError: Cannot run the event loop while another loop is running
    nest_asyncio.apply()

    # Click CLI
    main()
