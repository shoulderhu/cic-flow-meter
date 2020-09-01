import click
import json
import logging
import nest_asyncio
import os
import pandas as pd

from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, wait, FIRST_COMPLETED
from pyfiglet import Figlet
from pyshark import FileCapture

from netflow import NetFlow
from feature import Feature # feature


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


def worker(pcap, filter, index, label, csv):
    flows = {
        "tcp": {},
        "udp": {}
    }

    pkts = FileCapture(pcap, display_filter=filter, keep_packets=False)

    for idx, pkt in enumerate(pkts):
        tl = pkt.transport_layer.lower()
        stream = int(pkt[tl].stream)

        # Check requirement
        if index[tl] is not None and stream not in index[tl]:
            continue

        # Create new flow
        if stream not in flows[tl]:
            flows[tl][stream] = NetFlow(tl)

        # Calcualte statistics
        flows[tl][stream].upd_flow(pkt)

    df = pd.DataFrame(columns=Feature.col)

    for tl in ["tcp", "udp"]:
        for idx, flow in flows[tl].items():
            source = "{}-{}-{}".format(pcap, tl, idx)
            df = df.append(flow.to_df(source, label))

    df.to_csv(csv, index=False)
    return csv


if __name__ == "__main__":
    # Figlet
    f = Figlet(font="standard")
    print(f.renderText("CICFlowMeter"))

    # logging
    logging.getLogger().setLevel(logging.ERROR)

    # RuntimeError: Cannot run the event loop while another loop is running
    # nest_asyncio.apply()

    # Click CLI
    main()
