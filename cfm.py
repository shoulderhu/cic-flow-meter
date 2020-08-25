import click
import json
import logging
import os
from pyfiglet import Figlet
from pyshark import FileCapture

from NetFlow import NetFlow


@click.command()
@click.option("-r", "--read-dir", "rd",
              help="Read packet data from TEXT.",
              default=".", show_default=True)
@click.option("-w", "--write-dir", "wd",
              help="Write packet data to TEXT.",
              default="out.csv", show_default=True)
@click.option("--flow-timeout", "flow_timeout",
              help="Flow Timeout.",
              default=120000000, show_default=True)
@click.option("--activity-timeout", "activity_timeout",
              help="Activity Timeout.",
              default=5000000, show_default=True)
def main(rd, wd, flow_timeout, activity_timeout):
    """ CIC Flow Meter """

    # rd check
    # if not os.path.isfile(rd):
    #     click_fail("The pcap file does not exist!")

    # if not os.access(rd, os.R_OK):
    #     click_fail("The pcap file is not readable.")

    # TODO: .pcap MIME

    # wr check

    # TODO: wr check

    logging.debug("Infile: %s", rd)
    logging.debug("Outfile: %s", wd)

    get_flow(rd)
    print()


def click_fail(msg):
    with click.Context(main) as context:
        context.fail(msg)


def get_flow(rd):
    # config
    with open("config.json", "r") as f:
        config = json.load(f)

    for key, val in config.items():
        for i in [2]: # val["index"]:
            filter = "{}.stream eq {}".format(val["proto"], i)
            pkts = FileCapture(os.path.join(rd, val["path"]),
                               display_filter=filter, keep_packets=False)
            flow = NetFlow(pkts, val["proto"])


if __name__ == "__main__":
    # Figlet
    f = Figlet(font="standard")
    print(f.renderText("CICFlowMeter"))

    # logging
    logging.getLogger().setLevel(logging.ERROR)

    # Click CLI
    main()
