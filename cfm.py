import click
import logging
import mimetypes
import os
import sys
from pyfiglet import Figlet


def click_fail(msg):
    with click.Context(main) as context:
        context.fail(msg)


@click.command()
@click.option("-r", "--read-file", "rd",
              help="Read packet data from TEXT.",
              required=True)
@click.option("-w", "--write-file", "wr",
              help="Write packet data to TEXT.",
              default="out.csv", show_default=True)
@click.option("--flow-timeout", "flow_timeout",
              help="Flow Timeout.",
              default=120000000, show_default=True)
@click.option("--activity-timeout", "activity_timeout",
              help="Activity Timeout.",
              default=5000000, show_default=True)
def main(rd, wr, flow_timeout, activity_timeout):
    """ CIC Flow Meter """

    # rd check
    if not os.path.isfile(rd):
        click_fail("The pcap file does not exist!")

    if not os.access(rd, os.R_OK):
        click_fail("The pcap file is not readable.")

    # TODO: .pcap MIME

    # wr check

    # TODO: wr check

    logging.debug("Infile: %s", rd)
    logging.debug("Outfile: %s", wr)


if __name__ == "__main__":
    # logging
    logging.getLogger().setLevel(logging.DEBUG)

    # Figlet
    f = Figlet(font="standard")
    print(f.renderText("CICFlowMeter"))

    # Click CLI
    main()
