import pandas as pd


class Feature:
    col = ["Flow ID", "Timestamp", "Duration",
           "Flow Pkt Len", "Flow Pkt Size", "Flow Pkt Size Min", "Flow Pkt Size Max", "Flow Pkt Size Mean", "Flow Pkt Size Std",
           "Fwd Pkt Len", "Fwd Pkt Size", "Fwd Pkt Size Min", "Fwd Pkt Size Max", "Fwd Pkt Size Mean", "Fwd Pkt Size Std",
           "Bwd Pkt Len", "Bwd Pkt Size", "Bwd Pkt Size Min", "Bwd Pkt Size Max", "Bwd Pkt Size Mean", "Bwd Pkt Size Std",
           "Flow Pkts/s", "Flow Bytes/s", "Fwd Pkts/s", "Fwd Bytes/s", "Bwd Pkts/s", "Bwd Bytes/s",
           "Flow IAT Total", "Flow IAT Min", "Flow IAT Max", "Flow IAT Mean", "Flow IAT Std",
           "Fwd IAT Total", "Fwd IAT Min", "Fwd IAT Max", "Fwd IAT Mean", "Fwd IAT Std",
           "Bwd IAT Total", "Bwd IAT Min", "Bwd IAT Max", "Bwd IAT Mean", "Bwd IAT Std",
           "Fwd PSH Flags", "Fwd URG Flags", "Bwd PSH Flags", "Bwd URG Flags",
           "Flow FIN Flags", "Flow SYN Flags", "Flow RST Flags", "Flow PSH Flags",
           "Flow ACK Flags", "Flow URG Flags", "Flow ECE Flags", "Flow CWR Flags",
           "Fwd Header Size", "Bwd Hdr Size", "Down/Up Ratio",
           "Fwd Window Size", "Bwd Window Size",
           "Fwd Payload Len", "Source", "Label"]
    idx = list(set(range(len(col))) - {col.index("Flow ID"), col.index("Timestamp"),
                                       col.index("Source"), col.index("Label")})

    def __init__(self):
        self.df = pd.DataFrame(columns=Feature.col)

    def append(self, result):
        self.df = self.df.append(result)

    def export(self, path):
        self.df.to_csv(path, index=False)


feature = Feature()
