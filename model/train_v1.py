import numpy as np
import pandas as pd
import warnings
import os 

warnings.simplefilter(action='ignore', category=RuntimeWarning)
# Define the number of rows per chunk
CHUNKSIZE = 100000
COLS = [
    "IPV4_SRC_ADDR",
    "L4_SRC_PORT",
    "IPV4_DST_ADDR",
    "L4_DST_PORT",
    "PROTOCOL",
    "L7_PROTO",
    "IN_BYTES",
    "IN_PKTS",
    "OUT_BYTES",
    "OUT_PKTS",
    "TCP_FLAGS",
    "CLIENT_TCP_FLAGS",
    "SERVER_TCP_FLAGS",
    "FLOW_DURATION_MILLISECONDS",
    "DURATION_IN",
    "DURATION_OUT",
    "MIN_TTL",
    "MAX_TTL",
    "LONGEST_FLOW_PKT",
    "SHORTEST_FLOW_PKT",
    "MIN_IP_PKT_LEN",
    "MAX_IP_PKT_LEN",
    "SRC_TO_DST_SECOND_BYTES",
    "DST_TO_SRC_SECOND_BYTES",
    "RETRANSMITTED_IN_BYTES",
    "RETRANSMITTED_IN_PKTS",
    "RETRANSMITTED_OUT_BYTES",
    "RETRANSMITTED_OUT_PKTS",
    "SRC_TO_DST_AVG_THROUGHPUT",
    "DST_TO_SRC_AVG_THROUGHPUT",
    "NUM_PKTS_UP_TO_128_BYTES",
    "NUM_PKTS_128_TO_256_BYTES",
    "NUM_PKTS_256_TO_512_BYTES",
    "NUM_PKTS_512_TO_1024_BYTES",
    "NUM_PKTS_1024_TO_1514_BYTES",
    "TCP_WIN_MAX_IN",
    "TCP_WIN_MAX_OUT",
    "ICMP_TYPE",
    "ICMP_IPV4_TYPE",
    "DNS_QUERY_ID",
    "DNS_QUERY_TYPE",
    "DNS_TTL_ANSWER",
    "FTP_COMMAND_RET_CODE",
    "Label",
    "Attack",
    "Dataset",
]


def split_csv(csv_location):
    storage_location = "/home/h4r15h/dataset/sniffy/splitted/"
    counter = 0
    chunks = pd.read_csv(csv_location, chunksize=CHUNKSIZE)
    for chunk in chunks:
        if counter == 0:
            df = pd.DataFrame(chunk)
            df.to_csv(f'{storage_location}dataset{counter}.csv')
            print(f"Write succussful for :{storage_location}dataset{counter}.csv")
            counter +=1
        else:
            df = pd.DataFrame(chunk)
            df.columns = COLS
            df.to_csv(f'{storage_location}dataset{counter}.csv')
            print(f"Write succussful for :{storage_location}dataset{counter}.csv")
            counter +=1



def import_data(csv_location):
    raw_dataset = pd.read_csv(csv_location)
    np_array = raw_dataset.to_numpy()
    return np_array

