import pandas as pd

# Define the number of rows per chunk
chunksize = 5000000 
cols = [
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


# Create an iterator by passing the chunksize argument
# This does not load the entire file into memory immediately
chunks = pd.read_csv('/mnt/8tb_hdd/harish/ds2/dataset.csv', chunksize=chunksize)
storage_spot = '/mnt/8tb_hdd/harish/ds2/splited/'
# Example: calculate the total sum of a 'sales' column across the entire file
dataset_number = 0
for chunk in chunks:

    # Process each chunk; for example, sum a column
    if dataset_number == 0:
        df = pd.DataFrame(chunk)
        df.to_csv(f'{storage_spot}dataset{dataset_number}.csv',index=False)
        print(f'write successfull for: {storage_spot}dataset{dataset_number}.csv')
        dataset_number += 1
    else:
        
        # Read the file without assuming a header, then assign the new names
        df = pd.DataFrame(chunk)
        df.columns = cols 
        
        # Save the DataFrame to a new CSV file
        df.to_csv(f"{storage_spot}dataset{dataset_number}.csv", index=False)
        print(f'write successfull for: {storage_spot}dataset{dataset_number}.csv')
        dataset_number +=1 
        

