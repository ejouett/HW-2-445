import dpkt
import pandas as pd
import matplotlib.pyplot as plt

# Load the CSV exported from Wireshark
csv_file = "HW-2/board.csv"

# Read the CSV file into a DataFrame
df = pd.read_csv(csv_file)

# Ensure correct column names (modify if needed)
df.columns = [col.strip() for col in df.columns]  # Strip whitespace
required_columns = ["Time", "Source", "Destination", "Protocol", "Length", "Info"]
for col in required_columns:
    if col not in df.columns:
        raise ValueError(f"Missing required column: {col}")

# Filter ICMP packets
icmp_df = df[df["Protocol"] == "ICMP"].copy()

# Extract timestamps, lengths, and ICMP information
icmp_df["Time"] = pd.to_numeric(icmp_df["Time"])  # Convert time to float
icmp_df["Length"] = pd.to_numeric(icmp_df["Length"])  # Convert length to int

# Sorting packets by time
icmp_df.sort_values(by="Time", inplace=True)

# 1. Compute Average Latency (RTT)
request_times = {}
rtts = []
for _, row in icmp_df.iterrows():
    info = row["Info"]
    time = row["Time"]
    
    if "Echo (ping) request" in info:
        seq_num = info.split("seq=")[-1].split(" ")[0]  # Extract sequence number
        request_times[seq_num] = time
    elif "Echo (ping) reply" in info:
        seq_num = info.split("seq=")[-1].split(" ")[0]
        if seq_num in request_times:
            rtt = time - request_times[seq_num]
            rtts.append(rtt)

avg_latency = sum(rtts) / len(rtts) * 1000 if rtts else 0  # Convert to ms
print(f"Average ICMP Latency: {avg_latency:.2f} ms")

# 2. Compute Average Throughput
total_bytes = icmp_df["Length"].sum()
duration = icmp_df["Time"].max() - icmp_df["Time"].min()
avg_throughput = total_bytes / duration if duration > 0 else 0
print(f"Average Throughput: {avg_throughput:.2f} bytes/sec")

# 3. Plot Data Rate vs. Time
icmp_df["Time_Bin"] = icmp_df["Time"] // 1  # Group by second
data_rate = icmp_df.groupby("Time_Bin")["Length"].sum()

plt.figure(figsize=(10, 5))
plt.plot(data_rate.index, data_rate.values, marker="o", linestyle="-", color="b")
plt.xlabel("Time (seconds)")
plt.ylabel("Data Rate (bytes/sec)")
plt.title("ICMP Data Rate Over Time")
plt.grid()
plt.show()

# 4. Compute Loss Rate
num_requests = icmp_df["Info"].str.contains("Echo (ping) request").sum()
num_replies = icmp_df["Info"].str.contains("Echo (ping) reply").sum()
loss_rate = ((num_requests - num_replies) / num_requests * 100) if num_requests > 0 else 0
print(f"Packet Loss Rate: {loss_rate:.2f}%")
