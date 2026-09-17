## Summary:
Big = 128KB, Small = 128B
- Fast Big: 29.4 Gbits/sec
- Fast Small: 2.63 Gbits/sec
- Slow Big: 29.2 Gbits/sec
- Slow Small: 2.60 Gbits/sec

## Details
```
$ task perf-mooring
task: [perf-server-start] docker exec clab-kind-with-bgp-domestic0 iperf3 -s -D
task: [perf-mooring-fast] echo "=== Mooring Fast Path: Big Packets ==="
kubectl exec -n default domestic1-client-kind-with-bgp-worker -- iperf3 -c 192.168.0.100 -t 30

=== Mooring Fast Path: Big Packets ===
Connecting to host 192.168.0.100, port 5201
[  5] local 10.64.0.3 port 48270 connected to 192.168.0.100 port 5201
[ ID] Interval           Transfer     Bitrate         Retr  Cwnd
[  5]   0.00-1.00   sec  3.32 GBytes  28.5 Gbits/sec    0    388 KBytes
[  5]   1.00-2.00   sec  3.08 GBytes  26.5 Gbits/sec    0    507 KBytes
[  5]   2.00-3.00   sec  3.31 GBytes  28.4 Gbits/sec    0    747 KBytes
[  5]   3.00-4.00   sec  3.44 GBytes  29.5 Gbits/sec    0    784 KBytes
[  5]   4.00-5.00   sec  2.89 GBytes  24.9 Gbits/sec    0   1.11 MBytes
[  5]   5.00-6.00   sec  3.24 GBytes  27.8 Gbits/sec    0   1.11 MBytes
[  5]   6.00-7.00   sec  3.38 GBytes  29.1 Gbits/sec    0   1.11 MBytes
[  5]   7.00-8.00   sec  3.25 GBytes  27.9 Gbits/sec    0   1.32 MBytes
[  5]   8.00-9.00   sec  2.55 GBytes  21.9 Gbits/sec    0   1.38 MBytes
[  5]   9.00-10.00  sec  3.36 GBytes  28.8 Gbits/sec    0   1.38 MBytes
[  5]  10.00-11.00  sec  2.36 GBytes  20.3 Gbits/sec    0   1.38 MBytes
[  5]  11.00-12.00  sec  3.37 GBytes  29.0 Gbits/sec    0   1.38 MBytes
[  5]  12.00-13.00  sec  3.36 GBytes  28.9 Gbits/sec    0   1.38 MBytes
[  5]  13.00-14.00  sec  3.34 GBytes  28.7 Gbits/sec    0   1.38 MBytes
[  5]  14.00-15.00  sec  3.40 GBytes  29.2 Gbits/sec    0   1.38 MBytes
[  5]  15.00-16.00  sec  3.32 GBytes  28.5 Gbits/sec    0   1.38 MBytes
[  5]  16.00-17.00  sec  3.26 GBytes  28.0 Gbits/sec    0   1.38 MBytes
[  5]  17.00-18.00  sec  3.35 GBytes  28.8 Gbits/sec    0   1.38 MBytes
[  5]  18.00-19.00  sec  3.31 GBytes  28.5 Gbits/sec    0   1.38 MBytes
[  5]  19.00-20.00  sec  3.42 GBytes  29.4 Gbits/sec    0   1.38 MBytes
[  5]  20.00-21.00  sec  3.34 GBytes  28.6 Gbits/sec    0   3.23 MBytes
[  5]  21.00-22.00  sec  3.26 GBytes  28.1 Gbits/sec    0   3.23 MBytes
[  5]  22.00-23.00  sec  3.42 GBytes  29.3 Gbits/sec    0   3.23 MBytes
[  5]  23.00-24.00  sec  3.31 GBytes  28.5 Gbits/sec    0   3.23 MBytes
[  5]  24.00-25.00  sec  3.34 GBytes  28.7 Gbits/sec    0   3.23 MBytes
[  5]  25.00-26.00  sec  3.40 GBytes  29.2 Gbits/sec    0   3.23 MBytes
[  5]  26.00-27.00  sec  3.27 GBytes  28.1 Gbits/sec    0   3.23 MBytes
[  5]  27.00-28.00  sec  2.72 GBytes  23.3 Gbits/sec    0   3.23 MBytes
[  5]  28.00-29.00  sec  3.33 GBytes  28.6 Gbits/sec    0   3.23 MBytes
[  5]  29.00-30.00  sec  3.45 GBytes  29.6 Gbits/sec    0   3.23 MBytes
- - - - - - - - - - - - - - - - - - - - - - - - -
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-30.00  sec   103 GBytes  29.4 Gbits/sec    0             sender
[  5]   0.00-30.00  sec   103 GBytes  29.4 Gbits/sec                  receiver

iperf Done.
task: [perf-mooring-fast] echo "=== Mooring Fast Path: Small Packets (128-byte blocks) ==="
kubectl exec -n default domestic1-client-kind-with-bgp-worker -- iperf3 -c 192.168.0.100 -t 30 -l 128

=== Mooring Fast Path: Small Packets (128-byte blocks) ===
Connecting to host 192.168.0.100, port 5201
[  5] local 10.64.0.3 port 32974 connected to 192.168.0.100 port 5201
[ ID] Interval           Transfer     Bitrate         Retr  Cwnd
[  5]   0.00-1.00   sec   314 MBytes  2.63 Gbits/sec    0    240 KBytes
[  5]   1.00-2.00   sec   313 MBytes  2.63 Gbits/sec    0    240 KBytes
[  5]   2.00-3.00   sec   313 MBytes  2.63 Gbits/sec    0    240 KBytes
[  5]   3.00-4.00   sec   314 MBytes  2.63 Gbits/sec    0    240 KBytes
[  5]   4.00-5.00   sec   312 MBytes  2.62 Gbits/sec    0    240 KBytes
[  5]   5.00-6.00   sec   311 MBytes  2.61 Gbits/sec    0    240 KBytes
[  5]   6.00-7.00   sec   313 MBytes  2.63 Gbits/sec    0    240 KBytes
[  5]   7.00-8.00   sec   312 MBytes  2.62 Gbits/sec    0    240 KBytes
[  5]   8.00-9.00   sec   310 MBytes  2.60 Gbits/sec    0    240 KBytes
[  5]   9.00-10.00  sec   311 MBytes  2.61 Gbits/sec    0    240 KBytes
[  5]  10.00-11.00  sec   313 MBytes  2.62 Gbits/sec    0    240 KBytes
[  5]  11.00-12.00  sec   313 MBytes  2.63 Gbits/sec    0    240 KBytes
[  5]  12.00-13.00  sec   313 MBytes  2.62 Gbits/sec    0    240 KBytes
[  5]  13.00-14.00  sec   312 MBytes  2.62 Gbits/sec    0    240 KBytes
[  5]  14.00-15.00  sec   314 MBytes  2.63 Gbits/sec    0    240 KBytes
[  5]  15.00-16.00  sec   312 MBytes  2.62 Gbits/sec    0    240 KBytes
[  5]  16.00-17.00  sec   315 MBytes  2.64 Gbits/sec    0    240 KBytes
[  5]  17.00-18.00  sec   313 MBytes  2.63 Gbits/sec    0    240 KBytes
[  5]  18.00-19.00  sec   312 MBytes  2.62 Gbits/sec    0    240 KBytes
[  5]  19.00-20.00  sec   314 MBytes  2.63 Gbits/sec    0    240 KBytes
[  5]  20.00-21.00  sec   313 MBytes  2.63 Gbits/sec    0    240 KBytes
[  5]  21.00-22.00  sec   313 MBytes  2.63 Gbits/sec    0    240 KBytes
[  5]  22.00-23.00  sec   313 MBytes  2.62 Gbits/sec    0    240 KBytes
[  5]  23.00-24.00  sec   314 MBytes  2.63 Gbits/sec    0    240 KBytes
[  5]  24.00-25.00  sec   314 MBytes  2.63 Gbits/sec    0    240 KBytes
[  5]  25.00-26.00  sec   315 MBytes  2.64 Gbits/sec    0    240 KBytes
[  5]  26.00-27.00  sec   313 MBytes  2.63 Gbits/sec    0    240 KBytes
[  5]  27.00-28.00  sec   313 MBytes  2.63 Gbits/sec    0    240 KBytes
[  5]  28.00-29.00  sec   315 MBytes  2.64 Gbits/sec    0    240 KBytes
[  5]  29.00-30.00  sec   313 MBytes  2.62 Gbits/sec    0    240 KBytes
- - - - - - - - - - - - - - - - - - - - - - - - -
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-30.00  sec  9.17 GBytes  2.63 Gbits/sec    0             sender
[  5]   0.00-30.00  sec  9.17 GBytes  2.63 Gbits/sec                  receiver

iperf Done.
task: [perf-mooring-slow] echo "=== Mooring Slow Path: Big Packets ==="
kubectl exec -n default domestic1-client-kind-with-bgp-worker2 -- iperf3 -c 192.168.0.100 -t 30

=== Mooring Slow Path: Big Packets ===
Connecting to host 192.168.0.100, port 5201
[  5] local 10.64.0.33 port 50092 connected to 192.168.0.100 port 5201
[ ID] Interval           Transfer     Bitrate         Retr  Cwnd
[  5]   0.00-1.00   sec  3.32 GBytes  28.5 Gbits/sec    0    840 KBytes
[  5]   1.00-2.00   sec  3.37 GBytes  28.9 Gbits/sec    0   1.03 MBytes
[  5]   2.00-3.00   sec  3.25 GBytes  27.9 Gbits/sec    0   1.03 MBytes
[  5]   3.00-4.00   sec  3.45 GBytes  29.6 Gbits/sec    0   1.03 MBytes
[  5]   4.00-5.00   sec  3.38 GBytes  29.0 Gbits/sec    0   1.03 MBytes
[  5]   5.00-6.00   sec  2.82 GBytes  24.2 Gbits/sec    0   1.03 MBytes
[  5]   6.00-7.00   sec  3.39 GBytes  29.1 Gbits/sec    0   1.03 MBytes
[  5]   7.00-8.00   sec  3.37 GBytes  29.0 Gbits/sec    0   1.03 MBytes
[  5]   8.00-9.00   sec  3.40 GBytes  29.2 Gbits/sec    0   1.58 MBytes
[  5]   9.00-10.00  sec  3.23 GBytes  27.7 Gbits/sec    0   1.58 MBytes
[  5]  10.00-11.00  sec  3.26 GBytes  28.0 Gbits/sec    0   1.58 MBytes
[  5]  11.00-12.00  sec  3.15 GBytes  27.1 Gbits/sec    0   2.36 MBytes
[  5]  12.00-13.00  sec  3.32 GBytes  28.5 Gbits/sec    0   2.36 MBytes
[  5]  13.00-14.00  sec  3.23 GBytes  27.7 Gbits/sec    0   2.36 MBytes
[  5]  14.00-15.00  sec  3.13 GBytes  26.9 Gbits/sec    0   2.36 MBytes
[  5]  15.00-16.00  sec  3.27 GBytes  28.1 Gbits/sec    0   2.36 MBytes
[  5]  16.00-17.00  sec  3.30 GBytes  28.4 Gbits/sec    0   2.36 MBytes
[  5]  17.00-18.00  sec  3.32 GBytes  28.5 Gbits/sec    0   2.36 MBytes
[  5]  18.00-19.00  sec  3.25 GBytes  28.0 Gbits/sec    0   2.36 MBytes
[  5]  19.00-20.00  sec  3.39 GBytes  29.1 Gbits/sec    0   2.36 MBytes
[  5]  20.00-21.00  sec  3.09 GBytes  26.6 Gbits/sec    0   2.36 MBytes
[  5]  21.00-22.00  sec  3.23 GBytes  27.7 Gbits/sec    0   2.36 MBytes
[  5]  22.00-23.00  sec  3.14 GBytes  27.0 Gbits/sec    0   2.36 MBytes
[  5]  23.00-24.00  sec  3.39 GBytes  29.1 Gbits/sec    0   2.36 MBytes
[  5]  24.00-25.00  sec  3.11 GBytes  26.7 Gbits/sec    0   2.36 MBytes
[  5]  25.00-26.00  sec  2.99 GBytes  25.7 Gbits/sec    0   2.36 MBytes
[  5]  26.00-27.00  sec  2.95 GBytes  25.3 Gbits/sec    0   2.36 MBytes
[  5]  27.00-28.00  sec  3.27 GBytes  28.1 Gbits/sec    0   2.36 MBytes
[  5]  28.00-29.00  sec  2.97 GBytes  25.5 Gbits/sec    0   2.36 MBytes
[  5]  29.00-30.00  sec  3.12 GBytes  26.8 Gbits/sec    0   2.36 MBytes
- - - - - - - - - - - - - - - - - - - - - - - - -
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-30.00  sec   102 GBytes  29.2 Gbits/sec    0             sender
[  5]   0.00-30.00  sec   102 GBytes  29.2 Gbits/sec                  receiver

iperf Done.
task: [perf-mooring-slow] echo "=== Mooring Slow Path: Small Packets (128-byte blocks) ==="
kubectl exec -n default domestic1-client-kind-with-bgp-worker2 -- iperf3 -c 192.168.0.100 -t 30 -l 128

=== Mooring Slow Path: Small Packets (128-byte blocks) ===
Connecting to host 192.168.0.100, port 5201
[  5] local 10.64.0.33 port 57306 connected to 192.168.0.100 port 5201
[ ID] Interval           Transfer     Bitrate         Retr  Cwnd
[  5]   0.00-1.00   sec   310 MBytes  2.60 Gbits/sec    0    286 KBytes
[  5]   1.00-2.00   sec   307 MBytes  2.57 Gbits/sec    0    286 KBytes
[  5]   2.00-3.00   sec   305 MBytes  2.56 Gbits/sec    0    286 KBytes
[  5]   3.00-4.00   sec   308 MBytes  2.59 Gbits/sec    0    286 KBytes
[  5]   4.00-5.00   sec   309 MBytes  2.59 Gbits/sec    0    286 KBytes
[  5]   5.00-6.00   sec   307 MBytes  2.57 Gbits/sec    0    286 KBytes
[  5]   6.00-7.00   sec   309 MBytes  2.59 Gbits/sec    0    286 KBytes
[  5]   7.00-8.00   sec   311 MBytes  2.61 Gbits/sec    0    286 KBytes
[  5]   8.00-9.00   sec   312 MBytes  2.61 Gbits/sec    0    286 KBytes
[  5]   9.00-10.00  sec   310 MBytes  2.60 Gbits/sec    0    286 KBytes
[  5]  10.00-11.00  sec   310 MBytes  2.60 Gbits/sec    0    286 KBytes
[  5]  11.00-12.00  sec   310 MBytes  2.60 Gbits/sec    0    286 KBytes
[  5]  12.00-13.00  sec   310 MBytes  2.60 Gbits/sec    0    286 KBytes
[  5]  13.00-14.00  sec   309 MBytes  2.59 Gbits/sec    0    286 KBytes
[  5]  14.00-15.00  sec   310 MBytes  2.60 Gbits/sec    0    286 KBytes
[  5]  15.00-16.00  sec   311 MBytes  2.61 Gbits/sec    0    286 KBytes
[  5]  16.00-17.00  sec   311 MBytes  2.61 Gbits/sec    0    286 KBytes
[  5]  17.00-18.00  sec   311 MBytes  2.60 Gbits/sec    0    286 KBytes
[  5]  18.00-19.00  sec   309 MBytes  2.59 Gbits/sec    0    286 KBytes
[  5]  19.00-20.00  sec   310 MBytes  2.60 Gbits/sec    0    286 KBytes
[  5]  20.00-21.00  sec   310 MBytes  2.60 Gbits/sec    0    286 KBytes
[  5]  21.00-22.00  sec   310 MBytes  2.60 Gbits/sec    0    286 KBytes
[  5]  22.00-23.00  sec   310 MBytes  2.60 Gbits/sec    0    286 KBytes
[  5]  23.00-24.00  sec   310 MBytes  2.60 Gbits/sec    0    286 KBytes
[  5]  24.00-25.00  sec   310 MBytes  2.60 Gbits/sec    0    286 KBytes
[  5]  25.00-26.00  sec   310 MBytes  2.60 Gbits/sec    0    286 KBytes
[  5]  26.00-27.00  sec   309 MBytes  2.59 Gbits/sec    0    286 KBytes
[  5]  27.00-28.00  sec   309 MBytes  2.59 Gbits/sec    0    286 KBytes
[  5]  28.00-29.00  sec   308 MBytes  2.58 Gbits/sec    0    286 KBytes
[  5]  29.00-30.00  sec   310 MBytes  2.60 Gbits/sec    0    286 KBytes
- - - - - - - - - - - - - - - - - - - - - - - - -
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-30.00  sec  9.07 GBytes  2.60 Gbits/sec    0             sender
[  5]   0.00-30.00  sec  9.06 GBytes  2.60 Gbits/sec                  receiver

iperf Done.
task: [perf-server-stop] docker exec clab-kind-with-bgp-domestic0 pkill iperf3 || true
```
