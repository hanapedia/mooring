## Summary:
Big = 128KB, Small = 128B
- Fast Big: 30.0 Gbits/sec
- Fast Small: 2.64 Gbits/sec
- Slow Big: 30.2 Gbits/sec
- Slow Small: 2.61 Gbits/sec

## Details
```
$ task perf-mooring
task: [perf-server-start] docker exec clab-kind-with-bgp-domestic0 iperf3 -s -D
task: [perf-mooring-fast] echo "=== Mooring Fast Path: Big Packets ==="
kubectl exec -n default domestic1-client-kind-with-bgp-worker -- iperf3 -c 192.168.0.100 -t 30

=== Mooring Fast Path: Big Packets ===
Connecting to host 192.168.0.100, port 5201
[  5] local 10.64.1.125 port 34686 connected to 192.168.0.100 port 5201
[ ID] Interval           Transfer     Bitrate         Retr  Cwnd
[  5]   0.00-1.00   sec  3.40 GBytes  29.2 Gbits/sec    0    378 KBytes
[  5]   1.00-2.00   sec  3.42 GBytes  29.4 Gbits/sec    0    498 KBytes
[  5]   2.00-3.00   sec  3.17 GBytes  27.2 Gbits/sec    0    498 KBytes
[  5]   3.00-4.00   sec  3.39 GBytes  29.1 Gbits/sec    0    950 KBytes
[  5]   4.00-5.00   sec  3.32 GBytes  28.5 Gbits/sec    0    996 KBytes
[  5]   5.00-6.00   sec  3.15 GBytes  27.1 Gbits/sec    0   1.09 MBytes
[  5]   6.00-7.00   sec  3.24 GBytes  27.8 Gbits/sec    0   1.09 MBytes
[  5]   7.00-8.00   sec  3.50 GBytes  30.1 Gbits/sec    0   1.09 MBytes
[  5]   8.00-9.00   sec  3.39 GBytes  29.1 Gbits/sec    0   1.09 MBytes
[  5]   9.00-10.00  sec  3.18 GBytes  27.3 Gbits/sec    0   1.09 MBytes
[  5]  10.00-11.00  sec  3.28 GBytes  28.1 Gbits/sec    0   2.46 MBytes
[  5]  11.00-12.00  sec  3.12 GBytes  26.8 Gbits/sec    0   2.46 MBytes
[  5]  12.00-13.00  sec  3.46 GBytes  29.7 Gbits/sec    0   2.46 MBytes
[  5]  13.00-14.00  sec  2.94 GBytes  25.2 Gbits/sec    0   2.46 MBytes
[  5]  14.00-15.00  sec  3.32 GBytes  28.5 Gbits/sec    0   2.46 MBytes
[  5]  15.00-16.00  sec  3.04 GBytes  26.1 Gbits/sec    0   2.46 MBytes
[  5]  16.00-17.00  sec  2.67 GBytes  22.9 Gbits/sec    0   2.46 MBytes
[  5]  17.00-18.00  sec  3.48 GBytes  29.9 Gbits/sec    0   2.46 MBytes
[  5]  18.00-19.00  sec  3.41 GBytes  29.3 Gbits/sec    0   2.46 MBytes
[  5]  19.00-20.00  sec  3.31 GBytes  28.4 Gbits/sec    0   2.46 MBytes
[  5]  20.00-21.00  sec  3.44 GBytes  29.5 Gbits/sec    0   2.46 MBytes
[  5]  21.00-22.00  sec  3.38 GBytes  29.0 Gbits/sec    0   2.46 MBytes
[  5]  22.00-23.00  sec  3.36 GBytes  28.8 Gbits/sec    0   2.46 MBytes
[  5]  23.00-24.00  sec  3.42 GBytes  29.4 Gbits/sec    0   2.46 MBytes
[  5]  24.00-25.00  sec  3.38 GBytes  29.1 Gbits/sec    0   2.46 MBytes
[  5]  25.00-26.00  sec  3.02 GBytes  26.0 Gbits/sec    0   2.46 MBytes
[  5]  26.00-27.00  sec  3.40 GBytes  29.2 Gbits/sec    0   2.46 MBytes
[  5]  27.00-28.00  sec  3.10 GBytes  26.6 Gbits/sec    0   2.46 MBytes
[  5]  28.00-29.00  sec  2.89 GBytes  24.8 Gbits/sec    0   2.46 MBytes
[  5]  29.00-30.00  sec  2.95 GBytes  25.3 Gbits/sec    0   2.46 MBytes
- - - - - - - - - - - - - - - - - - - - - - - - -
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-30.00  sec   105 GBytes  30.0 Gbits/sec    0             sender
[  5]   0.00-30.00  sec   105 GBytes  30.0 Gbits/sec                  receiver

iperf Done.
task: [perf-mooring-fast] echo "=== Mooring Fast Path: Small Packets (128-byte blocks) ==="
kubectl exec -n default domestic1-client-kind-with-bgp-worker -- iperf3 -c 192.168.0.100 -t 30 -l 128

=== Mooring Fast Path: Small Packets (128-byte blocks) ===
Connecting to host 192.168.0.100, port 5201
[  5] local 10.64.1.125 port 45600 connected to 192.168.0.100 port 5201
[ ID] Interval           Transfer     Bitrate         Retr  Cwnd
[  5]   0.00-1.00   sec   315 MBytes  2.64 Gbits/sec    0    240 KBytes
[  5]   1.00-2.00   sec   312 MBytes  2.62 Gbits/sec    0    240 KBytes
[  5]   2.00-3.00   sec   313 MBytes  2.62 Gbits/sec    0    240 KBytes
[  5]   3.00-4.00   sec   313 MBytes  2.62 Gbits/sec    0    240 KBytes
[  5]   4.00-5.00   sec   313 MBytes  2.62 Gbits/sec    0    240 KBytes
[  5]   5.00-6.00   sec   314 MBytes  2.64 Gbits/sec    0    240 KBytes
[  5]   6.00-7.00   sec   315 MBytes  2.64 Gbits/sec    0    240 KBytes
[  5]   7.00-8.00   sec   313 MBytes  2.63 Gbits/sec    0    240 KBytes
[  5]   8.00-9.00   sec   314 MBytes  2.63 Gbits/sec    0    240 KBytes
[  5]   9.00-10.00  sec   315 MBytes  2.64 Gbits/sec    0    240 KBytes
[  5]  10.00-11.00  sec   314 MBytes  2.64 Gbits/sec    0    240 KBytes
[  5]  11.00-12.00  sec   313 MBytes  2.63 Gbits/sec    0    240 KBytes
[  5]  12.00-13.00  sec   315 MBytes  2.64 Gbits/sec    0    240 KBytes
[  5]  13.00-14.00  sec   314 MBytes  2.63 Gbits/sec    0    240 KBytes
[  5]  14.00-15.00  sec   314 MBytes  2.63 Gbits/sec    0    240 KBytes
[  5]  15.00-16.00  sec   314 MBytes  2.64 Gbits/sec    0    240 KBytes
[  5]  16.00-17.00  sec   315 MBytes  2.64 Gbits/sec    0    240 KBytes
[  5]  17.00-18.00  sec   315 MBytes  2.64 Gbits/sec    0    240 KBytes
[  5]  18.00-19.00  sec   315 MBytes  2.64 Gbits/sec    0    240 KBytes
[  5]  19.00-20.00  sec   314 MBytes  2.63 Gbits/sec    0    240 KBytes
[  5]  20.00-21.00  sec   312 MBytes  2.62 Gbits/sec    0    240 KBytes
[  5]  21.00-22.00  sec   314 MBytes  2.63 Gbits/sec    0    240 KBytes
[  5]  22.00-23.00  sec   316 MBytes  2.65 Gbits/sec    0    240 KBytes
[  5]  23.00-24.00  sec   315 MBytes  2.64 Gbits/sec    0    240 KBytes
[  5]  24.00-25.00  sec   314 MBytes  2.63 Gbits/sec    0    240 KBytes
[  5]  25.00-26.00  sec   314 MBytes  2.64 Gbits/sec    0    240 KBytes
[  5]  26.00-27.00  sec   315 MBytes  2.64 Gbits/sec    0    240 KBytes
[  5]  27.00-28.00  sec   316 MBytes  2.65 Gbits/sec    0    240 KBytes
[  5]  28.00-29.00  sec   316 MBytes  2.65 Gbits/sec    0    240 KBytes
[  5]  29.00-30.00  sec   316 MBytes  2.65 Gbits/sec    0    240 KBytes
- - - - - - - - - - - - - - - - - - - - - - - - -
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-30.00  sec  9.21 GBytes  2.64 Gbits/sec    0             sender
[  5]   0.00-30.00  sec  9.20 GBytes  2.64 Gbits/sec                  receiver

iperf Done.
task: [perf-mooring-slow] echo "=== Mooring Slow Path: Big Packets ==="
kubectl exec -n default domestic1-client-kind-with-bgp-worker2 -- iperf3 -c 192.168.0.100 -t 30

=== Mooring Slow Path: Big Packets ===
Connecting to host 192.168.0.100, port 5201
[  5] local 10.64.2.101 port 50348 connected to 192.168.0.100 port 5201
[ ID] Interval           Transfer     Bitrate         Retr  Cwnd
[  5]   0.00-1.00   sec  3.43 GBytes  29.4 Gbits/sec    0    258 KBytes
[  5]   1.00-2.00   sec  3.17 GBytes  27.2 Gbits/sec    0    554 KBytes
[  5]   2.00-3.00   sec  3.19 GBytes  27.4 Gbits/sec    0    554 KBytes
[  5]   3.00-4.00   sec  3.49 GBytes  30.0 Gbits/sec    0    554 KBytes
[  5]   4.00-5.00   sec  3.47 GBytes  29.8 Gbits/sec    0    895 KBytes
[  5]   5.00-6.00   sec  3.39 GBytes  29.1 Gbits/sec    0    895 KBytes
[  5]   6.00-7.00   sec  3.30 GBytes  28.3 Gbits/sec    0    895 KBytes
[  5]   7.00-8.00   sec  3.45 GBytes  29.7 Gbits/sec    0    895 KBytes
[  5]   8.00-9.00   sec  3.56 GBytes  30.6 Gbits/sec    0   1.40 MBytes
[  5]   9.00-10.00  sec  3.27 GBytes  28.1 Gbits/sec    0   1.40 MBytes
[  5]  10.00-11.00  sec  3.45 GBytes  29.6 Gbits/sec    0   1.40 MBytes
[  5]  11.00-12.00  sec  3.44 GBytes  29.5 Gbits/sec    0   1.40 MBytes
[  5]  12.00-13.00  sec  3.48 GBytes  29.9 Gbits/sec    0   1.40 MBytes
[  5]  13.00-14.00  sec  3.19 GBytes  27.4 Gbits/sec    0   1.40 MBytes
[  5]  14.00-15.00  sec  3.38 GBytes  29.0 Gbits/sec    0   1.40 MBytes
[  5]  15.00-16.00  sec  3.43 GBytes  29.5 Gbits/sec    0   2.10 MBytes
[  5]  16.00-17.00  sec  3.33 GBytes  28.6 Gbits/sec    0   2.10 MBytes
[  5]  17.00-18.00  sec  3.28 GBytes  28.2 Gbits/sec    0   2.10 MBytes
[  5]  18.00-19.00  sec  3.48 GBytes  29.9 Gbits/sec    0   2.10 MBytes
[  5]  19.00-20.00  sec  2.94 GBytes  25.3 Gbits/sec    0   2.10 MBytes
[  5]  20.00-21.00  sec  3.06 GBytes  26.3 Gbits/sec    0   2.10 MBytes
[  5]  21.00-22.00  sec  2.80 GBytes  24.0 Gbits/sec    0   2.10 MBytes
[  5]  22.00-23.00  sec  3.48 GBytes  29.9 Gbits/sec    0   2.10 MBytes
[  5]  23.00-24.00  sec  3.22 GBytes  27.7 Gbits/sec    0   2.10 MBytes
[  5]  24.00-25.00  sec  3.08 GBytes  26.5 Gbits/sec    0   2.10 MBytes
[  5]  25.00-26.00  sec  3.46 GBytes  29.7 Gbits/sec    0   2.10 MBytes
[  5]  26.00-27.00  sec  2.20 GBytes  18.9 Gbits/sec    0   2.10 MBytes
[  5]  27.00-28.00  sec  3.40 GBytes  29.2 Gbits/sec    0   2.10 MBytes
[  5]  28.00-29.00  sec  2.84 GBytes  24.4 Gbits/sec    0   2.10 MBytes
[  5]  29.00-30.00  sec  2.97 GBytes  25.5 Gbits/sec    0   2.10 MBytes
- - - - - - - - - - - - - - - - - - - - - - - - -
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-30.00  sec   105 GBytes  30.2 Gbits/sec    0             sender
[  5]   0.00-30.00  sec   105 GBytes  30.2 Gbits/sec                  receiver

iperf Done.
task: [perf-mooring-slow] echo "=== Mooring Slow Path: Small Packets (128-byte blocks) ==="
kubectl exec -n default domestic1-client-kind-with-bgp-worker2 -- iperf3 -c 192.168.0.100 -t 30 -l 128

=== Mooring Slow Path: Small Packets (128-byte blocks) ===
Connecting to host 192.168.0.100, port 5201
[  5] local 10.64.2.101 port 35688 connected to 192.168.0.100 port 5201
[ ID] Interval           Transfer     Bitrate         Retr  Cwnd
[  5]   0.00-1.00   sec   312 MBytes  2.62 Gbits/sec    0    443 KBytes
[  5]   1.00-2.00   sec   310 MBytes  2.60 Gbits/sec    0    443 KBytes
[  5]   2.00-3.00   sec   308 MBytes  2.58 Gbits/sec    0    443 KBytes
[  5]   3.00-4.00   sec   312 MBytes  2.61 Gbits/sec    0    443 KBytes
[  5]   4.00-5.00   sec   309 MBytes  2.60 Gbits/sec    0    443 KBytes
[  5]   5.00-6.00   sec   311 MBytes  2.61 Gbits/sec    0    443 KBytes
[  5]   6.00-7.00   sec   311 MBytes  2.61 Gbits/sec    0    443 KBytes
[  5]   7.00-8.00   sec   311 MBytes  2.61 Gbits/sec    0    443 KBytes
[  5]   8.00-9.00   sec   312 MBytes  2.61 Gbits/sec    0    443 KBytes
[  5]   9.00-10.00  sec   312 MBytes  2.62 Gbits/sec    0    443 KBytes
[  5]  10.00-11.00  sec   310 MBytes  2.60 Gbits/sec    0    443 KBytes
[  5]  11.00-12.00  sec   311 MBytes  2.61 Gbits/sec    0    443 KBytes
[  5]  12.00-13.00  sec   311 MBytes  2.61 Gbits/sec    0    443 KBytes
[  5]  13.00-14.00  sec   311 MBytes  2.61 Gbits/sec    0    443 KBytes
[  5]  14.00-15.00  sec   311 MBytes  2.61 Gbits/sec    0    443 KBytes
[  5]  15.00-16.00  sec   311 MBytes  2.61 Gbits/sec    0    443 KBytes
[  5]  16.00-17.00  sec   311 MBytes  2.61 Gbits/sec    0    443 KBytes
[  5]  17.00-18.00  sec   311 MBytes  2.61 Gbits/sec    0    443 KBytes
[  5]  18.00-19.00  sec   312 MBytes  2.61 Gbits/sec    0    443 KBytes
[  5]  19.00-20.00  sec   312 MBytes  2.62 Gbits/sec    0    443 KBytes
[  5]  20.00-21.00  sec   312 MBytes  2.62 Gbits/sec    0    443 KBytes
[  5]  21.00-22.00  sec   312 MBytes  2.61 Gbits/sec    0    443 KBytes
[  5]  22.00-23.00  sec   312 MBytes  2.62 Gbits/sec    0    443 KBytes
[  5]  23.00-24.00  sec   311 MBytes  2.61 Gbits/sec    0    443 KBytes
[  5]  24.00-25.00  sec   311 MBytes  2.61 Gbits/sec    0    443 KBytes
[  5]  25.00-26.00  sec   312 MBytes  2.62 Gbits/sec    0    443 KBytes
[  5]  26.00-27.00  sec   311 MBytes  2.61 Gbits/sec    0    443 KBytes
[  5]  27.00-28.00  sec   312 MBytes  2.61 Gbits/sec    0    443 KBytes
[  5]  28.00-29.00  sec   312 MBytes  2.61 Gbits/sec    0    443 KBytes
[  5]  29.00-30.00  sec   310 MBytes  2.60 Gbits/sec    0    443 KBytes
- - - - - - - - - - - - - - - - - - - - - - - - -
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-30.00  sec  9.11 GBytes  2.61 Gbits/sec    0             sender
[  5]   0.00-30.00  sec  9.11 GBytes  2.61 Gbits/sec                  receiver

iperf Done.
task: [perf-server-stop] docker exec clab-kind-with-bgp-domestic0 pkill iperf3 || true

```
