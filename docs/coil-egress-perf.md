## Summary:
Big = 128KB, Small = 128B
- Fast Big: 23.4 Gbits/sec
- Fast Small: 2.55 Gbits/sec
- Slow Big: 15.0 Gbits/sec
- Slow Small: 2.39 Gbits/sec

## Details
```
$ task perf-coil
task: [perf-server-start] docker exec clab-kind-with-bgp-domestic0 iperf3 -s -D
task: [perf-coil-fast] echo "=== Coil Fast Path: Big Packets ==="
kubectl exec -n default coil-perf-client-kind-with-bgp-worker -- iperf3 -c 192.168.0.100 -t 30

=== Coil Fast Path: Big Packets ===
Connecting to host 192.168.0.100, port 5201
[  5] local 10.64.0.33 port 53974 connected to 192.168.0.100 port 5201
[ ID] Interval           Transfer     Bitrate         Retr  Cwnd
[  5]   0.00-1.00   sec  2.68 GBytes  23.0 Gbits/sec    0    478 KBytes
[  5]   1.00-2.00   sec  2.71 GBytes  23.3 Gbits/sec    0    478 KBytes
[  5]   2.00-3.00   sec  2.71 GBytes  23.2 Gbits/sec    0    570 KBytes
[  5]   3.00-4.00   sec  2.72 GBytes  23.4 Gbits/sec    0    570 KBytes
[  5]   4.00-5.00   sec  2.72 GBytes  23.3 Gbits/sec    0    570 KBytes
[  5]   5.00-6.00   sec  2.71 GBytes  23.3 Gbits/sec    0    570 KBytes
[  5]   6.00-7.00   sec  2.72 GBytes  23.4 Gbits/sec    0    718 KBytes
[  5]   7.00-8.00   sec  2.73 GBytes  23.5 Gbits/sec    0    718 KBytes
[  5]   8.00-9.00   sec  2.73 GBytes  23.4 Gbits/sec    0    718 KBytes
[  5]   9.00-10.00  sec  2.72 GBytes  23.4 Gbits/sec    0   1.30 MBytes
[  5]  10.00-11.00  sec  2.75 GBytes  23.6 Gbits/sec    0   1.30 MBytes
[  5]  11.00-12.00  sec  2.69 GBytes  23.1 Gbits/sec    0   1.96 MBytes
[  5]  12.00-13.00  sec  2.69 GBytes  23.1 Gbits/sec    0   2.94 MBytes
[  5]  13.00-14.00  sec  2.69 GBytes  23.1 Gbits/sec    0   2.94 MBytes
[  5]  14.00-15.00  sec  2.68 GBytes  23.0 Gbits/sec    0   2.94 MBytes
[  5]  15.00-16.00  sec  2.71 GBytes  23.3 Gbits/sec    0   2.94 MBytes
[  5]  16.00-17.00  sec  2.68 GBytes  23.0 Gbits/sec    0   2.94 MBytes
[  5]  17.00-18.00  sec  2.70 GBytes  23.2 Gbits/sec    0   2.94 MBytes
[  5]  18.00-19.00  sec  2.72 GBytes  23.3 Gbits/sec    0   2.94 MBytes
[  5]  19.00-20.00  sec  2.68 GBytes  23.0 Gbits/sec    0   2.94 MBytes
[  5]  20.00-21.00  sec  2.76 GBytes  23.7 Gbits/sec    0   2.94 MBytes
[  5]  21.00-22.00  sec  2.73 GBytes  23.5 Gbits/sec    0   2.94 MBytes
[  5]  22.00-23.00  sec  2.72 GBytes  23.4 Gbits/sec    0   2.94 MBytes
[  5]  23.00-24.00  sec  2.74 GBytes  23.5 Gbits/sec    0   2.94 MBytes
[  5]  24.00-25.00  sec  2.75 GBytes  23.7 Gbits/sec    0   2.94 MBytes
[  5]  25.00-26.00  sec  2.74 GBytes  23.6 Gbits/sec    0   2.94 MBytes
[  5]  26.00-27.00  sec  2.75 GBytes  23.6 Gbits/sec    0   2.94 MBytes
[  5]  27.00-28.00  sec  2.72 GBytes  23.4 Gbits/sec    0   2.94 MBytes
[  5]  28.00-29.00  sec  2.75 GBytes  23.6 Gbits/sec    0   2.94 MBytes
[  5]  29.00-30.00  sec  2.76 GBytes  23.7 Gbits/sec    0   2.94 MBytes
- - - - - - - - - - - - - - - - - - - - - - - - -
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-30.00  sec  81.8 GBytes  23.4 Gbits/sec    0             sender
[  5]   0.00-30.00  sec  81.8 GBytes  23.4 Gbits/sec                  receiver

iperf Done.
task: [perf-coil-fast] echo "=== Coil Fast Path: Small Packets (128-byte blocks) ==="
kubectl exec -n default coil-perf-client-kind-with-bgp-worker -- iperf3 -c 192.168.0.100 -t 30 -l 128

=== Coil Fast Path: Small Packets (128-byte blocks) ===
Connecting to host 192.168.0.100, port 5201
[  5] local 10.64.0.33 port 35766 connected to 192.168.0.100 port 5201
[ ID] Interval           Transfer     Bitrate         Retr  Cwnd
[  5]   0.00-1.00   sec   306 MBytes  2.57 Gbits/sec    0    276 KBytes
[  5]   1.00-2.00   sec   304 MBytes  2.55 Gbits/sec    0    276 KBytes
[  5]   2.00-3.00   sec   303 MBytes  2.54 Gbits/sec    0    276 KBytes
[  5]   3.00-4.00   sec   303 MBytes  2.55 Gbits/sec    0    276 KBytes
[  5]   4.00-5.00   sec   303 MBytes  2.54 Gbits/sec    0    276 KBytes
[  5]   5.00-6.00   sec   302 MBytes  2.53 Gbits/sec    0    276 KBytes
[  5]   6.00-7.00   sec   303 MBytes  2.54 Gbits/sec    0    276 KBytes
[  5]   7.00-8.00   sec   305 MBytes  2.56 Gbits/sec    0    276 KBytes
[  5]   8.00-9.00   sec   305 MBytes  2.56 Gbits/sec    0    276 KBytes
[  5]   9.00-10.00  sec   305 MBytes  2.56 Gbits/sec    0    276 KBytes
[  5]  10.00-11.00  sec   304 MBytes  2.55 Gbits/sec    0    276 KBytes
[  5]  11.00-12.00  sec   304 MBytes  2.55 Gbits/sec    0    276 KBytes
[  5]  12.00-13.00  sec   306 MBytes  2.57 Gbits/sec    0    276 KBytes
[  5]  13.00-14.00  sec   306 MBytes  2.57 Gbits/sec    0    276 KBytes
[  5]  14.00-15.00  sec   305 MBytes  2.55 Gbits/sec    0    276 KBytes
[  5]  15.00-16.00  sec   305 MBytes  2.56 Gbits/sec    0    276 KBytes
[  5]  16.00-17.00  sec   305 MBytes  2.56 Gbits/sec    0    276 KBytes
[  5]  17.00-18.00  sec   304 MBytes  2.55 Gbits/sec    0    276 KBytes
[  5]  18.00-19.00  sec   304 MBytes  2.55 Gbits/sec    0    276 KBytes
[  5]  19.00-20.00  sec   305 MBytes  2.56 Gbits/sec    0    276 KBytes
[  5]  20.00-21.00  sec   304 MBytes  2.55 Gbits/sec    0    276 KBytes
[  5]  21.00-22.00  sec   303 MBytes  2.54 Gbits/sec    0    276 KBytes
[  5]  22.00-23.00  sec   303 MBytes  2.54 Gbits/sec    0    276 KBytes
[  5]  23.00-24.00  sec   302 MBytes  2.53 Gbits/sec    0    276 KBytes
[  5]  24.00-25.00  sec   303 MBytes  2.54 Gbits/sec    0    276 KBytes
[  5]  25.00-26.00  sec   305 MBytes  2.56 Gbits/sec    0    276 KBytes
[  5]  26.00-27.00  sec   305 MBytes  2.56 Gbits/sec    0    276 KBytes
[  5]  27.00-28.00  sec   301 MBytes  2.52 Gbits/sec    0    276 KBytes
[  5]  28.00-29.00  sec   306 MBytes  2.57 Gbits/sec    0    276 KBytes
[  5]  29.00-30.00  sec   306 MBytes  2.57 Gbits/sec    0    276 KBytes
- - - - - - - - - - - - - - - - - - - - - - - - -
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-30.00  sec  8.91 GBytes  2.55 Gbits/sec    0             sender
[  5]   0.00-30.00  sec  8.91 GBytes  2.55 Gbits/sec                  receiver

iperf Done.
task: [perf-coil-slow] echo "=== Coil Slow Path: Big Packets ==="
kubectl exec -n default coil-perf-client-kind-with-bgp-worker2 -- iperf3 -c 192.168.0.100 -t 30

=== Coil Slow Path: Big Packets ===
Connecting to host 192.168.0.100, port 5201
[  5] local 10.64.0.65 port 36434 connected to 192.168.0.100 port 5201
[ ID] Interval           Transfer     Bitrate         Retr  Cwnd
[  5]   0.00-1.00   sec  1.70 GBytes  14.6 Gbits/sec    3    350 KBytes
[  5]   1.00-2.00   sec  1.71 GBytes  14.7 Gbits/sec    0    377 KBytes
[  5]   2.00-3.00   sec  1.72 GBytes  14.8 Gbits/sec    0    377 KBytes
[  5]   3.00-4.00   sec  1.73 GBytes  14.9 Gbits/sec    0    902 KBytes
[  5]   4.00-5.00   sec  1.75 GBytes  15.0 Gbits/sec    0    902 KBytes
[  5]   5.00-6.00   sec  1.75 GBytes  15.1 Gbits/sec    0    902 KBytes
[  5]   6.00-7.00   sec  1.75 GBytes  15.0 Gbits/sec    0    902 KBytes
[  5]   7.00-8.00   sec  1.74 GBytes  15.0 Gbits/sec    0    902 KBytes
[  5]   8.00-9.00   sec  1.75 GBytes  15.0 Gbits/sec    0    902 KBytes
[  5]   9.00-10.00  sec  1.77 GBytes  15.2 Gbits/sec    0    902 KBytes
[  5]  10.00-11.00  sec  1.74 GBytes  14.9 Gbits/sec    0    902 KBytes
[  5]  11.00-12.00  sec  1.59 GBytes  13.6 Gbits/sec    0    902 KBytes
[  5]  12.00-13.00  sec  1.62 GBytes  13.9 Gbits/sec    0    902 KBytes
[  5]  13.00-14.00  sec  1.51 GBytes  13.0 Gbits/sec    0    902 KBytes
[  5]  14.00-15.00  sec  1.23 GBytes  10.6 Gbits/sec    0   1.33 MBytes
[  5]  15.00-16.00  sec  1.18 GBytes  10.2 Gbits/sec    0   1.33 MBytes
[  5]  16.00-17.00  sec  1.50 GBytes  12.9 Gbits/sec    0   1.33 MBytes
[  5]  17.00-18.00  sec  1.21 GBytes  10.4 Gbits/sec    0   1.33 MBytes
[  5]  18.00-19.00  sec  1.73 GBytes  14.8 Gbits/sec    0   1.33 MBytes
[  5]  19.00-20.00  sec  1.64 GBytes  14.0 Gbits/sec    0   1.33 MBytes
[  5]  20.00-21.00  sec  1.65 GBytes  14.2 Gbits/sec   30   1.99 MBytes
[  5]  21.00-22.00  sec  1.65 GBytes  14.2 Gbits/sec    0   1.99 MBytes
[  5]  22.00-23.00  sec  1.55 GBytes  13.3 Gbits/sec    0   1.99 MBytes
[  5]  23.00-24.00  sec  1.59 GBytes  13.7 Gbits/sec    0   1.99 MBytes
[  5]  24.00-25.00  sec  1.69 GBytes  14.5 Gbits/sec    0   1.99 MBytes
[  5]  25.00-26.00  sec  1.37 GBytes  11.7 Gbits/sec    0   1.99 MBytes
[  5]  26.00-27.00  sec  1.74 GBytes  14.9 Gbits/sec    0   1.99 MBytes
[  5]  27.00-28.00  sec  1.73 GBytes  14.8 Gbits/sec    0   1.99 MBytes
[  5]  28.00-29.00  sec  1.73 GBytes  14.9 Gbits/sec    0   1.99 MBytes
[  5]  29.00-30.00  sec  1.73 GBytes  14.9 Gbits/sec    0   1.99 MBytes
- - - - - - - - - - - - - - - - - - - - - - - - -
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-30.00  sec  52.4 GBytes  15.0 Gbits/sec   33             sender
[  5]   0.00-30.00  sec  52.4 GBytes  15.0 Gbits/sec                  receiver

iperf Done.
task: [perf-coil-slow] echo "=== Coil Slow Path: Small Packets (128-byte blocks) ==="
kubectl exec -n default coil-perf-client-kind-with-bgp-worker2 -- iperf3 -c 192.168.0.100 -t 30 -l 128

=== Coil Slow Path: Small Packets (128-byte blocks) ===
Connecting to host 192.168.0.100, port 5201
[  5] local 10.64.0.65 port 45988 connected to 192.168.0.100 port 5201
[ ID] Interval           Transfer     Bitrate         Retr  Cwnd
[  5]   0.00-1.00   sec   287 MBytes  2.40 Gbits/sec    0    285 KBytes
[  5]   1.00-2.00   sec   285 MBytes  2.39 Gbits/sec    0    285 KBytes
[  5]   2.00-3.00   sec   279 MBytes  2.34 Gbits/sec    0    285 KBytes
[  5]   3.00-4.00   sec   282 MBytes  2.37 Gbits/sec    0    285 KBytes
[  5]   4.00-5.00   sec   284 MBytes  2.38 Gbits/sec    0    285 KBytes
[  5]   5.00-6.00   sec   284 MBytes  2.38 Gbits/sec    0    285 KBytes
[  5]   6.00-7.00   sec   283 MBytes  2.37 Gbits/sec    0    285 KBytes
[  5]   7.00-8.00   sec   285 MBytes  2.39 Gbits/sec    0    285 KBytes
[  5]   8.00-9.00   sec   285 MBytes  2.39 Gbits/sec    0    285 KBytes
[  5]   9.00-10.00  sec   286 MBytes  2.40 Gbits/sec    0    285 KBytes
[  5]  10.00-11.00  sec   286 MBytes  2.40 Gbits/sec    0    285 KBytes
[  5]  11.00-12.00  sec   285 MBytes  2.39 Gbits/sec    0    285 KBytes
[  5]  12.00-13.00  sec   286 MBytes  2.40 Gbits/sec    0    285 KBytes
[  5]  13.00-14.00  sec   286 MBytes  2.40 Gbits/sec    0    285 KBytes
[  5]  14.00-15.00  sec   286 MBytes  2.40 Gbits/sec    0    285 KBytes
[  5]  15.00-16.00  sec   286 MBytes  2.40 Gbits/sec    0    285 KBytes
[  5]  16.00-17.00  sec   286 MBytes  2.40 Gbits/sec    0    285 KBytes
[  5]  17.00-18.00  sec   286 MBytes  2.40 Gbits/sec    0    285 KBytes
[  5]  18.00-19.00  sec   286 MBytes  2.40 Gbits/sec    0    285 KBytes
[  5]  19.00-20.00  sec   287 MBytes  2.41 Gbits/sec    0    285 KBytes
[  5]  20.00-21.00  sec   287 MBytes  2.41 Gbits/sec    0    285 KBytes
[  5]  21.00-22.00  sec   286 MBytes  2.40 Gbits/sec    0    285 KBytes
[  5]  22.00-23.00  sec   286 MBytes  2.40 Gbits/sec    0    285 KBytes
[  5]  23.00-24.00  sec   286 MBytes  2.40 Gbits/sec    0    285 KBytes
[  5]  24.00-25.00  sec   287 MBytes  2.41 Gbits/sec    0    285 KBytes
[  5]  25.00-26.00  sec   286 MBytes  2.40 Gbits/sec    0    285 KBytes
[  5]  26.00-27.00  sec   286 MBytes  2.40 Gbits/sec    0    285 KBytes
[  5]  27.00-28.00  sec   286 MBytes  2.40 Gbits/sec    0    285 KBytes
[  5]  28.00-29.00  sec   286 MBytes  2.40 Gbits/sec    0    285 KBytes
[  5]  29.00-30.00  sec   286 MBytes  2.40 Gbits/sec    0    285 KBytes
- - - - - - - - - - - - - - - - - - - - - - - - -
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-30.00  sec  8.36 GBytes  2.39 Gbits/sec    0             sender
[  5]   0.00-30.00  sec  8.36 GBytes  2.39 Gbits/sec                  receiver

iperf Done.
task: [perf-server-stop] docker exec clab-kind-with-bgp-domestic0 pkill iperf3 || true
```
