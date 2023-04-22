import socket
import struct
import time
import argparse 
import os 
import csv
import ipaddress
from scapy.all import *
import random
import networkx as nx
import matplotlib.pyplot as plt

class Traceroute:
    def __init__(self, destination, protocol="UDP", port=33434, max_hops=30, timeout=2, queries=3, dns=False, output_file=False, graph=False, payload_length=60):
        self.destination = destination
        self.max_hops = max_hops
        self.timeout = timeout
        self.port = port
        self.hops = 0
        self.dns = dns
        self.protocol = protocol.upper()
        self.output_file = output_file
        self.payload = payload_length
        self.graph = graph

    def run_ipv4(self):
        output_dict = {socket.gethostbyname(socket.gethostname()):["localhost",'']}
        self.delete_file(self.destination)
        while True:
            self.hops += 1
            delays = []
            delays_without_ms = []
            ips = []
            for n in range(nqueries):
                ttl = self.hops
                if self.protocol == "UDP":
                    sender_address, delay = self.traceroute_udp(self.port, self.destination, ttl, self.payload)
                    delay_str = "{:.3f}".format(delay)
                    delay = float(delay_str)
                    delays_without_ms.append(delay)
                    delays.append(str(delay))
                elif self.protocol == "TCP":
                    self.port = 80
                    sender_address, delay = self.traceroute_tcp(self.port, self.destination, ttl, self.payload)
                    delay_str = "{:.3f}".format(delay)
                    delay = float(delay_str)
                    delays_without_ms.append(delay)
                    delays.append(str(delay))
                elif self.protocol == "ICMP":
                    sender_address, delay = self.traceroute_icmp(self.port, self.destination, ttl, self.payload)
                    delay_str = "{:.3f}".format(delay)
                    delay = float(delay_str)
                    delays_without_ms.append(delay)
                    delays.append(str(delay))
                else:
                    print("Invalid protocol")
                    exit(0)
                try:
                    if not self.dns:
                        try:
                            hostname = socket.gethostbyaddr(sender_address)[0]
                            avg = float("{:.3f}".format(sum(delays_without_ms)/len(delays_without_ms)))
                            output_dict[str(sender_address)] = [hostname, avg]
                        except socket.error:
                            hostname = sender_address
                            if sender_address == "*":
                                output_dict[str(self.hops)] = [self.hops, ""]
                            else:
                                output_dict[str(sender_address)] = [sender_address, avg]
                    else: 
                        hostname = ""
                        avg = float("{:.3f}".format(sum(delays_without_ms)/len(delays_without_ms)))
                        if sender_address == "*":
                            output_dict[str(self.hops)] = [self.hops, avg]
                        else:
                            output_dict[str(sender_address)] = [sender_address, avg]
                except Exception as e:
                    sender_address = None
                    hostname = "*"
                    output_dict[str(hostname)] = [random.randint(1, 100), ""]
            if sender_address != "*":
                print(f"{self.hops}\t{hostname} ({sender_address})\t{' ms '.join(delays)} ms")
                if self.output_file:
                    self.generate_output_file_hostname_available(self.hops, self.destination,sender_address, hostname, delays)
            else:
                host = sender_address + " "
                print(f"{self.hops}\t {host * nqueries}")
                if self.output_file:
                    self.generate_output_file_hostname_not_available(self.destination, host, self.hops)

            if sender_address == socket.gethostbyname(self.destination) or self.hops == self.max_hops:
                    break
        
        if self.graph:
            self.generate_graph(output_dict, self.destination)
        else:
            pass
    def traceroute_tcp(self, port, dest_addr, ttl, payload):            
            ip_packet = IP(dst=dest_addr, ttl=ttl)
            tcp_packet = TCP(sport=RandShort(), dport=port, flags='S')

            try:
                packet = ip_packet / tcp_packet / Raw(payload)
                send_time = time.time()
                response = sr1(packet, verbose=0, timeout=self.timeout)
                if response:
                    recv_time = time.time()
                    delay = round((recv_time - send_time) * 1000, 2)
                    return response.src, delay
                else:
                    recv_time = time.time()
                    delay = round((recv_time - send_time) * 1000, 2)
                    return "*", delay
            except Exception as e:
                print("An error occurred:", e)

    def traceroute_udp(self, port, dest_addr, ttl, payload):
            payload = bytes('A' * payload, 'utf-8')
            ip_packet = IP(dst=dest_addr, ttl=ttl)
            udp_packet = UDP(sport=RandShort(), dport=port)
            
            try:   
                packet = ip_packet / udp_packet
                packet = ip_packet / udp_packet / Raw(payload)
                send_time = time.time()
                response = sr1(packet, verbose=0, timeout=5)

                if response:
                    recv_time = time.time()
                    delay = round((recv_time - send_time) * 1000, 2)
                    return response.src, delay
                else:
                    recv_time = time.time()
                    delay = round((recv_time - send_time) * 1000, 2)
                    return "*", delay
            except Exception as e:
                print("An error occurred:", e)

    def traceroute_icmp(self, port, dest_addr, ttl, payload):
            ip_packet = IP(dst=dest_addr, ttl=ttl)
            icmp_packet = ICMP(id=RandShort(), seq=ttl, type=8, code=0)
            try: 
                packet = ip_packet / icmp_packet / Raw(payload)
                send_time = time.time()
                response = sr1(packet, verbose=0, timeout=5)
                if response:
                    recv_time = time.time()
                    delay = round((recv_time - send_time) * 1000, 2)
                    return response.src, delay
                else:
                    recv_time = time.time()
                    delay = round((recv_time - send_time) * 1000, 2)
                    return "*", delay
            except Exception as e:
                print("An error occurred:", e)

    def generate_output_file_hostname_available(self, hops, destination,sender_address="*", hostname=None, delays=None):
        line = f"{self.hops}\t{hostname} ({sender_address})\t{' '.join(delays)} ms\n"
        filename = f"{destination}.txt"
        with open(filename, "a") as file:
            file.write(line)
    
    def generate_output_file_hostname_not_available(self, destination, hostname, hops):
        line = f"{self.hops}\t {hostname * nqueries}"
        filename = f"{destination}.txt"
        with open(filename, "a+") as file:
            file.write(line)
    
    def delete_file(self, destination):
        filename = f"{destination}.txt"
        if os.path.exists(filename):
            os.remove(filename)
        else: pass

    def generate_graph(self, output_dict, destination):
        G = nx.Graph()
        nodes_list = list(output_dict.keys())
        edge_labels = {}
        for i in range(len(nodes_list) -1):
            current_node = nodes_list[i]
            next_node = nodes_list[(i + 1) % len(nodes_list)]

            G.add_edge(current_node, next_node)
            if output_dict[next_node][1] != "":
                edge_labels[(current_node, next_node)] = str(output_dict[next_node][1]) + " ms "
            else:
                edge_labels[(current_node, next_node)] = "!" + " ms "


        nx.set_edge_attributes(G, edge_labels, 'label')
        cycles = list(nx.simple_cycles(G))  
        for cycle in cycles:
            if nodes_list[0] in cycle:
                linear_path = cycle
                break
        
        for ip, info in output_dict.items():
            hostname, delay = info
            if str(hostname) == ip:
                G.add_node(ip, label=ip)
            else:
                G.add_node(ip, label=f"{hostname}\n{ip}")

        node_colors = ['green' if node == nodes_list[0] else 'grey' for node in G.nodes()]
        node_colors[-1] = 'red'
        pos = nx.spring_layout(G, k=1)

        nx.draw_networkx_nodes(G, pos,node_size=1000, node_color=node_colors)
        node_labels = nx.get_node_attributes(G, 'label')
        nx.draw_networkx_labels(G, pos, labels=node_labels,font_weight="bold", font_size=10, font_color='black')
        nx.draw_networkx_edges(G, pos)
        nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels,font_weight="bold", font_size=10, label_pos=0.5)
        plt.axis('off')
        plt.savefig(f"{destination}.png")
        plt.show() 



def check_ip_valide(ip):
    try:
        ipaddress.ip_address(ip)
        return True 
    except:
        return False



def read_ips_from_file(filename):
    file, file_extension = os.path.splitext(filename)
    ips = []
    if not os.path.exists(filename) or not os.path.isfile(filename):
        print("file does not exists or wrong")
        exit(0)
    if file_extension == ".txt":
        try:
            with open(filename, 'r') as f:
                for line in f:
                    ip = line.strip()
                    if ip:
                        ips.append(ip)
        except:
            print("error parsing file")
    elif file_extension == ".csv":
        try:
            file = open(filename)
            csvreader = csv.reader(file)
            for row in csvreader:
                rows.append(row)
            file.close()
        except:
            print("error parsing file")
    else:
        print("Wrong file extension")
        exit(0)
    return ips


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Traceroute implementation with options.')
    parser.add_argument('file', type=str, help='Path to the file containing the IP addresses')
    parser.add_argument('-m', '-M','--max-hops', type=int, default=30, help='Maximum number of hops to reach the destination. Default is 30')
    parser.add_argument('-t', '--timeout', type=int, default=2, help='Time to wait for a response in seconds. Default is 2')
    parser.add_argument('-q', '--queries', type=int, default=3, help='Number of probes to send to each hop. Default is 3')
    parser.add_argument('-n', '--dns', help='no dns resolution', action="store_true")
    parser.add_argument('-P', '--protocol', type=str, default="UDP", help='Protocol to use (UDP, TCP, ICMP). Default is UDP')
    parser.add_argument('-p', '--port', type=int, default=33434, help='Destination port. Default is 33434')
    parser.add_argument('-o', '--output', help='Write output to file instead of console. Default is False', action="store_true")
    parser.add_argument('-l', '--payload', type=int, default=60, help='Payload length of the packets sent. Default is 60')
    parser.add_argument('-T', '--tcp', help='use tcp protocol', action="store_true")
    parser.add_argument('-U', '--udp', help='use udp protocol', action="store_true")
    parser.add_argument('-I', '--icmp', help='use icmp protocol', action="store_true")
    parser.add_argument('-6', '--ipv6', help='traceroute for ip v6', action="store_true")
    parser.add_argument('-g', '-G', '--graph', default=False, help='Generate a graph showing the path taken by the packets. Default is False', action="store_true")
    args = parser.parse_args()

    max_hops = args.max_hops
    timeout = args.timeout
    nqueries = args.queries
    port = args.port
    n = args.dns
    output = args.output
    protocol = args.protocol
    payload_length = args.payload
    graph = args.graph
    if args.tcp:
        protocol = "TCP"
    elif args.udp:
        protocol = "UDP"
    elif args.icmp:
        protocol = "ICMP"
    try:
        if check_ip_valide(args.file):
            print(f"traceroute to ({args.file}), {max_hops} hops max, {payload_length} byte packets")
            traceroute = Traceroute(args.file, protocol=protocol,port=port, max_hops=max_hops,
                timeout=timeout, queries=nqueries, dns=n, output_file=output, graph=graph, payload_length=payload_length)
            traceroute.run_ipv4()
        else:
            ips = read_ips_from_file(args.file)
            for ip in ips:
                print(f"traceroute to {args.file} ({ip}), {max_hops} hops max, {payload_length} byte packets")
                traceroute = Traceroute(ip, protocol="UDP",port=port, max_hops=max_hops,
                    timeout=timeout, queries=nqueries, dns=n, output_file=output, graph=graph, payload_length=payload_length)
                traceroute.run_ipv4()
    except:
        exit(0)

    