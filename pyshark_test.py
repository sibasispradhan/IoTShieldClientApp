import psutil
import socket
from datetime import datetime

# ------ Custom Libraries -------
import utils

def get_wifi_interface():
    interfaces = psutil.net_if_addrs()

    eth0_interface = next((iface for iface, addrs in interfaces.items() if
                           iface == 'eth0' and any(addr.family == socket.AF_INET for addr in addrs)), None)
    if eth0_interface:
        return eth0_interface

    wifi_interface = next((iface for iface, addrs in interfaces.items() if
                           iface == 'Wi-Fi' and any(addr.family == socket.AF_INET for addr in addrs)), None)
    if wifi_interface:
        return wifi_interface

    return "eth0"

def return_outline(packet):
    output_line = ",".join([
        packet.sniff_timestamp,
        packet.ip.src_host if hasattr(packet, 'ip') and hasattr(packet.ip, 'src_host') else '0',
        packet.ip.dst_host if hasattr(packet, 'ip') and hasattr(packet.ip, 'dst_host') else '0',
        packet.arp.dst.proto_ipv4 if hasattr(packet, 'arp') and hasattr(packet.arp, 'dst') and hasattr(packet.arp.dst,
                                                                                                       'proto_ipv4') else '0',
        packet.arp.opcode if hasattr(packet, 'arp') and hasattr(packet.arp, 'opcode') else '0',
        packet.arp.hw.size if hasattr(packet, 'arp') and hasattr(packet.arp, 'hw') and hasattr(packet.arp.hw,
                                                                                               'size') else '0',
        packet.arp.src.proto_ipv4 if hasattr(packet, 'arp') and hasattr(packet.arp, 'src') and hasattr(packet.arp.src,
                                                                                                       'proto_ipv4') else '0',
        packet.icmp.checksum if hasattr(packet, 'icmp') and hasattr(packet.icmp, 'checksum') else '0',
        packet.icmp.seq_le if hasattr(packet, 'icmp') and hasattr(packet.icmp, 'seq_le') else '0',
        packet.icmp.transmit_timestamp if hasattr(packet, 'icmp') and hasattr(packet.icmp,
                                                                              'transmit_timestamp') else '0',
        packet.icmp.unused if hasattr(packet, 'icmp') and hasattr(packet.icmp, 'unused') else '0',
        packet.http.file_data if hasattr(packet, 'http') and hasattr(packet.http, 'file_data') else '0',
        packet.http.content_length if hasattr(packet, 'http') and hasattr(packet.http, 'content_length') else '0',
        packet.http.request.uri.query if hasattr(packet, 'http') and hasattr(packet.http, 'request') and hasattr(
            packet.http.request, 'uri') and hasattr(packet.http.request.uri, 'query') else '0',
        packet.http.request.method if hasattr(packet, 'http') and hasattr(packet.http, 'request') and hasattr(
            packet.http.request, 'method') else '0',
        packet.http.referer if hasattr(packet, 'http') and hasattr(packet.http, 'referer') else '0',
        packet.http.request.full_uri if hasattr(packet, 'http') and hasattr(packet.http, 'request') and hasattr(
            packet.http.request, 'full_uri') else '0',
        packet.http.request.version if hasattr(packet, 'http') and hasattr(packet.http, 'request') and hasattr(
            packet.http.request, 'version') else '0',
        packet.http.response if hasattr(packet, 'http') and hasattr(packet.http, 'response') else '0',
        packet.http.tls_port if hasattr(packet, 'http') and hasattr(packet.http, 'tls_port') else '0',
        packet.tcp.ack if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'ack') else '0',
        packet.tcp.ack_raw if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'ack_raw') else '0',
        packet.tcp.checksum if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'checksum') else '0',
        packet.tcp.connection.fin if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'connection') and hasattr(
            packet.tcp.connection, 'fin') else '0',
        packet.tcp.connection.rst if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'connection') and hasattr(
            packet.tcp.connection, 'rst') else '0',
        packet.tcp.connection.syn if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'connection') and hasattr(
            packet.tcp.connection, 'syn') else '0',
        packet.tcp.connection.synack if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'connection') and hasattr(
            packet.tcp.connection, 'synack') else '0',
        packet.tcp.dstport if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'dstport') else '0',
        packet.tcp.flags if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'flags') else '0',
        packet.tcp.flags.ack if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'flags') and hasattr(packet.tcp.flags,
                                                                                                    'ack') else '0',
        packet.tcp.len if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'len') else '0',
        packet.tcp.options if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'options') else '0',
        packet.tcp.payload if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'payload') else '0',
        packet.tcp.seq if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'seq') else '0',
        packet.tcp.srcport if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'srcport') else '0',
        packet.udp.port if hasattr(packet, 'udp') and hasattr(packet.udp, 'port') else '0',
        packet.udp.stream if hasattr(packet, 'udp') and hasattr(packet.udp, 'stream') else '0',
        packet.udp.time_delta if hasattr(packet, 'udp') and hasattr(packet.udp, 'time_delta') else '0',
        packet.dns.qry.name if hasattr(packet, 'dns') and hasattr(packet.dns, 'qry') and hasattr(packet.dns.qry,
                                                                                                 'name') else '0',
        packet.dns.qry.name.len if hasattr(packet, 'dns') and hasattr(packet.dns, 'qry') and hasattr(packet.dns.qry,
                                                                                                     'name') and hasattr(
            packet.dns.qry.name, 'len') else '0',
        packet.dns.qry.qu if hasattr(packet, 'dns') and hasattr(packet.dns, 'qry') and hasattr(packet.dns.qry,
                                                                                               'qu') else '0',
        packet.dns.qry.type if hasattr(packet, 'dns') and hasattr(packet.dns, 'qry') and hasattr(packet.dns.qry,
                                                                                                 'type') else '0',
        packet.dns.retransmission if hasattr(packet, 'dns') and hasattr(packet.dns, 'retransmission') else '0',
        packet.dns.retransmit_request if hasattr(packet, 'dns') and hasattr(packet.dns, 'retransmit_request') else '0',
        packet.dns.retransmit_request_in if hasattr(packet, 'dns') and hasattr(packet.dns,
                                                                               'retransmit_request_in') else '0',
        packet.mqtt.conack.flags if hasattr(packet, 'mqtt') and hasattr(packet.mqtt, 'conack') and hasattr(
            packet.mqtt.conack, 'flags') else '0',
        packet.mqtt.conflag.cleansess if hasattr(packet, 'mqtt') and hasattr(packet.mqtt, 'conflag') and hasattr(
            packet.mqtt.conflag, 'cleansess') else '0',
        packet.mqtt.conflags if hasattr(packet, 'mqtt') and hasattr(packet.mqtt, 'conflags') else '0',
        packet.mqtt.hdrflags if hasattr(packet, 'mqtt') and hasattr(packet.mqtt, 'hdrflags') else '0',
        packet.mqtt.len if hasattr(packet, 'mqtt') and hasattr(packet.mqtt, 'len') else '0',
        packet.mqtt.msg_decoded_as if hasattr(packet, 'mqtt') and hasattr(packet.mqtt, 'msg_decoded_as') else '0',
        packet.mqtt.msg if hasattr(packet, 'mqtt') and hasattr(packet.mqtt, 'msg') else '0',
        packet.mqtt.msgtype if hasattr(packet, 'mqtt') and hasattr(packet.mqtt, 'msgtype') else '0',
        packet.mqtt.proto_len if hasattr(packet, 'mqtt') and hasattr(packet.mqtt, 'proto_len') else '0',
        packet.mqtt.protoname if hasattr(packet, 'mqtt') and hasattr(packet.mqtt, 'protoname') else '0',
        packet.mqtt.topic if hasattr(packet, 'mqtt') and hasattr(packet.mqtt, 'topic') else '0',
        packet.mqtt.topic_len if hasattr(packet, 'mqtt') and hasattr(packet.mqtt, 'topic_len') else '0',
        packet.mqtt.ver if hasattr(packet, 'mqtt') and hasattr(packet.mqtt, 'ver') else '0',
        packet.mbtcp.len if hasattr(packet, 'mbtcp') and hasattr(packet.mbtcp, 'len') else '0',
        packet.mbtcp.trans_id if hasattr(packet, 'mbtcp') and hasattr(packet.mbtcp, 'trans_id') else '0',
        packet.mbtcp.unit_id if hasattr(packet, 'mbtcp') and hasattr(packet.mbtcp, 'unit_id') else '0'
    ])
    return output_line

def pkt_process(packet):
    output_line = return_outline(packet)

    val_arr = output_line.split(",")
    # Select specific columns based on indices
    indices_to_select = [14, 18, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 33, 34, 35, 36, 46, 47, 48, 49, 52,
                         53, 56]
    packet_val = [val_arr[i] for i in indices_to_select]

    http_response = 1 if packet_val[1] == 'True' else packet_val[1]
    data = utils.CustomData(
        httprequestmethod=packet_val[0],
        httpresponse=float(http_response),
        tcpack=float(packet_val[2]) if packet_val[2].replace('.', '', 1).isdigit() else 0,
        tcpack_raw=float(packet_val[3]) if packet_val[3].replace('.', '', 1).isdigit() else 0,
        tcpchecksum=float(int(packet_val[4], 16)),
        tcpconnectionfin=float(packet_val[5]) if packet_val[5].replace('.', '', 1).isdigit() else 0,
        tcpconnectionrst=float(int(packet_val[6], 16)),
        tcpconnectionsyn=float(packet_val[7]) if packet_val[7].replace('.', '', 1).isdigit() else 0,
        tcpconnectionsynack=float(packet_val[8]) if packet_val[8].replace('.', '', 1).isdigit() else 0,
        tcpdstport=float(packet_val[9]) if packet_val[9].replace('.', '', 1).isdigit() else 0,
        tcpflags=float(int(packet_val[10], 16)),
        tcpflagsack=float(packet_val[11]) if packet_val[11].replace('.', '', 1).isdigit() else 0,
        tcplen=float(int(packet_val[12], 16)),
        tcpseq=float(packet_val[13]) if packet_val[13].replace('.', '', 1).isdigit() else 0,
        tcpsrcport=float(packet_val[14]) if packet_val[14].replace('.', '', 1).isdigit() else 0,
        udpport=float(packet_val[15]) if packet_val[15].replace('.', '', 1).isdigit() else 0,
        udpstream=float(packet_val[16]) if packet_val[16].replace('.', '', 1).isdigit() else 0,
        mqttconflagcleansess=float(packet_val[17]) if packet_val[17].replace('.', '', 1).isdigit() else 0,
        mqttconflags=float(packet_val[18]) if packet_val[18].replace('.', '', 1).isdigit() else 0,
        mqtthdrflags=float(packet_val[19]) if packet_val[19].replace('.', '', 1).isdigit() else 0,
        mqttlen=float(packet_val[20]) if packet_val[20].replace('.', '', 1).isdigit() else 0,
        mqttmsgtype=float(packet_val[21]) if packet_val[21].replace('.', '', 1).isdigit() else 0,
        mqttproto_len=float(packet_val[22]) if packet_val[22].replace('.', '', 1).isdigit() else 0,
        mqtttopic_len=float(packet_val[23]) if packet_val[23].replace('.', '', 1).isdigit() else 0
    )

    final_data = data.get_data_as_dataframe()
    ml_pred, ml_label = utils.predict(final_data)
    timestamp_datetime = datetime.fromtimestamp(float(val_arr[0]))
    formatted_timestamp = timestamp_datetime.strftime('%Y-%m-%d %H:%M:%S')
    final_data['ip_src_host'] = val_arr[1]
    final_data['ip_dst_host'] = val_arr[2]
    final_data['attack_label'] = ml_label
    final_data['attack_type'] = ml_pred 
    final_data['created_at'] = formatted_timestamp
    # print(ml_pred)
    #ml_label = 1
    return final_data, ml_pred, ml_label
