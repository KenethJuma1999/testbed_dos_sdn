from __future__ import print_function

import array
import time
from collections import defaultdict
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller import dpset
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib import snortlib


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'snortlib': snortlib.SnortLib, 'dpset': dpset.DPSet}

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.snort = kwargs['snortlib']
        self.snort_port = 5
        self.dpset = kwargs['dpset']

        self.tcp_packet_count = defaultdict(int)
        self.udp_packet_count = defaultdict(int)
        self.packet_threshold = 1000  # Umbral de paquetes por segundo
        self.time_window = 1  # Ventana de tiempo en segundos
        self.last_checked = defaultdict(lambda: time.time())

        socket_config = {'unixsock': False}
        self.snort.set_config(socket_config)
        self.snort.start_socket_server()

    def packet_print(self, pkt):
        pkt = packet.Packet(array.array('B', pkt))

        _ipv4 = pkt.get_protocol(ipv4.ipv4)
        _icmp = pkt.get_protocol(icmp.icmp)
        _tcp = pkt.get_protocol(tcp.tcp)
        _udp = pkt.get_protocol(udp.udp)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth:
            eth_src = eth.src
            eth_dst = eth.dst
            eth_type = eth.ethertype

        if _ipv4:
            ipv4_src = _ipv4.src
            ipv4_dst = _ipv4.dst

        if _icmp:
            icmp_type = _icmp.type
            icmp_code = _icmp.code

        def print_box(text):
            border = '+' + '-' * (len(text) + 2) + '+'
            print(border)
            print('| ' + text + ' |')
            print(border)

        print_box("Trafico ICMP Sospechoso Detectado por Snort")
        print_box("MAC origen: %s, MAC destino: %s, Tipo de dato: %d" % (eth_src, eth_dst, eth_type))
        print_box("IPv4 origen: %s, IPv4 destino: %s" % (ipv4_src, ipv4_dst))
        #print_box("ICMP tipo: %d, " % (icmp_type))

    @set_ev_cls(snortlib.EventAlert, MAIN_DISPATCHER)
    def _dump_alert(self, ev):
        msg = ev.msg

        pkt = packet.Packet(array.array('B', msg.pkt))
        _ipv4 = pkt.get_protocol(ipv4.ipv4)

        if _ipv4:
            self.packet_print(msg.pkt)
        self.fix_alert(ev)
    
    def fix_alert(self, ev):
        msg = ev.msg
        pkt = msg.pkt
        pkt = packet.Packet(array.array('B', pkt))
        _ipv4 = str(pkt.get_protocol(ipv4.ipv4))
        _mac = str(pkt.get_protocol(ethernet.ethernet))

        srcIP = _ipv4.split("'")[3]
        srcMAC = _mac.split("'")[3]

        def print_box2(text):
            border = '+' + '-' * (len(text) + 2) + '+'
            print(border)
            print('| ' + text + ' |')
            print(border)
        
        print_box2('IP Origen del atacante= %s' %srcIP)
        print_box2('MAC Origen del atacante= %s'%srcMAC)

        print_box2('Mitigacion Iniciada....')
        print_box2('Bloqueando la MAC de origen: %s...' %srcMAC)

        dp_set = self.dpset.get_all()

        i = 0
        for dp in dp_set:
            i += 1
            datapath = dp[1]

            parser = datapath.ofproto_parser
            match = parser.OFPMatch(eth_src=srcMAC)
            actions = []
            self.add_flow(datapath, 150, match, actions, table_id=0)

            print_box2('Regla de flujo anadida al switch: %d' %i) 

        print_box2('Mitigacion Terminada....')

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, table_id=1):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst, table_id=table_id)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst, table_id=table_id)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        icmp_pkt = pkt.get_protocol(icmp.icmp)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        dst = eth.dst
        src = eth.src

        dpid = format(datapath.id, "d").zfill(16)
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("Paquete en Switch:%s MACsrc:%s MACdst:%s Port:%s", dpid, src, dst, in_port)

        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = []
        current_time = time.time()
        if current_time - self.last_checked[dpid] > self.time_window:
            self.tcp_packet_count[dpid] = 0
            self.udp_packet_count[dpid] = 0
            self.last_checked[dpid] = current_time

        if ipv4_pkt and tcp_pkt:
            self.tcp_packet_count[dpid] += 1
            if self.tcp_packet_count[dpid] > self.packet_threshold:
                actions.append(parser.OFPActionOutput(self.snort_port))

        elif ipv4_pkt and udp_pkt:
            self.udp_packet_count[dpid] += 1
            if self.udp_packet_count[dpid] > self.packet_threshold:
                actions.append(parser.OFPActionOutput(self.snort_port))

        if icmp_pkt and icmp_pkt.type == 8:
            actions.append(parser.OFPActionOutput(out_port))
            actions.append(parser.OFPActionOutput(self.snort_port))
        else:
            actions.append(parser.OFPActionOutput(out_port))

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
