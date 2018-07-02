import logging
import json

from ryu.app.wsgi import ControllerBase
from ryu.app.wsgi import Response
from ryu.app.wsgi import WSGIApplication

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.controller import conf_switch

from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_3_parser

from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4

# format for data
# {'nw_ip':'X.X.X.X'}
# commands
# curl -X GET http://localhost:8080/blocker/list
# curl -X POST -d {'nw_ip':'X.X.X.X'} http://localhost:8080/blocker/list/add
# curl DELETE -d {'nw_ip':'X.X.X.X'} http://localhost:8080/blocker/list/del

class SwitchAPI(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
	_CONTEXTS = {'conf_switch': conf_switch.ConfSwitchSet, 'wsgi': WSGIApplication}
	
    def __init__(self, *args, **kwargs):
		super(SwitchAPI, self).__init__(*args, **kwargs)
		
		# logger configure
		SwitchController.set_logger(self.logger)
		
		wsgi = kwargs['wsgi']
		self.data = {}
		self.data['conf_switch'] = kwargs['conf_switch']
		wsgi.registory['SwitchController'] = self.data
        
		self.mac_to_port = {}
		
		mapper = wsgi.mapper
		path = '/blocker'
		
		# Get list of blocked ip
		uri = path + '/list'
		mapper.connect('blocker', uri, controller=SwitchController, action='get_ip', conditions=dict(method=['GET']))
		
		# Add IP to block list
		uri = path + '/list/add'
		mapper.connect('blocker', uri, controller=SwitchController, action='add_ip', conditions=dict(method=['POST']), requirements=requirements)
		
		# Remove IP from block list
		uri = path + '/list/del'
		mapper.connect('blocker', uri, controller=SwitchController, action='del_ip', conditions=dict(method=['DELETE']), requirements=requirements)
		
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        SwitchController.add_flow(datapath, 0, match, actions)
		
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
	    SwitchController.packet_in_handler(ev)
		
class SwitchController(ControllerBase):
    block_list = []
	_LOGGER = None
	
    def __init__(self, req, link, data, **config):
        super(SwitchController, self).__init__(req, link, data, **config)
        self.conf_switch = data
		
	@classmethod
    def set_logger(cls, logger):
        cls._LOGGER = logger
        cls._LOGGER.propagate = False
        hdlr = logging.StreamHandler()
        fmt_str = '[FW][%(levelname)s] %(message)s'
        hdlr.setFormatter(logging.Formatter(fmt_str))
        cls._LOGGER.addHandler(hdlr)
		
    # GET /blocker/list
	def get_ip(self, req, **_kwargs):
	    msgs = []
		ip_num = 0
	    for ips in self.block_list:
		    ip_num += 1
		    msg = {'%d':'%s' %(ip_num, ips)}
			msgs.append(msg)
		body = json.dumps(msgs)
		return Response(content_type='application/json', body=body)
	
	# POST /blocker/list/add
    def add_ip(self, req, **_kwargs):
		try:
            ip_add = req.json if req.body else {}
        except ValueError:
            MainController._LOGGER.debug('invalid syntax %s', req.body)
            return Response(status=400)
	    self.block_list.append(ip_add['nw_ip'])
		msg = {'result':'added', 'nw_ip':ip_add['nw_ip']}
        body = json.dumps(msg)
        return Response(content_type='application/json', body=body)
		
	# POST /blocker/list/del
    def del_ip(self, req, **_kwargs):
		try:
            ip_add = req.json if req.body else {}
        except ValueError:
            MainController._LOGGER.debug('invalid syntax %s', req.body)
            return Response(status=400)
	    self.block_list.remove(ip_add['nw_ip'])
		msg = {'result':'deleted', 'nw_ip':ip_add['nw_ip']}
        body = json.dumps(msg)
        return Response(content_type='application/json', body=body)	

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)
		
	def packet_in_handler(self, ev):
	    msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
	    ip = pkt.get_protocol(ipv4.ipv4)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

#        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]
	
#	block_this = ['182.18.171.90','216.18.168.16','157.240.13.35']
#182.18.171.90- srm website
#216.18.168.16- porn site
#157.240.13.35- facebook
#
	    if ip is not None:
#		self.logger.info("%packet in - %s %s %s %s", dpid, ip.src, ip.dst, in_port )
		    for block_ip in SwitchController.block_list:
			    if ip.src == block_ip or ip.dst == block_ip:
				    actions = []
				    self.logger.info("Blocked Flow - Source ip: %s , Blacklisted destination ip: %s", ip.src, ip.dst)
				    if ip.src == block_ip:
					    match = parser.OFPMatch(in_port=in_port, eth_type=0x800, ipv4_src = ip.src)
					#self.add_flow(datapath, 1, match, actions)
				    else:
					    match = parser.OFPMatch(in_port=in_port, eth_type=0x800,  ipv4_dst = ip.dst)
				    self.add_flow(datapath, 1, match, actions)
				    self.logger.info("The flow to avoid communication from the blacklisted IP has been set")
			    else:
				    continue

 # install a flow to avoid packet_in next time

		if out_port != ofproto.OFPP_FLOOD:
			match = parser.OFPMatch(in_port=in_port, eth_type=0x800, ipv4_src=ip.src, ipv4_dst=ip.dst)
			self.add_flow(datapath, 1, match, actions)
			self.logger.info("Flow to avoid packet in to RYU controller has been set")

	    data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)