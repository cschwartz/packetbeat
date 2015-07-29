from pbtests.packetbeat import TestCase

"""
Tests for OpenFlow OFPT_PACKET_IN messages
"""
class Test(TestCase):

    def test_ofpt_packet_in(self):
        """
        Should parse packet_in messages
        """
        self.render_config_template(
            openflow_ports=[6633],
        )
        self.run_packetbeat(pcap="openflow_packet_in.pcap")

        objs = self.read_output()
        print(objs)
        assert len(objs) == 1
        o = objs[0]

        assert o["openflow.version"] == "1.0"
        assert o["openflow.type"] == "OFPT_PACKET_IN"
        assert o["openflow.transaction_id"] == 0
#        assert o["openflow.in_port"] == 25
