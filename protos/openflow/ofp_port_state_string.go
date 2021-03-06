// generated by stringer -type=ofp_port_state; DO NOT EDIT

package openflow

import "fmt"

const (
	_ofp_port_state_name_0 = "OFPPS_STP_LISTENOFPPS_LINK_DOWN"
	_ofp_port_state_name_1 = "OFPPS_STP_LEARN"
	_ofp_port_state_name_2 = "OFPPS_STP_FORWARD"
	_ofp_port_state_name_3 = "OFPPS_STP_BLOCK"
)

var (
	_ofp_port_state_index_0 = [...]uint8{0, 16, 31}
	_ofp_port_state_index_1 = [...]uint8{0, 15}
	_ofp_port_state_index_2 = [...]uint8{0, 17}
	_ofp_port_state_index_3 = [...]uint8{0, 15}
)

func (i ofp_port_state) String() string {
	switch {
	case 0 <= i && i <= 1:
		return _ofp_port_state_name_0[_ofp_port_state_index_0[i]:_ofp_port_state_index_0[i+1]]
	case i == 256:
		return _ofp_port_state_name_1
	case i == 512:
		return _ofp_port_state_name_2
	case i == 768:
		return _ofp_port_state_name_3
	default:
		return fmt.Sprintf("ofp_port_state(%d)", i)
	}
}
