// generated by stringer -type=ofp_flow_mod_command; DO NOT EDIT

package openflow

import "fmt"

const _ofp_flow_mod_command_name = "OFPFC_ADDOFPFC_MODIFYOFPFC_MODIFY_STRICTOFPFC_DELETEOFPFC_DELETE_STRICT"

var _ofp_flow_mod_command_index = [...]uint8{0, 9, 21, 40, 52, 71}

func (i ofp_flow_mod_command) String() string {
	if i >= ofp_flow_mod_command(len(_ofp_flow_mod_command_index)-1) {
		return fmt.Sprintf("ofp_flow_mod_command(%d)", i)
	}
	return _ofp_flow_mod_command_name[_ofp_flow_mod_command_index[i]:_ofp_flow_mod_command_index[i+1]]
}
