// generated by stringer -type=ofp_stats_type; DO NOT EDIT

package openflow

import "fmt"

const (
	_ofp_stats_type_name_0 = "OFPST_DESCOFPST_FLOWOFPST_AGGREGATEOFPST_TABLEOFPST_PORTOFPST_QUEUE"
	_ofp_stats_type_name_1 = "OFPST_EXPERIMENTER"
)

var (
	_ofp_stats_type_index_0 = [...]uint8{0, 10, 20, 35, 46, 56, 67}
	_ofp_stats_type_index_1 = [...]uint8{0, 18}
)

func (i ofp_stats_type) String() string {
	switch {
	case 0 <= i && i <= 5:
		return _ofp_stats_type_name_0[_ofp_stats_type_index_0[i]:_ofp_stats_type_index_0[i+1]]
	case i == 65535:
		return _ofp_stats_type_name_1
	default:
		return fmt.Sprintf("ofp_stats_type(%d)", i)
	}
}
