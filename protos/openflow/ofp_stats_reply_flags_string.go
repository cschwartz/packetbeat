// generated by stringer -type=ofp_stats_reply_flags; DO NOT EDIT

package openflow

import "fmt"

const _ofp_stats_reply_flags_name = "OFPSF_REPLY_MORE"

var _ofp_stats_reply_flags_index = [...]uint8{0, 16}

func (i ofp_stats_reply_flags) String() string {
	i -= 1
	if i >= ofp_stats_reply_flags(len(_ofp_stats_reply_flags_index)-1) {
		return fmt.Sprintf("ofp_stats_reply_flags(%d)", i+1)
	}
	return _ofp_stats_reply_flags_name[_ofp_stats_reply_flags_index[i]:_ofp_stats_reply_flags_index[i+1]]
}
