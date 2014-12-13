udp make session flow :
	s -> c1 : query_addrlist_a
	c1 -> s : report_addrlist
	s -> c2 : query_addrlist_b  c2 have c1's addresses
	c2 -> s : report_addrlist
	s -> c1 : tell_bust_a  c1 have c2's addresses
	c1 -> s : success_bust_a
	s -> c2 : tell_bust_b
	c2 -> s : makeholeok or makeholefail

author: vzex@163.com
