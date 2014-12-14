# Dog Tunnel

## Introduction

Dog tunnel provide a P2P tunnel between your any two network, via UDP protocol on top of KCP.
It's amazing fast and stable , gain better performance than other tunnel solution.
It's written with pure golang by vzex.



## Specification


### udp make session flow :

```
s -> c1 : query_addrlist_a
c1 -> s : report_addrlist
s -> c2 : query_addrlist_b  c2 have c1's addresses
c2 -> s : report_addrlist
s -> c1 : tell_bust_a  c1 have c2's addresses
c1 -> s : success_bust_a
s -> c2 : tell_bust_b
c2 -> s : makeholeok or makeholefail
```
## License

[MIT License](LICENSE)

## Credits

author: vzex@163.com
