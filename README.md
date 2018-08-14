dns
===

A featureless authoritative DNS server.

Supports:

 - UDP + TCP
 - Seccomp syscall filtering

Bugs:

 - Only one question per requests
 - Ignore Additional Fields
 - BPF filtering for UDP has false positive
 - No BFP packet filtering for TCP
 - BPF filtering for UDP is broken
