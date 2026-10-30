# nftguard: POAM-024 residual (b) on a real kernel

Evidence for LINUX_VERIFICATION L25: the `plat-pool-source-guard` nft rule
and platd's `cross_node_hairpin` start gate, checked with real nftables in
three network namespaces. Results: `report.md`.

Run as root in a disposable Linux VM (it creates and deletes the netns
`ng-plat`, `ng-ext`, `ng-cl`; needs nftables, iproute2, tcpdump, python3
with scapy), after `cargo build --release -p platd`:

    sh deploy/tests/nftguard/mkconf.sh config/platd.example.toml deploy/tests/nftguard
    sudo bash deploy/tests/nftguard/run-case.sh B
    sudo bash deploy/tests/nftguard/startcheck.sh deploy/tests/nftguard/cfgB.toml \
        deploy/tests/nftguard/stateB/nftd/plat.nft.expected B-snapshot
    sudo ip netns del ng-plat; sudo ip netns del ng-ext; sudo ip netns del ng-cl

Set `NFTGUARD_WORK` to keep generated files elsewhere.
