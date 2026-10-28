# Compliance

usg-plat is built for NIST SP 800-53 Rev 5 ATO readiness as a network
boundary translator. These documents are the ATO evidence; each control claim
names a code location and a test. Source annotations use
`// COMPLIANCE MAPPING:` and known gaps are marked `// POAM:`.

| Document | Contents |
|----------|----------|
| [NIST 800-53 mapping](NIST_800-53_MAPPING.md) | Control-by-control implementation status, with an indicative NIAP NDcPP cross-reference |
| [RFC compliance](RFC_COMPLIANCE.md) | RFC 6052, 6146, 7915, 4787, 5382, 7857 and related MUST/SHOULD conformance |
| [SIEM logging](SIEM_LOGGING.md) | Audit record schema, SIEM correlation fields, hash chain and retention |
| [POA&M](POAM.md) | Plan of Action and Milestones: open findings and known gaps |
| [Linux verification](LINUX_VERIFICATION.md) | Linux-only checks (unit sandbox, forward policy, TUN) not yet run |

!!! warning "Not yet verified on Linux"
    Controls that depend on the systemd unit, the nftables forward policy or
    the TUN backend stay unverified until the
    [Linux verification checklist](LINUX_VERIFICATION.md) has been run.
