# What is this?

A couple of utilities written in Golang to process password dumps.

# Why?

In order to make those dumps usable for analysis and for setting up alerts during a security in depth strategy.

Some of those dumps are filled with junk or unusable information that needs to be cleaned out such as password hashes.

There are other asssets of interest such as email addresses that could be processed further in order to detect if an address in one of my domains is compromised.

# How?

Using Go and Linux commands such as `parallel`, we can design and implement simple workloads that receive input through pipes that can be batched into blocks that can be assigned to each processor.

**Example**
```
time cat rockyou2024 | parallel -j16 --block 200M --pipe ./filter -bigcrypt -blowfish -crypt -des -email -lanman -md5 -nt -sha256 -sha512 -stdin > filtered.txt
```

Otherwise, you can execute these utils as normal binaries.
