# Design Note

Resource Constraints subsystem is open to adding Resources and Algorithms.

1. Resources

Current supported resources are TLS Handshake and Active Queue. We'll add more target resources
like Disk IO, Network IO, EventSystem, and Memory.

2. Algorithms

We have a simple algorithm for now, but there're many approaches to divide tokens for properties
- e.g. using historical data, prediction...etc.

![design](https://apple.box.com/s/b2yhz25dm4wx27ga9sep59rpdmzzeeh7)
