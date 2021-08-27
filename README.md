# sleepyseal
A BFT consensus implementation based on the passive core / active driver model.

## What is the concept here?

Byzantine fault tolerant (BFT) consensus protocol allows a set of honest parties to agree on a sequence of values -- often transactions in a database system -- despite some failures and the presence of a minority of corrupt participants. They are at the heart of proof-of-stake blockchains, and generally high-reliability distributed systems through *state-machine replication*. So they are a big deal, and their correctness, reliability, security and performance is important.

Most designs for BFT consensus follow the theoretical model for distributed systems: protocol participants (nodes) send messages to each other, and react upon receiving messages by processing their state, sending messages to others. Some messages are the result of internal events like timers, changing conditions, etc. In brief, the nodes are **active**: they all communicate with each other, initiate and serve requests, and can all send messages to each other. In theory a node sending a message to another is a simple matter. In reality this involves maintaining network state, managing TCP channels, managing re-connections, managing buffers (which may become infinite), and working out a myriad of tuning parameters such as timeouts, retry counters, backoff schedules, etc. 

Building active nodes is a nightmare, and we know this because we designed and implemented the active [Narwhal & Tusk](https://github.com/facebookresearch/narwhal) consensus core. It is very performant and correct. But has to be tuned very carefully to ensure good performance. And the tuning has to change according to the environment it operates in: the network conditions, the loads etc. Code managing the safety and liveness of the consensus is mixed, making it hard to maintain and much larger than I would like a security system to be.

## Can consensus cores be (mostly) passive? 

A **passive** node never initiates a network communication. For example, a simple web server does not initiate network operations: it simply waits for requests from clients, and responds to the same client with a response. However consensus protocols need nodes to communicate with each other -- how could they be passive?

To overcome this we have dedicated, but untrusted, clients (called *drivers*) in-charge of passing information between consensus nodes. Furthermore, we can implement a protocol that does not rely at all on drivers for safety. For liveness an additional assumption is necessary that an honest driver will exist and relay information between cores within a maximum delay. This extends the established partial-synchrony assumption.

## Enter SleepySeal.

In brief Sleepyseal implements a single-shard (primary-only) [Tusk](https://arxiv.org/abs/2105.11827) consensus (a 2-round variant of [DAG-Rider](https://arxiv.org/abs/2102.08325)) using the passive node paradigm outlined above. Each node simply waits for a driver request, processes it to update its state, and then responds with the updated state. 

Drivers contact multiple passive cores, aggregate their signed responses and construct new requests. These requests are sent back to the cores to facilitate protocol progress. Repeating this pattern allows the consensus protocol to make progress without nodes ever taking to each other, or initiating any connection. 

Authorities operating a node may also operate an active driver to ensure progress is made. However, the active driver does not have to retain any state (can crash at any time), and does not need access to any secret to operate correctly. In that sense the passive node and the active driver(s) are truly de-coupled systems.