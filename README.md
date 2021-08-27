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

### The punishing details

Tusk consensus operates over the Narwhal structured mempool. Narwhal build a DAG of blocks and certificates. At each round each node publishes a block (comprised of a *header* and *data*) for the round containing a quorum of certificates from the previous round. The block is then send to all other nodes, and once a quorum have signed the header the signatures form a *certificate* for the block in that round. Once a quorum of these are gathered by a node they advance to the next round, and include them in their new block. 

Tusk adds no new messages: at odd rounds it determines a node that would be the 'leader', and at even rounds it determines if a block from that leader has strong support (ie at least one honest node has made a certificate containing it). If so this becomes the tip of the consensus: all blocks transitively included in this tip must be downloaded, each past leader checked for strong support, and transactions in blocks sequenced. 

If you are confused, its because you need to read [DAG-Rider](https://arxiv.org/abs/2102.08325) then [Tusk](https://arxiv.org/abs/2105.11827). There is no way of compressing 20 pages of technical docs into two paragraphs. The explanation around why all this works is rather convoluted, but the resulting protocol simple -- which is a blessing.

Now, in sleepyseal nodes do not send any information to each other. So data, headers, signatures, and certificates must be relayed through drivers. To keep things simple we restrict the type of information that drivers can relay as part of a response, into two types of bundles:

* A *header bundle* contains a quorum of blocks from a single round. Upon receiving such a bundle a node has enough information to move to the round, and sign any blocks from authorities it has not seen a block from before. Providing a header bundle to a quorum of nodes should allow a driver to get a quorum of certificates.

* A *certificate bundle* contains a quorum of certificates for a round. A node receiving such a bundle of information can safely advance to the next round, and create a new block containing all known certificates from the previous round.

The advantage in expecting such bundles -- rather than any assortment of information -- is that the node logic is further simplified. Furthermore, all bundles contain enough information to move from a previous round, which does away from the need to store information of multiple rounds. They force drivers to aggregate messages into bundles that -- in case nodes are honest -- would make fast progress.