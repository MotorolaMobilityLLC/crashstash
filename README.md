CrashStash
==========

CrashStash is a distribution framework with emphasis on automating fuzzing
frameworks. CrashStash is made up of two main components, the Server and
Clients as well as fuzzing framework dependent Nodes. By itself CrashStash
does not provide much value, it is only a piece of a larger system.

[Cluster Diagram] (cluster_diagram.jpg)

Server
------

CrashStash Server provides a base for creating a distributed fuzzing cluster.
The server is responsible for the distribution of work and test cases in the
form of WorkUnits as well as providing plugin and client updates. The
scheduling is based on weights assigned to each plugin and are distributed
randomly based on these weights. The distribution of both the plugins and the
test cases can be disable on an individual basis.

The server processes incoming client requests and responds to each request
type with the appropriate information.

The possible incoming client requests are:
* Work Request -- provides the server with details such as the current
client version, list of plugins (and version info) and the client OS.

* Work Report -- provides information about the WorkUnit that was
processed such as duration and iterations.

* Results Report -- list of Results that were generated during the execution
of the WorkUnit.

The possible responses include:
* Client Update -- the server can respond to a work request with a client
update package if the client that made the request has out of date client
software.

* Plugin Update -- this response is given when plugin is out of date. It
contains an updated version of the plugin package.

* WorkUnit -- includes which plugin to run, the test case to use, duration,
maximum number of iterations and maximum number of results allowed. This
response is given when a client request is made and both the client and
plugin are up to date.

* OK -- sent to acknowledge the previous transaction from the client when
no other response is appropriate

* Error/Retry -- sent in the situation where the previous transaction
failed. This is usually due to high server load and either file transfers
or database transactions could not be completed.

NOTE: django hides most of the DB details. See [models.py](csserver/models.py)

The collection of machines running the client software that connect to the
server are known as the cluster. The cluster can be scaled up or down depending
on the priority of the Plugins that are under analysis. The work scales well
because of the isolation provided by the clients and the nature of the random
work being done. The parallelized work can be run on a very large scale to
provide lots of coverage quickly.


Web UI
------

TODO: The web UI is not complete yet.

Triage:
The results can be reviewed and triaged using the web UI. The results are
organized by Plugin and defect and all the details contained in a Result
can be viewed along with the number of times the defect has been found.
The results can then be entered in to the bug tracking system, a click to log
button should be available that populates the entry in a bug tracker.

Administration:
The web UI also provides an interface to allow the administration of the
cluster. Test cases, plugins and client software can all be added and updated
via the web UI. The plugin priority on the cluster can also be managed here.
Plugin specific properties such as test cases can be managed here as well.


Client
------

CrashStash provides an interface that allows users to automate work on the
client such as running fuzzers as well as collecting and reporting results back
to a CrashStash server. With a CrashStash server and multiple connected clients
a distributed fuzzing cluster can be created.

CrashStash Client enables:
* Work requests
* CrashStash client updates
* Plugin updates
* Result and work reporting

Node
----

This step may involve a fair amount of work. Automation of the execution and
the collection of results will need to be performed.

This is where the Result objects will be created and populated with the results
that are found by the plugin/fuzzer.

For an examples see the nodes directory.


Installation
------------

See individual INSTALL files.
