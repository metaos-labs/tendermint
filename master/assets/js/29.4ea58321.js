(window.webpackJsonp=window.webpackJsonp||[]).push([[29],{568:function(e,t,n){e.exports=n.p+"assets/img/cosmos-tendermint-stack-4k.6aa56af6.jpg"},635:function(e,t,n){"use strict";n.r(t);var i=n(1),a=Object(i.a)({},(function(){var e=this,t=e.$createElement,i=e._self._c||t;return i("ContentSlotsDistributor",{attrs:{"slot-key":e.$parent.slotKey}},[i("h1",{attrs:{id:"application-architecture-guide"}},[i("a",{staticClass:"header-anchor",attrs:{href:"#application-architecture-guide"}},[e._v("#")]),e._v(" Application Architecture Guide")]),e._v(" "),i("p",[e._v("Here we provide a brief guide on the recommended architecture of a\nTendermint blockchain application.")]),e._v(" "),i("p",[e._v("The following diagram provides a superb example:")]),e._v(" "),i("p",[i("img",{attrs:{src:n(568),alt:"cosmos-tendermint-stack"}})]),e._v(" "),i("p",[e._v('We distinguish here between two forms of "application". The first is the\nend-user application, like a desktop-based wallet app that a user downloads,\nwhich is where the user actually interacts with the system. The other is the\nABCI application, which is the logic that actually runs on the blockchain.\nTransactions sent by an end-user application are ultimately processed by the ABCI\napplication after being committed by the Tendermint consensus.')]),e._v(" "),i("p",[e._v("The end-user application in this diagram is the "),i("a",{attrs:{href:"https://lunie.io/",target:"_blank",rel:"noopener noreferrer"}},[e._v("Lunie"),i("OutboundLink")],1),e._v(" app, located at the bottom\nleft. Lunie communicates with a REST API exposed by the application.\nThe application with Tendermint nodes and verifies Tendermint light-client proofs\nthrough the Tendermint Core RPC. The Tendermint Core process communicates with\na local ABCI application, where the user query or transaction is actually\nprocessed.")]),e._v(" "),i("p",[e._v("The ABCI application must be a deterministic result of the Tendermint\nconsensus - any external influence on the application state that didn't\ncome through Tendermint could cause a consensus failure. Thus "),i("em",[e._v("nothing")]),e._v("\nshould communicate with the ABCI application except Tendermint via ABCI.")]),e._v(" "),i("p",[e._v("If the ABCI application is written in Go, it can be compiled into the\nTendermint binary. Otherwise, it should use a unix socket to communicate\nwith Tendermint. If it's necessary to use TCP, extra care must be taken\nto encrypt and authenticate the connection.")]),e._v(" "),i("p",[e._v("All reads from the ABCI application happen through the Tendermint "),i("code",[e._v("/abci_query")]),e._v("\nendpoint. All writes to the ABCI application happen through the Tendermint\n"),i("code",[e._v("/broadcast_tx_*")]),e._v(" endpoints.")]),e._v(" "),i("p",[e._v("The Light-Client Daemon is what provides light clients (end users) with\nnearly all the security of a full node. It formats and broadcasts\ntransactions, and verifies proofs of queries and transaction results.\nNote that it need not be a daemon - the Light-Client logic could instead\nbe implemented in the same process as the end-user application.")]),e._v(" "),i("p",[e._v("Note for those ABCI applications with weaker security requirements, the\nfunctionality of the Light-Client Daemon can be moved into the ABCI\napplication process itself. That said, exposing the ABCI application process\nto anything besides Tendermint over ABCI requires extreme caution, as\nall transactions, and possibly all queries, should still pass through\nTendermint.")]),e._v(" "),i("p",[e._v("See the following for more extensive documentation:")]),e._v(" "),i("ul",[i("li",[i("a",{attrs:{href:"https://github.com/cosmos/cosmos-sdk/pull/1028",target:"_blank",rel:"noopener noreferrer"}},[e._v("Interchain Standard for the Light-Client REST API"),i("OutboundLink")],1)]),e._v(" "),i("li",[i("a",{attrs:{href:"https://docs.tendermint.com/master/rpc/",target:"_blank",rel:"noopener noreferrer"}},[e._v("Tendermint RPC Docs"),i("OutboundLink")],1)]),e._v(" "),i("li",[i("RouterLink",{attrs:{to:"/tendermint-core/running-in-production.html"}},[e._v("Tendermint in Production")])],1),e._v(" "),i("li",[i("a",{attrs:{href:"https://github.com/tendermint/tendermint/tree/95cf253b6df623066ff7cd4074a94e7a3f147c7a/spec/abci",target:"_blank",rel:"noopener noreferrer"}},[e._v("ABCI spec"),i("OutboundLink")],1)])])])}),[],!1,null,null,null);t.default=a.exports}}]);