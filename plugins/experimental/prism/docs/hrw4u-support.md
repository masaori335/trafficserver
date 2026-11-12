# hrw4u support in prism.so

What of `.hrw4u` prism.so on this branch runs once it is compiled to IR, by the categories `.hrw4u` has, with the
`header_rewrite` each one compiles to for a `.conf`. "Not supported" is what `prism-vm-support.sandbox.yaml` denies;
prism.so's IR reader (`src/ir_reader.cc`) has no builtin for it either. In the `header_rewrite` columns, "none" means
it has no spelling for it. The `prism.so` column names what the IR runs: a builtin, an opcode, or nothing. Hooks are
those the spelling compiles in (`tools/hrw4u --output ir --sandbox prism-vm-support.sandbox.yaml`) and its builtin runs
in; "all" is every hook below.

## Hooks

| `.hrw4u` | `header_rewrite` | Status | Notes |
| --- | --- | --- | --- |
| `TXN_START` | `TXN_START` | Supported | from `plugin.config` only |
| `READ_REQUEST` | `READ_REQUEST_HDR` | Supported | from `plugin.config` only |
| `PRE_REMAP` | `READ_REQUEST_PRE_REMAP` | Supported | from `plugin.config` only |
| `REMAP` | `REMAP_PSEUDO` | Supported | from a remap rule only |
| none | `POST_REMAP` | Not supported | |
| `SEND_REQUEST` | `SEND_REQUEST_HDR` | Supported | |
| `READ_RESPONSE` | `READ_RESPONSE_HDR` | Supported | |
| `SEND_RESPONSE` | `SEND_RESPONSE_HDR` | Supported | |
| `TXN_CLOSE` | `TXN_CLOSE` | Supported | |

## Sections

| `.hrw4u` | `header_rewrite` | Status | Notes |
| --- | --- | --- | --- |
| `VARS` | `STATE-FLAG`, `STATE-INT8`, `STATE-INT16` slots | Supported | `bool`, `int8` and `int16` |
| `SESSION_VARS` | `SESSION-FLAG`, `SESSION-INT8`, `SESSION-INT16` slots | Not supported | |
| `INSTANCE_VARS` | none | Supported | IR 1.1 (`--ir-version 1.1`): `string` only, set once when the instance loads, by the IR's `Instance:` section |

## Functions

| `.hrw4u` | `header_rewrite` | `prism.so` | Hooks | Status | Notes |
| --- | --- | --- | --- | --- | --- |
| `access("<path>")` | `%{ACCESS:<path>}` | — | — | Not supported | |
| `add-header(<name>, "<value>")` | `add-header` | the hook's `BI_ADD_*_HEADER` | all but `TXN_START`, `TXN_CLOSE` | Supported | with a warning; the name is not quoted |
| `cache()` | `%{CACHE}` | — | — | Not supported | |
| `cidr(<v4>,<v6>)` | `%{CIDR:<v4>,<v6>}` | — | — | Not supported | |
| `counter("<name>")` | `counter` | — | — | Not supported | |
| `inbound.resp.set-redirect(<code>, "<url>")`, `outbound.resp.set-redirect(...)`, `set-redirect(...)` | `set-redirect` | — | — | Not supported | |
| `inbound.url.keep_query("<keys>")`, `outbound.url.keep_query(...)`, `keep_query(...)` | `rm-destination QUERY <keys> [I]` | — | — | Not supported | |
| `inbound.url.remove_query("<keys>")`, `outbound.url.remove_query(...)`, `remove_query(...)` | `rm-destination QUERY <keys>` | — | — | Not supported | |
| `internal()` | `%{INTERNAL-TRANSACTION}`, `%{INTERNAL-TXN}` | — | — | Not supported | |
| `no-op()` | `no-op` | nothing | all | Supported | |
| `prism::<name>(...)` | none | `call.load` or `call.pure` of the binding (opcodes) | as each function allows | Supported | IR 1.1; the functions are in `src/cripts_bindings.cc`, see the README's Akamai G2O section |
| `random(<n>)` | `%{RANDOM:<n>}` | `BI_RANDOM` | all | Supported | |
| `run-plugin("<plugin>", "<arg>", ...)` | `run-plugin` | — | — | Not supported | |
| `set-body-from("<url>")` | `set-body-from` | — | — | Not supported | |
| `set-config("<record>", <value>)` | `set-config` | — | — | Not supported | |
| `set-debug()` | `set-debug` | — | — | Not supported | |
| `set-plugin-cntl(<control>, "<value>")` | `set-plugin-cntl` | — | — | Not supported | |
| `skip-remap(<bool>)` | `skip-remap` | — | — | Not supported | |
| `ssn-txn-count()` | `%{SSN-TXN-COUNT}` | — | — | Not supported | |
| `txn-count()` | `%{TXN-COUNT}` | — | — | Not supported | |

## Conditions

| `.hrw4u` | `header_rewrite` | `prism.so` | Hooks | Status | Notes |
| --- | --- | --- | --- | --- | --- |
| `<variable>` in `VARS` | `%{STATE-FLAG:<n>}`, `%{STATE-INT8:<n>}`, `%{STATE-INT16:<n>}` | `load.v` (an opcode) | all | Supported | |
| `<variable>` in `SESSION_VARS` | `%{SESSION-FLAG:<n>}`, `%{SESSION-INT8:<n>}`, `%{SESSION-INT16:<n>}` | — | — | Not supported | |
| `<variable>` in `INSTANCE_VARS` | none | `load.i` (an opcode) | — | Not supported | `.hrw4u` reads one only outside a condition |
| `capture.<n>` | `%{LAST-CAPTURE:<n>}` | — | — | Not supported | |
| `false`, `true` | `%{FALSE}`, `%{TRUE}` | `const.i` (an opcode) | all | Supported | |
| `from.url.<field>`, `from.url.query.<name>` | `%{FROM-URL:<field>}`, `%{FROM-URL:QUERY:<name>}` | — | — | Not supported | |
| `geo.<field>` | `%{GEO:<field>}` | — | — | Not supported | |
| `http.cntl.<control>` | `%{HTTP-CNTL:<control>}` | — | — | Not supported | |
| `id.<field>` | `%{ID:<field>}` | — | — | Not supported | |
| `inbound.conn.<field>` | `%{INBOUND:<field>}` | — | — | Not supported | includes `REMOTE-ADDR` and `LOCAL-ADDR`; write `inbound.ip` and `inbound.server` |
| `inbound.cookie.<name>` | `%{COOKIE:<name>}` | — | — | Not supported | |
| `inbound.ip` | `%{IP:CLIENT}` | `BI_IP_CLIENT` | all | Supported | |
| `inbound.method` | `%{METHOD}` | — | — | Not supported | |
| `inbound.req.<name>` | `%{CLIENT-HEADER:<name>}` | `BI_CLIENT_HEADER` | all but `TXN_START`, `TXN_CLOSE` | Supported | |
| `inbound.resp.<name>` | `%{HEADER:<name>}` | `BI_CLIENT_RESP_HEADER` | `SEND_RESPONSE` | Supported | |
| `inbound.server` | `%{IP:INBOUND}` | `BI_IP_INBOUND` | all | Supported | |
| `inbound.status` | `%{STATUS}` | `BI_CLIENT_RESP_STATUS` | `SEND_RESPONSE` | Supported | |
| `inbound.url.<field>` | `%{CLIENT-URL:<field>}` | `BI_CLIENT_URL` | all but `TXN_START`, `TXN_CLOSE` | Supported | |
| `inbound.url.query.<name>` | `%{CLIENT-URL:QUERY:<name>}` | `BI_CLIENT_URL_PARAM` | all but `TXN_START`, `TXN_CLOSE` | Supported | |
| `nexthop.<field>` | `%{NEXT-HOP:<field>}` | — | — | Not supported | |
| `now` | `%{NOW}`, `%{NOW:EPOCH}` | `BI_NOW` | all | Supported | `.hrw4u` has no `now.EPOCH` |
| `now.<part>` | `%{NOW:<part>}` | `BI_NOW` | all | Supported | |
| `outbound.conn.<field>` | `%{OUTBOUND:<field>}` | — | — | Not supported | |
| `outbound.cookie.<name>` | `%{COOKIE:<name>}` | — | — | Not supported | |
| `outbound.ip` | `%{IP:SERVER}` | — | — | Not supported | |
| `outbound.method` | `%{METHOD}` | — | — | Not supported | |
| `outbound.req.<name>` | `%{SERVER-HEADER:<name>}` | `BI_SERVER_HEADER` | `SEND_REQUEST`, `READ_RESPONSE`, `SEND_RESPONSE` | Supported | |
| `outbound.resp.<name>` | `%{HEADER:<name>}` | `BI_SERVER_RESP_HEADER` | `READ_RESPONSE` | Supported | |
| `outbound.server` | `%{IP:OUTBOUND}` | — | — | Not supported | |
| `outbound.status` | `%{STATUS}` | `BI_SERVER_RESP_STATUS` | `READ_RESPONSE` | Supported | |
| `outbound.url.<field>` | `%{SERVER-URL:<field>}` | `BI_SERVER_URL` | `SEND_REQUEST`, `READ_RESPONSE`, `SEND_RESPONSE` | Supported | |
| `outbound.url.query.<name>` | `%{SERVER-URL:QUERY:<name>}` | — | — | Not supported | |
| `tcp.info` | `%{TCP-INFO}` | — | — | Not supported | |
| `to.url.<field>`, `to.url.query.<name>` | `%{TO-URL:<field>}`, `%{TO-URL:QUERY:<name>}` | — | — | Not supported | |
| none | `%{CLIENT-CERT}`, `%{DBM}`, `%{SNI}`, `%{URL:<field>}` | — | — | Not supported | |

## Operators

| `.hrw4u` | `header_rewrite` | `prism.so` | Hooks | Status | Notes |
| --- | --- | --- | --- | --- | --- |
| `<variable> = <value>`, in `VARS` | `set-state-flag`, `set-state-int8`, `set-state-int16` | `store.v` (an opcode) | all | Supported | |
| `<variable> = <value>`, in `SESSION_VARS` | `set-session-flag`, `set-session-int8`, `set-session-int16` | — | — | Not supported | |
| `http.cntl.<control> = <bool>` | `set-http-cntl` | — | — | Not supported | |
| `http.status = <code>`, `inbound.status = <code>`, `outbound.status = <code>` | `set-status` | — | — | Not supported | |
| `http.status.reason = "<reason>"`, and on `inbound.status.reason`, `outbound.status.reason` | `set-status-reason` | — | — | Not supported | |
| `inbound.conn.dscp = <n>`, `outbound.conn.dscp = <n>` | `set-conn-dscp` | — | — | Not supported | |
| `inbound.conn.mark = <n>`, `outbound.conn.mark = <n>` | `set-conn-mark` | — | — | Not supported | |
| `inbound.cookie.<name> = "<value>"`, `= ""`, and on `outbound.cookie.` | `set-cookie`, `rm-cookie` | — | — | Not supported | |
| `inbound.req.<name> = "<value>"`, `+= "<value>"`, `= ""` | `set-header`, `add-header`, `rm-header` | `BI_SET_CLIENT_HEADER`, `BI_ADD_CLIENT_HEADER`, `BI_RM_CLIENT_HEADER` | `READ_REQUEST`, `PRE_REMAP`, `REMAP` | Supported | |
| `inbound.resp.<name> = "<value>"`, `+= "<value>"`, `= ""` | `set-header`, `add-header`, `rm-header` | `BI_SET_CLIENT_RESP_HEADER`, `BI_ADD_CLIENT_RESP_HEADER`, `BI_RM_CLIENT_RESP_HEADER` | `SEND_RESPONSE` | Supported | |
| `inbound.resp.body = "<body>"` | `set-body` | — | — | Not supported | |
| `inbound.url.<field> = "<value>"`, `= ""`, and on `outbound.url.` | `set-destination`, `rm-destination` | — | — | Not supported | |
| `outbound.req.<name> = "<value>"`, `+= "<value>"`, `= ""` | `set-header`, `add-header`, `rm-header` | `BI_SET_SERVER_HEADER`, `BI_ADD_SERVER_HEADER`, `BI_RM_SERVER_HEADER` | `SEND_REQUEST` | Supported | |
| `outbound.resp.<name> = "<value>"`, `+= "<value>"`, `= ""` | `set-header`, `add-header`, `rm-header` | `BI_SET_SERVER_RESP_HEADER`, `BI_ADD_SERVER_RESP_HEADER`, `BI_RM_SERVER_RESP_HEADER` | `READ_RESPONSE` | Supported | |
| none | `add-cookie`, `deny-tls`, `set-cc-alg`, `set-effective-address`, `set-next-hop-strategy`, `timeout-out` | — | — | Not supported | |

## Modifiers

| `.hrw4u` | `header_rewrite` | Status | Notes |
| --- | --- | --- | --- |
| none | `[CASE]` | Supported | the default |
| `with EXT`, `with MID`, `with PRE`, `with SUF` | `[EXT]`, `[MID]`, `[PRE]`, `[SUF]` | Supported | on a string `==` or set |
| `with NOCASE` | `[NOCASE]` | Supported | on a string `==`, a set or a regular expression |
| `with NORM` | `[NORM]` | Not supported | |
| `keep_query(...)` | `[I]`, `[INV]` | Not supported | on `rm-destination QUERY`; see Functions |
| none | `[QSA]` | Not supported | on `set-destination` and `set-redirect` |

## Language

| `.hrw4u` | `header_rewrite` | Status |
| --- | --- | --- |
| `if ... { } elif ... { } else { }` | `if` / `elif` / `else` | Supported |
| `&&`, `\|\|` | `[AND]`, `[OR]` | Supported |
| `!`, `!=`, `!~`, `!in` | `[NOT]` | Supported |
| `( ... )` | `%{GROUP}` / `%{GROUP:END}` | Supported |
| `==`, `<`, `>` | `=`, `<`, `>` | Supported |
| `~ /<regex>/` | a regular expression | Supported |
| `in ["<a>", "<b>"]`, `in [<n>, <m>]`, `in {<cidr>, <cidr>}` | string, integer and IP range sets | Supported |
| `"...{<expr>}..."` | `%{...}` in a string | Supported |
| `break` | `[L]`, `[LAST]` | Supported |
