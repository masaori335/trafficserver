# Resource Constraints


Restrict resources per property.


# Extention of sni.yaml


The `tag` is a new key to identify property.

```
sni:
  - fqdn: a.example.com
    tag: foo
  - fqdn: b.localhost
    tag: bar
```

The hash (FNV1a) of tag is set to the Continuation on SNI hook.
TODO: set tag_id at remapping

```
// I_Continuation.h
class Continuation : private force_VFPT_to_top
{
public:
  ...
  /**
    Identifier of property (SNI/Reamp)
   */
  uint32_t tag_id = 0;
```


# Resource Types


- SNI (TLS Handshake)
- Active_Q (NetVConnection Active Queue)
- Disk_Read
- Disk_Write

# Reactive Token Bucket

Algorithms of resource constraints.

## Version 0:

Gathering stats only. No constraints.

## Version 1:

Reserve resource depends on demands.

- When a property exceeds the limit, temporal limit will be applied.
- Divide resources into "RED" and "BLUE" zone by config.
- Divide BLUE zone per property by demands.


# Configs


## `proxy.config.resource.max_stats_size` INT 1000

- restart required

Maximum stats size per limitter

## `proxy.config.resource.top_n` INT 10

- reloadable

Number of properties to set dedicated buckets. Rest of small properties will use global bucket.

## `proxy.config.resource.TYPE.mode` INT 0

- reloadable

Mode of resource constrains feature per resource type.

- 0 : Disabled
- 1 : Stats Only
- 2 : Restrict

## `proxy.config.resource.TYPE.limit` INT 0

- reloadable

Limit of the resource type (per thread)

## `proxy.config.resource.TYPE.penalty_duration` INT 60

- reloadable

How long set the temporal limit if a property exceeds the limit

## `proxy.config.resource.TYPE.red_zone` FLOAT 0.2

- reloadable

The rate of the RED zone of the V1 algorithm


# Metrics


## Global Buckets

`proxy.process.resource.global.TYPE.(observed|token)`

## Property Dedicated Buckets

TODO: naming of these buckets. "specific bucket" is better? any good ideas?

Combination of resource type and tag.

`proxy.process.resource.TYPE.TAG.(observed|token|denied|overflowed)`

```
proxy.process.resource.active_q.bar.denied 0
proxy.process.resource.active_q.bar.observed 0
proxy.process.resource.active_q.bar.tmp_limit 0
proxy.process.resource.active_q.bar.token 0
proxy.process.resource.active_q.foo.denied 0
proxy.process.resource.active_q.foo.observed 0
proxy.process.resource.active_q.foo.tmp_limit 0
proxy.process.resource.active_q.foo.token 0
proxy.process.resource.active_q.total.observed 0
proxy.process.resource.active_q.total.token 0
proxy.process.resource.sni.bar.denied 0
proxy.process.resource.sni.bar.observed 0
proxy.process.resource.sni.bar.tmp_limit 0
proxy.process.resource.sni.bar.token 0
proxy.process.resource.sni.foo.denied 0
proxy.process.resource.sni.foo.observed 0
proxy.process.resource.sni.foo.tmp_limit 0
proxy.process.resource.sni.foo.token 0
proxy.process.resource.sni.total.observed 0
proxy.process.resource.sni.total.token 0
```
