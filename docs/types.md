# Types
### Table of Contents
1. [ScionISD](#scionisd)
2. [ScionAS](#scionas)
3. [ScionIA](#scionia)


## ScionISD
### Definition
```typedef uint16_t ScionISD;```

### Description
`ScionISD` is used to represent a ISD (Isolation Domain) number using `16 bits`.

## ScionAS
### Definition
```typedef uint64_t ScionAS;```

### Description
`ScionAS` is used to represent a AS (Autonomous System) number using `48 bits`. The upper 16 bits are ignored.

## ScionIA
### Definition
```typedef uint64_t ScionIA;```

### Description
`ScionIA` is used to represent a combined ISD-AS number using `64 bits`. The upper 16 bits reperesnt the ISD, the lower 48 bits represent the AS number.
