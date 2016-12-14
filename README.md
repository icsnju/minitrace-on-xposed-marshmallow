# MiniTracing for ART

## Build

Check a legacy README for [ART 5.1.1](https://bitbucket.org/txgu/mini-tracing-art5)

## Design

### Data Selection

1. Log every executed instructions

2. To facilitate online-learning algorithm,
we should have a way to harvest coverage data as efficient as possible.
The old design of logging every executed instruction is not feasible as there may be tremendous data.
So, a better way would be to log only branch instructions (only conditional?).

1. `if_xxx`
2. `tableswitch` and `lookupswitch`
3. `goto`
4. `return` and `throw`

### Parser



### Data Output Channel

1. File
2. socket via adb


