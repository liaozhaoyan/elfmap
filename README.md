# elfmap
get all elf file symbols

# functions
refer to test.lua:

```lua
local elfmap = require("elfmap")

-- get libc path from env
local m = elfmap.new(libc)
local count = 0
for _, start, stop, sym in m:maps() do
    count = count + 1
    print(start, stop, sym)
end

assert(count == m:count(), string.format("map: %d, count:%d", count, m:count()))

local start, _ = m:symbol("pthread_self")
assert(start > 0)
local sym = m:query(start)
assert(sym == "pthread_self")
```

* new： new a elfmap object, the only parameter is the path to the elf file.

```
local m = elfmap.new(libc)
```

* maps：Iterate through all the symbol tables in the elf file.

```
for _, start, stop, sym in m:maps() do
    print(start, stop, sym)
end
```

* count: Gets the number of all symbols in the ELF file.
* symbol: Gets the address offset of the specified symbol

```
local start, stop = m:symbol("pthread_self")
```

* query: Queries the symbol information corresponding to the specified address, returns the name, start and end address of the symbol, or \[unknown\], -1, -1 if there is no matching result

```
local sym, start, stop = m:query(start)
```

 

