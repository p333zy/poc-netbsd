-- Retrieve the string from beyond the stack bounds
local S = RetrieveString1()

local text, hex = HexExtract:Extract(S, 256)
systm.print("@@@BEGIN-HEXDUMP label=STAGE1\n");
HexExtract:DumpHex(hex)
systm.print("@@@END-HEXDUMP\n");

-- -- Nil the string reference to avoid the GC process visiting it
S = nil

-- Release arrays 
ReleaseForgeSArrays()

-- Trigger GC to get us back to a clean slate
text = nil
hex = nil
TriggerGC(20)
