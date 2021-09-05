#!/usr/bin/lua

function sleep (n)
    local t = os.clock()
    while os.clock() - t <= n do
        -- nothing
    end
end

local conncmd = 'conntrack -E'
local pipein  = assert(io.popen(conncmd,  'r'))

for line in pipein:lines() do
    
  words = {}
  for w in line:gmatch("%s") do 
    table.insert(words, w) 
  end

  print (words [2]) --> is

  for k, v in ipairs (words) do
    print (v)
  end -- for
  pipein:flush()
  
end
      
pipein:close()