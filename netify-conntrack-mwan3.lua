#!/usr/bin/lua

-- Lua doesn't have a built in sleep funtion so we build are own.

function sleep (n)
    local t = os.clock()
    while os.clock() - t <= n do
        -- nothing
    end
end


-- Variables to to pipe conntrack data into our script. 
-- We don't format it on the line, we use multiple variables
-- so its best to just use Lua.

local conncmd = 'conntrack -E'
local pipein  = assert(io.popen(conncmd,  'r'))

-- Function to split the conntrack string and put it into a table -- Tables can be arrays in Lua

function split (line)
  
  words = {}
  
  for w in line:gmatch("%S+") do 
    table.insert(words, w)
  end
  
  return words  

end

function reset (dst_IP)
  local reset = "conntrack -D -d " .. dst_IP
  os.execute(reset)
  
end
for line in pipein:lines() do
    

  conn_arr = split(line)

  status = string.gsub(conn_arr [1], "%A", "")
  
  -- We need to know if the NEW connection is TCP or UDP.
  -- conntrack formats these lines differently
  
  if (status == "NEW" and conn_arr [2] == "tcp")
     then
       
      dst_IP = string.gsub(conn_arr [7], "dst%=", "")
      -- print("tcp flow ", dst_IP)
      reset(dst_IP)
      
  
  elseif (status == "NEW" and conn_arr [2] == "udp") -- pick off UDP
      then
        if (string.gsub(conn_arr [8], "dport%=", "") ~= ("53" or "68" or "67"))
          then
            dport = string.gsub(conn_arr [8], "dport%=", "")
            
            dst_IP = string.gsub(conn_arr [6], "dst%=", "")
            
            -- print("udp flow ", dst_IP, " ", dport)
            
        end
  end
  pipein:flush()
  
end
      
pipein:close()