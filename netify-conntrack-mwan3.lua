#!/usr/bin/lua

function sleep (n)
    local t = os.clock()
    while os.clock() - t <= n do
        -- nothing
    end
end

local conncmd = 'conntrack -E'
local pipein  = assert(io.popen(conncmd,  'r'))

function split (line)
  
  words = {}
  
  for w in line:gmatch("%S+") do 
    table.insert(words, w)
  end
  
  return words  

end

for line in pipein:lines() do
    

  conn_arr = split(line)

  status = string.gsub(conn_arr [1], "%A", "")
  
  if (status == "NEW" and conn_arr [2] == "tcp")
     then
       
      dst_IP = string.gsub(conn_arr [7], "dst%=", "")
      print(dst_IP)
  
  esleif (status == "NEW" and conn_arr [2] == "udp")
      then
        dst_IP = string.gsub(conn_arr [6], "dst%=", "")
        print(dst_IP)
  end
  pipein:flush()
  
end
      
pipein:close()