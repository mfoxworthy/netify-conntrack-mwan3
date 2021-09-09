#!/usr/bin/lua

-- Author - Michael Foxworthy

-- This program will keep track of connections on load balanced policies with mwan3.
-- The flows are detected with the Netify plugins and the ipset sets are updated wit the dst_IP
-- If the intended interface isn't used, this program will terminate the connection and delete
-- the entries from the ipsets. It will add the entry to the correct ipset rule. The next time
-- the connection is tried it will take the correct path.


local posix = require "posix"
local logging_level = 1
local loglvl_arr = {'loglvl1', 'loglvl2', 'loglvl3'}

-- Lua doesn't have a built in sleep funtion so we build are own. Still figuring out if this is useful.

function sleep (n)
    local t = os.clock()
    while os.clock() - t <= n do
    end
end



--Logging logic. Probably find a logging lib somewhere and replace.

function loglvl1(message)
  if (logging_level == 1) then
    os.execute(string.format('logger -p err -t conntrack_fix %s', message))
 end
end
 
function loglvl2(message)
  if (logging_level <= 2) then
    os.execute(string.format('logger -p err -t conntrack_fix %s', message))
  end
end

function loglvl3(message)
  if (logging_level == 3) then
    os.execute(string.format('logger -p err -t conntrack_fix %s', message))
  end
end

function nolog()
  end
 


function logger(level, message)
  if (logging_level ~= 0) then
    if (level == 1) then
      loglvl1(message)
    elseif (level == 2) then
      loglvl2(message)
    elseif (level == 3) then
      loglvl3(message)
    else
      nolog()
    end
  end
end

-- Function to split the conntrack string and put it into a table -- Tables can be arrays in Lua

function split (line)
  words = {}
  for w in line:gmatch("%S+") do 
    table.insert(words, w)
  end
  return words  
end

-- Function to reset flow

function flow_reset (dst_IP, dport, set, del_set)
  local reset = 'conntrack -D -d ' .. dst_IP .. ' \>/dev/null 2\>\&1'
  --os.execute('ipset del -exist ' .. del_set .. ' ' .. dst_IP)
  --os.execute('ipset add -exist ' .. set .. ' ' .. dst_IP)
  sleep(1)
  os.execute(reset)
  logger(1, string.format('\'RESET connction for IP=%s DPORT=%s TO-SET=%s\'', dst_IP, dport, set))
end

-- Function to get iptables policy chain used by mwan3 for hooks

function fetchpolicy ()
  local polcmd = 'iptables -L mwan3_rules -t mangle | grep -v LOG | grep match-set | awk \'{print $1}\''
  local getpols = assert(io.popen(polcmd, 'r'))
  pols = {}
  for policy in getpols:lines() do
    table.insert(pols, policy)
  end
  getpols:close()  
  return pols
end

-- Funtion that fetches the rules from iptables -- Helper to figure out the ipsets mwan3 puts in.
-- We could have grabbed them from Netify configs but we wouldn't know the mark

function fetchipsets ()
  local ipsetcmd = 'iptables -L mwan3_rules -t mangle | grep -v LOG | grep match-set | awk \'{print $7}\''
  local getsets = assert(io.popen(ipsetcmd, 'r'))
  sets = {}
  for set in getsets:lines() do
    table.insert(sets, set)
  end
  getsets:close()
  return sets
end

-- Funtion to get marks from policies.

function fetchmarks (policy, ipsets)
  marks = {}
  for i, v in ipairs(policy) do
    local markcmd = 'iptables -L ' .. v .. ' -t mangle | grep MARK | awk \'{print $16}\' | cut -c -5'
    local getmarks = assert(io.popen(markcmd, 'r'))
    k = ipsets[i]
    for m in getmarks:lines() do
      marks[tonumber(m, 10)] = k
    end
    getmarks:close()
  end
  return marks
end

-- Heavy lifter funtion to test all flows then call the reset helper that resets flows and add the ip to the correct set.
-- If we have bugs, this is where we will find them :)

function fixconntrack (flow_mark, dst_IP, dport, nf_mark)
  flow_mark = tonumber(flow_mark)
  mark_check = 0 -- There are more marks than those used for ipsets. We don't want false positives
  set_count = 0
  if (flow_mark ~= nil) then
    for k, v in pairs(nf_mark) do
      if (flow_mark ~= k) then
        mark_check = mark_check + 1
      end
        
        set_count = set_count + 1
        print(v)
        local conncheckcmd = 'ipset test ' .. v .. ' ' .. dst_IP .. ',' .. dport
        local conncheck = assert(io.popen(conncheckcmd, 'r'))
        logger(1, string.format('\'Checking set %s\'', v))
        local conn_str = conncheck:read("*all")
        
          if string.find(conn_str, "Warning\:") then
            logger(1, string.format('\'Found IP=%s DPORT=%s IPSET=%s NF_MARK=%s\'', dst_IP, dport, v, k))
            in_table = k -- reassinment for readablility    
          end
        
      end
    end
  if (in_table == nil) then -- mark wasn't found in any ipsets
    logger(3, 'Not found in ipsets...')
  elseif (mark_check == set_count) then -- do nithing
  elseif (in_table ~= flow_mark) then -- compare the table mark with the mark found in the flow. if they don't match reset the flow.
    local set = nf_mark[in_table] -- nf_mark is the mark configured in netfilter for a particular ipset. Source of truth.
    local del_set = nf_mark[flow_mark]
    flow_reset(dst_IP, dport, set, del_set)
  end
end

function nf_conntrack (nf_mark)

  -- Variables to to pipe conntrack data into our script. 
  -- We don't format it on the line, we use multiple variables
  -- so its best to just use Lua.
  logger(1, '\'NF_CONNTRACK Started...\'')
  local conn_cmd = 'conntrack -E -b 10485760'
  local conn_in = assert(io.popen(conn_cmd,  'r'))
  for line in conn_in:lines() do
    conn_arr = split(line)
    if (conn_arr [1] ~= nil) then
      status = string.gsub(conn_arr [1], "%A", "")
    
        -- We need to know if the NEW connection is TCP or UDP.
        -- conntrack formats these lines differently
    
        if (status == "NEW" and conn_arr [2] == "tcp") then
          dst_IP = string.gsub(conn_arr [7], "dst%=", "")
          dport = string.gsub(conn_arr [9], "dport%=", "")
          if (string.gsub(conn_arr [15], "mark%=", "") == nil) then -- need to figure out the empty ones but for now we'll ride through it.
              logger(1, '\'No tag found\'')
          else
            flow_mark = string.gsub(conn_arr [15], "mark%=", "")
            local l_cmd = string.format('\'New flow detected IP=%s DPORT=%s NF_MARK=%s\'', dst_IP, dport, flow_mark)
            logger(1, l_cmd )
          end
            fixconntrack(flow_mark, dst_IP, dport, nf_mark)
        elseif (status == "NEW" and conn_arr [2] == "udp") then-- pick off UDP
          if (string.gsub(conn_arr [8], "dport%=", "") ~= ("53" or "68" or "67")) then -- ommit local UDP. Need a better fuction for this.
            dport = string.gsub(conn_arr [8], "dport%=", "")
            dst_IP = string.gsub(conn_arr [6], "dst%=", "")
          end
        else
          logger(3, '\'Connection is not TCP or UDP\'')
        end
    end
  end
end

-- Set tables up at start so we don't keep looking at static data.
-- Future version will build a table and stagre this data to improve performance.

policy = fetchpolicy()
ipsets = fetchipsets()
nf_marks = fetchmarks(policy, ipsets)


-- Kick things off.
function detach_conntrack()
    local pid = posix.fork()
    if pid == 0 then -- this is the child process
      nf_conntrack(nf_marks)
    else             -- this is the parent process
        -- nothing
    end
end


--detach_conntrack()
nf_conntrack(nf_marks)


