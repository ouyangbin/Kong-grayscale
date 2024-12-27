-- local m_package_path = package.path
-- package.path = string.format("%s/?.lua;%s",ngx.var.document_root, m_package_path)

local constants = require "kong.constants"
local BasePlugin = require "kong.plugins.base_plugin"


local kong = kong
local type = type

local cjson = require("cjson")

-- 旧版本返回
local function_return_old = { code = 1, data = {version ="old"} , msg = "success"}
-- 新版本返回
local function_return_new = { code = 1, data = {version ="new"} , msg = "success" }


local GrayScaleHandler = BasePlugin:extend()


GrayScaleHandler.PRIORITY = 999
GrayScaleHandler.VERSION = "1.0.0"


function GrayScaleHandler:new()
  GrayScaleHandler.super.new(self, "grayscale")
end



-- 根据accessToken获取Token信息
--
local function getTagInfo(redis,userId)


  --从Redis中获取

  local grayKey = "GrayFunctionVersionIndex"

  local tag,err = redis:get(grayKey)


  if err == nil then
  -- ngx.log(ngx.NOTICE,"1. 用户信息为：" , tokenInfo);
  -- local data = cjson.decode(tokenInfo)
  return tag
  end

  return nil
  end

function getParamValue(userInfo,paramKey,fieldCondition)
  local value = getParamValueFromRequest(paramKey)
  if value == nil or value == ngx.null and fieldCondition ~= nil and #fieldCondition > 0 then
    if userInfo ~= nil then
      if type(userInfo[""..fieldCondition]) == "number" then
        value = tostring(userInfo[""..fieldCondition])
      else
        value = userInfo[""..fieldCondition]
      end

    end
  end
  if (value ~= ngx.null or value ~= nil) and type(value) == "number" then
    value = tostring(value)
  end
  return value
end



-- 根据参数名获取值
function getParamValueFromRequest(paramKey)
  local value = nil;
  if not paramKey or paramKey == nil or paramKey == "" then
    return nil
  end
  local headers = kong.request.get_headers()
  local query = kong.request.get_query()
  value = headers[paramKey]
  if not value then
    value = query[paramKey]
  else
    return value
  end
  if not value then
    local method = string.lower(kong.request.get_method())
    if method == 'put' or method == 'post' or method == 'get' or method == 'patch' then
      local body, err = kong.request.get_body()
      if not err then
        value = body[paramKey]
      end
    end
  else
    return value
  end
  return value;
end
-- 只算后端版本
local function getUserTag(conf)
  local result,hitInfo = getUserHitInfo(conf)
  if  result == nil then
    return nil
  end
  if result ~= nil and hitInfo ~= nil and hitInfo["versionTag"] ~= nil then
    return hitInfo["versionTag"];
  end
  return nil
end


function getUserHitInfo(conf)
  local redis, err = getRedis();
  if not redis or redis == nil then
    ngx.log(ngx.ERR, "初始化redis失败", err)
  end -- 初始化Redis失败

  local grayFunctionVersionIndexkey = "GrayFunctionVersionIndex"
  local grayFunctionVersionIndexValue,err = redis:get(grayFunctionVersionIndexkey)
  if grayFunctionVersionIndexValue == nil or grayFunctionVersionIndexValue == ngx.null then
    return nil
  end
  local grayFunctionVersionIndexValueArray = split(grayFunctionVersionIndexValue,",")
  local HitInfo = nil
  for _ ,grayFunctionVersionCode in ipairs(grayFunctionVersionIndexValueArray) do
    local  result ,hitInfo = isUserHitFunctionVersion(redis,conf,grayFunctionVersionCode)
    if result == true and hitInfo ~= nil then
      -- {"functionVersionCode":"","versionTag":"","ruleType:"realTime/batch","ruleId":"X"}
      -- tag = hitTag
      return result,hitInfo
    end
  end
  return nil

end

-- 灰度路由处理
local function grayRouteProcess(tag,debug)
  local service = kong.router.get_service()
  if tag ~= nil and #tag > 0 then
    kong.service.request.set_header("tag", tag)
    if debug ~= nil and debug == "true" then
      kong.response.set_header("tag", tag)
    end

    -- 设置upstream
    if type(service.name) == "string" then
      if service.name ~= nil and service.name ~= "gray-gateway" then
        local upstream_uri = ngx.var.upstream_uri
        local uri="/"..service.name..upstream_uri
        ngx.var.upstream_uri=uri
        local ok, err = kong.service.set_upstream("gray-gateway")
        if not ok then
          ngx.log(ngx.ERR, "设置gray-gateway 失败，原因为：",err)
          return nil
        end
      end
    else
      -- 如果服务名字不存在，返回空。
      -- kong.service.request.clear_header("tag")
      ngx.log(ngx.ERR, "服务名字为空！请求路径为：",ngx.var.upstream_uri)
      return nil
    end
    return nil
  end

end




--  给请求头增加灰度标签     -- isUserHitFunctionVersion  test版本，用于生产压测，回归等
local function grayTagHandler(conf,debug)

  local header_tag = getParamValueFromRequest("tag")

  -- 支持测试流量
  if header_tag ~= nil and header_tag == "test" then
    grayRouteProcess(header_tag,debug)
    return nil;
  end
  kong.service.request.clear_header("tag")

  local tag = getUserTag(conf)
  grayRouteProcess(tag,debug)
end


function GrayScaleHandler:access(conf)
  GrayScaleHandler.super.access(self)

  local returnHitInfo = getParamValueFromRequest("Gray-HitInfo")
  -- ngx.log(ngx.NOTICE, "returnHitInfo is :", returnHitInfo)

  local grayType = conf.gray_type
  if grayType ~= nil and grayType == 'api' then
    local ok, err = grayTagHandler(conf,returnHitInfo)
  else
    local data_return = {}
    local versionCode = getParamValueFromRequest(conf.version_code)
    if versionCode == null or  versionCode == ngx.null or #versionCode < 1 then
      -- ngx.log(ngx.ERR, "请求版本参数错误", err)

      --return kong.response.exit(502, data_return , nil)
      local result,userHitInfo = getUserHitInfo(conf)
      if userHitInfo ~= nil and returnHitInfo == "true" and  userHitInfo["versionTag"] ~= nil then
        data_return["tag"] = userHitInfo["versionTag"];
        data_return["hitInfo"] = userHitInfo;
      end
      data_return["code"] = 406
      -- 仅仅用来做用户请求头标签查看
      return kong.response.exit(200, data_return , nil)
    end

    local result, responseData = getUserFunctionVersionInfo(conf,versionCode)
    if returnHitInfo ~= nil and returnHitInfo == "true" then
      data_return["hitInfo"] = responseData
    end

    if result == nil then
      data_return["code"] = 502
      return kong.response.exit(502, data_return , nil)
    end

    -- data_return = {}

    if result == true then
      data_return = {}
      data_return = { code = 1, data = {version ="new"} , msg = "success" }
      -- function_return_new
      if returnHitInfo ~= nil and returnHitInfo == "true" then
        data_return["hitInfo"] = responseData
      end
      return kong.response.exit(200, data_return, nil)
    else
      data_return = {}
      data_return = { code = 1, data = {version ="old"} , msg = "success"}
      -- function_return_old
      if returnHitInfo ~= nil and returnHitInfo == "true" then
        data_return["hitInfo"] = responseData
      end
      return kong.response.exit(200, data_return, nil)
    end
  end
end


-- 获取redis连接
function getRedis()
  local redis_cluster = require("kong.plugins.grayscale.rediscluster")
  local config  = require("kong.plugins.grayscale.config")

  local redis, err = redis_cluster:new(config.redis)

  if not redis or redis == nil then
    ngx.log(ngx.ERR, "初始化redis失败", err)
    return nil, { code = 503, msg = "服务出错" }
  end -- 初始化Redis失败
  redis:set_timeouts(config.redis.connect_timeout or DEFAULT_CONNECTION_TIMEOUT,
          config.redis.send_timeout or DEFAULT_SEND_TIMEOUT,
          config.redis.read_timeout or DEFAULT_READ_TIMEOUT)

  -- redis:release_connection(redis_cluster, config.redis)
  return redis,nil;
end
--  用户是否命中功能版本, return boolean, isHitTag
function isUserHitFunctionVersion(redis,conf,functionVersionCode)
  -- grayscalefunctionversion
  local tokenCacheKey = "grayscalefunctionversion"..functionVersionCode
  local versionStatusAndTag,err = redis:get(tokenCacheKey)
  if versionStatusAndTag == nil or versionStatusAndTag == ngx.null then
    return true,{msg = "该版本已经结束灰度"}
  end
  local versionInfo = split(versionStatusAndTag, "#")
  local versionStatus = versionInfo[1]; -- ready  running   over
  local versionTagRedisValue =  versionInfo[2];  -- tag,v1
  if versionStatus == "ready" then
    return false
  end
  local versionTagArray = split(versionTagRedisValue,",")
  for _ ,versionTag in ipairs(versionTagArray) do
    local  result , ruleInfo = isUserHitVersion(redis,conf,versionTag)
    -- {"functionVersionCode":"","versionTag":"","ruleType:"realTime/batch","ruleId":"X"}
    if result == true and ruleInfo ~= nil then
      ruleInfo["versionTag"] = versionTag
      ruleInfo["functionVersionCode"] = functionVersionCode
      ngx.log(ngx.NOTICE,"用户命中，hitInfo is： " , cjson.encode(ruleInfo))
      return true,ruleInfo
    end
  end
  return false
end

-- 获取用户功能版本信息， 注册用户，非注册用户
function getUserFunctionVersionInfo(conf,functionVersionCode)

  --从Redis中获取
  local redis, err = getRedis();
  if not redis or redis == nil then
    return nil,{ code = 503, msg = "服务出错" }
  end -- 初始化Redis失败
  -- {"functionVersionCode":"","versionTag":"","ruleType:"realTime/batch","ruleId":"X"}
  local result ,versionInfo = isUserHitFunctionVersion(redis,conf,functionVersionCode)
  if result == true and versionInfo ~= nil then
    return result , versionInfo
  end
  return result;


end

-- deviceID  进行Hash算法 0-10 , 区域进行Hash判断, type的作用仅仅用来日志
function rangeHash(key,rangeValue,type)
  local subKey = getStringCharSum(key)
  local unRegisterPerSection = split(rangeValue, "-")
  local  section1 = unRegisterPerSection[1]
  local  section2 = unRegisterPerSection[2]
  local mod100 = subKey % 100;
  if mod100 >= tonumber(section1) and mod100 < tonumber(section2) then
    --if type == 1 then
    --  ngx.log(ngx.NOTICE,"用户灰度中，userId is： " , key)
    --else
    --  ngx.log(ngx.NOTICE,"设备灰度中，deviceId is： " , key)
    --end
    return nil,function_return_new
  end
  return nil,function_return_old

end

function rangeHashHit(key,rangeValue,type)
  local subKey = getStringCharSum(key)
  local unRegisterPerSection = split(rangeValue, "-")
  local  section1 = unRegisterPerSection[1]
  local  section2 = unRegisterPerSection[2]
  local mod100 = subKey % 100;
  if mod100 >= tonumber(section1) and mod100 < tonumber(section2) then
    --if type == 1 then
    --  ngx.log(ngx.NOTICE,"用户灰度中，userId is： " , key)
    --else
    --  ngx.log(ngx.NOTICE,"设备灰度中，deviceId is： " , key)
    --end
    return true
  end
  return false

end


-- Hash 函数
function getStringCharSum(key)
  if key == null or key == ngx.null or #key < 1 then
    return nil;
  else
    local length = string.len(key)
    local keySum = 0
    for i = 1, length do
      keySum = keySum + key:byte(i)
    end
    return keySum
  end

end

function split(str,reps)
  local resultStrList = {}
  string.gsub(str,'[^'..reps..']+',function (w)
    table.insert(resultStrList,w)
  end)
  return resultStrList
end

-- 获取版本信息

function getVersionRedisInfo(redis ,versionTag)
  local versionInfoKey = "GrayScale"..versionTag
  local versionInfoValue = redis:get(versionInfoKey)
  if versionInfoValue == nil or versionInfoValue == ngx.null then
    return nil
  end
  return cjson.decode(versionInfoValue)

end

--  用户，版本是否命中版本,返回命中的规则ID。 {"functionVersionCode":"","versionTag":"","ruleType:"realTime/batch","ruleId":"X"}
function isUserHitVersion(redis,conf,versionTag)

  local result = false;

  local versionRedisInfo = getVersionRedisInfo(redis,versionTag)
  if versionRedisInfo == nil then
    return false
  end
  local accessToken = getParamValueFromRequest(conf.token_key_name)

  local data,err = getTokenInfo(redis,accessToken)


  local userId = getParamValue(data,conf.userid_key_name,"userId")

-- 注册用户
  if userId ~= nil and userId ~= ngx.null and #userId > 0 then
    -- 批量比较
    local grayKey = "grayscale"..userId
    local tag,err = redis:get(grayKey)
    if tag ~= null and tag ~= ngx.null and #tag > 0 and tag == versionTag then
      -- 已经灰度
      return true , {ruleType = "batch",userId = userId}
    elseif  tag ~= null and tag ~= ngx.null and #tag > 0 and tag ~= versionTag then
      return false
    end
  end

  local ruleList = versionRedisInfo.ruleList

  for _, rule in ipairs(ruleList) do

    local ruleId = rule.ruleId
    local userTagList = rule.userTagList
    local percent = rule.percent


    local hasRuleCondition = false
    for _, userTag in ipairs(userTagList) do
      local tagValue = getParamValue(data,userTag.tagCode,userTag.fieldCondition)
      -- {"hashKeyType":"userId","ruleList":[{"ruleId":"2","percent":"0-80","userTagList":[{"tagCode":"cityId","tagValue":"~5","fieldCondition":"customCity"}]}]}
      if tagValue == nil or tagValue == ngx.null and userTag.fieldCondition ~= nil and #userTag.fieldCondition > 0 then
        if tagValue == nil and userTag.fieldCondition ~= nil and string.find(userTag.fieldCondition,"!") ~= nil then
          local conditionName = string.sub(userTag.fieldCondition, 2, string.len(userTag.fieldCondition))
          tagValue = getParamValue(data,conditionName,conditionName)
          if tagValue == nil or #tagValue < 1 then
            tagValue = "false"
          else
            tagValue = "true"
          end
        end
      end
      -- 获取 用户标签值为 tagValue

      if tagValue == nil or tagValue == ngx.null then
        break
      end
      -- {"hashKeyType":"userId","ruleList":[{"ruleId":"2","percent":"0-80","userTagList":[{"tagCode":"cityId","tagValue":"~5","fieldCondition":"customCity"}]}]}
      local userTageValue = userTag.tagValue

      if userTageValue == nil then
        break
      end

      local ruleUserTagValueArray = split(userTageValue,",")

      local isNegation = false;
      local  i, j = string.find(userTageValue,"~")
      if i == nil then
        isNegation = false
      else
        isNegation = true
      end

      local isHit = false
      if isNegation == true then
        isHit = true
      end

      for _,userTagValue in ipairs(ruleUserTagValueArray) do
        if i == nil then
          if type(tagValue) == "number" then
            if userTagValue == tostring(tagValue) then
              isHit = true
              break
            end
          else
            if userTagValue == tagValue then
              isHit = true
              break
            end
          end


        else
          -- 需要兼容取反情况

          if type(tagValue) == "number" then
            if userTagValue == "~"..tostring(tagValue) then
              isHit = false
              break
            end
          else
            if userTagValue == "~"..tagValue then
              isHit = false
              break
            end

          end
        end
      end
      if isHit == false then
        hasRuleCondition = false
        break
      end
      hasRuleCondition = true
    end


    --  具备执行该条规则的条件,表示已经匹配到一条规则
    if hasRuleCondition == true then
      -- {"hashKeyType":"userId","ruleList":[{"ruleId":"2","percent":"0-80","userTagList":[{"tagCode":"cityId","tagValue":"~5","fieldCondition":"customCity"}]}]}
      local versionRulePercentValue,err = rule.percent

      if versionRulePercentValue ~= null and versionRulePercentValue ~= ngx.null and #versionRulePercentValue > 0 then
        --  根据百分比进行选取

        local hashKeyValue,err = versionRedisInfo.hashKeyType

        if hashKeyValue == nil or hashKeyValue == ngx.null then
          return false;
        end
        local deviceID = nil
        if hashKeyValue == "deviceId" then

          deviceID = getParamValueFromRequest(conf.deviceid_key_name)

          if deviceID == nil or deviceID == ngx.null or #deviceID < 1 then
            return false;
          end
          result =  rangeHashHit(deviceID,versionRulePercentValue,2)
        elseif hashKeyValue == "userId" then
          if userId == nil or userId == ngx.null or #userId < 1 then
            return false
          end
          result =  rangeHashHit(userId,versionRulePercentValue,1)
        end

        if result == true then
          -- "ruleType:"realTime/batch"
          return true ,{ruleType = "realTime" ,ruleId = ruleId,userId = userId,deviceId = deviceID,hashKeyValue = hashKeyValue}
        end
      end
    end
  end
  return false
end


function getTokenInfo(redis, accessToken )
  if accessToken == nil then
    return nil, { status = 403101, message = "登录Token格式有误" }
  end

  -- 校验accessToken的合法性
  if accessToken and type(accessToken) == "table" then
    accessToken = accessToken[1]
  end
  --不存在,长度非法,格式非法
  if accessToken == nil or type(accessToken) ~= "string"  or #accessToken ~= 54 or not ngx.re.match(accessToken, [[^\w+$]], "jo") then
    return nil, { status = 403101, message = "登录Token格式有误" }
  end

  -- 直接根据时间判断是否已过期
  local now = os.date("%Y%m%d%H%M%S",ngx.time())
  local nowTime = os.date("%Y-%m-%d %H:%M:%S",ngx.time())
  local expireTime = string.sub(accessToken,-14)
  if expireTime<now then
    return nil, { status = 403101, message = "登录状态已过期" }
  end
  -- end
  --从Redis中获取

  local cacheKey = "controller_tokens"..accessToken
  local tokenInfo,err = redis:get(cacheKey)
  if err then
    ngx.log(ngx.ERR, "连接redis失败 ",  err)
  end --连接redis报错，则报警，但不做处理

  --缓存存在，直接返回缓存中数据
  if tokenInfo ~= nil and tokenInfo ~= ngx.null then
    if tokenInfo == "-1" then
      return nil, { status = 403101, message = "登录状态已失效" }
    end
    local data = cjson.decode(tokenInfo)
    -- 增加字段的判断,如没有userId
    -- ngx.log(ngx.ERR, tokenInfo)
    if data.userId == nil or data.errorMsg ~=nil then
      return nil, { status = 403101, message = data.errorMsg}
    end
    if data.expire<nowTime then
      return nil, { status = 403101, message = "登录状态已失效" }
    end

    return data
  end --
  return nil
end




return GrayScaleHandler
