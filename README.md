## Kong 插件
 灰度插件：部分用户的头部进行染色。<br>

## 1. 整体说明
   ### 1.1 概念说明
人群标签：指通过相关策略划定的用户组，并且给改组打上标签（gray,v1,v2）。
灰度实验：指为实现一次功能灰度实验而建立的一条版本记录，有一个唯一编号（versionCode），包括前端灰度实验和接口灰度实验。版本有三种状态（准备状态-ready、进行状态-running、结束状态-over），来控制整个实验的灰度过程。

### 1.2 整体方案说明
    
## 2. 项目说明
   本项目为Kong的GrayScale插件，支持前端灰度，后端灰度能力。本插件需要和策略引擎，灰度网关等配套使用。
