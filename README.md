# ARL-Web-Alone
ARL资产灯塔主系统纯Python启动版，支持后续自定义修改流程功能

<a href="https://github.com/youki992/ARL-Web-Alone"><img alt="LICENSE" src="https://img.shields.io/badge/LICENSE-GPL-important"></a>
![GitHub Repo stars](https://img.shields.io/github/stars/youki992/ARL-Web-Alone?color=success)
![GitHub forks](https://img.shields.io/github/forks/youki992/ARL-Web-Alone)
![GitHub all release](https://img.shields.io/github/downloads/youki992/ARL-Web-Alone/total?color=blueviolet)  

# 前置环境安装
大文件无法上传Github，app/tools文件夹下目前不包含大文件，需要下载release中的tools.zip并解压其中的文件到app/tools文件夹中（如有需要可以给里面的可执行文件赋权限）
## 一键安装Web端脚本
运行install-complete.sh脚本启动

![0f27c9ba-470c-4cf5-9cfd-082e078f1da9](http://image.aibochinese.com/i/2025/10/30/m7mx69.png)

安装完成如下

![b98de3d5-af8a-4f53-a307-44ca09393ae9](http://image.aibochinese.com/i/2025/10/30/m7vmhb.png)

## docker环境依赖
rabbitmq和mongdb还是通过docker启动，直接下载离线tar压缩包，网盘地址：
```
通过百度网盘分享的文件：arl_2.6.1.tar
链接：https://pan.baidu.com/s/12xacho0GxyJPkCRCXVIKNQ?pwd=2ks6 
提取码：2ks6

通过百度网盘分享的文件：arl_mongo.tar
链接：https://pan.baidu.com/s/1oySY8K-YhPKKrqUl5R5C4A?pwd=2ks6 
提取码：2ks6
```

然后运行下面的命令加载容器即可：
```
docker load -i rabbitmq-arl.tar
docker load -i mongodb-arl.tar
```

## 主程序启动
最后就是Web端启动，在最外面的目录中，使用Python命令启动即可（启动后自动后台运行，关闭页面不影响）

```
python start_all.py
```
启动成功，Web端启动在5003端口，访问http://服务器IP:5003

![f6794df5-9f0d-4f6b-a59b-172bc7e532c3](http://image.aibochinese.com/i/2025/10/30/m9jcac.png)

![7699cdfa-a83e-44fc-b513-b700ee42f03b](http://image.aibochinese.com/i/2025/10/30/m9j59m.png)

# 参考详细流程

https://mp.weixin.qq.com/s/__k_V1YXY1gmMiN3PDJO-Q
