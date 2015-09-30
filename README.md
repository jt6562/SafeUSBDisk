# 介绍
本项目软件部分是基于Android的USB驱动和ADB服务，实现的一个私有协议的加密U盘系统。

U盘固件是一个基于busybox的最小linux系统，kernel使用了Android系统版本，
Android使用的linux内核USB驱动的设计非常巧妙，几乎将现有的USB Gadget驱动都集成到一个框架之下。
通过用户态的配置可以启动不同的USB Gadget功能。

在本项目中，在ADB(Android Debug Bridge)的文件传输和控制协议基础上，增加的文件读写的加解密功能。
加密算法使用国密SM3和SM4算法。

# 安全校验流程
固件第一次上电时，通过随机数发生器(物理噪声源)生成唯一密钥。
对使用初始口令12345678使用SM3进行加密，并用加密后的口令对之前生成的唯一密钥进行加密，使用SM4算法。并将加密后的密钥文件1保存。
然后，使用同样的加密后口令对一段文字进行加密(使用了一段从知乎上的文字，挺有意思的)，同样操作，并保存为密钥文件2。

之后每次登陆都对口令执行相同的操作，并使用加密后的口令对同一段文字进行SM4加密，如果密文和之前保存的密钥文件2相同，则表明口令正确。



# device端开发环境搭建
这里使用了全志A10s作为硬件平台，所以用了全志的开发包

1.sdbd开发环境比较简单，只需要下载arm交叉编译工具链，在device/sdbd/目录下执行make
  即可。arm交叉编译工具链从lichee的buildroot的输出目录拷贝(buildroot/output/external-toolchain), 设置好PATH环境变量就可以编译了。

2.device目录下的adb是一个纯linux的adb编译版本，目前只能用于编译linux版本的adb工
  具，还无法编译出windows使用的adb库。
  adb的windows动态库编译需要一个完整的android开发环境，修改adb代码后，执行make
  USE_MINGW=y adb,在android开发环境的out/host/windows-x86/bin目录下就能找到编译
  好的文件

3.device端镜像创建方法:
a.将lichee_v1.6.tar.gz解压到开发目录dev下，将
  pack_eagle目录拷贝到dev/lichee下,目录结构如下：
  dev
  ├── lichee
  │   ├── boot
  │   ├── buildroot
  │   ├── linux-3.0
  │   ├── out
  │   ├── pack_eagle
  │   ├── tools
  │   └── u-boot
b.在lichee目录下执行./build.sh -p sun5i-lite -k 3.0 -m all
完成后可以看到在out目录下生成了kernel和其他内容。

c.拷贝a10s-safedisk-v1目录到dev/lichee/tools/pack/chips/sun5i/configs/linux下，这
样就能编译我们的镜像了。我将所有打包相关的配置文件和硬件配置文件都放在了这个目录
下，这样就不会使用默认配置了。

d.修改dev/lichee/tools/pack/pack脚本，修改227行，改为
     LICHEE_OUT=`cd ../../out/android; pwd`
# 注意
LICHEE_OUT目录是在out/android下，这个是lichee打包的一个bug，主要是因为全志没有提
供A10s的linux打包功能，所以有一些脚本没有做过检查

e.进入dev/lichee/pack_eagle目录，执行./pack,生成最终livesuite开始使用的镜像

3.device端根文件系统使用busybox创建, 用于更新hidefs
