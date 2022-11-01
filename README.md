# elrisc1

Драйвер для RISC1 собирается в OpenWRT.

Предполагается, что он будет расположен в директории
elv-openwrt/package/kernel/elrisc1

Для добавления драйвера следует использовать make menuconfig
```
Kernel modules --->
   Other modules  --->
    -*- kmod-elvees-risc1.................................... Elvees RISC1 driver
```
