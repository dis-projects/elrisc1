include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=elrisc1
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define KernelPackage/elvees-risc1
  SECTION:=kernel
  CATEGORY:=Kernel modules
  SUBMENU:=Other modules
  DEPENDS:=@TARGET_elvees_mcom03
  #DEPENDS+=+kmod-elvees-elcore50
  TITLE:=Elvees RISC1 driver
  AUTOLOAD:=$(call AutoProbe,risc1)
  FILES:= \
	$(PKG_BUILD_DIR)/risc1.ko
endef

define KernelPackage/elvees-risc1/description
  RISC1 syscall implementations.
endef

define KernelPackage/elvees-risc1/config
	source "$(SOURCE)/Config.in"
endef

define KernelPackage/elvees-risc1-rproc
  SECTION:=kernel
  CATEGORY:=Kernel modules
  SUBMENU:=Other modules
  DEPENDS:=@TARGET_elvees_mcom03 +@KERNEL_REMOTEPROC
  #DEPENDS+=+kmod-elvees-elcore50
  TITLE:=Elvees remoteproc RISC1 driver
  AUTOLOAD:=$(call AutoProbe,risc1-rproc)
  FILES:= \
	$(PKG_BUILD_DIR)/risc1-rproc.ko
endef

define KernelPackage/elvees-rproc-risc1/description
  RISC1 rproc implementations.
endef

PKG_EXTRA_CFLAGS:= \
	$(patsubst CONFIG_%, -D%=1, $(patsubst %=m,%,$(filter %=m,$(PKG_EXTRA_KCONFIG)))) \
	$(patsubst CONFIG_%, -D%=1, $(patsubst %=y,%,$(filter %=y,$(PKG_EXTRA_KCONFIG)))) \
	$(if $(CONFIG_TARGET_elvees_mcom03), -DRISC1_MCOM03=1) \
	$(if $(CONFIG_ERISC1_DRIVER_TRACE), -fno-inline) \

define Build/Compile
	$(MAKE) -C "$(LINUX_DIR)" \
		$(KERNEL_MAKE_FLAGS) \
		EXTRA_CFLAGS="$(PKG_EXTRA_CFLAGS) $(BUILDFLAGS)" \
		M="$(PKG_BUILD_DIR)" \
		modules
endef

define KernelPackage/elvees-risc1/install
	$(INSTALL_DIR) $(1)/usr/include/linux
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/risc1.h $(1)/usr/include/linux/
endef

$(eval $(call KernelPackage,elvees-risc1))
$(eval $(call KernelPackage,elvees-risc1-rproc))
