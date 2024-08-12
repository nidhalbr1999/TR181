#
# Copyright (C) 2020-2023 IOPSYS Software Solutions AB
#
# This is free software, licensed under the BSD-3-Clause
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=icwmp
PKG_VERSION:=9.6.7
PKG_SOURCE_VERSION:=7ff419cefc314156a0ac518972096ef0dfb87162
PKG_MIRROR_HASH:=skip
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_LICENSE:=BSD-3-Clause
PKG_LICENSE_FILES:=LICENSE

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk
include ../bbfdm/bbfdm.mk

define Package/icwmp
  SECTION:=utils
  CATEGORY:=Utilities
  SUBMENU:=TRx69
  TITLE:=TR069 CWMP client
  DEPENDS:=+libuci +libubox +libblobmsg-json +libubus +libjson-c +libcurl +mxml +libuuid +libbbfdm-api +libopenssl +rpcd +rpcd-mod-rpcsys
endef

define Package/icwmp/description
  Package to add TR069 client
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./* $(PKG_BUILD_DIR)/
endef

define Package/icwmp/install
	$(INSTALL_DIR) $(1)/etc/icwmpd
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_DIR) $(1)/lib/upgrade/keep.d
	$(INSTALL_DIR) $(1)/etc/udhcpc.user.d
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/icwmpd $(1)/usr/sbin/icwmpd
	$(INSTALL_DATA) ./files/etc/config/cwmp $(1)/etc/config/cwmp
	$(INSTALL_BIN) ./files/etc/firewall.cwmp $(1)/etc/firewall.cwmp
	$(INSTALL_BIN) ./files/etc/init.d/icwmpd $(1)/etc/init.d/icwmpd
	$(INSTALL_BIN) ./files/etc/uci-defaults/85-cwmp-set-userid $(1)/etc/uci-defaults/
	$(INSTALL_BIN) ./files/etc/uci-defaults/90-cwmpfirewall $(1)/etc/uci-defaults/
	$(INSTALL_BIN) ./files/etc/uci-defaults/95-set-random-inform-time $(1)/etc/uci-defaults/
	$(INSTALL_DATA) ./files/lib/upgrade/keep.d/icwmp $(1)/lib/upgrade/keep.d/icwmp
	$(INSTALL_BIN) ./files/etc/udhcpc.user.d/udhcpc_icwmp_opt125.user $(1)/etc/udhcpc.user.d/udhcpc_icwmp_opt125.user
	$(INSTALL_BIN) ./files/etc/udhcpc.user.d/udhcpc_icwmp_opt43.user $(1)/etc/udhcpc.user.d/udhcpc_icwmp_opt43.user
	$(call BbfdmInstallPlugin,$(1),./files/etc/bbfdm/json/CWMPManagementServer.json)
	$(call BbfdmInstallPlugin,$(1),$(PKG_BUILD_DIR)/libcwmpdm.so)
endef

$(eval $(call BuildPackage,icwmp))
