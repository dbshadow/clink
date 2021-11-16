include $(TOPDIR)/rules.mk

PKG_NAME:=clink
PKG_RELEASE:=1

PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/$(PKG_NAME)
	CATEGORY:=CAMEO Proprietary Software
	TITLE:=User Space APP for Communication by Netlink
	MAINTAINER:=JoE HuAnG
	DEPENDS:= +libev +kmod-clink-ko +sutil +uci 
endef

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/clink $(1)/usr/sbin
	$(INSTALL_BIN) ./files/clink.init $(1)/etc/init.d/clink
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
