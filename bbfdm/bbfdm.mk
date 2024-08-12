#
# Copyright (C) 2023 IOPSYS
#


define BbfdmInstallPlugin
	$(INSTALL_DIR) $(1)/etc/bbfdm/plugins
	$(INSTALL_DATA) $(2) $(1)/etc/bbfdm/plugins/
endef
