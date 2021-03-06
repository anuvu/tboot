# Copyright (c) 2006-2010, Intel Corporation
# All rights reserved.

# -*- mode: Makefile; -*-

#
# tboot makefile
#

include $(CURDIR)/Config.mk

TARGET := $(CURDIR)/tboot

# boot.o must be first
obj-y := common/boot.o
obj-y += common/acpi.o common/cmdline.o common/com.o common/e820.o
obj-y += common/elf.o common/hash.o common/index.o common/integrity.o
obj-y += common/linux.o common/loader.o common/memcmp.o common/memcpy.o
obj-y += common/misc.o common/mutex.o common/paging.o common/pci_cfgreg.o
obj-y += common/policy.o common/printk.o common/rijndael.o common/sha1.o
obj-y += common/strcmp.o common/strlen.o common/strncmp.o common/strncpy.o
obj-y += common/strtoul.o common/tb_error.o common/tboot.o common/tpm.o
obj-y += common/vga.o common/vmac.o common/vsprintf.o common/lz.o
obj-y += common/stdlib.o common/stdio.o common/ctype.o common/clock.o
obj-y += common/heap_alloc.o
obj-y += common/crypt.o
obj-y += common/asn1-oid.o common/asn1.o common/pkcs1.o common/pkcs7.o
obj-y += common/pecoff.o
obj-y += txt/acmod.o txt/errors.o txt/heap.o txt/mtrrs.o txt/txt.o
obj-y += txt/verify.o txt/vmcs.o
obj-y += common/tpm_12.o common/tpm_20.o 
obj-y += common/sha256.o

OBJS := $(obj-y)
OBJS += libtomcrypt/libtomcrypt.a
OBJS += libtomfastmath/libtfm.a
# libtomfastmath requires libgcc for some of the math, see link below
# -> https://stackoverflow.com/questions/34532528/undefined-reference-to-divdi3
OBJS += $(shell $(CC) $(CFLAGS) -print-libgcc-file-name)


TARGET_LDS := $(CURDIR)/common/tboot.lds

$(TARGET).gz : $(TARGET)
	gzip -n -f -9 < $< > $@

$(TARGET) : $(OBJS) $(TARGET_LDS)
	$(LD) $(LDFLAGS) -T $(TARGET_LDS) -N $(OBJS) -o $(@D)/.$(@F).0
	$(NM) -n $(@D)/.$(@F).0 >$(TARGET)-syms
	$(LD) $(LDFLAGS) -T $(TARGET_LDS) $(LDFLAGS_STRIP) $(@D)/.$(@F).0 -o $(TARGET)
	rm -f $(@D)/.$(@F).0

$(TARGET_LDS) : $(TARGET_LDS).x $(HDRS)
	$(CPP) -P -E -Ui386 $(AFLAGS) -o $@ $<

$(TARGET_LDS).x : FORCE

#
# universal rules
#
dist : install


build : $(TARGET).gz


install : $(DISTDIR)/boot/$(TARGET).gz

$(DISTDIR)/boot/$(TARGET).gz : $(TARGET).gz
	[ -d $(DISTDIR)/boot ] || $(INSTALL_DIR) $(DISTDIR)/boot
	$(INSTALL_DATA) $(TARGET).gz $(DISTDIR)/boot/$(notdir $(TARGET)).gz
	$(INSTALL_DATA) $(TARGET)-syms $(DISTDIR)/boot/$(notdir $(TARGET))-syms
	[ -d $(DISTDIR)/etc/grub.d ] || $(INSTALL_DIR) $(DISTDIR)/etc/grub.d
	$(INSTALL) -m755 -t $(DISTDIR)/etc/grub.d 20*


clean :
	$(MAKE) -C libtomfastmath clean
	$(MAKE) -C libtomcrypt clean
	rm -f $(TARGET)* $(TARGET_LDS) *~ include/*~ include/txt/*~ *.o common/*~ txt/*~ common/*.o txt/*.o
	rm -f tags TAGS cscope.files cscope.in.out cscope.out cscope.po.out

distclean : clean

#
# libtomfastmath/libtomcrypt
#

libtomfastmath/libtfm.a:
	CFLAGS='$(CFLAGS)' $(MAKE) -C libtomfastmath

libtomcrypt/libtomcrypt.a:
	CFLAGS='$(CFLAGS)' $(MAKE) -C libtomcrypt

#
#    TAGS / tags
#
define all_sources
    ( find . -name '*.[chS]' -print )
endef
define set_exuberant_flags
    exuberant_flags=`$1 --version 2>/dev/null | grep -iq exuberant && \
	echo "-I __initdata,__exitdata,__acquires,__releases \
	    -I EXPORT_SYMBOL \
	    --extra=+f --c-kinds=+px"`
endef

.PHONY: TAGS
TAGS : 
	rm -f TAGS; \
	$(call set_exuberant_flags,etags); \
	$(all_sources) | xargs etags $$exuberant_flags -a

.PHONY: tags
tags : 
	rm -f tags; \
	$(call set_exuberant_flags,ctags); \
	$(all_sources) | xargs ctags $$exuberant_flags -a

#
#    cscope
#
.PHONY: cscope
cscope :
	$(all_sources) > cscope.files
	cscope -k -b -q

#
#    MAP
#
.PHONY: MAP
MAP :
	$(NM) -n $(TARGET)-syms | grep -v '\(compiled\)\|\(\.o$$\)\|\( [aUw] \)\|\(\.\.ng$$\)\|\(LASH[RL]DI\)' > System.map

#
# implicit rules
#

HDRS := $(wildcard $(CURDIR)/include/*.h)
HDRS += $(wildcard $(CURDIR)/include/txt/*.h)

BUILD_DEPS := $(ROOTDIR)/Config.mk $(CURDIR)/Config.mk $(CURDIR)/Makefile

# fix case where gcc doesn't use builtin memcmp() when built w/o optimizations
ifeq ($(debug),y)
CFLAGS += -O2
endif

%.o : %.c $(HDRS) $(BUILD_DEPS)
	$(CC) $(CFLAGS) -c $< -o $@

%.o : %.S $(HDRS) $(BUILD_DEPS)
	$(CC) $(AFLAGS) -c $< -o $@

%.i : %.c $(HDRS) $(BUILD_DEPS)
	$(CPP) $(CFLAGS) $< -o $@

# -std=gnu{89,99} gets confused by # as an end-of-line comment marker
%.s : %.S $(HDRS)  $(BUILD_DEPS)
	$(CPP) $(AFLAGS) $< -o $@
