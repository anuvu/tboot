# The TXT/sig Project

For more information contact Paul Moore at <pmoore2@cisco.com> or
<paul@paul-moore.com>.

## Overview

The TXT/sig project is a development fork of the tboot project to add support
for signed PECOFF kernels, the same binary format used by UEFI Secure Boot.

There have been a few presentations given on the TXT/sig work, the first was
at the 2019 Linux Security Summit North America.  Links to the slides and
a recording of the talk can be found below:

* Presentation Recording
  - https://www.youtube.com/watch?v=Qbjz_5jUE9o

* Slides
  - https://www.paul-moore.com/docs/lss-securing_tpm_with_txt-pmoore-201909-r2.pdf

The original tboot project can be found on SourceForge at the link below:

* https://sourceforge.net/projects/tboot

## Toolchain Reference

The following sections are not intended as a complete HOW-TO for using
TXT/tboot, but rather a reference for those who are familiar with the basic
concepts behind TXT.

### Creating a Verified Launch Policy (VLP) with PECOFF Signature Verification

The Verified Launch Policy (VLP) is the policy used by tboot itself to enforce
boot policies on the kernel, initial ramdisk, and/or kernel command line.  The
VLP also controls which TPM PCRs are extended by tboot and what measurements
are used for the PCR extensions.

If you are bundling the VLP into the Launch Control Policy (LCP) you will need
to convert the VLP into a LCP policy element, see the examples later in this
document.

*NOTE: The commands below require the TXT/sig patchset.*

```
# tb_polgen --create --type nonfatal --alg sha256 --ctrl 0x00 pecoff.vlp
# tb_polgen --add --num 0 --pcr 20 --hash pecoff pecoff.vlp
# tb_polgen --show pecoff.vlp
policy:
         version: 2
         policy_type: TB_POLTYPE_CONT_NON_FATAL
         hash_alg: TB_HALG_SHA256
         policy_control: 00000000 ()
         num_entries: 1
         policy entry[0]:
                 mod_num: 0
                 pcr: 20
                 hash_type: TB_HTYPE_PECOFF
                 num_hashes: 0
```

### Creating a Launch Control Policy (LCP)

The TXT Launch Control Policy (LCP) is composed over several different types
of "policy elements".  The sections below describe how to create these policy
elements and how to combine them into a LCP.

#### Creating LCP Policy Elements

##### Creating a Platform Configuration (PCONF) Policy Element

The Platform Configuration (PCONF) policy element captures a TPM PCR quote of
the permitted TPM static root of trust PCR state.  The static root of trust
PCRs are typically PCR[0] through PCR[7].  The PCRs which are contained in the
quote, and their values, are both configurable in the PCONF policy element.
The PCONF policy element is read, and enforced by, the TXT ACM and not tboot.

*NOTE: The commands below require the TXT/sig patchset.  While the TPM2 PCONF*
*policy element is not specific to TXT/sig, the upstream tboot project does*
*not provide TPM PCONF support in the lcp2_crtpolelt tool.*

```
# lcp2_crtpolelt --create --type pconf2 --ctrl 0x00 --alg sha256 \
    --pcr0 <PCR[0] hash, e.g. 755567de6e0a3ee1b71a895b76abad92d52c7d78f60a8957f576ad7736a30618> \
    --pcr2 <PCR[2] hash, e.g. e19482e83387d6d0acbf2f4f12bb2883eda598b5b03bd8e32ec5ed007b9a39c7> \
    --out pconf2.elt
```

##### Creating a Measured Launch Environment (MLE) Policy Element

The Measured Launch Environment (MLE) policy element measures the tboot binary
and command line to ensure that only an authorized tboot configuration is
executed.  The MLE policy element is read, and enforced by, the TXT ACM and not
tboot.

```
# lcp2_mlehash --create --alg sha256 \
	[--cmdline "<tboot_cmdline>"] <tboot_binary> > mle_hash
# lcp2_crtpolelt --create --type mle --alg sha256 \
	--ctrl 0x00 --minver 0 --out mle.elt mle_hash
```

##### Converting a VLP into an LCP Policy Element

If you are bundling the Verified Launch Policy (VLP) into the LCP you will need
to convert it into a LCP policy element.

```
# lcp2_crtpolelt --create \
	--type custom --uuid tboot --ctrl 0x00 \
	--out vlp_pecoff.elt pecoff.vlp
```

##### Creating a Certificate Payload Policy Element

If you are using TXT/sig you need to include a certificate payload in the LCP
which contains a collection of certificates that have been used to sign the
kernel images you want to authorize.  The certificates need not be the top
level CAs, intermediate CAs can be used.

The certificates need to be in DER format, and it is possible to include
multiple certificates by concatenating them together.

*NOTE: The commands below require the TXT/sig patchset.*

```
# lcp2_crtpolelt --create \
	--type custom --uuid certificates --ctrl 0x00 \
	--out test.elt test.der
```

#### Building a LCP from Policy Elements

Once you have created the different LCP policy elements that you wish to use,
you need to combine them using the commands below for either a signed or
unsigned LCP.  A signed LCP allows you to write a single value to the TPM's
NVRAM and change the LCP module passed to tboot so long as the LCP signing
authority remains constant.

##### Unsigned LCP

```
# lcp2_crtpollist --create --out lists_unsig.lst \
	<policy_element_1> ... <policy_element_N>
# lcp2_crtpol --create --type list --pol lists.pol \
	--alg sha256 --sign 0x0A --ctrl 0x00 --data lists.data lists_unsig.lst
```

##### Signed LCP

First you need to create an unsigned Launch Control Policy (LCP) using the
steps above, once you have created an unsigned LCP you can follow the steps
below.

Creating signing keys:

```
# openssl genrsa -out privkey.pem 2048
# openssl rsa -pubout -in privkey.pem -out pubkey.pem
```

Creating the LCP:

```
# cp lists_unsig.lst lists_sig.lst
# lcp2_crtpollist --sign --pub pubkey.pem --priv privkey.pem \
	--out lists_sig.lst
# lcp2_crtpol --create --type list --alg sha256 --sign 0x0A --ctrl 0x00 \
	--pol lists_sig.pol --data lists_sig.data lists_sig.lst
```

### Taking Ownership of the TPM

If you don't currently have anything stored in the TPM, it may be wise to clear
the TPM before taking ownership.  In order to clear the TPM you typically need
to issue a command through the system's BIOS configuration, in some cases an
administrator/supervisor password must be set before clearing the TPM.

Once the TPM has been cleared, you can take ownership using the command below;
the passwords need not be the same.

```
# tpm2_takeownership -o <password> -e <password> -l <password>
```

### Defining the LCP TPM nvindex

```
# tpm2_nvdefine -x 0x1c10106 -a 0x40000001 -P <password> -s 70 -t 0x204000A
```

### Loading the LCP into the TPM

```
# tpm2_nvwrite -x 0x1c10106 -a 0x40000001 -P <password> lists.pol
```

## Extensions to the tboot Bootloader

The TXT/sig project extends the tboot bootloader to optionally perform signed
PECOFF signature verification.  In order to enable this functionality, the
Launch Control Policy (LCP) must include a certificate payload policy element
(see the reference above) as well as a Verified Launch Policy (VLP) which
includes a policy entry for performing PECOFF signature verification (see the
reference above).

Assuming the above is done, and a signed kernel is booted such that it can be
verified using one of the certificates in the LCP certificate payload, you
should see something similar when booting via tboot (this example is booting
a signed Fedora kernel):

```
TBOOT: ******************* TBOOT *******************
TBOOT:    2018-11-30 15:00 +0800 1.9.9
TBOOT: *********************************************
...
TBOOT: reading Launch Control Policy from TPM NV...
TBOOT:  :70 bytes read
TBOOT: in unwrap_lcp_policy
TBOOT: imported 2 TXT/sig LCP certs
TBOOT: TXT/sig trusted certificate list:
TBOOT:   CN="Testing CA", serial=0xd1e2a3d4b5e6e7f8
TBOOT:   CN="Fedora Secure Boot CA", serial=0x009976f2f4
TBOOT: policy:
TBOOT:   version: 2
TBOOT:   policy_type: TB_POLTYPE_CONT_NON_FATAL
TBOOT:   hash_alg: TB_HALG_SHA256
TBOOT:   policy_control: 00000000 ()
TBOOT:   num_entries: 1
TBOOT:   policy entry[0]:
TBOOT:           mod_num: 0
TBOOT:           pcr: 20
TBOOT:           hash_type: TB_HTYPE_PECOFF
TBOOT:           num_hashes: 0
...
TBOOT: verifying policy 
TBOOT: PECOFF TXT/sig verification succeeded
TBOOT: extending TXT/sig trust root into PCR[20]
TBOOT: TXT/sig trust root:
TBOOT:   CN="Fedora Secure Boot CA", serial=0x009976f2f4
...
TBOOT: Initrd from 0x665f3000 to 0x69dffa00
TBOOT: Kernel (protected mode) from 0x1000000 to 0x1911cc8
TBOOT: Kernel (real mode) from 0x90000 to 0x94600
TBOOT: Linux cmdline from 0x98d00 to 0x99100:
TBOOT:  root=UUID=7dc4c64b-5413-49c5-a79b-1e35c9e9e981 ro console=ttyS0,115200
TBOOT:   intel_iommu=on
TBOOT: transfering control to kernel @0x1000000...
```

## Additional Information

### TPM2 tboot extpol Setting

On TPM2 based systems there is the potential for multiple PCR banks supporting
different hash algorithms.  The TXT/sig patchset includes a patch which adds a
new "extpol" setting for tboot which queries the TXT ACM and selects the best
extpol setting to support the most number of PCR banks possible.  The pseudo
GRUB2 tboot example below demonstrates this:

```
menuentry 'tboot example' {
        echo         'Loading tboot ...'
        multiboot    /tboot.gz logging=serial,memory,vga extpol=acm
        echo         'Loading Linux Kernel ...'
        module       /vmlinuz intel_iommu=on
        echo         'Loading initial ramdisk ...'
        module       /initramfs.img
        echo         'Loading LCP data file ...'
        module       /list.data
```

### TPM PCR Reference

*NOTE: PCR[0-15] are cleared on power-up/hard-reset. PCR[17-20] are reset on a successful TXT secure launch.  PCR[20-22] can be reset by the Trusted OS in secure mode; note the overlap for PCR[20]. PCR[23] can be reset by anyone.*

* PCR[0]: BIOS code, Core Root of Trust Measurement (CRTM)
* PCR[1]: BIOS configuration
* PCR[2]: Option ROM code
* PCR[3]: Option ROM configuration
* PCR[4]: Initial Program Loader (IPL) code, typically the MBR
* PCR[5]: Initial Program Loader (IPL) configuration
* PCR[6]: Platform state changes, state transition and wake events (?) 
* PCR[7]: Host platform manufacturer control (?)
* PCR[8-15]: Reserved for the OS 
* PCR[16]: Reserved for debugging 
* PCR[17]: DRTM and Launch Control Policy (LCP)
* PCR[18]: Trusted OS statup code
* PCR[19]: Trusted OS (e.g. OS configuration)
* PCR[20]: Trusted OS (e.g. kernel + startup code)
* PCR[21]: Defined by Trusted OS
* PCR[22]: Defined by Trusted OS
* PCR[23]: Reserved for applications

### External References

* "Intel® Trusted Execution Technology (Intel TXT) Software Development Guide"
  - https://www.intel.com/content/www/us/en/software-developers/intel-txt-software-development-guide.html

* "Intel Trusted Execution Technology for Server Platforms" by William Futral and James Greene
   - https://www.apress.com/gp/book/9781430261483

* TPM 2.0 Library Specification
  - https://trustedcomputinggroup.org/resource/tpm-library-specification

* Portable Executable (PE) and Common Object File Format (COFF) Specification
  - https://docs.microsoft.com/en-us/windows/win32/debug/pe-format

* Windows Authenticode Portable Executable Signature Format
  - http://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/Authenticode_PE.docx

* PKCS #7, Cryptographic Message Syntax, version 1.5
  - https://tools.ietf.org/html/rfc2315

* PKCS #1, RSA Cryptography Specifications version 2.2
  - https://tools.ietf.org/html/rfc8017
