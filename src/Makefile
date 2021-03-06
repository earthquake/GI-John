#
# This file is part of John the Ripper password cracker,
# Copyright (c) 1996-2011 by Solar Designer
#
# ...with changes in the jumbo patch, by various authors
#

CC = gcc
AS = $(CC)
LD = $(CC)
CPP = $(CC)
CP = cp
LN = ln -sf
RM = rm -f
TR = tr
SED = sed
NULL = /dev/null
CPPFLAGS = -E
OMPFLAGS =
# gcc with OpenMP
#OMPFLAGS = -fopenmp
# Sun Studio with OpenMP (set the OMP_NUM_THREADS env var at runtime)
#OMPFLAGS = -xopenmp
CFLAGS = -c -Wall -O2 -fomit-frame-pointer -I/usr/local/include $(OMPFLAGS)
# -DHAVE_SKEY
ASFLAGS = -c $(OMPFLAGS)
LDFLAGS = -s -L/usr/local/lib -L/usr/local/ssl/lib -lcrypto -lm $(OMPFLAGS)
# -lskey
LDFLAGS_SOLARIS = -lrt -lnsl -lsocket
LDFLAGS_MKV = -s -lm
OPT_NORMAL = -funroll-loops
OPT_INLINE = -finline-functions

JOHN_OBJS = \
	DES_fmt.o DES_std.o DES_bs.o DES_bs_b.o \
	BSDI_fmt.o \
	MD5_fmt.o MD5_std.o \
	BF_fmt.o BF_std.o \
	AFS_fmt.o \
	LM_fmt.o \
	NT_fmt.o \
	XSHA_fmt.o \
	BFEgg_fmt.o \
	DOMINOSEC_fmt.o \
	lotus5_fmt.o \
	oracle_fmt.o \
	oracle11_fmt.o \
	MYSQL_fmt.o \
	mysqlSHA1_fmt.o \
	KRB4_fmt.o KRB4_std.o \
	KRB5_fmt.o KRB5_std.o \
	md5_go.o \
	rawMD5go_fmt.o md5_eq.o \
	PO_fmt.o \
	md5.o \
	hmacmd5.o \
	hmacMD5_fmt.o \
	IPB2_fmt.o \
	rawSHA1_fmt.o \
	sha1_gen_fmt.o \
	rawMD4_fmt.o \
	md4_gen_fmt.o \
	NSLDAP_fmt.o NSLDAPS_fmt.o OPENLDAPS_fmt.o base64.o \
	md4.o smbencrypt.o \
	mscash_fmt.o \
	mscash2_fmt.o \
	NETLM_fmt.o \
	NETNTLM_fmt.o \
	NETLMv2_fmt.o \
	NETNTLMv2_fmt.o \
	NETHALFLM_fmt.o \
	MSCHAPv2_fmt.o \
	mssql_fmt.o \
	mssql05_fmt.o \
	EPI_fmt.o \
	PHPS_fmt.o \
	MYSQL_fast_fmt.o \
	pixMD5_fmt.o \
	sapG_fmt.o sapB_fmt.o \
	NS_fmt.o \
	HDAA_fmt.o \
	phpassMD5_fmt.o \
	md5_gen_fmt.o md5_gen_parser.o md5_gen_preloads.o \
	DMD5_fmt.o \
	SKEY_fmt.o \
	dummy.o \
	batch.o bench.o charset.o common.o compiler.o config.o cracker.o \
	crc32.o external.o formats.o getopt.o idle.o inc.o john.o list.o \
	loader.o logger.o math.o memory.o misc.o options.o params.o path.o \
	recovery.o rpp.o rules.o signals.o single.o status.o tty.o wordlist.o \
	mkv.o mkvlib.o \
	gijohn.o \
	unshadow.o \
	unafs.o \
	undrop.o \
	unique.o

BENCH_DES_OBJS_ORIG = \
	DES_fmt.o DES_std.o

BENCH_DES_OBJS_DEPEND = \
	$(BENCH_DES_OBJS_ORIG)

BENCH_DES_BS_OBJS_DEPEND = \
	DES_bs_b.o

BENCH_MD5_OBJS_DEPEND = \
	MD5_fmt.o MD5_std.o

BENCH_BF_OBJS_DEPEND = \
	BF_fmt.o BF_std.o

BENCH_OBJS = \
	$(BENCH_DES_OBJS_DEPEND) \
	DES_bs.o $(BENCH_DES_BS_OBJS_DEPEND) \
	$(BENCH_MD5_OBJS_DEPEND) \
	$(BENCH_BF_OBJS_DEPEND) \
	bench-t.o best.o common.o config.o formats.o math.o memory.o miscnl.o \
	params.o path.o signals.o tty.o

GENMKVPWD_OBJS = \
	genmkvpwd.o mkvlib.o memory.o miscnl.o

PROJ = ../run/john ../run/unshadow ../run/unafs ../run/unique ../run/undrop \
	../run/genmkvpwd ../run/mkvcalcproba ../run/calc_stat \
	../run/tgtsnarf
PROJ_DOS = ../run/john.bin ../run/john.com \
	../run/unshadow.com ../run/unafs.com ../run/unique.com ../run/undrop.com
PROJ_WIN32 = ../run/john.exe \
	../run/unshadow.exe ../run/unafs.exe ../run/unique.exe \
	../run/undrop.exe \
	../run/genmkvpwd.exe ../run/mkvcalcproba.exe ../run/calc_stat.exe
PROJ_WIN32_MINGW = ../run/john-mingw.exe \
	../run/unshadow.exe ../run/unafs.exe ../run/unique.exe \
	../run/undrop.exe \
	../run/genmkvpwd.exe ../run/mkvcalcproba.exe ../run/calc_stat.exe
	

default:
	@echo "To build John the Ripper, type:"
	@echo "	make clean SYSTEM"
	@echo "where SYSTEM can be one of the following:"
	@echo "linux-x86-64             Linux, x86-64 with SSE2 (best tested)"
	@echo "linux-x86-64-avx         Linux, x86-64 with AVX (experimental)"
	@echo "linux-x86-64-xop         Linux, x86-64 with AVX and XOP (experimental)"
#	@echo "linux-x86-64-32-sse2     Linux, x86-64, 32-bit with SSE2"
#	@echo "linux-x86-64-32-mmx      Linux, x86-64, 32-bit with MMX"
	@echo "linux-x86-sse2           Linux, x86 32-bit with SSE2 (best tested if 32-bit)"
	@echo "linux-x86-mmx            Linux, x86 32-bit with MMX (for old computers)"
	@echo "linux-x86-any            Linux, x86 32-bit (for truly ancient computers)"
	@echo "linux-x86-avx            Linux, x86 32-bit with AVX (experimental)"
	@echo "linux-x86-xop            Linux, x86 32-bit with AVX and XOP (experimental)"
	@echo "linux-alpha              Linux, Alpha"
	@echo "linux-sparc              Linux, SPARC 32-bit"
	@echo "linux-ppc32-altivec      Linux, PowerPC w/AltiVec (best)"
	@echo "linux-ppc32              Linux, PowerPC 32-bit"
#	@echo "linux-ppc64-altivec      Linux, PowerPC 64-bit w/AltiVec"
	@echo "linux-ppc64              Linux, PowerPC 64-bit"
	@echo "linux-ia64               Linux, IA-64"
	@echo "freebsd-x86-64           FreeBSD, x86-64 with SSE2 (best)"
	@echo "freebsd-x86-sse2         FreeBSD, x86 with SSE2 (best if 32-bit)"
	@echo "freebsd-x86-mmx          FreeBSD, x86 with MMX"
	@echo "freebsd-x86-any          FreeBSD, x86"
	@echo "freebsd-alpha            FreeBSD, Alpha"
	@echo "openbsd-x86-64           OpenBSD, x86-64 with SSE2 (best)"
	@echo "openbsd-x86-sse2         OpenBSD, x86 with SSE2 (best if 32-bit)"
	@echo "openbsd-x86-mmx          OpenBSD, x86 with MMX"
	@echo "openbsd-x86-any          OpenBSD, x86"
	@echo "openbsd-alpha            OpenBSD, Alpha"
	@echo "openbsd-sparc64          OpenBSD, SPARC 64-bit (best)"
	@echo "openbsd-sparc            OpenBSD, SPARC 32-bit"
	@echo "openbsd-ppc32            OpenBSD, PowerPC 32-bit"
	@echo "openbsd-ppc64            OpenBSD, PowerPC 64-bit"
	@echo "openbsd-pa-risc          OpenBSD, PA-RISC"
	@echo "openbsd-vax              OpenBSD, VAX"
	@echo "netbsd-sparc64           NetBSD, SPARC 64-bit"
	@echo "netbsd-vax               NetBSD, VAX"
	@echo "solaris-sparc64-cc       Solaris, SPARC V9 64-bit, cc (best)"
	@echo "solaris-sparc64-gcc      Solaris, SPARC V9 64-bit, gcc"
	@echo "solaris-sparcv9-cc       Solaris, SPARC V9 32-bit, cc"
	@echo "solaris-sparcv8-cc       Solaris, SPARC V8 32-bit, cc"
	@echo "solaris-sparc-gcc        Solaris, SPARC 32-bit, gcc"
	@echo "solaris-x86-64-cc        Solaris, x86-64 with SSE2, cc (best)"
	@echo "solaris-x86-64-gcc       Solaris, x86-64 with SSE2, gcc"
	@echo "solaris-x86-sse2-cc      Solaris 9 4/04+, x86 with SSE2, cc"
	@echo "solaris-x86-sse2-gcc     Solaris 9 4/04+, x86 with SSE2, gcc"
	@echo "solaris-x86-mmx-cc       Solaris, x86 with MMX, cc"
	@echo "solaris-x86-mmx-gcc      Solaris, x86 with MMX, gcc"
	@echo "solaris-x86-any-cc       Solaris, x86, cc"
	@echo "solaris-x86-any-gcc      Solaris, x86, gcc"
	@echo "sco-x86-any-gcc          SCO, x86, gcc"
	@echo "sco-x86-any-cc           SCO, x86, cc"
	@echo "tru64-alpha              Tru64 (Digital UNIX, OSF/1), Alpha"
	@echo "aix-ppc32                AIX, PowerPC 32-bit"
	@echo "macosx-x86-64            Mac OS X 10.5+, Xcode 3.0+, x86-64 with SSE2 (best)"
	@echo "macosx-x86-sse2          Mac OS X, x86 with SSE2"
	@echo "macosx-ppc32-altivec     Mac OS X, PowerPC w/AltiVec (best)"
	@echo "macosx-ppc32             Mac OS X, PowerPC 32-bit"
#	@echo "macosx-ppc64-altivec     Mac OS X, PowerPC 64-bit w/AltiVec"
	@echo "macosx-ppc64             Mac OS X 10.4+, PowerPC 64-bit"
	@echo "macosx-universal         Mac OS X, Universal Binary (x86 + x86-64 + PPC)"
	@echo "hpux-pa-risc-gcc         HP-UX, PA-RISC, gcc"
	@echo "hpux-pa-risc-cc          HP-UX, PA-RISC, ANSI cc"
	@echo "irix-mips64-r10k         IRIX, MIPS 64-bit (R10K) (best)"
	@echo "irix-mips64              IRIX, MIPS 64-bit"
	@echo "irix-mips32              IRIX, MIPS 32-bit"
	@echo "dos-djgpp-x86-mmx        DOS, DJGPP, x86 with MMX"
	@echo "dos-djgpp-x86-any        DOS, DJGPP, x86"
	@echo "win32-cygwin-x86-sse2    Win32, Cygwin, x86 with SSE2 (best)"
	@echo "win32-cygwin-x86-mmx     Win32, Cygwin, x86 with MMX"
	@echo "win32-cygwin-x86-any     Win32, Cygwin, x86"
	@echo "win32-mingw-x86-sse2     Win32, MinGW, x86 with SSE2 (best)"
	@echo "win32-mingw-x86-mmx      Win32, MinGW, x86 with MMX"
	@echo "win32-mingw-x86-any      Win32, MinGW, x86"
	@echo "beos-x86-sse2            BeOS, x86 with SSE2 (best)"
	@echo "beos-x86-mmx             BeOS, x86 with MMX"
	@echo "beos-x86-any             BeOS, x86"
	@echo "generic                  Any other Unix-like system with gcc"

linux-x86-64:
	$(LN) x86-64.h arch.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) c3_fmt.o x86-64.o" \
		CFLAGS="$(CFLAGS) -DHAVE_CRYPT" \
		LDFLAGS="$(LDFLAGS) -lcrypt"

linux-x86-64-avx:
	$(LN) x86-64.h arch.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) c3_fmt.o x86-64.o" \
		CFLAGS="$(CFLAGS) -mavx -DHAVE_CRYPT" \
		LDFLAGS="$(LDFLAGS) -lcrypt"

linux-x86-64-xop:
	$(LN) x86-64.h arch.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) c3_fmt.o x86-64.o" \
		CFLAGS="$(CFLAGS) -mxop -DHAVE_CRYPT" \
		LDFLAGS="$(LDFLAGS) -lcrypt"

linux-x86-64-32-sse2:
	$(LN) x86-sse.h arch.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) c3_fmt.o x86.o x86-sse.o sha1-mmx.o md5-mmx.o" \
		CFLAGS="$(CFLAGS) -m32 -DHAVE_CRYPT" \
		ASFLAGS="$(ASFLAGS) -m32" \
		LDFLAGS="$(LDFLAGS) -m32 -lcrypt"

linux-x86-64-32-mmx:
	$(LN) x86-mmx.h arch.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) c3_fmt.o x86.o x86-mmx.o sha1-mmx.o md5-mmx.o" \
		CFLAGS="$(CFLAGS) -m32 -DHAVE_CRYPT" \
		ASFLAGS="$(ASFLAGS) -m32" \
		LDFLAGS="$(LDFLAGS) -m32 -lcrypt"

linux-x86-sse2:
	$(LN) x86-sse.h arch.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) c3_fmt.o x86.o x86-sse.o sha1-mmx.o md5-mmx.o" \
		CFLAGS="$(CFLAGS) -DHAVE_CRYPT" \
		LDFLAGS="$(LDFLAGS) -lcrypt"

linux-x86-mmx:
	$(LN) x86-mmx.h arch.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) c3_fmt.o x86.o x86-mmx.o sha1-mmx.o md5-mmx.o" \
		CFLAGS="$(CFLAGS) -DHAVE_CRYPT" \
		LDFLAGS="$(LDFLAGS) -lcrypt"

linux-x86-any:
	$(LN) x86-any.h arch.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) c3_fmt.o x86.o" \
		CFLAGS="$(CFLAGS) -DHAVE_CRYPT" \
		LDFLAGS="$(LDFLAGS) -lcrypt"

linux-x86-avx:
	$(LN) x86-sse.h arch.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) c3_fmt.o x86.o" \
		CFLAGS="$(CFLAGS) -mavx -DHAVE_CRYPT" \
		LDFLAGS="$(LDFLAGS) -lcrypt"

linux-x86-xop:
	$(LN) x86-sse.h arch.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) c3_fmt.o x86.o" \
		CFLAGS="$(CFLAGS) -mxop -DHAVE_CRYPT" \
		LDFLAGS="$(LDFLAGS) -lcrypt"

linux-alpha:
	$(LN) alpha.h arch.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) c3_fmt.o alpha.o" \
		CFLAGS="$(CFLAGS) -DHAVE_CRYPT" \
		LDFLAGS="$(LDFLAGS) -lcrypt"

# This target is currently "undocumented" as ccc generates much slower
# code for the large unrolled loops in John; let's hope it gets fixed.
linux-alpha-ccc:
	$(LN) alpha.h arch.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) c3_fmt.o alpha.o" \
		CC=ccc \
		CFLAGS="-c -Wf,-switch,noil_schedule -DHAVE_CRYPT" \
		LDFLAGS="$(LDFLAGS) -lcrypt" \
		OPT_NORMAL="-fast" \
		OPT_INLINE="-O2 -arch host"

linux-sparc:
	$(LN) sparc32.h arch.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) c3_fmt.o" \
		CFLAGS="$(CFLAGS) -DHAVE_CRYPT" \
		LDFLAGS="$(LDFLAGS) -lcrypt"

linux-ppc32-altivec:
	$(LN) ppc32alt.h arch.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) c3_fmt.o" \
		CFLAGS="$(CFLAGS) -DHAVE_CRYPT" \
		LDFLAGS="$(LDFLAGS) -lcrypt" \
		OPT_INLINE="-finline-functions -finline-limit=4000 -maltivec"

linux-ppc32:
	$(LN) ppc32.h arch.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) c3_fmt.o" \
		CFLAGS="$(CFLAGS) -DHAVE_CRYPT" \
		LDFLAGS="$(LDFLAGS) -lcrypt"

# This is slightly slower than linux-ppc32-altivec for most hash types.
linux-ppc64-altivec:
	$(LN) ppc64alt.h arch.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) c3_fmt.o" \
		CFLAGS="$(CFLAGS) -m64 -DHAVE_CRYPT" \
		LDFLAGS="$(LDFLAGS) -m64 -lcrypt" \
		OPT_INLINE="-finline-functions -finline-limit=4000 -maltivec"

linux-ppc64:
	$(LN) ppc64.h arch.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) c3_fmt.o" \
		CFLAGS="$(CFLAGS) -m64 -DHAVE_CRYPT" \
		LDFLAGS="$(LDFLAGS) -m64 -lcrypt" \
		OPT_INLINE="-finline-functions -finline-limit=4000"

linux-ia64:
	$(LN) ia64.h arch.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) c3_fmt.o" \
		CFLAGS="$(CFLAGS) -DHAVE_CRYPT" \
		LDFLAGS="$(LDFLAGS) -lcrypt"

freebsd-x86-64:
	$(LN) x86-64.h arch.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) x86-64.o"

freebsd-x86-sse2:
	$(LN) x86-sse.h arch.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) x86.o x86-sse.o sha1-mmx.o md5-mmx.o" \
		ASFLAGS="$(ASFLAGS) -DBSD"

freebsd-x86-mmx:
	$(LN) x86-mmx.h arch.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) x86.o x86-mmx.o sha1-mmx.o md5-mmx.o" \
		ASFLAGS="$(ASFLAGS) -DBSD"

freebsd-x86-any:
	$(LN) x86-any.h arch.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) x86.o" \
		ASFLAGS="$(ASFLAGS) -DBSD"

freebsd-x86-any-a.out:
	$(LN) x86-any.h arch.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) x86.o" \
		ASFLAGS="$(ASFLAGS) -DUNDERSCORES -DALIGN_LOG -DBSD"

freebsd-alpha:
	$(LN) alpha.h arch.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) alpha.o"

openbsd-x86-64:
	$(LN) x86-64.h arch.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) x86-64.o"

openbsd-x86-sse2:
	$(LN) x86-sse.h arch.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) x86.o x86-sse.o sha1-mmx.o md5-mmx.o" \
		ASFLAGS="$(ASFLAGS) -DBSD"

openbsd-x86-mmx:
	$(LN) x86-mmx.h arch.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) x86.o x86-mmx.o sha1-mmx.o md5-mmx.o" \
		ASFLAGS="$(ASFLAGS) -DBSD"

openbsd-x86-any:
	$(LN) x86-any.h arch.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) x86.o" \
		ASFLAGS="$(ASFLAGS) -DBSD"

openbsd-x86-any-a.out:
	$(LN) x86-any.h arch.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) x86.o" \
		ASFLAGS="$(ASFLAGS) -DUNDERSCORES -DALIGN_LOG -DBSD"

openbsd-alpha:
	$(LN) alpha.h arch.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) alpha.o"

openbsd-sparc64:
	$(LN) sparc64.h arch.h
	$(MAKE) $(PROJ) \
		CFLAGS="$(CFLAGS) -m64 -mcpu=ultrasparc" \
		LDFLAGS="$(LDFLAGS) -m64"

openbsd-sparc:
	$(LN) sparc32.h arch.h
	$(MAKE) $(PROJ)

openbsd-ppc32:
	$(LN) ppc32.h arch.h
	$(MAKE) $(PROJ)

openbsd-ppc64:
	$(LN) ppc64.h arch.h
	$(MAKE) $(PROJ) \
		CFLAGS="$(CFLAGS) -m64" \
		LDFLAGS="$(LDFLAGS) -m64" \
		OPT_INLINE="-finline-functions -finline-limit=4000"

openbsd-pa-risc:
	$(LN) pa-risc.h arch.h
	$(MAKE) $(PROJ) \
		CFLAGS="-c -Wall -O3 -fomit-frame-pointer"

openbsd-vax:
	$(LN) vax.h arch.h
	$(MAKE) $(PROJ)

netbsd-sparc64:
	$(LN) sparc64.h arch.h
	$(MAKE) $(PROJ) \
		CFLAGS="$(CFLAGS) -m64 -mcpu=ultrasparc" \
		LDFLAGS="$(LDFLAGS) -m64"

netbsd-vax:
	$(LN) vax.h arch.h
	$(MAKE) $(PROJ)

solaris-sparc64-cc:
	$(LN) sparc64.h arch.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) c3_fmt.o" \
		CC=cc \
		CFLAGS="-c -fast -xarch=native64 -DHAVE_CRYPT $(OMPFLAGS)" \
		LDFLAGS="-s -xarch=native64 $(OMPFLAGS) -lc $(LDFLAGS_SOLARIS)" \
		OPT_NORMAL="" \
		OPT_INLINE="-xinline=s1,s2,s3,s4,s5,s6,s7,s8"

solaris-sparc64-gcc:
	$(LN) sparc64.h arch.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) c3_fmt.o" \
		CFLAGS="$(CFLAGS) -m64 -mcpu=ultrasparc -DHAVE_CRYPT" \
		LDFLAGS="$(LDFLAGS) -m64 $(LDFLAGS_SOLARIS)"

solaris-sparcv9-cc:
	$(LN) sparc32.h arch.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) c3_fmt.o" \
		CC=cc \
		CFLAGS="-c -xO4 -xarch=v8plusa -xchip=ultra -DHAVE_CRYPT $(OMPFLAGS)" \
		LDFLAGS="-s $(OMPFLAGS) -lc $(LDFLAGS_SOLARIS)" \
		OPT_NORMAL="" \
		OPT_INLINE="-xinline=s1,s2,s3,s4,s5,s6,s7,s8"

solaris-sparcv8-cc:
	$(LN) sparc32.h arch.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) c3_fmt.o" \
		CC=cc \
		CFLAGS="-c -xO4 -xarch=v8 -DHAVE_CRYPT $(OMPFLAGS)" \
		LDFLAGS="-s $(OMPFLAGS) -lc $(LDFLAGS_SOLARIS)" \
		OPT_NORMAL="" \
		OPT_INLINE="-xinline=s1,s2,s3,s4,s5,s6,s7,s8"

solaris-sparc-gcc:
	$(LN) sparc32.h arch.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) c3_fmt.o" \
		CFLAGS="$(CFLAGS) -DHAVE_CRYPT" \
		LDFLAGS="$(LDFLAGS) $(LDFLAGS_SOLARIS)"

solaris-x86-64-cc:
	$(LN) x86-64.h arch.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) c3_fmt.o x86-64.o" \
		CC=cc \
		CFLAGS="-c -fast -xarch=native64 -DHAVE_CRYPT $(OMPFLAGS)" \
		ASFLAGS="-c -xarch=native64 $(OMPFLAGS)" \
		LDFLAGS="-s -xarch=native64 $(OMPFLAGS) $(LDFLAGS_SOLARIS)" \
		OPT_NORMAL="" \
		OPT_INLINE="-xinline=s1,s2,s3,s4,s5,s6,s7,s8"

solaris-x86-64-gcc:
	$(LN) x86-64.h arch.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) c3_fmt.o x86-64.o" \
		CFLAGS="$(CFLAGS) -m64 -DHAVE_CRYPT" \
		ASFLAGS="$(CFLAGS) -m64" \
		LDFLAGS="$(LDFLAGS) -m64 $(LDFLAGS_SOLARIS)"

solaris-x86-sse2-cc:
	$(LN) x86-sse.h arch.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) c3_fmt.o solaris-x86.o x86-sse.o sha1-mmx.o md5-mmx.o" \
		CC=cc \
		CFLAGS="-c -fast -xarch=native -DHAVE_CRYPT $(OMPFLAGS)" \
		ASFLAGS="-c -xarch=native $(OMPFLAGS)" \
		LDFLAGS="-s -xarch=native $(OMPFLAGS) $(LDFLAGS_SOLARIS)" \
		OPT_NORMAL="" \
		OPT_INLINE="-xinline=s1,s2,s3,s4,s5,s6,s7,s8"

solaris-x86-sse2-gcc:
	$(LN) x86-sse.h arch.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) c3_fmt.o solaris-x86.o x86-sse.o sha1-mmx.o md5-mmx.o" \
		CFLAGS="$(CFLAGS) -DHAVE_CRYPT" \
		LDFLAGS="$(LDFLAGS) $(LDFLAGS_SOLARIS)"

solaris-x86-mmx-cc:
	$(LN) x86-mmx.h arch.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) c3_fmt.o solaris-x86.o x86-mmx.o sha1-mmx.o md5-mmx.o" \
		CC=cc \
		CFLAGS="-c -fast -xarch=native -DHAVE_CRYPT $(OMPFLAGS)" \
		ASFLAGS="-c -xarch=native $(OMPFLAGS)" \
		LDFLAGS="-s -xarch=native $(OMPFLAGS) $(LDFLAGS_SOLARIS)" \
		OPT_NORMAL="" \
		OPT_INLINE="-xinline=s1,s2,s3,s4,s5,s6,s7,s8"

solaris-x86-mmx-gcc:
	$(LN) x86-mmx.h arch.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) c3_fmt.o solaris-x86.o x86-mmx.o sha1-mmx.o md5-mmx.o" \
		CFLAGS="$(CFLAGS) -DHAVE_CRYPT" \
		LDFLAGS="$(LDFLAGS) $(LDFLAGS_SOLARIS)"

solaris-x86-any-cc:
	$(RM) arch.h
	ln -s x86-any.h arch.h
	$(MAKE) $(PROJ) \
		SHELL=/bin/sh \
		JOHN_OBJS="$(JOHN_OBJS) c3_fmt.o solaris-x86.o" \
		CC=cc \
		CFLAGS="-c -xO4 -DHAVE_CRYPT $(OMPFLAGS)" \
		ASFLAGS="-c $(OMPFLAGS)" \
		LDFLAGS="-s $(OMPFLAGS) -lc $(LDFLAGS_SOLARIS)" \
		OPT_NORMAL="" \
		OPT_INLINE="-xinline=s1,s2,s3,s4,s5,s6,s7,s8"

solaris-x86-any-gcc:
	$(RM) arch.h
	ln -s x86-any.h arch.h
	$(MAKE) $(PROJ) \
		SHELL=/bin/sh \
		JOHN_OBJS="$(JOHN_OBJS) c3_fmt.o solaris-x86.o" \
		CFLAGS="$(CFLAGS) -DHAVE_CRYPT" \
		LDFLAGS="$(LDFLAGS) -lc $(LDFLAGS_SOLARIS)"

# Older versions of Sun's assembler had a line length restriction (and some
# other problems, which affect newer versions as well and which are worked
# around in x86.S).
solaris-x86.o: x86.S
	$(CPP) $(CPPFLAGS) -P -DDUMBAS x86.S | $(TR) \; \\n > tmp.s
	$(AS) $(ASFLAGS) tmp.s -o solaris-x86.o
	$(RM) tmp.s

sco-x86-any-gcc:
	$(RM) arch.h
	ln -s x86-any.h arch.h
	$(MAKE) $(PROJ) \
		SHELL=/bin/sh \
		JOHN_OBJS="$(JOHN_OBJS) sco-x86.o"

sco-x86-any-cc:
	$(RM) arch.h
	ln -s x86-any.h arch.h
	$(MAKE) $(PROJ) \
		SHELL=/bin/sh \
		JOHN_OBJS="$(JOHN_OBJS) sco-x86.o" \
		CC=cc \
		CFLAGS="-c -b elf -O3" \
		ASFLAGS="-c -b elf" \
		OPT_NORMAL="-K loop_unroll,no_inline" \
		OPT_INLINE="-K inline"

# SCO is even worse than Solaris x86
sco-x86.o: x86.S
	$(CPP) $(CPPFLAGS) -DDUMBAS x86.S | \
		$(TR) \; \\n | $(SED) 's/\([%.]\) /\1/g' > tmp.s
	$(AS) $(ASFLAGS) tmp.s -o sco-x86.o
	$(RM) tmp.s

tru64-alpha:
	$(LN) alpha.h arch.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) digipaq-alpha.o" \
		CC=cc \
		CFLAGS="-c -O4 -arch host" \
		OPT_NORMAL="" \
		OPT_INLINE="-inline all"

# Digital/Compaq's cc and make use the .S suffix for a different purpose...
digipaq-alpha.o: alpha.S
	$(CPP) $(CPPFLAGS) alpha.S > tmp.s
	$(AS) $(ASFLAGS) tmp.s -o digipaq-alpha.o
	$(RM) tmp.s

aix-ppc32:
	$(LN) ppc32.h arch.h
	$(MAKE) $(PROJ) \
		CC=cc \
		CFLAGS="-c -qunroll=2 -qarch=ppc -qchars=signed" \
		LDFLAGS="-s -lbsd" \
		OPT_NORMAL="-O2" \
		OPT_INLINE="-O3 -Q=99 -w"

macosx-x86-64:
	$(LN) x86-64.h arch.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) x86-64.o" \
		ASFLAGS="$(ASFLAGS) -m64 -DUNDERSCORES -DBSD -DALIGN_LOG" \
		CFLAGS="$(CFLAGS) -m64" \
		LDFLAGS="$(LDFLAGS) -m64"

macosx-x86-sse2:
	$(LN) x86-sse.h arch.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) x86.o x86-sse.o sha1-mmx.o md5-mmx.o" \
		ASFLAGS="$(ASFLAGS) -m32 -DUNDERSCORES -DBSD -DALIGN_LOG" \
		CFLAGS="$(CFLAGS) -m32" \
		LDFLAGS="$(LDFLAGS) -m32"

macosx-x86-mmx:
	$(LN) x86-mmx.h arch.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) x86.o x86-mmx.o sha1-mmx.o md5-mmx.o" \
		ASFLAGS="$(ASFLAGS) -m32 -DUNDERSCORES -DBSD -DALIGN_LOG" \
		CFLAGS="$(CFLAGS) -m32" \
		LDFLAGS="$(LDFLAGS) -m32"

macosx-ppc32-altivec:
	$(LN) ppc32alt.h arch.h
	$(MAKE) $(PROJ) \
		CFLAGS="-c -Wall -fomit-frame-pointer" \
		OPT_NORMAL="-fast -mcpu=7450" \
		OPT_INLINE="-fast -mcpu=7450 -finline-limit=4000 -faltivec -maltivec"

# The -cross targets can be used to compile PowerPC binaries on x86.
macosx-ppc32-altivec-cross:
	$(LN) ppc32alt.h arch.h
	$(MAKE) $(PROJ) \
		ASFLAGS="$(ASFLAGS) -arch ppc" \
		CFLAGS="-c -Wall -arch ppc -fomit-frame-pointer" \
		LDFLAGS="$(LDFLAGS) -arch ppc" \
		OPT_NORMAL="-fast -mcpu=7450" \
		OPT_INLINE="-fast -mcpu=7450 -finline-limit=4000 -faltivec -maltivec"

# "cc -traditional-cpp" was needed on older versions of Mac OS X; it might
# actually be problematic on current ones, but those will hopefully use other
# make targets anyway (e.g., macosx-ppc32-altivec above).
macosx-ppc32:
	$(LN) ppc32.h arch.h
	$(MAKE) $(PROJ) \
		CC=cc \
		CFLAGS="-c -traditional-cpp" \
		OPT_NORMAL="-O2" \
		OPT_INLINE="-O3"

macosx-ppc32-cross:
	$(LN) ppc32.h arch.h
	$(MAKE) $(PROJ) \
		ASFLAGS="$(ASFLAGS) -arch ppc" \
		CFLAGS="-c -Wall -arch ppc -fomit-frame-pointer" \
		LDFLAGS="$(LDFLAGS) -arch ppc" \
		OPT_NORMAL="-O2" \
		OPT_INLINE="-O3 -finline-limit=4000"

# This is slightly slower than macosx-ppc32-altivec for most hash types.
macosx-ppc64-altivec:
	$(LN) ppc64alt.h arch.h
	$(MAKE) $(PROJ) \
		CFLAGS="-c -m64 -Wall -fomit-frame-pointer" \
		LDFLAGS="$(LDFLAGS) -m64" \
		OPT_NORMAL="-fast" \
		OPT_INLINE="-fast -finline-limit=4000 -faltivec -maltivec"

macosx-ppc64-altivec-cross:
	$(LN) ppc64alt.h arch.h
	$(MAKE) $(PROJ) \
		ASFLAGS="$(ASFLAGS) -arch ppc" \
		CFLAGS="-c -arch ppc -m64 -Wall -fomit-frame-pointer" \
		LDFLAGS="$(LDFLAGS) -arch ppc -m64" \
		OPT_NORMAL="-fast" \
		OPT_INLINE="-fast -finline-limit=4000 -faltivec -maltivec"

macosx-ppc64:
	$(LN) ppc64.h arch.h
	$(MAKE) $(PROJ) \
		CFLAGS="-c -m64 -Wall -fomit-frame-pointer" \
		LDFLAGS="$(LDFLAGS) -m64" \
		OPT_NORMAL="-fast" \
		OPT_INLINE="-fast -finline-limit=4000"

macosx-ppc64-cross:
	$(LN) ppc64.h arch.h
	$(MAKE) $(PROJ) \
		ASFLAGS="$(ASFLAGS) -arch ppc" \
		CFLAGS="-c -arch ppc -m64 -Wall -fomit-frame-pointer" \
		LDFLAGS="$(LDFLAGS) -arch ppc -m64" \
		OPT_NORMAL="-fast" \
		OPT_INLINE="-fast -finline-limit=4000"

john-macosx-x86-64:
	$(RM) *.o
	$(LN) x86-64.h arch.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) x86-64.o" \
		ASFLAGS="$(ASFLAGS) -arch x86_64 -m64 -DUNDERSCORES -DBSD -DALIGN_LOG" \
		CFLAGS="$(CFLAGS) -arch x86_64 -m64" \
		LDFLAGS="$(LDFLAGS) -arch x86_64 -m64"
	mv ../run/john john-macosx-x86-64

john-macosx-x86:
	$(RM) *.o
	$(LN) x86-sse.h arch.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) x86.o x86-sse.o sha1-mmx.o md5-mmx.o" \
		ASFLAGS="$(ASFLAGS) -arch i386 -m32 -DUNDERSCORES -DBSD -DALIGN_LOG" \
		CFLAGS="$(CFLAGS) -arch i386 -m32" \
		LDFLAGS="$(LDFLAGS) -arch i386 -m32"
	mv ../run/john john-macosx-x86

john-macosx-ppc:
	$(RM) *.o
	$(LN) ppc32alt.h arch.h
	$(MAKE) $(PROJ) \
		ASFLAGS="$(ASFLAGS) -arch ppc" \
		CFLAGS="-c -Wall -arch ppc -fomit-frame-pointer" \
		LDFLAGS="$(LDFLAGS) -arch ppc" \
		OPT_NORMAL="-fast -mcpu=7450" \
		OPT_INLINE="-fast -mcpu=7450 -finline-limit=4000 -faltivec -maltivec"
	mv ../run/john john-macosx-ppc

macosx-universal: john-macosx-x86-64 john-macosx-x86 john-macosx-ppc
	lipo -create john-macosx-x86-64 john-macosx-x86 john-macosx-ppc \
		-output ../run/john

hpux-pa-risc-gcc:
	$(LN) pa-risc.h arch.h
	$(MAKE) $(PROJ) \
		CFLAGS="-c -Wall -O3 -fomit-frame-pointer"

hpux-pa-risc-cc:
	$(LN) pa-risc.h arch.h
	$(MAKE) $(PROJ) \
		CC=cc \
		CFLAGS="-c -Aa -D_HPUX_SOURCE -DANSI_CPP" \
		LDFLAGS="-s" \
		OPT_NORMAL="+O2" \
		OPT_INLINE="+O3 +Oinline"

irix-mips64-r10k:
	$(LN) mips64.h arch.h
	$(MAKE) $(PROJ) \
		CC=cc \
		CFLAGS="-c -O2 -64 -mips4 -r10000 -signed" \
		LDFLAGS="-s -64 -mips4 -r10000" \
		OPT_NORMAL="-LNO:opt=1 -OPT:Olimit=2194" \
		OPT_INLINE="-INLINE:all"

irix-mips64:
	$(LN) mips64.h arch.h
	$(MAKE) $(PROJ) \
		CC=cc \
		CFLAGS="-c -O2 -64 -mips3 -signed" \
		LDFLAGS="-s -64 -mips3" \
		OPT_NORMAL="-LNO:opt=1 -OPT:Olimit=2194" \
		OPT_INLINE="-INLINE:all"

irix-mips32:
	$(LN) mips32.h arch.h
	$(MAKE) $(PROJ) \
		CC=cc \
		CFLAGS="-c -O2 -32 -signed" \
		LDFLAGS="-s -32" \
		OPT_NORMAL="-LNO:opt=1 -OPT:Olimit=2194" \
		OPT_INLINE="-INLINE:all"

dos-djgpp-x86-mmx:
	copy x86-mmx.h arch.h
	$(MAKE) $(PROJ_DOS) \
		JOHN_OBJS="$(JOHN_OBJS) x86.o x86-mmx.o sha1-mmx.o md5-mmx.o" \
		CFLAGS="$(CFLAGS) -mpreferred-stack-boundary=2" \
		ASFLAGS="$(ASFLAGS) -DUNDERSCORES -DALIGN_LOG"

dos-djgpp-x86-any:
	copy x86-any.h arch.h
	$(MAKE) $(PROJ_DOS) \
		JOHN_OBJS="$(JOHN_OBJS) x86.o" \
		CFLAGS="$(CFLAGS) -mpreferred-stack-boundary=2" \
		ASFLAGS="$(ASFLAGS) -DUNDERSCORES -DALIGN_LOG"

win32-cygwin-x86-sse2:
	$(CP) x86-sse.h arch.h
	$(MAKE) $(PROJ_WIN32) \
		JOHN_OBJS="$(JOHN_OBJS) x86.o x86-sse.o sha1-mmx.o md5-mmx.o" \
		CFLAGS="$(CFLAGS) -mpreferred-stack-boundary=2" \
		ASFLAGS="$(ASFLAGS) -DUNDERSCORES"

win32-cygwin-x86-mmx:
	$(CP) x86-mmx.h arch.h
	$(MAKE) $(PROJ_WIN32) \
		JOHN_OBJS="$(JOHN_OBJS) x86.o x86-mmx.o sha1-mmx.o md5-mmx.o" \
		CFLAGS="$(CFLAGS) -mpreferred-stack-boundary=2" \
		ASFLAGS="$(ASFLAGS) -DUNDERSCORES"

win32-cygwin-x86-any:
	$(CP) x86-any.h arch.h
	$(MAKE) $(PROJ_WIN32) \
		JOHN_OBJS="$(JOHN_OBJS) x86.o" \
		CFLAGS="$(CFLAGS) -mpreferred-stack-boundary=2" \
		ASFLAGS="$(ASFLAGS) -DUNDERSCORES"

win32-mingw-x86-sse2:
	$(CP) x86-sse.h arch.h
	$(MAKE) $(PROJ_WIN32_MINGW) \
		JOHN_OBJS="$(JOHN_OBJS) x86.o x86-sse.o sha1-mmx.o md5-mmx.o" \
		CFLAGS="$(CFLAGS) -Wall -mpreferred-stack-boundary=4 -msse2 -m32" \
		ASFLAGS="$(ASFLAGS) -DUNDERSCORES"

win32-mingw-x86-mmx:
	$(CP) x86-mmx.h arch.h
	$(MAKE) $(PROJ_WIN32_MINGW) \
		JOHN_OBJS="$(JOHN_OBJS) x86.o x86-mmx.o sha1-mmx.o md5-mmx.o" \
		CFLAGS="$(CFLAGS) -mpreferred-stack-boundary=3 -mmmx -m32" \
		ASFLAGS="$(ASFLAGS) -DUNDERSCORES"

win32-mingw-x86-any:
	$(CP) x86-any.h arch.h
	$(MAKE) $(PROJ_WIN32_MINGW) \
		JOHN_OBJS="$(JOHN_OBJS) x86.o" \
		CFLAGS="$(CFLAGS) -Wall -mpreferred-stack-boundary=2 -m32" \
		ASFLAGS="$(ASFLAGS) -DUNDERSCORES"

beos-x86-sse2:
	$(LN) x86-sse.h arch.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) x86.o x86-sse.o sha1-mmx.o md5-mmx.o"

beos-x86-mmx:
	$(LN) x86-mmx.h arch.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) x86.o x86-mmx.o sha1-mmx.o md5-mmx.o"

beos-x86-any:
	$(LN) x86-any.h arch.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) x86.o"

generic: generic.h
	$(RM) arch.h
	ln -s generic.h arch.h
	$(MAKE) $(PROJ)

generic.h:
	$(RM) arch.h
	$(CC) $(CFLAGS) detect.c
	$(LD) detect.o $(LDFLAGS) -o detect
	./best.sh "$(MAKE)" \
		"$(BENCH_DES_OBJS_DEPEND)" \
		"$(BENCH_DES_BS_OBJS_DEPEND)" \
		"$(BENCH_MD5_OBJS_DEPEND)" \
		"$(BENCH_BF_OBJS_DEPEND)"

bench: $(BENCH_OBJS)
	$(LD) $(BENCH_OBJS) $(LDFLAGS) -o bench

../run/john: $(JOHN_OBJS)
	$(LD) $(JOHN_OBJS) $(LDFLAGS) -o ../run/john

../run/unshadow: ../run/john
	$(RM) ../run/unshadow
	ln -s john ../run/unshadow

../run/unafs: ../run/john
	$(RM) ../run/unafs
	ln -s john ../run/unafs

../run/undrop: ../run/john
	$(RM) ../run/undrop
	ln -s john ../run/undrop

../run/unique: ../run/john
	$(RM) ../run/unique
	ln -s john ../run/unique

../run/john.bin: $(JOHN_OBJS)
	$(LD) $(JOHN_OBJS) $(LDFLAGS) -o ../run/john.exe
	if exist ..\run\john.bin del ..\run\john.bin
	ren ..\run\john.exe john.bin

../run/john.com: john.com
	copy john.com ..\run\john.com

../run/unshadow.com: john.com
	copy john.com ..\run\unshadow.com

../run/unafs.com: john.com
	copy john.com ..\run\unafs.com

../run/undrop.com: john.com
	copy john.com ..\run\undrop.com

../run/unique.com: john.com
	copy john.com ..\run\unique.com

john.com: john.asm
	@echo Use Borland TASM/TLINK to make JOHN.COM

../run/john.exe: $(JOHN_OBJS)
	$(LD) $(JOHN_OBJS) -lkernel32 -lcrypto -o ../run/john.exe
	strip ../run/john.exe

../run/john-mingw.exe: $(JOHN_OBJS)
	$(LD) $(JOHN_OBJS) -lkernel32 -leay32 -o ../run/john-mingw.exe
	strip ../run/john-mingw.exe
	cp ../run/john-mingw.exe ../run/john.exe

../run/unshadow.exe: symlink.c
	$(CC) symlink.c -o ../run/unshadow.exe
	strip ../run/unshadow.exe

../run/unafs.exe: symlink.c
	$(CC) symlink.c -o ../run/unafs.exe
	strip ../run/unafs.exe

../run/undrop.exe: symlink.c
	$(CC) symlink.c -o ../run/undrop.exe
	strip ../run/undrop.exe

../run/unique.exe: symlink.c
	$(CC) symlink.c -o ../run/unique.exe
	strip ../run/unique.exe

../run/genmkvpwd: $(GENMKVPWD_OBJS)
	$(LD) $(GENMKVPWD_OBJS) $(LDFLAGS) -o ../run/genmkvpwd

../run/genmkvpwd.exe: $(GENMKVPWD_OBJS)
	$(LD) $(GENMKVPWD_OBJS) $(LDFLAGS_MKV) -o ../run/genmkvpwd.exe

../run/mkvcalcproba: mkvcalcproba.o
	$(LD) mkvcalcproba.o $(LDFLAGS) -o ../run/mkvcalcproba

../run/mkvcalcproba.exe: mkvcalcproba.o
	$(LD) mkvcalcproba.o $(LDFLAGS_MKV) -o ../run/mkvcalcproba.exe

../run/calc_stat: calc_stat.o
	$(LD) calc_stat.o $(LDFLAGS) -o ../run/calc_stat

../run/calc_stat.exe: calc_stat.o
	$(LD) calc_stat.o $(LDFLAGS_MKV) -o ../run/calc_stat.exe

../run/tgtsnarf: tgtsnarf.o
	$(LD) tgtsnarf.o $(LDFLAGS) -o ../run/tgtsnarf

# Inlining the S-boxes produces faster code as long as they fit in the cache.
DES_bs_b.o: DES_bs_b.c sboxes.c nonstd.c sboxes-s.c
	$(CC) $(CFLAGS) $(OPT_INLINE) DES_bs_b.c

miscnl.o: misc.c
	$(CC) $(CFLAGS) $(OPT_NORMAL) -D_JOHN_MISC_NO_LOG misc.c -o miscnl.o

bench-t.o: bench.c
	$(CC) $(CFLAGS) $(OPT_NORMAL) -D_JOHN_BENCH_TMP bench.c -o bench-t.o

.c.o:
	$(CC) $(CFLAGS) $(OPT_NORMAL) $*.c

.S.o:
	$(AS) $(ASFLAGS) $*.S

# We don't have any files with .s suffix, this is for compiling in DOS only
.s.o:
	$(AS) $(ASFLAGS) $*.S

check:
	../run/john --make_check

depend:
	makedepend -fMakefile.dep -Y *.c 2>> /dev/null

clean:
	$(RM) $(PROJ) $(PROJ_DOS) $(PROJ_WIN32) $(PROJ_WIN32_MINGW)
	$(RM) ../run/john.exe john-macosx-* *.o *.bak core
	$(RM) detect bench generic.h arch.h tmp.s
	$(CP) $(NULL) Makefile.dep

include Makefile.dep
