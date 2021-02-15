SUFFIXES =
TESTS =
CLEANFILES =
DISTCLEANFILES =
bin_PROGRAMS =
noinst_HEADERS =
lib_LTLIBRARIES =
man_MANS =
noinst_LTLIBRARIES =
noinst_PROGRAMS =
include_HEADERS =
nobase_include_HEADERS =
check_PROGRAMS =
EXTRA_HEADERS =
BUILT_SOURCES=
EXTRA_DIST=
dist_doc_DATA=
dist_noinst_SCRIPTS =
check_SCRIPTS =

#includes additional rules from aminclude.am
@INC_AMINCLUDE@
DISTCLEANFILES+= aminclude.am

ACLOCAL_AMFLAGS = -I m4
EXTRA_DIST += README test-key.pem test-cert.pem

include src/include.am
include examples/cert_client/include.am
include examples/etsi_client/include.am
include scripts/include.am

check_SCRIPTS+= $(dist_noinst_SCRIPTS)

TESTS += $(check_SCRIPTS)
test: check
