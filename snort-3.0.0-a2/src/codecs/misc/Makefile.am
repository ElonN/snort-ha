
noinst_LIBRARIES = libmisc_codecs.a
libmisc_codecs_a_SOURCES = \
cd_default.cc

plugin_list = \
cd_gtp.cc \
cd_icmp4_ip.cc \
cd_icmp6_ip.cc \
cd_llc.cc \
cd_teredo.cc \
cd_user.cc

if STATIC_CODECS
libmisc_codecs_a_SOURCES += $(plugin_list)

else
cdlibdir = $(pkglibdir)/codecs

cdlib_LTLIBRARIES = libcd_gtp.la
libcd_gtp_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libcd_gtp_la_LDFLAGS = -export-dynamic -shared
libcd_gtp_la_SOURCES = cd_gtp.cc

cdlib_LTLIBRARIES += libcd_icmp4_ip.la
libcd_icmp4_ip_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libcd_icmp4_ip_la_LDFLAGS = -export-dynamic -shared
libcd_icmp4_ip_la_SOURCES = cd_icmp4_ip.cc

cdlib_LTLIBRARIES += libcd_icmp6_ip.la
libcd_icmp6_ip_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libcd_icmp6_ip_la_LDFLAGS = -export-dynamic -shared
libcd_icmp6_ip_la_SOURCES = cd_icmp6_ip.cc

cdlib_LTLIBRARIES += libcd_llc.la
libcd_llc_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libcd_llc_la_LDFLAGS = -export-dynamic -shared
libcd_llc_la_SOURCES = cd_llc.cc

cdlib_LTLIBRARIES += libcd_teredo.la
libcd_teredo_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libcd_teredo_la_LDFLAGS = -export-dynamic -shared
libcd_teredo_la_SOURCES = cd_teredo.cc

cdlib_LTLIBRARIES += libcd_user.la
libcd_user_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libcd_user_la_LDFLAGS = -export-dynamic -shared
libcd_user_la_SOURCES = cd_user.cc
endif

AM_CXXFLAGS = @AM_CXXFLAGS@

