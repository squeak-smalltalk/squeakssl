PLUGIN_LINK_LIBRARIES("-Wl,--no-as-needed" "-lrt" "-Wl,-Bstatic")
PLUGIN_REQUIRE_PACKAGE (LIBTLS libtls)
PLUGIN_LINK_LIBRARIES("-Wl,-Bdynamic" "-lrt")