from distutils.core import setup, Extension
import platform

libraries = ["weave", "nids", "net", "pcap", "ssl", "glib-2.0", "gthread-2.0"]

if platform.system() == "Windows":
	libraries += ["ws2_32", "iphlpapi", "psapi", "packet"]

weavemodule = Extension(
	"weave",
	sources = ["weavemodule.cpp",],
	libraries=libraries,
	library_dirs=["../"],
	include_dirs=["../"],
	language="c++"
)

setup(name = "Weave", version = "3.0", ext_modules = [weavemodule,])
