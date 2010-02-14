from distutils.core import setup, Extension

weavemodule = Extension(
	"weave",
	sources = ["weavemodule.cpp",],
	libraries=["weave", "nids", "pcap", "ssl"],
	library_dirs=["../"],
	include_dirs=["../"],
	language="c++"
)

setup(name = "Weave", version = "3.0", ext_modules = [weavemodule,])
