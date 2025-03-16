libfdt_src = files(
  'fdt.c',
  'fdt_empty_tree.c',
  'fdt_ro.c',
  'fdt_strerror.c',
  'fdt_wip.c',
  'fdt_addresses.c',
  'fdt_overlay.c',
  'fdt_rw.c',
  'fdt_sw.c',
)

libfdt = static_library(
  'fdt',
  libfdt_src,
  include_directories: inc
)

libfdt_dep = declare_dependency(link_with: libfdt)

