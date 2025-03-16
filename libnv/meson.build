libnv_src = files('libnv.c', 'bsd_nvpair.c') 

libnv = static_library(
  'nv',
  libnv_src,
  include_directories: inc
)

libnv_dep = declare_dependency(link_with: libnv)

