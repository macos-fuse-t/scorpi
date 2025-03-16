libutil_src = files('hexdump.c', 'expand_number.c', 'md5.c') 

libutil = static_library(
  'util',
  libutil_src,
  include_directories: inc
)

libutil_dep = declare_dependency(link_with: libutil)
