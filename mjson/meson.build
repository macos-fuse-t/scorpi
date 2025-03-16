libmjson_src = files(
  'mjson.c',
)

libmjson = static_library(
  'mjson',
  libmjson_src,
  include_directories: inc
)

libmjson_dep = declare_dependency(link_with: libmjson)

