test_src = files('nvlist_test.c')

nv_test_executable = executable(
  'nvlist_test',  # Name of the executable
  test_src,
  dependencies: libnv_dep,
  include_directories: inc
)

test('nvlist_test', nv_test_executable)

dtb = custom_target('test_dtb',
    input: 'test.dts',
    output: 'test.dtb',
    command: ['dtc', '-I', 'dts', '-O', 'dtb', '-o', '@OUTPUT@', '@INPUT@']
)

fdt_test_src = files('fdt_test.c')

fdt_test_executable = executable(
  'fdt_test', 
  fdt_test_src,
  dependencies: libfdt_dep,
  include_directories: inc,
)

test_env = environment()
test_env.set('TEST_DTB_FILE', meson.current_build_dir() / 'test.dtb')
test('fdt_test', fdt_test_executable, env: test_env, depends: dtb)