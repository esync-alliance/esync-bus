
macro(install_headers srcDir dstDir)
  file(GLOB_RECURSE headerFiles RELATIVE ${srcDir} ${srcDir}/*.h)
  foreach(headerFile in ${headerFiles})
    set(file ${srcDir}/${headerFile})
    if (EXISTS ${file})
      get_filename_component(name ${headerFile} NAME)
      #message(STATUS "${name}")
      execute_process(COMMAND ${CMAKE_COMMAND} -E create_symlink ${file} ${dstDir}/${name})
    endif()
  endforeach()
endmacro(install_headers)

#Generate INTEGRITY project files
macro(configure_files srcDir dstDir)
  message(STATUS "Generating the gpj file FROM ${srcDir} TO  directory ${dstDir}")
  file(GLOB cfgFiles RELATIVE ${srcDir} ${srcDir}/*.in)

  foreach(cfgFile in ${cfgFiles})
    set(filePath ${srcDir}/${cfgFile})
    if(EXISTS ${filePath})
      # Remove the extension .in from input file for output file
      string(REGEX REPLACE ".in$" "" dstFile ${cfgFile})
      configure_file(${filePath} ${dstDir}/${dstFile} @ONLY)
    endif()
  endforeach()
endmacro(configure_files)

configure_files(${CMAKE_SOURCE_DIR}/ghs_port ${CMAKE_BINARY_DIR})

if (NOT EXISTS ${CMAKE_BINARY_DIR}/include/libxl4bus)
  make_directory(${CMAKE_BINARY_DIR}/include/libxl4bus)
endif()

install_headers(${LIB_XL4BUS_DIR}/src ${CMAKE_BINARY_DIR}/include/libxl4bus)
