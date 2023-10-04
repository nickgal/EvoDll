cmake_minimum_required ( VERSION 3.0 )

project ( evo_dll )

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")

# include libdetours headers:
include_directories ( ${DETOURS_DIR}/Detours/src )

set (srcs
	main.cpp
)
set (hdrs
#put your headers here
)

add_library ( ${PROJECT_NAME} SHARED ${hdrs} ${srcs} ${rsrc})

# link with libdetours.lib
target_link_libraries ( ${PROJECT_NAME} ${DETOURS_LIB} )
add_dependencies(${PROJECT_NAME} libdetours)

set_target_properties(evo_dll PROPERTIES OUTPUT_NAME "evo")
set_target_properties(evo_dll PROPERTIES SUFFIX ".asi")

INSTALL( TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_PREFIX} COMPONENT ${PROJECT_NAME} )
