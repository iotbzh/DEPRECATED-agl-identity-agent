###########################################################################
# Copyright 2016 IoT.bzh
#
# author: José Bollo <jose.bollo@iot.bzh>
# author: Stéphane Desneux <stephane.desneux@iot.bzh>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
###########################################################################

cmake_minimum_required(VERSION 3.3)

###########################################################################

include(FindPkgConfig)

pkg_check_modules(EXTRAS REQUIRED json-c afb-daemon libcurl systemd)
add_compile_options(${EXTRAS_CFLAGS} -DFOR_AFB_BINDING)
include_directories(${EXTRAS_INCLUDE_DIRS})
link_libraries(${EXTRAS_LIBRARIES})

add_library(${PROJECT_NAME} MODULE
	agl-identity-binding.c
	u2f-bluez.c
	u2f-bt.c
	u2f-protocol.c
	authorization.c
	base64.c
	escape.c
	oidc-agent.c
	curl-wrap.c
	aia-get.c
)
set_target_properties(${PROJECT_NAME} PROPERTIES
	PREFIX ""
	LINK_FLAGS "-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/export.map"
)

install(TARGETS ${PROJECT_NAME} DESTINATION ${PROJECT_DESTINATION})

INSTALL(FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/config.json
    DESTINATION
    ${PROJECT_DESTINATION}
    )

