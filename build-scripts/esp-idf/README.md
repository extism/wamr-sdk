# extism-wamr as ESP-IDF component

You can build an ESP-IDF project with extism-wamr as a component:

- Make sure you have the ESP-IDF properly installed and setup
- In particular have the following paths set:
  - `EXTISM_WAMR_PATH` to point to your wamr-sdk repository
  - `IDF_PATH` to point to your ESP-IDF
  - `source $IDF_PATH/export.sh`
- Create a new project, e.g.: `idf.py create-project wamr-hello`
- In the newly created project folder edit the `CMakeList.txt`:

  ```
  cmake_minimum_required(VERSION 3.5)

  include($ENV{IDF_PATH}/tools/cmake/project.cmake)

  set (COMPONENTS ${IDF_TARGET} main freertos esptool_py extism-wamr)

  list(APPEND EXTRA_COMPONENT_DIRS "$ENV{EXTISM_WAMR_PATH}/build-scripts/esp-idf")

  project(wamr-hello)
  ```
- Develop your project in it's `main` component folder.

