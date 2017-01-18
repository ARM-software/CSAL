Using the Library in Python      {#python}
===========================

The `./python` directory in the CoreSight Access Library distribution contains source code and 
a Makefile to build a python add-in module for the library, enabling the use of the library 
within python scripts on platforms that support python.

Supplied Files
--------------

- `Makefile` : this will make the python module, either using the python-dev module within python
   or building a module standalone. This file will require modification for the target system.
- `setup.py` : Python script that sets up the `_csaccess` module using python.
- `csaccess.i` : Interface source file used to create the python module. Library includes are 
  declared here.
- `csreg_tc2.py` and `csregistration.py`: python example scripts using the library.


System Requirements
-------------------

The target system must have the following modules installed, in addition to a 2.x version of python.

 - `swig` : required for processing the interface files into a python compatible source file.
 - `python-dev`: a python module used to build the add-in module.


Modifying the `Makefile`
------------------------

The supplied `Makefile` will require modification to match the `python` installation on the 
target system. As supplied it is set up to test the build on a linux test platform.

The following lines from `Makefile` may need changing:-

    # gcc flags - these match those used by python 2.6 build utilities.
    #           - tune according to your python
    CFLAGS= -pthread -fno-strict-aliasing -DNDEBUG -g -fwrapv -O3 -Wall -Wstrict-prototypes -fPIC 

The lines above set up the compiler flags to match the parameters used for the target system python.

    ## python includes 
    PYTHON_INC_DIR=/arm/tools/python/python/2.6.5/rhe5-x86_64/include/python2.6/

Set the include directory to an appropriate path for the target system.

    ## python library - leave PYTHON_LIB_LINK empty if not linking to python library (python version dependent)
    PYTHON_LIB_DIR=/arm/tools/python/python/2.6.5/rhe5-x86_64/lib
    PYTHON_LIB_NAME=python2.6
    PYTHON_LIB_LINK=-L$(PYTHON_LIB_DIR) -l$(PYTHON_LIB_NAME)

Set up the link paths to the local python installation.


Building the Python Extension.
------------------------------

Both build methods will create a python extension dll `_csaccess.so` that can be loaded into a python script. 
This extension is linked against the dynamic version of the CoreSight Access Library, `libcsaccess.so`. 
Both must be present in the library search path to allow the extension module to work correctly.

The first, default, method uses `python` itself and `swig` to build the extension, using the `setup.py` script. 
See the `swig:` target in the `Makefile` for details.

The second method builds the extension module standalone, using `swig` and `gcc`. Use the command `make py_so` to 
use this build method.
