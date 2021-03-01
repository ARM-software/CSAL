Building the Library
====================

Default Build
-------------

The library and demos can be built from the root of the CSAL installation using the master
`makefile`. The default build will build a release version of the library and demos based
on the platform architecture set in the ARCH environment variable.

`ARCH` values:-
- `arm`  : default for 32 bit arm / aarch32 platforms - virtual and physical address sizes 32 bit.
- `arm64`: build for 64 bit / aarch64 platforms - virtual and physical address sizes 64 bit.

If the ARCH environment is not set, then the platform architecture is detected using the linux
`uname` command and an appropriate value used. If the platform is not ARM and no cross compile
is indicated, then the build will fail.

The default version will be a linux user application release build, built into the `./lib/<arch>/rel` 
sub-directory off the main CoreSight Access Library directory. This version will not have any 
of the optional components in the library. 

The library will be built as both a static link library `libcsaccess.a` and a 
dynamic link library `libcsaccess.so`.

The utility library will be built at the same time using the same parameters. This will
appear as `libcsacc_util.a` and `libcsacc_util.so`.

`make help` lists possible build targets.

Cross Compilation
-----------------
Cross compilation is supported by setting the `CROSS_COMPILE` and `ARCH` environment variables.

- `CROSS_COMPILE` : Name prefix for gcc compiler in use. Compiler invoked will be `<CROSS_COMPILE>gcc`.
Not set when compiling on native platform. It is assumed that the compiler is on the PATH.
- `ARCH`  : Target architecture - can be `arm` or `arm64`. This selects compile time defines. Assumes that the target compiler defaults to this architecture.

Additional Build Options
------------------------
The following options can be added the make command line:-
- `DEBUG=1`     : This will create the debug versions of the library in the `./lib/<arch>/dbg` subdirectory.
- `BAREMETAL=1` : This will create a BareMetal version of the library. Linux headers will not be used.

  The library will be delivered into the `./lib/<arch>/rel_bm` directory. This library is suitable for use 
  in embedded applications not running under Linux. Default architecture is `arm`. Set the `ARCH` environment
  variable to use `arm64`, or cross compile.


- `NOLPAE=1`    : This will create a version of the library without long physical address types on an `ARCH=arm64` platform. Not used on `arm` platforms.

- `LPAE=1`      :  This will create a version of the library with long physical address types on an `ARCH=arm` platform. LPAE is default on used on `arm64` platforms.

- `NO_DIAG=1`   : This will disable the diagnostic `printf()` messages. May be required for Baremetal version if
                  external printing unsupported.

- `NO_CHECK=1`  : This will disable additional diagnostic self checks - writes to CS registers are logged and read back.

- `DBG_HALT=1`  : This will build a version of the library with the optional v7 Architecture intrusive 
  halt mode debug functions built into the library. 
  
  The library names will be altered to `libcsaccess_dbghlt.a` and `libcsaccess_dbghlt.so`

Options can be combined on the command line to create specific versions of the library.

e.g. 

    make DEBUG=1 BAREMETAL=1

will create a debug version of the Baremetal library, delivered into the `./lib/<arch>/dbg_bm` directory.

Build Targets
-------------

all     : build library and demos.
lib     : build library only.
demos   : build the demos.
docs    : build doxygen documentation.
clean   : clean library and demos.
rebuild : clean and build all.
