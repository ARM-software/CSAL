Building the Library        {#buildlib}
====================

Default Build
-------------

The library and demos can be built from the root of the CSAL installation using the master
`makefile`. The default build will build a release version of the library and demos based
on the platform architecture (arm or arm64). Platform architecture is detected using the
linux `uname` command.

The default version will be a linux user application release build, built into the `./lib/<arch>/rel` 
sub-directory off the main CoreSight Access Library directory. This version will not have any 
of the optional components in the library. 

The library will be built as both a static link library `libcsaccess.a` and a 
dynamic link library `libcsaccess.so`.

The utility library will be built at the same time using the same parameters. This will
appear as `libcsacc_util.a` and `libcsacc_util.so`.

`make help` lists possible targets.

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

- `LPAE=1`      : This will create a version of the library with long physical address types - suitable for
                  use on cores using the LPAE extensions. This defines the `LPAE` macro at compile time to 
                  enable large physical addresses.

- `VA64=1`      : This will create a version of the library using 64 bit virtual address types. Suitable for 
                  V8 architecture cores. This defines the `CS_VA64BIT` macro at compile time to enable 64 bit 
                  virtual addresses.

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
