Building the Library        {#buildlib}
====================

Default Build
-------------

The library is build from within the `./build` directory using the supplied `Makefile`.
Simply change to the directory and run `make` to build the default version of the library.

The default version will be a linux user application release build, built into the `./lib/rel` 
sub-directory off the main CoreSight Access Library directory. This version will not have any 
of the optional components in the library. 

The library will be built as both a static link library `libcsaccess.a` and a 
dynamic link library `libcsaccess.so`.

The utility library will be built at the same time using the same parameters. This will
appear as `libcsacc_util.a` and `libcsacc_util.so`.

Additional Build Options
------------------------
The following options can be added the make command line:-
- `DEBUG=1`     : This will create the debug versions of the library in the `./lib/dbg` subdirectory.
- `BAREMETAL=1` : This will create a BareMetal version of the library. Linux headers will not be used.

  The library will be delivered into the `./lib/rel_bm` directory. This library is suitable for use 
  in embedded applications not running under Linux.

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

will create a debug version of the Baremetal library, delivered into the `./lib/dbg_bm` directory.
