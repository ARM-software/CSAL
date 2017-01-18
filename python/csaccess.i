%module csaccess
%include "cmalloc.i"
%include "cdata.i"
%{
  /* Write things here so the wrapper code knows about it... */
  /* This part is not processed/interpreted by SWIG */
  #include "csregistration.h"
  #include "csregisters.h"
  #include "csaccess.h"

%}

/* Unimplemented API calls - remove when done */
%ignore cs_trigsrc_portid;
%ignore cs_trigdst_portid;
%ignore cs_clear_trace_buffer;

/*
   Type maps for handling arrays
*/

/* Convert generic C arrays to python lists */
%typemap(out) SWIGTYPE[ANY] {
  int i;
  $result = PyList_New($1_dim0);
  for (i = 0; i < $1_dim0; i++) {
    PyObject *obj;
    obj = SWIG_NewPointerObj(&$1[i], $1_descriptor, SWIG_POINTER_EXCEPTION);
    PyList_SetItem($result, i, obj);
  }
}

%typemap(out) unsigned int [ANY] {
  int i;
  $result = PyList_New($1_dim0);
  for (i = 0; i < $1_dim0; i++) {
    PyObject *obj;
    obj = PyInt_FromLong($1[i]);
    PyList_SetItem($result, i, obj);
  }
}

/* Convert Python lists to C arrays */
%typemap(in) SWIGTYPE[ANY]($*1_ltype (*temp)[$1_dim0] = NULL) {
  int i, pyseqlength, carr_size, max;
  if (!PySequence_Check($input)) {
      PyErr_SetString(PyExc_TypeError,"Expecting a sequence");
      return NULL;
  }
  pyseqlength = PyObject_Length($input);
  carr_size = $1_dim0;

  max = pyseqlength <= carr_size ? pyseqlength : carr_size;
  for (i = 0; i < max; ++i) {
    PyObject *o = PySequence_GetItem($input, i);
    // Do a check somehow
    void *c_ptr;
    $1_ltype arg_ptr = ($1_ltype)c_ptr;
    SWIG_ConvertPtr(o, &c_ptr, $1_descriptor, SWIG_POINTER_EXCEPTION);
    (*temp)[i] = *arg_ptr;
    Py_DECREF(o);
  }
  $1 = *temp;
}

%include "csregisters.h"
%include "csaccess.h"
%include "cs_types.h"
%include "cs_cti_ect.h"
%include "cs_debug_sample.h"
%include "cs_etm_types.h"
%include "cs_etm.h"
%include "cs_pmu.h"
%include "cs_reg_access.h"
%include "cs_sw_stim.h"
%include "cs_topology.h"
%include "cs_trace_sink.h"
%include "cs_trace_source.h"

%malloc(unsigned char, char_buf)
%free(unsigned char, char_buf)
