#define PY_SSIZE_T_CLEAN
#include "Python.h"

static PyObject* SpamError;


static PyObject* spam_system(PyObject* self, PyObject* args) {
    const char* command;
    int sts;

    if (!PyArg_ParseTuple(args, "s", &command))
        return NULL;
    sts = system(command);
    if (sts < 0) {
        PyErr_SetString(SpamError, "System command failed");
        return NULL;
    }
    return PyLong_FromLong(sts);
}

static PyMethodDef SpamMethods[] = {
    {"system", spam_system, METH_VARARGS, "Execute a shell command"},
    {NULL, NULL, 0, NULL}
};

struct PyModuleDef spammodule = {
    PyModuleDef_HEAD_INIT,
    "spam",
    NULL,
    -1,
    SpamMethods
};

PyMODINIT_FUNC PyInit_spam(void) {
    PyObject* m;
    m = PyModule_Create(&spammodule);
    if (m == NULL)
        return NULL;

    SpamError = PyErr_NewException("spam.error", NULL, NULL);
    Py_XINCREF(SpamError);
    if (PyModule_AddObject(m, "error", SpamError) <  0) {
        Py_XDECREF(SpamError);
        Py_CLEAR(SpamError);
        Py_DECREF(m);
        return NULL;
    }
    return m;
}

//int main(int argc, char* argv[]) {
//
//    wchar_t* program = Py_DecodeLocale(argv[0], NULL);
//    if (program == NULL) {
//        fprintf(stderr, "Fatal error : cannot decode argv[0]\n");
//        exit(1);
//    }
//    if (PyImport_AppendInittab("spam", PyInit_spam) == -1) {
//        fprint(stderr, "Error: couldn't extend in-build modules table\n");
//        exit(1);
//    }
//
//    Py_SetProgramName(program);
//
//    Py_Initialize();
//    PyMem_RawFree(program);
//}
