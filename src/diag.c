/** Definition of diagnostic utility functions. */

#include "diag.h"
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>

static const char *progname = "someprogname";
unsigned int errors_emitted = 0;
unsigned int warnings_emitted = 0;

// Sets the program name to be used for all emitted logs.
void set_progname(const char *_progname)
{
    const char *slash = strrchr(_progname, '/');
#ifdef _WIN32
    const char *bslash = strrchr(_progname, '\\');
    if (!slash || (bslash && bslash > slash))
    {
        slash = bslash;
    }
#endif
    progname = slash ? slash + 1 : _progname;
}

/* The following functions use the format `someprogname: something: some message */

void emit_fatal(const char *fmt, ...)
{
    va_list args;
    fprintf(stderr, "%s: \x1b[91mfatal error:\x1b[97m ", progname);
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fputs("\x1b[0m\n", stderr);
    exit(1);
}

/* These two pile up */

void emit_error(const char *fmt, ...)
{
    va_list args;
    fprintf(stderr, "%s: \x1b[91merror:\x1b[97m ", progname);
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fputs("\x1b[0m\n", stderr);
    errors_emitted++;
}

void emit_warning(const char *fmt, ...)
{
    va_list args;
    fprintf(stderr, "%s: \x1b[95mwarning:\x1b[97m ", progname);
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fputs("\x1b[0m\n", stderr);
    warnings_emitted++;
}

// Seems out of place... but good to have.

#ifdef _WIN32
#   define WIN32_LEAN_AND_MEAN
#   include <windows.h>

// Enables VT mode on Windows, ensuring we have proper color output. Even on conhost.exe and such.
void maybe_enable_vt_mode(void)
{
    HANDLE stdout_handle = GetStdHandle(STD_OUTPUT_HANDLE);
    if (stdout_handle == INVALID_HANDLE_VALUE)
    {
        return;
    }

    DWORD mode = 0;
    if (!GetConsoleMode(stdout_handle, &mode))
    {
        return;
    }

    mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    SetConsoleMode(stdout_handle, mode);
}
#else
// On POSIX terminals, ANSI escape codes usually just work.
void maybe_enable_vt_mode(void)
{
}
#endif