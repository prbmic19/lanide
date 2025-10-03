/** Declarations for diagnostic utility functions. */

#pragma once

extern unsigned int errors_emitted;
extern unsigned int warnings_emitted;

extern void set_progname(const char *_progname);
extern void emit_fatal(const char *fmt, ...);
extern void emit_error(const char *fmt, ...);
extern void emit_warning(const char *fmt, ...);
extern void optional_enable_vt_mode(void);