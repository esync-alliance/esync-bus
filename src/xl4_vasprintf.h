#ifndef __XL4_VASPRINTF__
#define __XL4_VASPRINTF__

#if XL4_PROVIDE_VASPRINTF

// all of our use of asprintf is through f_asprintf
// which only uses vasprintf
int xl4_vasprintf(char **buf, const char *fmt, va_list ap);

#ifdef vasprintf
#undef vasprintf
#endif

#define vasprintf xl4_vasprintf

#endif // XL4_PROVIDE_VASPRINTF

#endif // __XL4_VASPRINTF__
