/*
 * Macros for printing info or errors.
 * Other general-purpose macros for MySQL compatibility.
 *
 * Allows us to share code with the MySQL plugin.
 *
 *
 * Audit plugin logging
 *
 * NOTE: Refer to elog.h for detailed explanation on each log level!!
 * 		 Like, when message is sent to server log/client, when its abort transaction etc
 */
extern bool audit_logging;

#define AUDIT_LOG_PREFIX 	"Audit Plugin: "
#define WARNING_PREFIX 		"WARNING: "
#define ERROR_PREFIX 	 	"ERROR: "
#define AUDIT_WARNING_PREFIX AUDIT_LOG_PREFIX WARNING_PREFIX
#define AUDIT_ERROR_PREFIX 	 AUDIT_LOG_PREFIX ERROR_PREFIX

/*
 * To enable plugin debug logs:
 * 	1. build 'audit.so' with 'PG_CPPFLAGS += -DPLUGIN_DEBUG' (in Makefile.pg.in)
 * 	2. add 'audit.debug_logs = 1' in postgresql.conf file
 * 	3. enable PostgreSQL logging from requested log level (since our macros using elog() )
 */
#ifdef PLUGIN_DEBUG
	#define CONDITIONAL_LOG(PREFIX, ...)                   				\
								do										\
								{ 										\
									if (audit_logging) 					\
									{									\
										elog(LOG, PREFIX __VA_ARGS__);	\
									}									\
								} while(0)

	#define AUDIT_DEBUG_LOG(...)   CONDITIONAL_LOG(AUDIT_LOG_PREFIX, __VA_ARGS__)
#else //Release
	#define AUDIT_DEBUG_LOG(...)
#endif


#define ALWAYS_LOG(PREFIX, ...)	                     			\
							do									\
							{ 									\
								elog(LOG, PREFIX __VA_ARGS__);	\
							} while(0)


#define AUDIT_WARNING_LOG(...) ALWAYS_LOG(AUDIT_WARNING_PREFIX, __VA_ARGS__)
#define AUDIT_ERROR_LOG(...)   ALWAYS_LOG(AUDIT_ERROR_PREFIX, __VA_ARGS__)


/* 
 * General 
 */
#define array_elements(array)		(sizeof(array) / sizeof(array[0]))

