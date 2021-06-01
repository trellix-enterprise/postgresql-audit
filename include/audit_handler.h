/*
 * audit_handler.h
 *
 *  Created on: Feb 6, 2011
 *      Author: guyl
 *
 * Modified for PostgreSQL
 * 	Aharon Robbins
 * 	April 2016
 */

#ifndef AUDIT_HANDLER_H_
#define AUDIT_HANDLER_H_

#include <time.h>
#include <sys/types.h>
#include <unistd.h>

#include <yajl/yajl_gen.h>

#ifndef PCRE_STATIC
#define PCRE_STATIC
#endif

#include <pcre.h>

#include "pgsql_inc.h"
#include "audit_event.h"

#include <vector>
#include <string>

#define AUDIT_PROTOCOL_VERSION "1.0"

/*
 * On  success,  the  number of bytes written are returned (zero indicates nothing was written).  On error, -1 is returned,
 */
typedef ssize_t (*audit_write_func)(const char *, size_t);

/**
 * Interface for an io writer
 */
class IWriter {
public:
	virtual ~IWriter() {}
	// return negative on fail
	virtual ssize_t write(const char *data, size_t size) = 0;
	inline ssize_t write_str(const char *str)
	{
		return write(str, strlen(str));
	}
	// return 0 on success
	virtual int open(const char *io_dest, bool log_errors) = 0;
	virtual void close() = 0;
};

struct ProcError {
	int sqlerrcode;       /* encoded ERRSTATE */
	std::string message;  /* primary error message (translated) */
};

struct PostgreSQL_proc {
	pid_t	pid;
	const char *db_name;
	const char *user;
	const char *priv_user;
	const char *hostname;
	const char *ip;
	const char *os_user;
	const char *appname;
	unsigned int query_id;
	bool connected;
	bool initialized;
	int auth_status;
	std::vector<ProcError> error_list;

	PostgreSQL_proc()
		: pid(),
		db_name(""),
		user(""),
		priv_user(""),
		hostname(""),
		ip(""),
		os_user(""),
		appname(""),
		query_id(0),
		connected(false),
		initialized(),
		auth_status()
	{
	}
};

/**
 * Base for audit formatter
 */
class Audit_formatter {
public:
	virtual ~Audit_formatter() {}

	/**
	 * Format an audit event from the passed thread
	 * Will write out its output using the audit_write_func.
	 *
	 * @return -1 on a failure
	 */
	virtual ssize_t event_format(const PostgreSQL_proc *proc, AuditEventStackItem *pItem, IWriter *writer) = 0;

	/**
	 * Format a message when handler is started
	 * @return -1 on a failure
	 */

	virtual ssize_t start_msg_format(IWriter *writer) { return 0; }

	/**
	 * Format a message when handler is stopped
	 * @return -1 on a failure
	 */
	virtual ssize_t stop_msg_format(IWriter *writer) { return 0; }

	/**
	 * Format a generic message
	 * @return -1 on a failure
	 */
	virtual ssize_t command_format(const PostgreSQL_proc *proc, const char *command, const char *query, IWriter *writer) = 0;
};


/**
 * Format the audit even in json format
 */
class Audit_json_formatter : public Audit_formatter {
public:
	static const char *DEF_MSG_DELIMITER;

	Audit_json_formatter()
		: m_msg_delimiter(NULL),
		m_write_start_msg(true),
		m_perform_password_masking(NULL),
		m_password_mask_regex_preg(NULL),
		m_password_mask_regex_compiled(false)
	{
		// elog(LOG, "%s:%d:%d: Audit_json_formatter constructor called", __FILE__, __LINE__, getpid());
	}

	virtual ~Audit_json_formatter()
	{
		if (m_password_mask_regex_preg)
		{
			m_password_mask_regex_compiled = false;
			pcre_free(m_password_mask_regex_preg);
			m_password_mask_regex_preg = NULL;
		}
	}

	virtual ssize_t event_format(const PostgreSQL_proc *proc, AuditEventStackItem *pItem, IWriter *writer);
	virtual ssize_t start_msg_format(IWriter *writer);
	virtual ssize_t command_format(const PostgreSQL_proc *proc, const char *command, const char *query, IWriter *writer);

	/**
	 * Utility method used to compile a regex program.
	 * Will compile and log errors if necessary.
	 * Return null if fails
	 */
	static pcre *regex_compile(const char *str);

	/**
	 * Message delimiter. Should point to a valid json string
	 * (supporting the json escapping format).
	 * Will only be checked at the start. Public so can be set by sysvar.
	 *
	 * We only support a delimiter up to 32 chars
	 */
	char *m_msg_delimiter;

	/**
	 * Compile password masking regex
	 * Return true on success
	 */
	bool compile_password_masking_regex(const char *str);

	/**
	 * Boolean indicating if to log start msg.
	 * Public so sysvar can update.
	 */
	bool m_write_start_msg;


	/**
	 * Callback function to determine if password masking should be performed
	 */
	bool (*m_perform_password_masking)(const char *cmd);

protected:

	Audit_json_formatter& operator =(const Audit_json_formatter& b);
	Audit_json_formatter(const Audit_json_formatter& );

	/**
	 * Regex used for password masking
	 */
	pcre *m_password_mask_regex_preg;

	/**
	 * Boolean indicating if password masking regex is compiled
	 */
	bool m_password_mask_regex_compiled;
};

/**
 * Base class for audit handlers. Provides basic locking setup.
 */
class Audit_handler {
public:
	static const size_t MAX_AUDIT_HANDLERS_NUM = 4;
	static const size_t JSON_FILE_HANDLER = 1;
	static const size_t JSON_UNIX_SOCKET_HANDLER = 2;
//	static const size_t JSON_TCP_SOCKET_HANDLER = 3;

	static Audit_handler *m_audit_handler_list[];

	/**
	 * Will iterate the handler list and set session info,
	 * and send connect message.
	 */
	static void log_audit_connect();

	/**
	 * Will iterate the handler list and log using each handler
	 */
	static void log_audit_all(AuditEventStackItem *pItem);

	/**
	 * Will iterate the handler list and send connect message.
	 */
	static void log_audit_disconnect();

	/**
	 * Will iterate the handler list and stop all handlers
	 */
	static void stop_all();

	Audit_handler(const PostgreSQL_proc& proc) :
		m_initialized(false),
		m_enabled(false),
		m_formatter(NULL),
		m_failed(false),
		m_log_io_errors(true),
		m_proc(proc),
		m_handler_type("unknown")
	{
	}

	virtual ~Audit_handler()
	{
	}

	/**
	 * Should be called to initialize.
	 *
	 * @frmt the formatter to use in this handler (does not manage
	 * destruction of this object)
	 * @return 0 on success
	 */
	int init(Audit_formatter *formatter)
	{
		m_formatter = formatter;
		if (m_initialized)
		{
			// elog(LOG, "pid = %d, %s Audit_handler::init - initialized!", getpid(), m_handler_type);
			return 0;
		}

		m_initialized = true;
		// elog(LOG, "%d %s Audit_handler::init all done", getpid(), handler_type());
		return 0;
	}

	bool is_init()
	{
		return m_initialized;
	}

	void set_enable(bool val);

	bool is_enabled()
	{
		return m_enabled;
	}

	/**
	 * will close and start the handler
	 */
	void flush();

	/**
	 * Will get relevant shared lock and call internal method of handler
	 */
	void log_audit(AuditEventStackItem *pItem);

	/**
	 * Will get relevant shared lock and call internal method of handler
	 */
	virtual void log_connect() = 0;

	/**
	 * Will get relevant shared lock and call internal method of handler
	 */
	virtual void log_disconnect() = 0;

	/**
	 * Public so can be configured via sysvar
	 */
	unsigned int m_retry_interval;

	/**
	 * Allow updating the proc info.
	 */

protected:
	virtual void handler_start();
	// will call internal method and set failed as needed
	bool handler_start_nolock();
	virtual void handler_stop();
	virtual bool handler_start_internal() = 0;
	virtual void handler_stop_internal() = 0;
	virtual bool handler_log_audit(AuditEventStackItem *pItem) = 0;
	bool m_initialized;
	bool m_enabled;
	Audit_formatter *m_formatter;
	bool m_failed;
	bool m_log_io_errors;
	time_t m_last_retry_sec_ts;
	const PostgreSQL_proc& m_proc;

	inline void set_failed()
	{
		time(&m_last_retry_sec_ts);
		m_failed = true;
		m_log_io_errors = false;
	}
	inline bool is_failed_now()
	{
		return m_failed && (m_retry_interval < 0 ||
				difftime(time(NULL), m_last_retry_sec_ts) > m_retry_interval);
	}
	// override default assignment and copy to protect against
	// creating additional instances
	Audit_handler & operator=(const Audit_handler&);
	Audit_handler(const Audit_handler&);

	const char *const handler_type() const { return m_handler_type; }
	void set_handler_type(const char *str)
	{
		m_handler_type = str;
	}
private:
	// for debug
	const char *m_handler_type;
};

/**
 * Base class for handler which have io and need a lock
 */
class Audit_io_handler: public Audit_handler, public IWriter {
public:
	Audit_io_handler(const PostgreSQL_proc& proc)
		: Audit_handler(proc), m_io_dest(NULL), m_io_type(NULL)
	{
		set_handler_type("io");
	}

	virtual ~Audit_io_handler()
	{
	}


	/**
	 * target we write to (socket/file). Public so we update via sysvar
	 */
	char *m_io_dest;

	/**
	 * Will get relevant shared lock and call internal method of handler
	 */
	virtual void log_connect();

	/**
	 * Will get relevant shared lock and call internal method of handler
	 */
	virtual void log_disconnect();

protected:
	virtual bool handler_start_internal();
	virtual void handler_stop_internal();
	// used for logging messages
	const char *m_io_type;
};

class Audit_file_handler: public Audit_io_handler {
public:

	Audit_file_handler(const PostgreSQL_proc& proc) :
		Audit_io_handler(proc) ,m_sync_period(0), m_bufsize(0), m_log_file(NULL), m_sync_counter(0)
	{
		m_io_type = "file";
		set_handler_type("file");
	}

	virtual ~Audit_file_handler()
	{
	}

	/**
	 * The period to use for syncing to the file system. 0 means we don't sync.
	 * 1 means each write we sync. Larger than 1 means every sync_period we sync.
	 *
	 * We leave this public so the mysql sysvar function can update this variable directly.
	 */
	unsigned int m_sync_period;

	/**
	 * The buf size used by the file stream. 0 = use default,
	 * negative or 1 = no buffering
	 */
	long m_bufsize;

	/**
	 * Write function we pass to formatter
	 */
	ssize_t write(const char *data, size_t size);

	void close();

	int open(const char *io_dest, bool m_log_errors);
protected:
	// override default assignment and copy to protect against creating
	// additional instances
	Audit_file_handler & operator=(const Audit_file_handler&);
	Audit_file_handler(const Audit_file_handler&);

	/**
	 * Will acquire locks and call handler_write
	 */
	virtual bool handler_log_audit(AuditEventStackItem *pItem);
	FILE *m_log_file;
	// the period to use for syncing
	unsigned int m_sync_counter;
};

class Audit_unix_socket_handler: public Audit_io_handler {
public:

	Audit_unix_socket_handler(const PostgreSQL_proc& proc) :
		Audit_io_handler(proc) ,m_connect_timeout(1), m_fd(-1)
	{
		m_io_type = "socket";
		set_handler_type("socket");
	}

	virtual ~Audit_unix_socket_handler()
	{
	}

	/**
	 * Connect timeout in secconds
	 * FIXME: Not used in PostgreSQL plugin.
	 */
	unsigned int m_connect_timeout;

	/**
	 * Write function we pass to formatter
	 */
	ssize_t write(const char *data, size_t size);

	void close();

	int open(const char *io_dest, bool log_errors);

protected:
	// override default assignment and copy to protect against creating additional instances
	Audit_unix_socket_handler & operator=(const Audit_unix_socket_handler&);
	Audit_unix_socket_handler(const Audit_unix_socket_handler&);

	/**
	 * Will acquire locks and call handler_write
	 */
	virtual bool handler_log_audit(AuditEventStackItem *pItem);

private:
	int m_fd;	// UNIX domain socket file descriptor
};

#if 0	// Future
class Audit_tcp_socket_handler: public Audit_io_handler {
public:

	Audit_tcp_socket_handler() :
		m_fd(-1), m_connect_timeout(1)
	{
		m_io_type = "socket";
	}

	virtual ~Audit_tcp_socket_handler()
	{
	}

	/**
	 * Connect timeout in secconds
	 */
	unsigned int m_connect_timeout;

	/**
	 * Write function we pass to formatter
	 */
	ssize_t write(const char *data, size_t size);

	void close();

	int open(const char *io_dest, bool log_errors);

protected:
	// override default assignment and copy to protect against creating additional instances
	Audit_tcp_socket_handler & operator=(const Audit_tcp_socket_handler&);
	Audit_tcp_socket_handler(const Audit_tcp_socket_handler&);

	/**
	 * Will acquire locks and call handler_write
	 */
	virtual bool handler_log_audit(AuditEventStackItem *pItem);

private:
	int m_fd;	// socket file descriptor
};
#endif

class Audit_utils {
public:
	static const char *plugin_socket_name();
	static const char *db_unix_socket_name();
	// other stuff here...
};

#endif /* AUDIT_HANDLER_H_ */
