/*
 * audit_handler.cc
 *
 *  Created on: Feb 6, 2011
 *      Author: guyl
 *
 * Modifications for PostgreSQL, Spring 2016.
 */

#include <sys/un.h>		// for definition of sockaddr_un
#include <stdio_ext.h>		// for __fbufsize
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string>

#include "sql_print.h"

#include "audit_handler.h"

// in audit.cc
extern char *getFullObjectName(const RangeVar *rangevar);

// initialize static stuff
Audit_handler *Audit_handler::m_audit_handler_list[Audit_handler::MAX_AUDIT_HANDLERS_NUM];
const char *Audit_json_formatter::DEF_MSG_DELIMITER = "\\n";	// FIXME. This isn't used...

void Audit_handler::stop_all()
{
	for (size_t i = 0; i < MAX_AUDIT_HANDLERS_NUM; ++i)
	{
		if (m_audit_handler_list[i] != NULL)
		{
			m_audit_handler_list[i]->set_enable(false);
		}
	}
}

void Audit_handler::log_audit_all(AuditEventStackItem *pItem)
{
	for (size_t i = 0; i < MAX_AUDIT_HANDLERS_NUM; ++i)
	{
		if (m_audit_handler_list[i] != NULL)
		{
			m_audit_handler_list[i]->log_audit(pItem);
		}
	}
}

void Audit_handler::log_audit_connect()
{
	for (size_t i = 0; i < MAX_AUDIT_HANDLERS_NUM; ++i)
	{
		if (m_audit_handler_list[i] != NULL)
		{
			m_audit_handler_list[i]->log_connect();
		}
	}
}

void Audit_handler::log_audit_disconnect()
{
	for (size_t i = 0; i < MAX_AUDIT_HANDLERS_NUM; ++i)
	{
		if (m_audit_handler_list[i] != NULL)
		{
			m_audit_handler_list[i]->log_disconnect();
		}
	}
}

void Audit_io_handler::log_connect()
{
	if (! m_enabled)
	{
		return;
	}

	m_formatter->command_format(& m_proc, "Connect", "Connect", this);
}

void Audit_io_handler::log_disconnect()
{
	if (! m_enabled)
	{
		return;
	}

	if (! m_proc.connected)
	{
		if (m_proc.user[0] != '\0')	// failed login
		{
			AUDIT_DEBUG_LOG("audit failed login event, user [%s]", m_proc.user);
			m_formatter->command_format(& m_proc, "Failed Login", "Failed Login", this);
			return;
		}
	}

	m_formatter->command_format(& m_proc, "Quit", "Quit", this);
}


void Audit_handler::set_enable(bool val)
{
	// elog(LOG, "%d %s set_enable(%s) called", getpid(),
	// 	handler_type(), val ? "true" : "false");
	if (m_enabled == val) // we are already enabled simply return
	{
		// elog(LOG, "%d %s set_enable(%s) m_enabled already at %s, returning early", getpid(),
		// 	handler_type(),
		// 	val ? "true" : "false",
		// 	m_enabled ? "true" : "false");
		return;
	}
	m_enabled = val;
	if (m_enabled)
	{
		// call the startup of the handler
		// elog(LOG, "%d %s set_enable - starting handler", getpid(),
		// 	handler_type());
		handler_start();
	}
	else
	{
		// call the cleanup of the handler
		// elog(LOG, "%d %s set_enable - stopping handler", getpid(),
		// 	handler_type());
		handler_stop();
	}
}

void Audit_handler::flush()
{
	if (! m_enabled) // if not running we don't flush
	{
		return;
	}
	// call the cleanup of the handler
	handler_stop();
	// call the startup of the handler
	handler_start();
	AUDIT_DEBUG_LOG("Log flush complete");
}

void Audit_handler::log_audit(AuditEventStackItem *pItem)
{
	if (! m_enabled)
	{
		return;
	}

	// check if failed
	bool do_log = true;
	if (m_failed)
	{
		do_log = false;
		bool retry = m_retry_interval > 0 &&
			difftime(time(NULL), m_last_retry_sec_ts) > m_retry_interval;
		if (retry)
		{
			do_log = handler_start_nolock();
		}
	}
	if (do_log)
	{
		if (! handler_log_audit(pItem))
		{
			// Failure might be due to socket re-creation (for example, Sensor was restarted)
			// In order not to miss all events till next retry,
			// try to re-open socket now and report the event
			if (handler_start_nolock() && handler_log_audit(pItem))
			{
				elog(LOG, "%s successfully reconnected to socket", AUDIT_LOG_PREFIX);
			}
			else
			{
				set_failed();
				handler_stop_internal();
			}
		}
	}
}

void Audit_file_handler::close()
{
	if (m_log_file)
	{
		fclose(m_log_file);
	}
	m_log_file = NULL;
}

ssize_t Audit_file_handler::write(const char *data, size_t size)
{
	if (m_log_file == NULL)
	{
		AUDIT_ERROR_LOG("file: %s is not open!", m_io_dest);
		return -1;
	}

	if (size > SSIZE_MAX)
	{
		AUDIT_DEBUG_LOG("unsigned write size is larger than signed max");
	}
	// careful: pay attention to ordering of arguments to fwrite
	ssize_t res = fwrite(data, 1, size, m_log_file);
	// In POSIX, a negative return from fwrite indicates an error
	if (res < 0 || res != (ssize_t) size) // log the error
	{
		AUDIT_DEBUG_LOG("pid %d: failed writing to file: %s. Err: %s",
				getpid(), m_io_dest, strerror(errno));
	}
	return res;
}

int Audit_file_handler::open(const char *io_dest, bool log_errors)
{
	m_log_file = fopen(io_dest, "a");
	if (! m_log_file)
	{
		if (log_errors)
		{
			AUDIT_DEBUG_LOG("unable to open file %s: %s. audit file handler disabled!!",
					m_io_dest, strerror(errno));
		}
		return -1;
	}

	// log file could have sensitive info, don't allow other read perm.
	const int perms = S_IRUSR | S_IWUSR | S_IRGRP;	// -rw-r-----
	(void) fchmod(fileno(m_log_file), perms);

	ssize_t bufsize = BUFSIZ;
	int res = 0;
	// 0 -> use default, 1 or negative -> disabled
	if (m_bufsize > 1)
	{
		bufsize = m_bufsize;
	}

	if (m_bufsize == 1 || m_bufsize < 0)
	{
		// disabled
		res = setvbuf(m_log_file, NULL,  _IONBF, 0);
	}
	else
	{
		res = setvbuf(m_log_file, NULL, _IOFBF, bufsize);
	}

	if (res)
	{
		AUDIT_DEBUG_LOG("unable to set bufsize [%zd (%ld)] for file %s: %s.",
				bufsize, m_bufsize, m_io_dest, strerror(errno));
	}
	AUDIT_DEBUG_LOG("bufsize for file [%s]: %zd. Value of json_file_bufsize: %ld.", m_io_dest,
			__fbufsize(m_log_file), m_bufsize);
	return 0;
}

// no locks. called by handler_start and when it is time to retry
bool Audit_io_handler::handler_start_internal()
{
	// elog(LOG, "%d %s start_internal called", getpid(), handler_type());
	if (! m_io_dest || strlen(m_io_dest) == 0)
	{
		if (m_log_io_errors)
		{
			AUDIT_DEBUG_LOG("%s: io destination not set. Not connecting.",
					  m_io_type);
		}
		return false;
	}
	if (open(m_io_dest, m_log_io_errors) != 0)
	{
		// open failed
		AUDIT_DEBUG_LOG("%d %s handler, open failed: %s",
				getpid(), handler_type(), strerror(errno));
		return false;
	}

	// elog(LOG, "%d %s handler, writing start message", getpid(), handler_type());
	ssize_t res = m_formatter->start_msg_format(this);
	/*
	 * Sanity check of writing to the log. If we fail, we print an
	 * error and disable this handler.
	 */
	if (res < 0)
	{
		if (m_log_io_errors)
		{
#if PG_VERSION_NUM >= 120000
			const char *error_string = strerror(errno);
			ereport(WARNING, (errcode(ERRCODE_IO_ERROR),
					errmsg(
					"%s unable to write header msg to %s: %s.",
					AUDIT_ERROR_PREFIX, m_io_dest, error_string)));
#else
			AUDIT_ERROR_LOG("unable to write header msg to %s: %s.",
					m_io_dest, strerror(errno));
#endif
		}
		close();
		return false;
	}
	AUDIT_DEBUG_LOG("%s success opening %s.", m_io_type, m_io_dest);
	return true;
}

void Audit_io_handler::handler_stop_internal()
{
	// AUDIT_DEBUG_LOG("%d %s stop_internal called", getpid(), handler_type());
	if (! m_failed)
	{
		m_formatter->stop_msg_format(this);
	}
	close();
}

bool Audit_handler::handler_start_nolock()
{
	// AUDIT_DEBUG_LOG("%d %s handler_start_nolock - calling internal version", getpid(), handler_type());
	bool res = handler_start_internal();
	if (res)
	{
		m_failed = false;
	}
	else
	{
		set_failed();
	}
	return res;
}

void Audit_handler::handler_start()
{
	m_log_io_errors = true;
	// AUDIT_DEBUG_LOG("%d %s handler_start - calling nolock version", getpid(), handler_type());
	handler_start_nolock();
}

void Audit_handler::handler_stop()
{
	handler_stop_internal();
}

bool Audit_file_handler::handler_log_audit(AuditEventStackItem *pItem)
{
	// format and write
	bool res = (m_formatter->event_format(& m_proc, pItem, this) >= 0);

	// deal with flushing
	if (res && m_sync_period && ++m_sync_counter >= m_sync_period)
	{
		m_sync_counter = 0;

		// Note fflush() only flushes the user space buffers provided by the C library.
		// To ensure that the data is physically stored on disk the kernel buffers must
		// be flushed too, e.g. with sync(2) or fsync(2).
		res = (fflush(m_log_file) == 0);
		if (res)
		{
			int fd = fileno(m_log_file);
			res = (fsync(fd) == 0);
		}
	}
	return res;
}

/////////////////// Audit_unix_socket_handler //////////////////////////////////

void Audit_unix_socket_handler::close()
{
	if (m_fd >= 0)
	{
		::close(m_fd);
	}
	m_fd = -1;
}

ssize_t Audit_unix_socket_handler::write(const char *data, size_t size)
{
	if (m_fd < 0)
	{
#if PG_VERSION_NUM >= 120000
		ereport(WARNING, (errcode(ERRCODE_IO_ERROR),
				errmsg(
				"%s pid %d: socket fd invalid (%d)",
				AUDIT_ERROR_PREFIX, getpid(), m_fd)));
#else
		AUDIT_DEBUG_LOG("pid %d: socket fd invalid (%d)",
			 getpid(), m_fd);
#endif
		errno = EBADF;
		return -1;
	}

	ssize_t res = ::write(m_fd, data, size);
	if (res < 0) // log the error
	{
#if PG_VERSION_NUM >= 120000
		const char *error_string = strerror(errno);
		ereport(WARNING, (errcode(ERRCODE_IO_ERROR),
				errmsg(
				"%s pid %d: failed writing to socket: %s. Err: %s",
				AUDIT_ERROR_PREFIX, getpid(), m_io_dest, error_string)));
#else
		AUDIT_ERROR_LOG("pid %d: failed writing to socket: %s. Err: %s",
				getpid(), m_io_dest, strerror(errno));
#endif
		return -1;
	}
	return res;
}

int Audit_unix_socket_handler::open(const char *io_dest, bool log_errors)
{
	// ensure initialized to invalid
	m_fd = -1;

	// open the socket
	int sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0)
	{
		if (log_errors)
		{
#if PG_VERSION_NUM >= 120000
			const char *error_string = strerror(errno);
			ereport(WARNING, (errcode(ERRCODE_IO_ERROR),
					errmsg(
					"%s unable to create unix socket: %s.",
					AUDIT_ERROR_PREFIX, error_string)));
#else
			AUDIT_ERROR_LOG("unable to create unix socket: %s.",
					strerror(errno));
#endif
		}
		return -1;
	}

	// setup socket address structure
	struct sockaddr_un UNIXaddr;
	UNIXaddr.sun_family = AF_UNIX;
	strncpy(UNIXaddr.sun_path, io_dest, sizeof(UNIXaddr.sun_path) - 1);
	UNIXaddr.sun_path[strlen(io_dest)] = '\0';

	// connect the socket
	if (connect(sock, (struct sockaddr *) & UNIXaddr, sizeof(UNIXaddr)) < 0)
	{
		if (log_errors)
		{
#if PG_VERSION_NUM >= 120000
			const char *error_string = strerror(errno);
			ereport(WARNING, (errcode(ERRCODE_IO_ERROR),
					errmsg(
					"%s unable to connect to socket: %s. err: %s.",
					AUDIT_ERROR_PREFIX, m_io_dest, error_string)));
#else
			AUDIT_ERROR_LOG(
				"unable to connect to socket: %s. err: %s.",
				 m_io_dest, strerror(errno));
#endif
		}
		this->close();
		::close(sock);
		return -2;
	}
	m_fd = sock;	// save the file descriptor
	return 0;
}

bool Audit_unix_socket_handler::handler_log_audit(AuditEventStackItem *pItem)
{
	return (m_formatter->event_format(& m_proc, pItem, this) >= 0);
}

//////////////////////// Audit Socket handler end ///////////////////////////////////////////


static yajl_gen_status yajl_add_string(yajl_gen hand, const char *str)
{
	return yajl_gen_string(hand, (const unsigned char *) str, strlen(str));
}

static void yajl_add_string_val(yajl_gen hand, const char *name, const char *val)
{
	if (0 == val)
	{
		return; // we don't add NULL values to json
	}
	yajl_add_string(hand, name);
	yajl_add_string(hand, val);
}

static void yajl_add_string_val(yajl_gen hand, const char *name, const char *val, size_t val_len)
{
	yajl_add_string(hand, name);
	yajl_gen_string(hand, (const unsigned char *) val, val_len);
}

static void yajl_add_uint64(yajl_gen gen, const char *name, uint64 num)
{
	const size_t max_int64_str_len = 21;
	char buf[max_int64_str_len];

	snprintf(buf, max_int64_str_len, "%llu", (long long unsigned) num);
	yajl_add_string_val(gen, name, buf);
}

static void yajl_add_obj(yajl_gen gen, const char *db, const char *ptype, const char *name = NULL)
{
	if (db)
	{
		yajl_add_string_val(gen, "db", db);
	}

	if (name)
	{
		yajl_add_string_val(gen, "name", name);
	}

	yajl_add_string_val(gen, "obj_type", ptype);
}

/* get the current time of day in milliseconds */

static inline uint64 get_current_time_in_ms()
{
	// time in microseconds
	struct timeval tv;
	gettimeofday(& tv, NULL);
	uint64 ts = tv.tv_sec; //first cast tv.tv_sec to uint64 to prevent overflow on 32bit machine
	ts *= 1000; 
	ts += tv.tv_usec / 1000;

	return ts;
}

ssize_t Audit_json_formatter::start_msg_format(IWriter *writer)
{
	if (! m_write_start_msg) // disabled
	{
		elog(LOG, "%d m_write_start_msg = false, returning early", getpid());
		return 0;
	}

	// initialize yajl
	yajl_gen gen = yajl_gen_alloc(NULL);
	yajl_gen_map_open(gen);
	yajl_add_string_val(gen, "msg-type", "header");

	// time in milliseconds
	uint64 ts = get_current_time_in_ms();
	yajl_add_uint64(gen, "date", ts);

	// plugin version info
	yajl_add_string_val(gen, "audit-version", POSTGRESQL_AUDIT_PLUGIN_VERSION "-" POSTGRESQL_AUDIT_PLUGIN_REVISION);
	yajl_add_string_val(gen, "audit-protocol-version", AUDIT_PROTOCOL_VERSION);

	// hostname running PostgreSQL
	char hostname[HOST_NAME_MAX];
	if (gethostname(hostname, sizeof hostname) < 0)
	{
		// this is accurate, if generic and uninformative
		strcpy(hostname, "localhost");
	}
	yajl_add_string_val(gen, "hostname", hostname);

	// server version, get from configuration variable
	const char *server_version = GetConfigOption("server_version", false, false);
	yajl_add_string_val(gen, "postgresql-version", server_version);

	// name of the binary. try to read it from /proc/<mypid>/exe.
	char binary_name[PATH_MAX + 1];
	char proc_name[100];
	memset(binary_name, 0, sizeof binary_name);
	sprintf(proc_name, "/proc/%d/exe", getpid());
	ssize_t count = readlink(proc_name, binary_name, sizeof(binary_name) - 1);
	if (count > 0)
	{
		binary_name[count] = '\0';
		yajl_add_string_val(gen, "postgresql-program", binary_name);
	}
	else
	{
		// use PostgreSQL's idea of the program name as a fallback
		yajl_add_string_val(gen, "postgresql-program", application_name);
	}

	yajl_add_string_val(gen, "postgresql-socket", Audit_utils::db_unix_socket_name());

	yajl_add_uint64(gen, "postgresql-port", PostPortNumber);
	ssize_t res = -2;

	yajl_gen_status stat = yajl_gen_map_close(gen); // close the object
	if (stat == yajl_gen_status_ok) // all is good write the buffer out
	{
		const unsigned char *text = NULL;
		size_t len = 0;
		yajl_gen_get_buf(gen, &text, &len);
		// print the json
		res = writer->write((const char *)text, len);
		if (res >= 0)
		{
			// TODO: use the msg_delimiter
			res = writer->write("\n", 1);
		}
	}
	yajl_gen_free(gen); // free the generator
	return res;
}

// This routine replaces clear text with the string in `replace', leaving the rest of the string intact.
//
// str			- pointer to start of original string
// str_len		- length thereof
// cleartext_start	- start of cleartext to replace
// cleartext_len	- length of cleartext
// replace		- \0 terminated string with replacement text
static const char *replace_in_string(
					const char *str, size_t str_len,
					size_t cleartext_start, size_t cleartext_len,
					const char *replace)
{
	size_t to_alloc = str_len + strlen(replace) + 1;
	char *new_str = (char *) palloc(to_alloc);
	memset(new_str, '\0', to_alloc);

	// point to text after clear text
	const char *trailing = str + cleartext_start + cleartext_len;
	// how much text after clear text to copy in
	size_t final_to_move = ((str + str_len) - trailing);

	char *pos = new_str;
	memcpy(pos, str, cleartext_start);	// copy front of string
	pos += cleartext_start;

	memcpy(pos, replace, strlen(replace));	// copy replacement text
	pos += strlen(replace);

	memcpy(pos, trailing, final_to_move);	// copy trailing part of string

	return new_str;
}

// Get the name of the object from a list cell. The cell can contain a list;
// this can happen in drop statements and maybe others.

static std::string get_name_from_cell(void *cell_ptr, bool useLastInList)
{
	std::string obj_name;
	Value *v = (Value *) cell_ptr;

	if (cell_ptr == NULL)	// shouldn't happen
	{
		return obj_name;
	}

	if (v->type == T_String) 
	{ 
		obj_name += v->val.str;
	} 
	else if (v->type == T_List
#if PG_VERSION_NUM >= 100001
			|| v->type == T_ObjectWithArgs
			|| v->type == T_TypeName
#endif
			)
	{
		ListCell *cell;
		List *list = (List *) cell_ptr;
#if PG_VERSION_NUM >= 100001
		if (v->type == T_ObjectWithArgs)
		{ /*DROP FUNCTION, DROP AGGREGATE */
			list = ((ObjectWithArgs *) cell_ptr)->objname;
		}
		else if (v->type == T_TypeName)
		{ /* DROP DOMAIN */
			list = ((TypeName *) cell_ptr)->names;
		}
#endif
		if (useLastInList)
		{
			ListCell *last = list_tail(list);
#if PG_VERSION_NUM >= 130000
			v = (Value *) last->ptr_value;
#else
			v = (Value *) last->data.ptr_value;
#endif
			obj_name += v->val.str;
		}
		else
		{
			foreach(cell, list)
			{
#if PG_VERSION_NUM >= 130000
				obj_name += get_name_from_cell(cell->ptr_value, false);	// recursive call
#else
				obj_name += get_name_from_cell(cell->data.ptr_value, false);	// recursive call
#endif

#if PG_VERSION_NUM >= 130000
				if (lnext(list, cell) != NULL)
#else
				if (lnext(cell) != NULL)
#endif
				{
					obj_name += ".";
				}
			}
		}
	}
	else if (v->type == T_RangeVar)
	{
		RangeVar *rv = (RangeVar *) cell_ptr;
		char *full_name = getFullObjectName(rv);

		if (full_name != NULL)
		{
			obj_name += full_name;
			pfree(full_name);
		}
	}
#if PG_VERSION_NUM >= 90500
	else if (v->type == T_RoleSpec)
	{
		RoleSpec *rs = (RoleSpec *) cell_ptr;
		if (rs->roletype == ROLESPEC_CSTRING)
		{
			obj_name += rs->rolename;
		}
		else
		{
			obj_name += "[UNKNOWN]";	// shouldn't happen
		}
	}
#endif
	else	// also shouldn't happen
	{
		obj_name += "[UNKNOWN]";
	}

	return obj_name;
}

static const char *get_database_name()
{
	const char *db_name = MyProcPort->database_name;

	if (db_name == NULL || db_name[0] == '\0')
	{
		db_name = "[unknown]";
	}

	return db_name;
}

ssize_t Audit_json_formatter::event_format(const PostgreSQL_proc *proc, AuditEventStackItem *pItem, IWriter *writer)
{
	// initialize yajl
	yajl_gen gen = yajl_gen_alloc(NULL);
	yajl_gen_map_open(gen);
	yajl_add_string_val(gen, "msg-type", "activity");
	uint64 ts = get_current_time_in_ms();
	yajl_add_uint64(gen, "date", ts);

	yajl_add_uint64(gen, "thread-id", proc->pid);
	yajl_add_uint64(gen, "query-id", proc->query_id);

	yajl_add_string_val(gen, "user", proc->user);
	yajl_add_string_val(gen, "priv_user", proc->priv_user);
	yajl_add_string_val(gen, "host", proc->hostname);
	yajl_add_string_val(gen, "ip", proc->ip);

	yajl_add_string_val(gen, "os_user", proc->os_user);
	yajl_add_string_val(gen, "appname", proc->appname);

	const char *cmd = pItem->auditEvent.command;
	yajl_add_string_val(gen, "cmd", cmd);

	yajl_add_string(gen, "error_list");
	yajl_gen_array_open(gen);
	const ListCell* errorList = list_head(pItem->auditEvent.errorList);
	while (errorList) {
		const AuditError* error = (const AuditError*)lfirst(errorList);
		yajl_gen_map_open(gen);
		yajl_add_string_val(gen, "sqlstate", unpack_sql_state(error->sqlerrcode));  // unpack the alphanumeric SQLSTATE
		yajl_add_string_val(gen, "message", error->message);
		yajl_gen_map_close(gen);
#if PG_VERSION_NUM >= 130000
		errorList = lnext(pItem->auditEvent.errorList, errorList);
#else
		errorList = lnext(errorList);
#endif
	}
	yajl_gen_array_close(gen);

	const char *db_name = get_database_name();

	if (pItem->auditEvent.objectName != NULL)
	{
		yajl_add_string(gen, "objects");
		yajl_gen_array_open(gen);

		yajl_gen_map_open(gen);
		const char *obj_name = pItem->auditEvent.objectName;
		if (pItem->auditEvent.objectType == NULL)
		{
			yajl_add_obj (gen, db_name, "TABLE", obj_name );
		}
		else
		{
			const char *obj_type = pItem->auditEvent.objectType;
			yajl_add_obj (gen, db_name, obj_type, obj_name );
		}
		yajl_gen_map_close(gen);

		yajl_gen_array_close(gen);
	}
	else if (pItem->auditEvent.objectList != NULL)
	{
		yajl_add_string(gen, "objects");
		yajl_gen_array_open(gen);

		const char *obj_type = pItem->auditEvent.objectType;

		std::string obj_name;

		if (pItem->auditEvent.useLastInList && list_length(pItem->auditEvent.objectList) > 1)
		{
			ListCell *last = list_tail(pItem->auditEvent.objectList);
#if PG_VERSION_NUM >= 130000
			Value *v = (Value *) last->ptr_value;
#else
			Value *v = (Value *) last->data.ptr_value;
#endif
			obj_name = v->val.str;

			yajl_gen_map_open(gen);
			yajl_add_obj(gen, db_name, obj_type, obj_name.c_str());
			yajl_gen_map_close(gen);
		}
		else
		{
			ListCell *cell;
			foreach(cell, pItem->auditEvent.objectList)
			{
#if PG_VERSION_NUM >= 130000
				obj_name = get_name_from_cell(cell->ptr_value,
#else
				obj_name = get_name_from_cell(cell->data.ptr_value,
#endif
					pItem->auditEvent.useLastInList);

				yajl_gen_map_open(gen);
				yajl_add_obj(gen, db_name, obj_type, obj_name.c_str());
				yajl_gen_map_close(gen);
			}
		}

		yajl_gen_array_close(gen);
	}

	const char *query = pItem->auditEvent.commandText;
	size_t qlen = 0;
	if ( query )
	{
		qlen = strlen(query);
	}

	if (query && qlen > 0)
	{
		const char *query_text = query;
		size_t query_len = qlen;
		bool free_query_text = false;

		if (m_perform_password_masking
			&& m_password_mask_regex_compiled
			&& m_password_mask_regex_preg
			&& m_perform_password_masking(cmd))
		{
			// do password masking
			int matches[90] = { 0 };
			if (pcre_exec(m_password_mask_regex_preg, NULL, query_text, query_len, 0, 0, matches, array_elements(matches)) >= 0)
			{
				// search for the first substring that matches with the name psw
				char *first = NULL, *last = NULL;
				int entrysize = pcre_get_stringtable_entries(m_password_mask_regex_preg, "psw", &first, &last);
				if (entrysize > 0)
				{
					for (unsigned char *entry = (unsigned char *)first; entry <= (unsigned char *)last; entry += entrysize)
					{
						// first 2 bytes give us the number
						int n = (((int)(entry)[0]) << 8) | (entry)[1];
						if (n > 0 && n < (int)array_elements(matches) && matches[n*2] >= 0)
						{
							// We have a match.

							// Starting with MySQL 5.7, we cannot use the String::replace() function.
							// Doing so causes a crash in the string's destructor. It appears that the
							// interfaces in MySQL have changed fairly drastically. So we just do the
							// replacement ourselves.
							const char *pass_replace = "***";
							const char *updated = replace_in_string(
											query_text,
											query_len,
											matches[n*2],
											matches[(n*2) + 1] - matches[n*2],
											pass_replace);
							query_text = updated;
							query_len = strlen(query_text);
							free_query_text = true;	// came from palloc in replace_in_string
							break;
						}
					}
				}
			}
		}
		yajl_add_string_val(gen, "query", query_text, query_len);
		if (free_query_text)
		{
			pfree((void *) query_text);
		}
	}
	else
	{
		if (cmd != NULL && strlen(cmd) != 0)
		{
			yajl_add_string_val(gen, "query", cmd, strlen(cmd));
		}
		else
		{
			yajl_add_string_val(gen, "query", "n/a", strlen("n/a"));
		}
	}

	ssize_t res = -2;
	yajl_gen_status stat = yajl_gen_map_close(gen); // close the object
	if (stat == yajl_gen_status_ok) // all is good write the buffer out
	{
		const unsigned char *text = NULL;
		size_t len = 0;
		yajl_gen_get_buf(gen, &text, &len);
		// print the json
		res = writer->write((const char *)text, len);
		if (res >= 0)
		{
			// TODO: use the msg_delimiter
			res = writer->write("\n", 1);
		}
	}
	yajl_gen_free(gen); // free the generator
	return res;
}

// centralize YAJL handling
ssize_t Audit_json_formatter::command_format(const PostgreSQL_proc *proc, const char *command, const char *query, IWriter *writer)
{
	yajl_gen gen = yajl_gen_alloc(NULL);
	yajl_gen_map_open(gen);
	yajl_add_string_val(gen, "msg-type", "activity");
	uint64 ts = get_current_time_in_ms();
	yajl_add_uint64(gen, "date", ts);

	yajl_add_uint64(gen, "thread-id", proc->pid);
	yajl_add_uint64(gen, "query-id", proc->query_id);

	yajl_add_string_val(gen, "user", proc->user);
	yajl_add_string_val(gen, "priv_user", proc->priv_user);
	yajl_add_string_val(gen, "host", proc->hostname);
	yajl_add_string_val(gen, "ip", proc->ip);

	yajl_add_string_val(gen, "os_user", proc->os_user);
	yajl_add_string_val(gen, "appname", proc->appname);

	yajl_add_string_val(gen, "cmd", command);
	yajl_add_string_val(gen, "query", query);

	yajl_add_string(gen, "error_list");
	yajl_gen_array_open(gen);
	for (size_t i = 0; i < proc->error_list.size(); i++) {
		const ProcError& error = proc->error_list[i];
		yajl_gen_map_open(gen);
		yajl_add_string_val(gen, "sqlstate", unpack_sql_state(error.sqlerrcode));  // unpack the alphanumeric SQLSTATE
		yajl_add_string_val(gen, "message", error.message.c_str());
		yajl_gen_map_close(gen);
	}
	yajl_gen_array_close(gen);

	ssize_t res = -2;
	yajl_gen_status stat = yajl_gen_map_close(gen); // close the object
	if (stat == yajl_gen_status_ok) // all is good write the buffer out
	{
		const unsigned char *text = NULL;
		size_t len = 0;
		yajl_gen_get_buf(gen, &text, &len);
		// print the json
		res = writer->write((const char *)text, len);
		if (res >= 0)
		{
			// TODO: use the msg_delimiter
			res = writer->write("\n", 1);
		}
	}
	yajl_gen_free(gen); // free the generator
	return res;
}

pcre *Audit_json_formatter::regex_compile(const char *str)
{
	const char *error;
	int erroffset;
	static const int regex_flags =
		PCRE_DOTALL | PCRE_UTF8 | PCRE_CASELESS | PCRE_DUPNAMES;

	pcre *re = pcre_compile(str, regex_flags, &error, &erroffset, NULL);
	if (re == NULL)
	{
		AUDIT_DEBUG_LOG("unable to compile regex [%s]. offset: %d message: [%s].",
				str, erroffset, error);
	}
	return re;
}

bool Audit_json_formatter::compile_password_masking_regex(const char *str)
{
	// first free existing
	if (m_password_mask_regex_compiled)
	{
		m_password_mask_regex_compiled = false;
		// small sleep to let threads complete regexec
		usleep(10 * 1000);	// 10,000 microseconds
		pcre_free(m_password_mask_regex_preg);
	}

	bool success = false; // default is error (case of empty string)
	if (NULL != str && str[0] != '\0')
	{
		m_password_mask_regex_preg = regex_compile(str);
		if (m_password_mask_regex_preg)
		{
			m_password_mask_regex_compiled = true;
			success = true;
		}
	}
	return success;
}

const char *Audit_utils::db_unix_socket_name()
{
	// get path to PostgreSQL Unix domain socket
#define SOCKPATH_TEMPLATE "%s/.s.PGSQL.%d"
	bool got_it = false;
	static char buf[BUFSIZ];

	/*
	 * in case 'unix_socket_directories' (v9.3.0 and up) or 'unix_socket_directory' (before v9.3.0)
	 * configuration parameter is missing or empty,
	 * use the default location directory (/tmp directory)
	 */
	const char *unix_socket_directories = GetConfigOption("unix_socket_directories", true, false);

	if (unix_socket_directories != NULL)
	{
		// have to split it apart and find one, see similar code in PostmasterMain
		char	   *rawstring;
		List	   *elemlist;
		ListCell   *l;
		char buf[BUFSIZ];

		/* Need a modifiable copy of Unix_socket_directories */
		rawstring = pstrdup(unix_socket_directories);

		/* Parse string into list of directories */
		if (SplitDirectoriesString(rawstring, ',', &elemlist))
		{
			foreach(l, elemlist)
			{
				char *socketdir = (char *) lfirst(l);
				sprintf(buf, SOCKPATH_TEMPLATE, socketdir, PostPortNumber);
				struct stat statbuf;
				if (::stat(buf, & statbuf) == 0)
				{
					got_it = true;
					break;
				}
			}
		}
		pfree(rawstring);
		list_free_deep(elemlist);
	}

	if (! got_it)
	{
		// go for a default value
		sprintf(buf, SOCKPATH_TEMPLATE, "/tmp", PostPortNumber);
	}

	return buf;
}

static void replace_char(char *str, const char tofind, const char rplc)
{
	size_t n = 0;
	if (str)
	{
		n = strlen(str);
	}

	for (size_t i = 0; i< n; i++)
	{
		if (tofind == str[i])
		{
			str[i] = rplc;
		}
	}
}


const char *Audit_utils::plugin_socket_name()
{
	static char name_buff[BUFSIZ];

#define SOCKET_PARENT_DIRECTORY "/var/run/db-audit"
	const char *name_prefix = SOCKET_PARENT_DIRECTORY "/postgresql.audit_";

	// collect the parts
	char cwd_buff[BUFSIZ] = {0};
	getcwd(cwd_buff, array_elements(cwd_buff) - 1);

	size_t len = strlen(cwd_buff);
	if (cwd_buff[len-1] != '/')	// add it
	{
		cwd_buff[len++] = '/';
		cwd_buff[len++] = '\0';
	}

	char port_number[100];
	const char *db_sock = db_unix_socket_name();

	if (PostPortNumber > 0)
	{
		sprintf(port_number, "%u", PostPortNumber);
		db_sock = port_number;
	}

	len = strlen(name_prefix) + strlen(cwd_buff) + strlen(db_sock) + 1;
	if (len < sizeof(name_buff))
	{
		sprintf(name_buff, "%s%s%s", name_prefix, cwd_buff, db_sock);
	}
	else
	{
		AUDIT_ERROR_LOG("name_buff not big enough to set default name (have %lu bytes, need %lu).",
				(unsigned long)sizeof(name_buff), (unsigned long)len);
	}
		
	// replace / with _ in filename part of the full name
	replace_char(name_buff + strlen(name_prefix), '/', '_');

	return name_buff;
}
