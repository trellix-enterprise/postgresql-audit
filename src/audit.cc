/*
 * Intel Security Auditing Plugin for PostgreSQL.
 *
 * Copyright (C) 2016, Intel, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it under the terms of the GNU 
 * General Public License as published by the Free Software Foundation; version 2 of the License.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; 
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
 * See the GNU General Public License for more details.
 * 
 * See COPYING file for a copy of the GPL Version 2 license.
 *
 * Liberal use made of code from pgaudit plugin:
 * git://github.com/pgaudit/pgaudit
 *
 * Similarly liberal use made of code from McAfee mysql_audit plugin:
 * git://github.com/mcafee/mysql-audit
 *
 *------------------------------------------------------------------------------
 * pgaudit.c
 *
 * An audit logging extension for PostgreSQL. Provides detailed logging classes,
 * object level logging, and fully-qualified object names for all DML and DDL
 * statements where possible (See pgaudit.sgml for details).
 *
 * Copyright (c) 2014-2015, PostgreSQL Global Development Group
 *
 *------------------------------------------------------------------------------
 */

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>

/* PostgreSQL includes */
#include "pgsql_inc.h"

/* Some compatibility defines */
#include "sql_print.h"

// This includes most of the common headers
#include "audit_handler.h"

/* macro definitions */

#ifdef __GNUC__
#define SUPPRESS_NOT_USED_WARN __attribute__ ((unused))
#else
#define SUPPRESS_NOT_USED_WARN
#endif

/* forward declarations */

extern "C" {

PG_MODULE_MAGIC;

void _PG_init(void);
};

#if PG_VERSION_NUM >= 130000
static const char *commandTagToString(enum CommandTag cmdTag);
#else
static const char *commandTagToString(const char *cmdTag);
#endif

// Various variables
static PostgreSQL_proc g_proc;

// Possible audit handlers
static Audit_file_handler json_file_handler(g_proc);
static Audit_unix_socket_handler json_unix_socket_handler(g_proc);

// formatters
static Audit_json_formatter json_formatter;

// GUC Variables

// GUC variable for audit.json_file - true / false
bool json_file_handler_enable = true;

// GUC variable for audit.json_file_name
// char *json_file_name = NULL;
#define DEFAULT_JSON_FILENAME	"audit.json"

// GUC variable for audit.json_unix_socket - true / false
bool json_unix_socket_handler_enable = false;

// GUC variable for audit.json_unix_socket_name
char *dummy_json_unix_socket_name = NULL;

// GUC variable for audit.json_file_flush
bool json_file_handler_flush = false;

// GUC variable to enable/disable audit debug logs
bool audit_logging = false;

// plugin and protocol versions
static char audit_version[] = POSTGRESQL_AUDIT_PLUGIN_VERSION "-" POSTGRESQL_AUDIT_PLUGIN_REVISION;
static char *audit_version_ptr = audit_version;	// for CreateCustomStringVariable
static char audit_protocol_version[] = AUDIT_PROTOCOL_VERSION;
static char *audit_protocol_version_ptr = audit_version;	// for CreateCustomStringVariable


// regex stuff
static char *password_masking_regex = NULL;

#define _COMMENT_SPACE_ "(?:/\\*.*?\\*/|\\s)*?"
#define _QUOTED_PSW_ "[\'|\"](?<psw>.*?)(?<!\\\\)[\'|\"]"

// PostgreSQL looks pretty simple.
static const char default_pw_masking_regex[] = "password" _COMMENT_SPACE_ _QUOTED_PSW_ ;

// Functions used in configurating GUC varibles

/* check_json_file_name --- check that new value passed for json_file_name is valid */

extern "C" bool
check_json_file_name(char **newVal, void **extra, GucSource unused)
{
	char *newPath = NULL;

	if (*newVal == NULL)
	{
		return false;
	}

	newPath = strdup(*newVal);
	if (newPath != NULL)
	{
		*extra = newPath;
		return true;
	}

	return false;
}

/* check_json_unix_socket_name --- check that new value passed for json_unix_socket_name is valid */

extern "C" bool
check_json_unix_socket_name(char **newVal, void **extra, GucSource unused)
{
	char *newPath = NULL;

	if (newVal == NULL || *newVal == NULL)
	{
		return false;
	}

	newPath = strdup(*newVal);
	if (newPath != NULL)
	{
		*extra = newPath;
		return true;
	}

	return false;
}

/* assign_json_file_flush --- assign a new value to json_file_flush */

extern "C" void
assign_json_file_flush(bool newVal, void *extra)
{
	// always set to false. as we just flush if set to true and leave at 0
	json_file_handler_flush = false;
	// bool val = *(bool *) extra ? true : false;
	bool val = newVal;
	if (val && json_file_handler.is_init())
	{
		json_file_handler.flush();
	}
}

/* check_audit_version --- check that new value passed for audit_version is valid */

extern "C" bool
check_audit_version(char **newVal, void **extra, GucSource unused)
{
	return (strcmp(*newVal, audit_version) == 0);
}

/* check_audit_protocol_version --- check that new value passed for audit_protocol_version is valid */

extern "C" bool
check_audit_protocol_version(char **newVal, void **extra, GucSource unused)
{
	return (strcmp(*newVal, audit_protocol_version) == 0);
}

/* check_password_masking_regex --- check that new value passed for password_masking_regex is valid */

extern "C" bool
check_password_masking_regex(char **newVal, void **extra, GucSource unused)
{
	if (newVal == NULL || *newVal == NULL)
	{
		return false;
	}

	bool res = false;
	char *str_val = NULL;

	str_val = (char *) strdup(*newVal);
	if (str_val != NULL)
	{
		res = json_formatter.compile_password_masking_regex(str_val);
		if (! res)
		{
			free((void *) str_val);
			str_val = (char *) malloc(strlen(default_pw_masking_regex) + 1);
			if (str_val != NULL)
			{
				strcpy(str_val, default_pw_masking_regex);
				*extra = (void *) str_val;
				res = true;
			}
		}
		else
		{
			// res is already true
			*extra = (void *) str_val;
		}
	}

	return res;
}

/* check_whitelist_cmds --- check commands */

extern "C" bool
check_whitelist_cmds(char **newVal, void **extra, GucSource unused)
{
	char *newList = NULL;

	if (newVal == NULL || *newVal == NULL)
	{
		return false;
	}

	newList = strdup(*newVal);
	*extra = newList;

	return true;
}

static char *whitelist_cmds_ptr = NULL; //Dummy ptr
char **whitelist_cmds_array = NULL;
int whitelist_cmds_count = 0;

/* assign_white_list_cmds --- update the list of commands */

extern "C" void
assign_whitelist_cmds(const char *newVal, void *extra)
{
	AUDIT_DEBUG_LOG("assign_whitelist_cmds");

	if (newVal == NULL)
	{
		return;
	}

	if (whitelist_cmds_ptr)
	{
		free(whitelist_cmds_ptr);
		whitelist_cmds_ptr = NULL;
	}

	int newCount = 1;
	for (const char *cp = newVal; *cp != '\0'; cp++)
	{
		if (*cp == ',')
		{
			newCount++;
		}
	}

	if (newCount > whitelist_cmds_count)
	{
		if (whitelist_cmds_array)
		{
			free(whitelist_cmds_array);
			whitelist_cmds_array = NULL;
		}

		whitelist_cmds_array = (char **) malloc(newCount * sizeof(char *));
		if (whitelist_cmds_array != NULL)
		{
			whitelist_cmds_count = newCount;
		}
		else
		{
			whitelist_cmds_count = 0;
		}
	}

	if (whitelist_cmds_count > 0)
	{
		int i = 0;

		whitelist_cmds_array[i] = strdup(newVal);
		if (whitelist_cmds_array[i] != NULL)
		{
			for (char *cp = (char *) whitelist_cmds_array[0]; *cp != '\0'; cp++)
			{
				if (*cp == ',')
				{
					whitelist_cmds_array[++i] = cp + 1;
					*cp = '\0';
				}
			}
		}
		else
		{
			free(whitelist_cmds_array);
			whitelist_cmds_array = NULL;
			whitelist_cmds_count = 0;
		}
	}
}

/* check_do_password_masking --- check if a command requires password masking */

static bool check_do_password_masking(const char *cmd)
{
	// FIXME: Eventually do this with a configuration variable
	// with a list of commands.
	return (strcmp(cmd, "CREATE ROLE") == 0
		|| strcmp(cmd, "ALTER ROLE") == 0);
}

////////////////////////// pgaudit code //////////////////////////////

/* Bits within auditLogBitmap, defines the classes we understand */
#define LOG_DDL         (1 << 0)    /* CREATE/DROP/ALTER objects */
#define LOG_FUNCTION    (1 << 1)    /* Functions and DO blocks */
#define LOG_MISC        (1 << 2)    /* Statements not covered */
#define LOG_READ        (1 << 3)    /* SELECTs */
#define LOG_ROLE        (1 << 4)    /* GRANT/REVOKE, CREATE/ALTER/DROP ROLE */
#define LOG_WRITE       (1 << 5)    /* INSERT, UPDATE, DELETE, TRUNCATE */
#if PG_VERSION_NUM >= 120000
#define LOG_MISC_SET    (1 << 6)    /* SET ... */
#endif

#define LOG_NONE        0               /* nothing */
#define LOG_ALL         (0xFFFFFFFF)    /* All */
/*
 * String constants for log classes - used when processing tokens in the
 * pgaudit.log GUC.
 */
#define CLASS_DDL       "DDL"
#define CLASS_FUNCTION  "FUNCTION"
#define CLASS_MISC      "MISC"
#if PG_VERSION_NUM >= 120000
#define CLASS_MISC_SET  "MISC_SET"
#endif
#define CLASS_READ      "READ"
#define CLASS_ROLE      "ROLE"
#define CLASS_WRITE     "WRITE"

#define CLASS_NONE      "NONE"
#define CLASS_ALL       "ALL"

/*
 * Object type, used for SELECT/DML statements and function calls.
 *
 * For relation objects, this is essentially relkind (though we do not have
 * access to a function which will just return a string given a relkind;
 * getRelationTypeDescription() comes close but is not public currently).
 *
 * We also handle functions, so it isn't quite as simple as just relkind.
 *
 * This should be kept consistent with what is returned from
 * pg_event_trigger_ddl_commands(), as that's what we use for DDL.
 */
#define OBJECT_TYPE_TABLE           "TABLE"
#define OBJECT_TYPE_INDEX           "INDEX"
#define OBJECT_TYPE_SEQUENCE        "SEQUENCE"
#define OBJECT_TYPE_TOASTVALUE      "TOAST TABLE"
#define OBJECT_TYPE_VIEW            "VIEW"
#define OBJECT_TYPE_MATVIEW         "MATERIALIZED VIEW"
#define OBJECT_TYPE_COMPOSITE_TYPE  "COMPOSITE TYPE"
#define OBJECT_TYPE_FOREIGN_TABLE   "FOREIGN TABLE"
#define OBJECT_TYPE_FUNCTION        "FUNCTION"

#define OBJECT_TYPE_UNKNOWN         "UNKNOWN"

/*
 * Command, used for SELECT/DML and function calls.
 *
 * We hook into the executor, but we do not have access to the parsetree there.
 * Therefore we can't simply call CreateCommandTag() to get the command and have
 * to build it ourselves based on what information we do have.
 *
 * These should be updated if new commands are added to what the exectuor
 * currently handles.  Note that most of the interesting commands do not go
 * through the executor but rather ProcessUtility, where we have the parsetree.
 */
#define COMMAND_SELECT      "SELECT"
#define COMMAND_INSERT      "INSERT"
#define COMMAND_UPDATE      "UPDATE"
#define COMMAND_DELETE      "DELETE"
#define COMMAND_EXECUTE     "EXECUTE"
#define COMMAND_UNKNOWN     "UNKNOWN"

/*
 * String constants for testing role commands.  Rename and drop role statements
 * are assigned the nodeTag T_RenameStmt and T_DropStmt respectively.  This is
 * not very useful for classification, so we resort to comparing strings
 * against the result of CreateCommandTag(parsetree).
 */
#define COMMAND_ALTER_ROLE          "ALTER ROLE"
#define COMMAND_DROP_ROLE           "DROP ROLE"
#define COMMAND_GRANT               "GRANT"
#define COMMAND_REVOKE              "REVOKE"

/*
 * String constants used for redacting text after the password token in
 * CREATE/ALTER ROLE commands.
 */
#define TOKEN_PASSWORD             "password"
#define TOKEN_REDACTED             "<REDACTED>"

/*
 *  string constants for invalid statement syntax
 */
#define COMMAND_INVALID_SYNTAX		"INVALID_SYNTAX"

AuditEventStackItem *auditEventStack = NULL;

/*
 * pgAudit runs queries of its own when using the event trigger system.
 *
 * Track when we are running a query and don't log it.
 */
static bool internalStatement = false;

/*
 * Track running total for statements and substatements and whether or not
 * anything has been logged since the current statement began.
 */
static int64 statementTotal = 0;
static int64 substatementTotal = 0;
static int64 stackTotal = 0; //stack counter per statement
static int64 Counter = 0; // global counter, how many statements we audit

static bool statementLogged = false;

// Generate audit plugin version file, which enable by parsing its name to get version details
static char version_filename[256];
static pid_t postmaster_pid = 0;

/*
 * Stack functions
 *
 * Audit events can go down to multiple levels so a stack is maintained to keep
 * track of them.
 */

/*
 * From the original pgaudit plugin:
 *
 *	Respond to callbacks registered with MemoryContextRegisterResetCallback().
 *	Removes the event(s) off the stack that have become obsolete once the
 *	MemoryContext has been freed.  The callback should always be freeing the top
 *	of the stack, but the code is tolerant of out-of-order callbacks.
 *
 * Essentially, stack_pop() does the actual memory management. In PostgreSQL 9.5 and later,
 * this routine is called automatically as a callback. In earlier versions we do it manually.
 * This routine primarily manages the auxiliary variables `internalStatement',
 * `substatementTotal' and `statementLogged'.
 */
static void
stack_free(void *stackFree)
{
	AUDIT_DEBUG_LOG("stack_free");

	AuditEventStackItem *nextItem = auditEventStack;

	/* Only process if the stack contains items */
	while (nextItem != NULL)
	{
		AUDIT_DEBUG_LOG("stack not empty");

		/* Check if this item matches the item to be freed */
		if (nextItem == (AuditEventStackItem *) stackFree)
		{
			AUDIT_DEBUG_LOG("found requested freed item in stack, id: [%zd]", nextItem->stackId);

			--stackTotal;

			AUDIT_DEBUG_LOG("stackTotal: [%zd]", stackTotal);

			/* Move top of stack to the item after the freed item */
			auditEventStack = nextItem->next;

			/* If the stack is empty */
			if (auditEventStack == NULL)
			{
				AUDIT_DEBUG_LOG("reset internal state variables");

				/*
				 * Reset internal statement to false.  Normally this will be
				 * reset but in case of an error it might be left set.
				 */
				internalStatement = false;

				/*
				 * Reset sub statement total so the next statement will start
				 * from 1.
				 */
				substatementTotal = 0;

				/*
				 * Reset statement logged so that next statement will be
				 * logged.
				 */
				statementLogged = false;
			}
			AUDIT_DEBUG_LOG("stack_free done");
			return;
		}

		nextItem = nextItem->next;
	}

	AUDIT_DEBUG_LOG("stack_free done");
}

/*
 * Push a new audit event onto the stack and create a new memory context to
 * store it.
 */
static AuditEventStackItem *
stack_push()
{
	AUDIT_DEBUG_LOG("stack_push");

	MemoryContext contextAudit;
	MemoryContext contextOld;
	AuditEventStackItem *stackItem;

	/*
	 * Create a new memory context to contain the stack item.  This will be
	 * free'd on stack_pop, or by our callback when the parent context is
	 * destroyed.
	 */
	contextAudit = AllocSetContextCreate(CurrentMemoryContext,
			"pgaudit stack context",
#if PG_VERSION_NUM >= 110000
			ALLOCSET_DEFAULT_SIZES);
#else
			ALLOCSET_DEFAULT_MINSIZE,
			ALLOCSET_DEFAULT_INITSIZE,
			ALLOCSET_DEFAULT_MAXSIZE);
#endif

	if (contextAudit == NULL)
	{
		AUDIT_DEBUG_LOG("contextAudit is NULL, is this top-level context?");
	}

	/* Save the old context to switch back to at the end */
	contextOld = MemoryContextSwitchTo(contextAudit);

	/* Create our new stack item in our context */
	stackItem = (AuditEventStackItem *) palloc0(sizeof(AuditEventStackItem));
	stackItem->contextAudit = contextAudit;
	stackItem->stackId = ++stackTotal;
	++Counter;
	AUDIT_DEBUG_LOG("generated stack item Id: %zd, counter: [%zd]", stackItem->stackId, Counter);

#if PG_VERSION_NUM >= 90500
	/*
	 * Setup a callback in case an error happens.  stack_free() will truncate
	 * the stack at this item.
	 */
	stackItem->contextCallback.func = stack_free;
	stackItem->contextCallback.arg = (void *) stackItem;
	MemoryContextRegisterResetCallback(contextAudit,
			&stackItem->contextCallback);
#endif

	/* Push new item onto the stack */
	if (auditEventStack != NULL)
	{
		stackItem->next = auditEventStack;
	}
	else
	{
		AUDIT_DEBUG_LOG("first stackItem in stack");
		stackItem->next = NULL;
	}

	auditEventStack = stackItem;

	MemoryContextSwitchTo(contextOld);

	return stackItem;
}

/*
 * Pop an audit event from the stack by deleting the memory context that
 * contains it.  The callback to stack_free() does the actual pop.
 */
static void
stack_pop(int64 stackId)
{
	AUDIT_DEBUG_LOG("stack_pop, stackId: %zd", stackId);

	/* Make sure what we want to delete is at the top of the stack */
	if (auditEventStack != NULL && auditEventStack->stackId == stackId)
	{
		MemoryContextDelete(auditEventStack->contextAudit);
	}
	else
	{
		// not using log level WARNING directly, so log message will not be presented to client but only to server log
		AUDIT_DEBUG_LOG("WARNING: audit stack item " INT64_FORMAT " not found on top - cannot pop",
				stackId);
	}
}

/*
 * Check that an item is on the stack.  If not, an error will be raised since
 * this is a bad state to be in and it might mean audit records are being lost.
 */
static void
stack_valid(int64 stackId)
{
	AUDIT_DEBUG_LOG("stack_valid, stackId: %zd", stackId);

	AuditEventStackItem *nextItem = auditEventStack;

	/* Look through the stack for the stack entry */
	while (nextItem != NULL && nextItem->stackId != stackId)
	{
		nextItem = nextItem->next;
	}

	/* If we didn't find it, something went wrong. */
	if (nextItem == NULL)
	{
		// not using log level WARNING directly, so log message will not be presented to client but only to server log
		AUDIT_DEBUG_LOG("WARNING: audit stack item " INT64_FORMAT
				" not found - top of stack is " INT64_FORMAT "",
				stackId,
				auditEventStack == NULL ? (int64) -1 : auditEventStack->stackId);
	}
}

/*
 * Appends a properly quoted CSV field to StringInfo.
 */
static void
append_valid_csv(StringInfoData *buffer, const char *appendStr)
{
	AUDIT_DEBUG_LOG("append_valid_csv");

	const char *pChar;

	/*
	 * If the append string is null then do nothing.  NULL fields are not
	 * quoted in CSV.
	 */
	if (appendStr == NULL)
	{
		return;
	}

	/* Only format for CSV if appendStr contains: ", comma, \n, \r */
	if (strstr(appendStr, ",") || strstr(appendStr, "\"") ||
			strstr(appendStr, "\n") || strstr(appendStr, "\r"))
	{
		appendStringInfoCharMacro(buffer, '"');

		for (pChar = appendStr; *pChar; pChar++)
		{
			if (*pChar == '"')    /* double single quotes */
			{
				appendStringInfoCharMacro(buffer, *pChar);
			}

			appendStringInfoCharMacro(buffer, *pChar);
		}

		appendStringInfoCharMacro(buffer, '"');
	}
	/* Else just append */
	else
	{
		appendStringInfoString(buffer, appendStr);
	}
}

/*
 * Takes an AuditEvent, classifies it, then logs it if appropriate.
 *
 * Logging is decided based on if the statement is in one of the classes being
 * logged or if an object used has been marked for auditing.
 *
 * Objects are marked for auditing by the auditor role being granted access
 * to the object.  The kind of access (INSERT, UPDATE, etc) is also considered
 * and logging is only performed when the kind of access matches the granted
 * right on the object.
 *
 * This will need to be updated if new kinds of GRANTs are added.
 */
static void
log_audit_event(AuditEventStackItem *stackItem)
{
	AUDIT_DEBUG_LOG("log_audit_event");

	/* By default, put everything in the MISC class. */
	const char *className = CLASS_MISC;
	MemoryContext contextOld;
	StringInfoData auditStr;

	/* If this event has already been logged don't log it again */
	if (stackItem->auditEvent.logged)
	{
		return;
	}

	/* Classify the statement using log stmt level and the command tag */
	switch (stackItem->auditEvent.logStmtLevel)
	{
		/* All mods go in WRITE class, except EXECUTE */
	case LOGSTMT_MOD:
		className = CLASS_WRITE;

		switch (stackItem->auditEvent.commandTag)
		{
			/* Currently, only EXECUTE is different */
		case T_ExecuteStmt:
			className = CLASS_MISC;
			break;
		default:
			break;
		}
		break;

		/* These are DDL, unless they are ROLE */
	case LOGSTMT_DDL:
		className = CLASS_DDL;

		/* Identify role statements */
		switch (stackItem->auditEvent.commandTag)
		{
		case T_CreateRoleStmt:
		case T_AlterRoleStmt:

			/* Classify role statements */
		case T_GrantStmt:
		case T_GrantRoleStmt:
		case T_DropRoleStmt:
		case T_AlterRoleSetStmt:
		case T_AlterDefaultPrivilegesStmt:
			className = CLASS_ROLE;
			break;

			/*
			 * Rename and Drop are general and therefore we have to do
			 * an additional check against the command string to see
			 * if they are role or regular DDL.
			 */
		case T_RenameStmt:
		case T_DropStmt:
			if (pg_strcasecmp(stackItem->auditEvent.command,
						COMMAND_ALTER_ROLE) == 0 ||
					pg_strcasecmp(stackItem->auditEvent.command,
						COMMAND_DROP_ROLE) == 0)
			{
				className = CLASS_ROLE;
			}
			break;

		default:
			break;
		}
		break;

		/* Classify the rest */
	case LOGSTMT_ALL:
		switch (stackItem->auditEvent.commandTag)
		{
			/* READ statements */
		case T_CopyStmt:
		case T_SelectStmt:
		case T_PrepareStmt:
		case T_PlannedStmt:
			className = CLASS_READ;
			break;

			/* FUNCTION statements */
		case T_DoStmt:
			className = CLASS_FUNCTION;
			break;

#if PG_VERSION_NUM >= 120000
			/*
			 * SET statements reported as MISC but filtered by MISC_SET
			 * flags to maintain existing functionality.
			 */
		case T_VariableSetStmt:
			className = CLASS_MISC;
			break;
#endif

		default:
			break;
		}
		break;

	case LOGSTMT_NONE:
		break;
	}

	stackItem->auditEvent.granted = true;	// always log...

	/*
	 * Use audit memory context in case something is not free'd while
	 * appending strings and parameters.
	 */
	contextOld = MemoryContextSwitchTo(stackItem->contextAudit);

	/* Set statement and substatement IDs */
	if (stackItem->auditEvent.statementId == 0)
	{
		/* If nothing has been logged yet then create a new statement Id */
		if (!statementLogged)
		{
			statementTotal++;
			statementLogged = true;
		}

		stackItem->auditEvent.statementId = statementTotal;
		stackItem->auditEvent.substatementId = ++substatementTotal;
	}

	/*
	 * Create the audit substring
	 *
	 * The type-of-audit-log and statement/substatement ID are handled below,
	 * this string is everything else.
	 */
	initStringInfo(&auditStr);
	append_valid_csv(&auditStr, stackItem->auditEvent.command);

	appendStringInfoCharMacro(&auditStr, ',');
	append_valid_csv(&auditStr, stackItem->auditEvent.objectType);

	appendStringInfoCharMacro(&auditStr, ',');
	append_valid_csv(&auditStr, stackItem->auditEvent.objectName ? stackItem->auditEvent.objectName : "<no-object-name>");

	/*
	 * If auditLogStatmentOnce is true, then only log the statement and
	 * parameters if they have not already been logged for this substatement.
	 */
	appendStringInfoCharMacro(&auditStr, ',');
	if (!stackItem->auditEvent.statementLogged)
	{
		append_valid_csv(&auditStr, stackItem->auditEvent.commandText);

		appendStringInfoCharMacro(&auditStr, ',');

		/* Handle parameter logging */

		int paramIdx;
		int numParams;
		StringInfoData paramStrResult;
		ParamListInfo paramList = stackItem->auditEvent.paramList;

		numParams = paramList == NULL ? 0 : paramList->numParams;

		/* Create the param substring */
		initStringInfo(&paramStrResult);

		/* Iterate through all params */
		for (paramIdx = 0; paramList != NULL && paramIdx < numParams;
				paramIdx++)
		{
			ParamExternData *prm = &paramList->params[paramIdx];
			Oid typeOutput;
			bool typeIsVarLena;
			char *paramStr;

			/* Add a comma for each param */
			if (paramIdx != 0)
			{
				appendStringInfoCharMacro(&paramStrResult, ',');
			}

			/* Skip if null or if oid is invalid */
			if (prm->isnull || !OidIsValid(prm->ptype))
			{
				continue;
			}

			/* Output the string */
			getTypeOutputInfo(prm->ptype, &typeOutput, &typeIsVarLena);
			paramStr = OidOutputFunctionCall(typeOutput, prm->value);

			append_valid_csv(&paramStrResult, paramStr);
			pfree(paramStr);
		}

		if (numParams == 0)
		{
			appendStringInfoString(&auditStr, "<none>");
		}
		else
		{
			append_valid_csv(&auditStr, paramStrResult.data);
		}

		stackItem->auditEvent.statementLogged = true;
	}
	else
	{
		/* we were asked to not log it */
		appendStringInfoString(&auditStr,
				"<previously logged>,<previously logged>");
	}

	// audit: set info, call our audit handler
	stackItem->auditEvent.className = className;

	// check for commands in the whitelist, skip them if found
	bool skip = false;
	if (whitelist_cmds_count > 0)
	{
		for (int i = 0; i < whitelist_cmds_count; i++)
		{
			if (whitelist_cmds_array == NULL || whitelist_cmds_array[i]  == NULL)
			{
				// not using log level WARNING directly, so log message will not be presented to client but only to server log
				AUDIT_DEBUG_LOG("WARNING: invalid whitelist_cmds_array, returning");
				return;
			}

			if (strcasecmp(stackItem->auditEvent.command, whitelist_cmds_array[i]) == 0)
			{
				skip = true;
				break;
			}
		}
	}

	// log data to file and/or socket
	if (! skip)
	{
		g_proc.query_id++;
		Audit_handler::log_audit_all(stackItem);
	}

	stackItem->auditEvent.logged = true;

	MemoryContextSwitchTo(contextOld);
}

/*
 * Check if the role or any inherited role has any permission in the mask.  The
 * public role is excluded from this check and superuser permissions are not
 * considered.
 */
static bool
audit_on_acl(Datum aclDatum,
             Oid auditOid,
             AclMode mask)
{
	AUDIT_DEBUG_LOG("audit_on_acl");

	bool result = false;
	Acl *acl;
	AclItem *aclItemData;
	int aclIndex;
	int aclTotal;

	/* Detoast column's ACL if necessary */
	acl = DatumGetAclP(aclDatum);

	/* Get the acl list and total number of items */
	aclTotal = ACL_NUM(acl);
	aclItemData = ACL_DAT(acl);

	/* Check privileges granted directly to auditOid */
	for (aclIndex = 0; aclIndex < aclTotal; aclIndex++)
	{
		AclItem *aclItem = &aclItemData[aclIndex];

		if (aclItem->ai_grantee == auditOid && (aclItem->ai_privs & mask) != 0)
		{
			result = true;
			break;
		}
	}

	/*
	 * Check privileges granted indirectly via role memberships. We do this in
	 * a separate pass to minimize expensive indirect membership tests.  In
	 * particular, it's worth testing whether a given ACL entry grants any
	 * privileges still of interest before we perform the has_privs_of_role
	 * test.
	 */
	if (!result)
	{
		for (aclIndex = 0; aclIndex < aclTotal; aclIndex++)
		{
			AclItem *aclItem = &aclItemData[aclIndex];

			/* Don't test public or auditOid (it has been tested already) */
			if (aclItem->ai_grantee == ACL_ID_PUBLIC ||
					aclItem->ai_grantee == auditOid)
				continue;

			/*
			 * Check that the role has the required privileges and that it is
			 * inherited by auditOid.
			 */
			if ((aclItem->ai_privs & mask) != 0 && has_privs_of_role(auditOid, aclItem->ai_grantee))
			{
				result = true;
				break;
			}
		}
	}

	/* if we have a detoasted copy, free it */
	if (acl && (Pointer) acl != DatumGetPointer(aclDatum))
	{
		pfree(acl);
	}

	return result;
}

/*
 * Check if a role has any of the permissions in the mask on a relation.
 */
SUPPRESS_NOT_USED_WARN static bool
audit_on_relation(Oid relOid,
                  Oid auditOid,
                  AclMode mask)
{
	AUDIT_DEBUG_LOG("audit_on_relation");

	bool result = false;
	HeapTuple tuple;
	Datum aclDatum;
	bool isNull;

	/* Get relation tuple from pg_class */
	tuple = SearchSysCache1(RELOID, ObjectIdGetDatum(relOid));
	if (!HeapTupleIsValid(tuple))
	{
		return false;
	}

	/* Get the relation's ACL */
	aclDatum = SysCacheGetAttr(RELOID, tuple, Anum_pg_class_relacl,
			&isNull);

	/* Only check if non-NULL, since NULL means no permissions */
	if (!isNull)
	{
		result = audit_on_acl(aclDatum, auditOid, mask);
	}

	/* Free the relation tuple */
	ReleaseSysCache(tuple);

	return result;
}

/*
 * Check if a role has any of the permissions in the mask on a column.
 */
SUPPRESS_NOT_USED_WARN static bool
audit_on_attribute(Oid relOid,
                   AttrNumber attNum,
                   Oid auditOid,
                   AclMode mask)
{
	AUDIT_DEBUG_LOG("audit_on_attribute");

	bool result = false;
	HeapTuple attTuple;
	Datum aclDatum;
	bool isNull;

	/* Get the attribute's ACL */
	attTuple = SearchSysCache2(ATTNUM,
			ObjectIdGetDatum(relOid),
			Int16GetDatum(attNum));
	if (!HeapTupleIsValid(attTuple))
	{
		return false;
	}

	/* Only consider attributes that have not been dropped */
	if (!((Form_pg_attribute) GETSTRUCT(attTuple))->attisdropped)
	{
		aclDatum = SysCacheGetAttr(ATTNUM, attTuple, Anum_pg_attribute_attacl,
				&isNull);

		if (!isNull)
		{
			result = audit_on_acl(aclDatum, auditOid, mask);
		}
	}

	/* Free attribute */
	ReleaseSysCache(attTuple);

	return result;
}

// initialize_event --- set up an event based on command type or condition
#define initialize_event(eventptr, level, tag, command_value) \
	eventptr->auditEvent.logStmtLevel = level; \
	eventptr->auditEvent.commandTag = tag; \
	eventptr->auditEvent.command = commandTagToString(command_value);

// Collect common event initialization into macros to keep things synchronized.
// Applies to log_select_dml() and to audit_ExecutorStart_hook().
#if PG_VERSION_NUM >= 130000
#define initialize_select_event(eventptr) initialize_event(eventptr, LOGSTMT_ALL, T_SelectStmt, CMDTAG_SELECT)
#define initialize_insert_event(eventptr) initialize_event(eventptr, LOGSTMT_MOD, T_InsertStmt, CMDTAG_INSERT)
#define initialize_update_event(eventptr) initialize_event(eventptr, LOGSTMT_MOD, T_UpdateStmt, CMDTAG_UPDATE)
#define initialize_delete_event(eventptr) initialize_event(eventptr, LOGSTMT_MOD, T_DeleteStmt, CMDTAG_DELETE)
#else
#define initialize_select_event(eventptr) initialize_event(eventptr, LOGSTMT_ALL, T_SelectStmt, COMMAND_SELECT)
#define initialize_insert_event(eventptr) initialize_event(eventptr, LOGSTMT_MOD, T_InsertStmt, COMMAND_INSERT)
#define initialize_update_event(eventptr) initialize_event(eventptr, LOGSTMT_MOD, T_UpdateStmt, COMMAND_UPDATE)
#define initialize_delete_event(eventptr) initialize_event(eventptr, LOGSTMT_MOD, T_DeleteStmt, COMMAND_DELETE)
#endif

/*
 * Create AuditEvents for SELECT/DML operations via executor permissions checks.
 */
static void
log_select_dml(Oid auditOid, List *rangeTabls)
{
	AUDIT_DEBUG_LOG("log_select_dml");

	if (auditEventStack == NULL)
	{
		// not using log level WARNING directly, so log message will not be presented to client but only to server log
		AUDIT_DEBUG_LOG("WARNING: auditEventStack is NULL, returning");
		return;
	}

	ListCell *lr;
	bool found = false;

	/* Do not log if this is an internal statement */
	if (internalStatement)
	{
		return;
	}

	foreach(lr, rangeTabls)
	{
		Oid relOid;
		Relation rel;
		RangeTblEntry *rte = (RangeTblEntry *) lfirst(lr);

		/* We only care about tables, and can ignore subqueries etc. */
		if (rte->rtekind != RTE_RELATION)
		{
			continue;
		}

		found = true;

		relOid = rte->relid;
		rel = relation_open(relOid, NoLock);

		/*
		 * Default is that this was not through a grant, to support session
		 * logging.  Will be updated below if a grant is found.
		 */
		auditEventStack->auditEvent.granted = false;

		/*
		 * We don't have access to the parsetree here, so we have to generate
		 * the node type, object type, and command tag by decoding
		 * rte->requiredPerms and rte->relkind.
		 */
		if (rte->requiredPerms & ACL_INSERT)
		{
			initialize_insert_event(auditEventStack);
		}
		else if (rte->requiredPerms & ACL_UPDATE)
		{
			initialize_update_event(auditEventStack);
		}
		else if (rte->requiredPerms & ACL_DELETE)
		{
			initialize_delete_event(auditEventStack);
		}
		else if (rte->requiredPerms & ACL_SELECT)
		{
			initialize_select_event(auditEventStack);
		}
		else
		{
			relation_close(rel, NoLock);
			continue;	// don't log from UNKNOWN
		}

		/* Use the relation type to assign object type */
		switch (rte->relkind)
		{
		case RELKIND_RELATION:
			auditEventStack->auditEvent.objectType = OBJECT_TYPE_TABLE;
			break;

		case RELKIND_INDEX:
#if PG_VERSION_NUM >= 110000
		case RELKIND_PARTITIONED_INDEX:
#endif
			auditEventStack->auditEvent.objectType = OBJECT_TYPE_INDEX;
			break;

		case RELKIND_SEQUENCE:
			auditEventStack->auditEvent.objectType = OBJECT_TYPE_SEQUENCE;
			break;

		case RELKIND_TOASTVALUE:
			auditEventStack->auditEvent.objectType = OBJECT_TYPE_TOASTVALUE;
			break;

		case RELKIND_VIEW:
			auditEventStack->auditEvent.objectType = OBJECT_TYPE_VIEW;
			break;

		case RELKIND_COMPOSITE_TYPE:
			auditEventStack->auditEvent.objectType = OBJECT_TYPE_COMPOSITE_TYPE;
			break;

		case RELKIND_FOREIGN_TABLE:
			auditEventStack->auditEvent.objectType = OBJECT_TYPE_FOREIGN_TABLE;
			break;

		case RELKIND_MATVIEW:
			auditEventStack->auditEvent.objectType = OBJECT_TYPE_MATVIEW;
			break;

		default:
			auditEventStack->auditEvent.objectType = OBJECT_TYPE_UNKNOWN;
			break;
		}

		/* Get a copy of the relation name and assign it to object name */
		auditEventStack->auditEvent.objectName =
			quote_qualified_identifier(get_namespace_name(
						RelationGetNamespace(rel)),
					RelationGetRelationName(rel));
		relation_close(rel, NoLock);

		// Original pgaudit code set this based on different conditions
		// We always log.
		auditEventStack->auditEvent.granted = true;

		/* Do relation level logging if a grant was found */
		if (auditEventStack->auditEvent.granted)
		{
			auditEventStack->auditEvent.logged = false;
			log_audit_event(auditEventStack);
		}

		pfree(auditEventStack->auditEvent.objectName);
		auditEventStack->auditEvent.objectName = NULL;
	}

	/*
	 * If no tables were found that means that RangeTbls was empty or all
	 * relations were in the system schema.  In that case still log a session
	 * record.
	 */
	if (!found)
	{
		auditEventStack->auditEvent.granted = false;
		auditEventStack->auditEvent.logged = false;

		log_audit_event(auditEventStack);
	}
}

/*
 * Create AuditEvents for non-catalog function execution, as detected by
 * log_object_access() below.
 */
static void
log_function_execute(Oid objectId)
{
	AUDIT_DEBUG_LOG("log_function_execute");

	HeapTuple proctup;
	Form_pg_proc proc;
	AuditEventStackItem *stackItem;

	/* Get info about the function. */
	proctup = SearchSysCache1(PROCOID, ObjectIdGetDatum(objectId));

	if (!proctup)
	{
		elog(ERROR, "cache lookup failed for function %u", objectId);
	}

	proc = (Form_pg_proc) GETSTRUCT(proctup);

	/*
	 * Logging execution of all pg_catalog functions would make the log
	 * unusably noisy.
	 */
#if PG_VERSION_NUM >= 120000
	if (IsCatalogNamespace(proc->pronamespace))
#else
	if (IsSystemNamespace(proc->pronamespace))
#endif
	{
		ReleaseSysCache(proctup);
		return;
	}

	/* Push audit event onto the stack */
	stackItem = stack_push();

	/* Generate the fully-qualified function name. */
	stackItem->auditEvent.objectName =
		quote_qualified_identifier(get_namespace_name(proc->pronamespace),
				NameStr(proc->proname));
	ReleaseSysCache(proctup);

	/* Log the function call */
	stackItem->auditEvent.logStmtLevel = LOGSTMT_ALL;
	stackItem->auditEvent.commandTag = T_DoStmt;
#if PG_VERSION_NUM >= 130000
	stackItem->auditEvent.command = commandTagToString(CMDTAG_EXECUTE);
#else
	stackItem->auditEvent.command = COMMAND_EXECUTE;
#endif
	stackItem->auditEvent.objectType = OBJECT_TYPE_FUNCTION;
	stackItem->auditEvent.commandText = stackItem->next->auditEvent.commandText;
	log_audit_event(stackItem);

	/* Pop audit event from the stack */
	stack_pop(stackItem->stackId);
#if PG_VERSION_NUM < 90500
	stack_free(stackItem);
#endif
}

/*
 * Hook functions
 */
static ExecutorCheckPerms_hook_type next_ExecutorCheckPerms_hook = NULL;
static ProcessUtility_hook_type next_ProcessUtility_hook = NULL;
static object_access_hook_type next_object_access_hook = NULL;
static ExecutorStart_hook_type next_ExecutorStart_hook = NULL;
SUPPRESS_NOT_USED_WARN static ExecutorEnd_hook_type next_ExecutorEnd_hook = NULL;
static ClientAuthentication_hook_type next_ClientAuthentication_hook = NULL;
static emit_log_hook_type next_emit_log_hook = NULL; // Bug #1136533, hook to capture invalid statement syntax

/*
 * Get IP address of remote end using getpeername.
 * From http://beej.us/guide/bgnet/output/html/multipage/getpeernameman.html
 *
 * C code from that site is in the public domain. See:
 * http://beej.us/guide/bgnet/output/html/multipage/intro.html#copyright
 */

static char *remoteIP(int s)
{
	AUDIT_DEBUG_LOG("remoteIP");

	// assume s is a connected socket

	socklen_t len;
	struct sockaddr_storage addr;
	static char ipstr[INET6_ADDRSTRLEN];

	len = sizeof addr;
	getpeername(s, (struct sockaddr*)&addr, &len);

	// deal with both IPv4 and IPv6:
	if (addr.ss_family == AF_INET)
	{
		struct sockaddr_in *s = (struct sockaddr_in *)&addr;
		inet_ntop(AF_INET, &s->sin_addr, ipstr, sizeof ipstr);
	}
	else if (addr.ss_family == AF_INET6)
	{
		// AF_INET6
		struct sockaddr_in6 *s = (struct sockaddr_in6 *)&addr;
		inet_ntop(AF_INET6, &s->sin6_addr, ipstr, sizeof ipstr);
	}
	else if (addr.ss_family == AF_UNIX)
	{
		strcpy(ipstr, "127.0.0.1");
	}

	return ipstr;
}

// Check if a string is an IP address. Allow for both IPv4 and IPv6.
// Let inet_pton do the heavy lifting.

static bool isIPAddress(const char *string)
{
	AUDIT_DEBUG_LOG("isIPAddress");

	struct in_addr v4addr;
	struct in6_addr v6addr;

	bool ret = false;
	if (strchr(string, ':') == NULL)
	{
		ret = (inet_pton(AF_INET, string, & v4addr) > 0);
	}
	else
	{
		ret = (inet_pton(AF_INET6, string, & v6addr) > 0);
	}

	return ret;
}

static void updateProc(PostgreSQL_proc *proc, Port *port)
{
	AUDIT_DEBUG_LOG("updateProc");

	if (strcmp(port->remote_host, "[local]") == 0
	    || strcmp(port->remote_host, "127.0.0.1") == 0)
	{
		proc->hostname = "localhost";
	}
	else
	{
		proc->hostname = port->remote_host;
	}

	if (port->remote_host != NULL && isIPAddress(port->remote_host))
	{
		proc->ip = port->remote_host;
	}
	else if (proc->ip[0] == '\0')
	{
		proc->ip = remoteIP(port->sock);
	}

	// appname from guc
	const char *guc_appname = NULL;
	ListCell* cell;
	foreach(cell, port->guc_options) {  // alternating list of option name and value

		// In Postgres, the macro lfirst() was used to mean "the data in this
		// cons cell". To avoid changing every usage of lfirst(), that meaning
		// has been kept. As a result, lfirst() takes a ListCell and returns
		// the data it contains.
		if (strcmp("application_name", (const char*)lfirst(cell))) {
			continue;
		}
		else
		{
#if PG_VERSION_NUM >= 130000
			guc_appname = (const char*)lfirst(lnext(port->guc_options, cell));
#else
			guc_appname = (const char*)lfirst(lnext(cell));
#endif
			break;
		}
	}
	
	if (guc_appname && guc_appname[0] != '\0')
		proc->appname = guc_appname;

	// os_user from SO_PEERCRED
	struct sockaddr_storage addr = {};
	socklen_t len = sizeof addr;
	if (getsockname(port->sock, (struct sockaddr*)&addr, &len) == -1) {
		AUDIT_DEBUG_LOG("updateProc: getsockname failed: %m");
		return;
	}

	if (addr.ss_family != AF_UNIX)
		return;

	struct ucred cred = {};
	socklen_t cred_len = sizeof cred;
	if (getsockopt(port->sock, SOL_SOCKET, SO_PEERCRED, &cred, &cred_len) == -1) {
		AUDIT_DEBUG_LOG("updateProc: getsockopt SO_PEERCRED failed: %m");
		return;
	}

	if (!cred.pid) {
		AUDIT_DEBUG_LOG("updateProc: cred.pid == 0");
		return;
	}

	static char buf[BUFSIZ];
	static struct passwd pwbuf;
	struct passwd* pwd = NULL;
	if (getpwuid_r(cred.uid, &pwbuf, buf, sizeof(buf), &pwd) || !pwd) {
		AUDIT_DEBUG_LOG("updateProc: getpwuid_r [%d] failed: %m", cred.uid);
		return;
	}

	proc->os_user = pwd->pw_name;

	if (proc->appname[0])
		return;

	// appname from SO_PEERCRED
	static char proc_buf[PATH_MAX+1];
	static char data[PATH_MAX+1];
	snprintf(proc_buf, sizeof(proc_buf) - 1, "/proc/%d/exe", cred.pid);
	if (readlink(proc_buf, data, sizeof(data) - 1) == -1) {
		AUDIT_DEBUG_LOG("updateProc: readlink[%s] failed: %m", proc_buf);
		return;
	}

	const char* appname = data;
	for (int i = 0; data[i]; i++)
		if (data[i] == '/')
			appname = &data[i];
	if (appname[1])
		proc->appname = &appname[1];
}

static bool initHandlers(Port *port, PostgreSQL_proc *proc)
{
	AUDIT_DEBUG_LOG("initHandlers");

	// store minimal information early in order to be able to log failed login message
	proc->pid = getpid();
	if (port)
	{
		proc->db_name = port->database_name;
		proc->user = port->user_name;
	}

	int res = json_file_handler.init(&json_formatter);
	if (res != 0)
	{
		// best guess at error code
		AUDIT_ERROR_LOG("unable to init json file handler. res: %d. Aborting.", res);
		return false;
	}

	res = json_unix_socket_handler.init(&json_formatter);
	if (res != 0)
	{
		AUDIT_ERROR_LOG("unable to init json socket handler. res: %d. Aborting.", res);
		return false;
	}

	return true;
}

/*
 * Hook ClientAuthentication in order to get connection / start of
 * session info.
 */

#define logval(x) (x != NULL && *x != '\0' ? x : "null or empty")

static void
audit_ClientAuthentication_hook(Port *port, int status)
{
	AUDIT_DEBUG_LOG("audit_ClientAuthentication_hook");

	if (! initHandlers(port, &g_proc))
	{
		AUDIT_ERROR_LOG("initHandlers failed");
	}

	// call forward since we need the info in port.
	// it might not return...
	if (next_ClientAuthentication_hook)
	{
		(*next_ClientAuthentication_hook)(port, status);
	}

	updateProc(&g_proc, port);

	// Audit_handler::m_audit_handler_list elements were already inited by _PG_init, we don't need to redo that.

	// Enable handlers according to what we have in *file_handler_enable
	// (this is set accordingly by GUC functionality)
	// if the handler is enabled, it will generate a header message
	//
	// IMPORTANT: Do this here, on a per connection basis. If we enable
	// the handlers in _PG_init we get a header message for every process
	// forked, not just those serving clients, which is not at all what we want.
	json_file_handler.set_enable(json_file_handler_enable);
	json_unix_socket_handler.set_enable(json_unix_socket_handler_enable);
	g_proc.initialized = true;
	g_proc.auth_status = status;

	// Looks like we need to check the user ourselves to get the failed login event.
	Oid role = get_role_oid(port->user_name, true);
	if (role == InvalidOid)
	{
		AUDIT_DEBUG_LOG("Failed login detected");
		return;
	}

	// In other cases, if status was not ok, we should get a failed login message
	if (status == STATUS_OK)
	{
		AUDIT_DEBUG_LOG("Successful connection detected");
		// log connection - set up info in each handler
		// this sets proc.m_connected to true in each handler's
		// PostgreSQL_proc member.
		g_proc.connected = true;
		g_proc.query_id++;
		Audit_handler::log_audit_connect();
	}

	AUDIT_DEBUG_LOG("audit_ClientAuthentication_hook: status[%d]", status);
}

/*
 * Hook ExecutorStart to get the query text and basic command type for queries
 * that do not contain a table and so can't be idenitified accurately in
 * ExecutorCheckPerms.
 */
static void
audit_ExecutorStart_hook(QueryDesc *queryDesc, int eflags)
{
	AUDIT_DEBUG_LOG("audit_ExecutorStart_hook");

	if (queryDesc == NULL)
	{
		AUDIT_DEBUG_LOG("WARNINIG: queryDesc is NULL, returning");
		return;
	}

	AuditEventStackItem *stackItem = NULL;

	if (! internalStatement)
	{
		/* Push the audit event onto the stack */
		stackItem = stack_push();

		/* Initialize command using queryDesc->operation */
		switch (queryDesc->operation)
		{
		case CMD_SELECT:
			initialize_select_event(stackItem);
			break;

		case CMD_INSERT:
			initialize_insert_event(stackItem);
			break;

		case CMD_UPDATE:
			initialize_update_event(stackItem);
			break;

		case CMD_DELETE:
			initialize_delete_event(stackItem);
			break;

		default:
#if PG_VERSION_NUM >= 130000
			initialize_event(stackItem, LOGSTMT_ALL, T_Invalid, CMDTAG_UNKNOWN);
#else
			initialize_event(stackItem, LOGSTMT_ALL, T_Invalid, COMMAND_UNKNOWN);
#endif
			break;
		}

		/* Initialize the audit event */
		stackItem->auditEvent.commandText = queryDesc->sourceText;
		stackItem->auditEvent.paramList = queryDesc->params;
	}

	/* Call the previous hook or standard function */
	if (next_ExecutorStart_hook)
	{
		next_ExecutorStart_hook(queryDesc, eflags);
	}
	else
	{
		standard_ExecutorStart(queryDesc, eflags);
	}

	/*
	 * Move the stack memory context to the query memory context.  This needs
	 * to be done here because the query context does not exist before the
	 * call to standard_ExecutorStart() but the stack item is required by
	 * audit_ExecutorCheckPerms_hook() which is called during
	 * standard_ExecutorStart().
	 */
	if (stackItem)
	{
		MemoryContextSetParent(stackItem->contextAudit,
				queryDesc->estate->es_query_cxt);
	}
}

/*
 * Hook ExecutorCheckPerms to do session and object auditing for DML.
 */
static bool
audit_ExecutorCheckPerms_hook(List *rangeTabls, bool abort1)
{
	AUDIT_DEBUG_LOG("audit_ExecutorCheckPerms_hook");

	Oid auditOid = InvalidOid;

	/* Get the audit oid if the role exists */
	// auditOid = get_role_oid(auditRole, true);

	/* Log DML if the audit role is valid or session logging is enabled */
	if (! IsAbortedTransactionBlockState())
	{
		log_select_dml(auditOid, rangeTabls);
	}

	/* Call the next hook function */
	if (next_ExecutorCheckPerms_hook &&
			!(*next_ExecutorCheckPerms_hook)(rangeTabls, abort1))
	{
		return false;
	}

	return true;
}

// create a full name for an object from catalog/schema/relation

char *getFullObjectName(const RangeVar *rangevar)
{
	size_t len;

	len = strlen(rangevar->relname) + 1;
	if (rangevar->schemaname != NULL)
	{
		len += strlen(rangevar->schemaname) + 1;
	}
	if (rangevar->catalogname != NULL)
	{
		len += strlen(rangevar->catalogname) + 1;
	}

	char *name = (char *) palloc(len);
	if (name == NULL)	// shouldn't happen
	{
		return NULL;
	}

	memset(name, '\0', len);

	if (rangevar->catalogname != NULL)
	{
		sprintf(name, "%s.", rangevar->catalogname);
	}
	if (rangevar->schemaname != NULL)
	{
		strcat(name, rangevar->schemaname);
		strcat(name, ".");
	}
	strcat(name, rangevar->relname);

	return name;
}


// convert all known object types to string

static const char *objectTypeToString(enum ObjectType objtype)
{
	switch (objtype)
	{
	case OBJECT_AGGREGATE: return "AGGREGATE";
	case OBJECT_ATTRIBUTE: return "ATTRIBUTE";
	case OBJECT_CAST: return "CAST";
	case OBJECT_COLLATION: return "COLLATION";
	case OBJECT_COLUMN: return "COLUMN";
	case OBJECT_CONVERSION: return "CONVERSION";
	case OBJECT_DATABASE: return "DATABASE";
	case OBJECT_DOMAIN: return "DOMAIN";
	case OBJECT_EXTENSION: return "EXTENSION";
	case OBJECT_FDW: return "FOREIGN DATA WRAPPER";	// foreign data wrapper
	case OBJECT_FOREIGN_SERVER: return "SERVER";
	case OBJECT_FOREIGN_TABLE: return "FOREIGN TABLE";
	case OBJECT_FUNCTION: return "FUNCTION";
	case OBJECT_INDEX: return "INDEX";
	case OBJECT_LANGUAGE: return "LANGUAGE";
	case OBJECT_LARGEOBJECT: return "LARGE OBJECT";
	case OBJECT_OPCLASS: return "OPERATOR CLASS";
	case OBJECT_OPERATOR: return "OPERATOR";
	case OBJECT_OPFAMILY: return "OPERATOR FAMILY";
	case OBJECT_ROLE: return "ROLE";
	case OBJECT_RULE: return "RULE";
	case OBJECT_SCHEMA: return "SCHEMA";
	case OBJECT_SEQUENCE: return "SEQUENCE";
	case OBJECT_TABLE: return "TABLE";
	case OBJECT_TABLESPACE: return "TABLESPACE";
	case OBJECT_TRIGGER: return "TRIGGER";
	case OBJECT_TSCONFIGURATION: return "TEXT SEARCH CONFIGURATION";
	case OBJECT_TSDICTIONARY: return "TEXT SEARCH DICTIONARY";
	case OBJECT_TSPARSER: return "TEXT SEARCH PARSER";
	case OBJECT_TSTEMPLATE: return "TEXT SEARCH TEMPLATE";
	case OBJECT_TYPE: return "TYPE";
	case OBJECT_VIEW: return "VIEW";
	case OBJECT_MATVIEW: return "MATERIALIZED VIEW";
	case OBJECT_EVENT_TRIGGER: return "EVENT TRIGGER";

#if PG_VERSION_NUM >= 110000
	case OBJECT_PROCEDURE: return "PROCEDURE";
	case OBJECT_ROUTINE: return "ROUTINE";
#endif

#if PG_VERSION_NUM >= 100001
	case OBJECT_PUBLICATION: return "PUBLICATION";
	case OBJECT_PUBLICATION_REL: return "PUBLICATION REL";
	case OBJECT_SUBSCRIPTION: return "SUBSCRIPTION";
	case OBJECT_STATISTIC_EXT: return "STATISTICS";
#endif

#if PG_VERSION_NUM >= 90600
	case OBJECT_ACCESS_METHOD: return "ACCESS METHOD";
#endif

#if PG_VERSION_NUM >= 90500
	case OBJECT_AMOP: return "AMOP";
	case OBJECT_AMPROC: return "AMPROC";
	case OBJECT_DEFACL: return "DEFACL";
	case OBJECT_DEFAULT: return "DEFAULT";
	case OBJECT_DOMCONSTRAINT: return "DOMAIN CONSTRAINT";
	case OBJECT_POLICY: return "POLICY";
	case OBJECT_TABCONSTRAINT: return "TABLE CONSTRAINT";
	case OBJECT_TRANSFORM: return "TRANSFORM";
	case OBJECT_USER_MAPPING: return "USER MAPPING";
#endif
	}

	return "[UNKNOWN]";
}


// convert all known command tags to string

#if PG_VERSION_NUM >= 130000
static const char *commandTagToString(enum CommandTag cmdTag)
{
	switch (cmdTag)
	{
	case CMDTAG_UNKNOWN: return "???";
	case CMDTAG_ALTER_ACCESS_METHOD: return "ALTER ACCESS METHOD";
	case CMDTAG_ALTER_AGGREGATE: return "ALTER AGGREGATE";
	case CMDTAG_ALTER_CAST: return "ALTER CAST";
	case CMDTAG_ALTER_COLLATION: return "ALTER COLLATION";
	case CMDTAG_ALTER_CONSTRAINT: return "ALTER CONSTRAINT";
	case CMDTAG_ALTER_CONVERSION: return "ALTER CONVERSION";
	case CMDTAG_ALTER_DATABASE: return "ALTER DATABASE";
	case CMDTAG_ALTER_DEFAULT_PRIVILEGES: return "ALTER DEFAULT PRIVILEGES";
	case CMDTAG_ALTER_DOMAIN: return "ALTER DOMAIN";
	case CMDTAG_ALTER_EVENT_TRIGGER: return "ALTER EVENT TRIGGER";
	case CMDTAG_ALTER_EXTENSION: return "ALTER EXTENSION";
	case CMDTAG_ALTER_FOREIGN_DATA_WRAPPER: return "ALTER FOREIGN DATA WRAPPER";
	case CMDTAG_ALTER_FOREIGN_TABLE: return "ALTER FOREIGN TABLE";
	case CMDTAG_ALTER_FUNCTION: return "ALTER FUNCTION";
	case CMDTAG_ALTER_INDEX: return "ALTER INDEX";
	case CMDTAG_ALTER_LANGUAGE: return "ALTER LANGUAGE";
	case CMDTAG_ALTER_LARGE_OBJECT: return "ALTER LARGE OBJECT";
	case CMDTAG_ALTER_MATERIALIZED_VIEW: return "ALTER MATERIALIZED VIEW";
	case CMDTAG_ALTER_OPERATOR: return "ALTER OPERATOR";
	case CMDTAG_ALTER_OPERATOR_CLASS: return "ALTER OPERATOR CLASS";
	case CMDTAG_ALTER_OPERATOR_FAMILY: return "ALTER OPERATOR FAMILY";
	case CMDTAG_ALTER_POLICY: return "ALTER POLICY";
	case CMDTAG_ALTER_PROCEDURE: return "ALTER PROCEDURE";
	case CMDTAG_ALTER_PUBLICATION: return "ALTER PUBLICATION";
	case CMDTAG_ALTER_ROLE: return "ALTER ROLE";
	case CMDTAG_ALTER_ROUTINE: return "ALTER ROUTINE";
	case CMDTAG_ALTER_RULE: return "ALTER RULE";
	case CMDTAG_ALTER_SCHEMA: return "ALTER SCHEMA";
	case CMDTAG_ALTER_SEQUENCE: return "ALTER SEQUENCE";
	case CMDTAG_ALTER_SERVER: return "ALTER SERVER";
	case CMDTAG_ALTER_STATISTICS: return "ALTER STATISTICS";
	case CMDTAG_ALTER_SUBSCRIPTION: return "ALTER SUBSCRIPTION";
	case CMDTAG_ALTER_SYSTEM: return "ALTER SYSTEM";
	case CMDTAG_ALTER_TABLE: return "ALTER TABLE";
	case CMDTAG_ALTER_TABLESPACE: return "ALTER TABLESPACE";
	case CMDTAG_ALTER_TEXT_SEARCH_CONFIGURATION: return "ALTER TEXT SEARCH CONFIGURATION";
	case CMDTAG_ALTER_TEXT_SEARCH_DICTIONARY: return "ALTER TEXT SEARCH DICTIONARY";
	case CMDTAG_ALTER_TEXT_SEARCH_PARSER: return "ALTER TEXT SEARCH PARSER";
	case CMDTAG_ALTER_TEXT_SEARCH_TEMPLATE: return "ALTER TEXT SEARCH TEMPLATE";
	case CMDTAG_ALTER_TRANSFORM: return "ALTER TRANSFORM";
	case CMDTAG_ALTER_TRIGGER: return "ALTER TRIGGER";
	case CMDTAG_ALTER_TYPE: return "ALTER TYPE";
	case CMDTAG_ALTER_USER_MAPPING: return "ALTER USER MAPPING";
	case CMDTAG_ALTER_VIEW: return "ALTER VIEW";
	case CMDTAG_ANALYZE: return "ANALYZE";
	case CMDTAG_BEGIN: return "BEGIN";
	case CMDTAG_CALL: return "CALL";
	case CMDTAG_CHECKPOINT: return "CHECKPOINT";
	case CMDTAG_CLOSE: return "CLOSE";
	case CMDTAG_CLOSE_CURSOR: return "CLOSE CURSOR";
	case CMDTAG_CLOSE_CURSOR_ALL: return "CLOSE CURSOR ALL";
	case CMDTAG_CLUSTER: return "CLUSTER";
	case CMDTAG_COMMENT: return "COMMENT";
	case CMDTAG_COMMIT: return "COMMIT";
	case CMDTAG_COMMIT_PREPARED: return "COMMIT PREPARED";
	case CMDTAG_COPY: return "COPY";
	case CMDTAG_COPY_FROM: return "COPY FROM";
	case CMDTAG_CREATE_ACCESS_METHOD: return "CREATE ACCESS METHOD";
	case CMDTAG_CREATE_AGGREGATE: return "CREATE AGGREGATE";
	case CMDTAG_CREATE_CAST: return "CREATE CAST";
	case CMDTAG_CREATE_COLLATION: return "CREATE COLLATION";
	case CMDTAG_CREATE_CONSTRAINT: return "CREATE CONSTRAINT";
	case CMDTAG_CREATE_CONVERSION: return "CREATE CONVERSION";
	case CMDTAG_CREATE_DATABASE: return "CREATE DATABASE";
	case CMDTAG_CREATE_DOMAIN: return "CREATE DOMAIN";
	case CMDTAG_CREATE_EVENT_TRIGGER: return "CREATE EVENT TRIGGER";
	case CMDTAG_CREATE_EXTENSION: return "CREATE EXTENSION";
	case CMDTAG_CREATE_FOREIGN_DATA_WRAPPER: return "CREATE FOREIGN DATA WRAPPER";
	case CMDTAG_CREATE_FOREIGN_TABLE: return "CREATE FOREIGN TABLE";
	case CMDTAG_CREATE_FUNCTION: return "CREATE FUNCTION";
	case CMDTAG_CREATE_INDEX: return "CREATE INDEX";
	case CMDTAG_CREATE_LANGUAGE: return "CREATE LANGUAGE";
	case CMDTAG_CREATE_MATERIALIZED_VIEW: return "CREATE MATERIALIZED VIEW";
	case CMDTAG_CREATE_OPERATOR: return "CREATE OPERATOR";
	case CMDTAG_CREATE_OPERATOR_CLASS: return "CREATE OPERATOR CLASS";
	case CMDTAG_CREATE_OPERATOR_FAMILY: return "CREATE OPERATOR FAMILY";
	case CMDTAG_CREATE_POLICY: return "CREATE POLICY";
	case CMDTAG_CREATE_PROCEDURE: return "CREATE PROCEDURE";
	case CMDTAG_CREATE_PUBLICATION: return "CREATE PUBLICATION";
	case CMDTAG_CREATE_ROLE: return "CREATE ROLE";
	case CMDTAG_CREATE_ROUTINE: return "CREATE ROUTINE";
	case CMDTAG_CREATE_RULE: return "CREATE RULE";
	case CMDTAG_CREATE_SCHEMA: return "CREATE SCHEMA";
	case CMDTAG_CREATE_SEQUENCE: return "CREATE SEQUENCE";
	case CMDTAG_CREATE_SERVER: return "CREATE SERVER";
	case CMDTAG_CREATE_STATISTICS: return "CREATE STATISTICS";
	case CMDTAG_CREATE_SUBSCRIPTION: return "CREATE SUBSCRIPTION";
	case CMDTAG_CREATE_TABLE: return "CREATE TABLE";
	case CMDTAG_CREATE_TABLE_AS: return "CREATE TABLE AS";
	case CMDTAG_CREATE_TABLESPACE: return "CREATE TABLESPACE";
	case CMDTAG_CREATE_TEXT_SEARCH_CONFIGURATION: return "CREATE TEXT SEARCH CONFIGURATION";
	case CMDTAG_CREATE_TEXT_SEARCH_DICTIONARY: return "CREATE TEXT SEARCH DICTIONARY";
	case CMDTAG_CREATE_TEXT_SEARCH_PARSER: return "CREATE TEXT SEARCH PARSER";
	case CMDTAG_CREATE_TEXT_SEARCH_TEMPLATE: return "CREATE TEXT SEARCH TEMPLATE";
	case CMDTAG_CREATE_TRANSFORM: return "CREATE TRANSFORM";
	case CMDTAG_CREATE_TRIGGER: return "CREATE TRIGGER";
	case CMDTAG_CREATE_TYPE: return "CREATE TYPE";
	case CMDTAG_CREATE_USER_MAPPING: return "CREATE USER MAPPING";
	case CMDTAG_CREATE_VIEW: return "CREATE VIEW";
	case CMDTAG_DEALLOCATE: return "DEALLOCATE";
	case CMDTAG_DEALLOCATE_ALL: return "DEALLOCATE ALL";
	case CMDTAG_DECLARE_CURSOR: return "DECLARE CURSOR";
	case CMDTAG_DELETE: return "DELETE";
	case CMDTAG_DISCARD: return "DISCARD";
	case CMDTAG_DISCARD_ALL: return "DISCARD ALL";
	case CMDTAG_DISCARD_PLANS: return "DISCARD PLANS";
	case CMDTAG_DISCARD_SEQUENCES: return "DISCARD SEQUENCES";
	case CMDTAG_DISCARD_TEMP: return "DISCARD TEMP";
	case CMDTAG_DO: return "DO";
	case CMDTAG_DROP_ACCESS_METHOD: return "DROP ACCESS METHOD";
	case CMDTAG_DROP_AGGREGATE: return "DROP AGGREGATE";
	case CMDTAG_DROP_CAST: return "DROP CAST";
	case CMDTAG_DROP_COLLATION: return "DROP COLLATION";
	case CMDTAG_DROP_CONSTRAINT: return "DROP CONSTRAINT";
	case CMDTAG_DROP_CONVERSION: return "DROP CONVERSION";
	case CMDTAG_DROP_DATABASE: return "DROP DATABASE";
	case CMDTAG_DROP_DOMAIN: return "DROP DOMAIN";
	case CMDTAG_DROP_EVENT_TRIGGER: return "DROP EVENT TRIGGER";
	case CMDTAG_DROP_EXTENSION: return "DROP EXTENSION";
	case CMDTAG_DROP_FOREIGN_DATA_WRAPPER: return "DROP FOREIGN DATA WRAPPER";
	case CMDTAG_DROP_FOREIGN_TABLE: return "DROP FOREIGN TABLE";
	case CMDTAG_DROP_FUNCTION: return "DROP FUNCTION";
	case CMDTAG_DROP_INDEX: return "DROP INDEX";
	case CMDTAG_DROP_LANGUAGE: return "DROP LANGUAGE";
	case CMDTAG_DROP_MATERIALIZED_VIEW: return "DROP MATERIALIZED VIEW";
	case CMDTAG_DROP_OPERATOR: return "DROP OPERATOR";
	case CMDTAG_DROP_OPERATOR_CLASS: return "DROP OPERATOR CLASS";
	case CMDTAG_DROP_OPERATOR_FAMILY: return "DROP OPERATOR FAMILY";
	case CMDTAG_DROP_OWNED: return "DROP OWNED";
	case CMDTAG_DROP_POLICY: return "DROP POLICY";
	case CMDTAG_DROP_PROCEDURE: return "DROP PROCEDURE";
	case CMDTAG_DROP_PUBLICATION: return "DROP PUBLICATION";
	case CMDTAG_DROP_ROLE: return "DROP ROLE";
	case CMDTAG_DROP_ROUTINE: return "DROP ROUTINE";
	case CMDTAG_DROP_RULE: return "DROP RULE";
	case CMDTAG_DROP_SCHEMA: return "DROP SCHEMA";
	case CMDTAG_DROP_SEQUENCE: return "DROP SEQUENCE";
	case CMDTAG_DROP_SERVER: return "DROP SERVER";
	case CMDTAG_DROP_STATISTICS: return "DROP STATISTICS";
	case CMDTAG_DROP_SUBSCRIPTION: return "DROP SUBSCRIPTION";
	case CMDTAG_DROP_TABLE: return "DROP TABLE";
	case CMDTAG_DROP_TABLESPACE: return "DROP TABLESPACE";
	case CMDTAG_DROP_TEXT_SEARCH_CONFIGURATION: return "DROP TEXT SEARCH CONFIGURATION";
	case CMDTAG_DROP_TEXT_SEARCH_DICTIONARY: return "DROP TEXT SEARCH DICTIONARY";
	case CMDTAG_DROP_TEXT_SEARCH_PARSER: return "DROP TEXT SEARCH PARSER";
	case CMDTAG_DROP_TEXT_SEARCH_TEMPLATE: return "DROP TEXT SEARCH TEMPLATE";
	case CMDTAG_DROP_TRANSFORM: return "DROP TRANSFORM";
	case CMDTAG_DROP_TRIGGER: return "DROP TRIGGER";
	case CMDTAG_DROP_TYPE: return "DROP TYPE";
	case CMDTAG_DROP_USER_MAPPING: return "DROP USER MAPPING";
	case CMDTAG_DROP_VIEW: return "DROP VIEW";
	case CMDTAG_EXECUTE: return "EXECUTE";
	case CMDTAG_EXPLAIN: return "EXPLAIN";
	case CMDTAG_FETCH: return "FETCH";
	case CMDTAG_GRANT: return "GRANT";
	case CMDTAG_GRANT_ROLE: return "GRANT ROLE";
	case CMDTAG_IMPORT_FOREIGN_SCHEMA: return "IMPORT FOREIGN SCHEMA";
	case CMDTAG_INSERT: return "INSERT";
	case CMDTAG_LISTEN: return "LISTEN";
	case CMDTAG_LOAD: return "LOAD";
	case CMDTAG_LOCK_TABLE: return "LOCK TABLE";
	case CMDTAG_MOVE: return "MOVE";
	case CMDTAG_NOTIFY: return "NOTIFY";
	case CMDTAG_PREPARE: return "PREPARE";
	case CMDTAG_PREPARE_TRANSACTION: return "PREPARE TRANSACTION";
	case CMDTAG_REASSIGN_OWNED: return "REASSIGN OWNED";
	case CMDTAG_REFRESH_MATERIALIZED_VIEW: return "REFRESH MATERIALIZED VIEW";
	case CMDTAG_REINDEX: return "REINDEX";
	case CMDTAG_RELEASE: return "RELEASE";
	case CMDTAG_RESET: return "RESET";
	case CMDTAG_REVOKE: return "REVOKE";
	case CMDTAG_REVOKE_ROLE: return "REVOKE ROLE";
	case CMDTAG_ROLLBACK: return "ROLLBACK";
	case CMDTAG_ROLLBACK_PREPARED: return "ROLLBACK PREPARED";
	case CMDTAG_SAVEPOINT: return "SAVEPOINT";
	case CMDTAG_SECURITY_LABEL: return "SECURITY LABEL";
	case CMDTAG_SELECT: return "SELECT";
	case CMDTAG_SELECT_FOR_KEY_SHARE: return "SELECT FOR KEY SHARE";
	case CMDTAG_SELECT_FOR_NO_KEY_UPDATE: return "SELECT FOR NO KEY UPDATE";
	case CMDTAG_SELECT_FOR_SHARE: return "SELECT FOR SHARE";
	case CMDTAG_SELECT_FOR_UPDATE: return "SELECT FOR UPDATE";
	case CMDTAG_SELECT_INTO: return "SELECT INTO";
	case CMDTAG_SET: return "SET";
	case CMDTAG_SET_CONSTRAINTS: return "SET CONSTRAINTS";
	case CMDTAG_SHOW: return "SHOW";
	case CMDTAG_START_TRANSACTION: return "START TRANSACTION";
	case CMDTAG_TRUNCATE_TABLE: return "TRUNCATE TABLE";
	case CMDTAG_UNLISTEN: return "UNLISTEN";
	case CMDTAG_UPDATE: return "UPDATE";
	case CMDTAG_VACUUM: return "VACUUM";
	case COMMAND_TAG_NEXTTAG: return "";
	}
	return "???";
}
#else
static const char *commandTagToString(const char *cmdTag)
{
	if (cmdTag != NULL)
	{
		 return cmdTag;
	}
	return COMMAND_UNKNOWN;
}
#endif


// get role name from a role spec

#if PG_VERSION_NUM >= 90500
static char *getRoleName(const Node *node)
{
	const RoleSpec *rs = (const RoleSpec *) node;

	if (rs != NULL && rs->roletype == ROLESPEC_CSTRING)
	{
		 return pstrdup(rs->rolename);
	}
	
	return pstrdup("[UNKNOWN]");
}
#else
static char *getRoleName(const char *rolename)
{
	if (rolename != NULL)
	{
		 return pstrdup(rolename);
	}
	
	return pstrdup("[UNKNOWN]");
}
#endif


// update the accessed object info

static void updateAccessedObjectInfo(struct AuditEvent *event, const Node *parsetree)
{
	DropStmt *dropStatement = NULL;
	DropRoleStmt *dropRole = NULL;
	AlterDomainStmt *alterDomain = NULL;
	AlterRoleStmt *alterRole = NULL;
	AlterRoleSetStmt *alterRoleSet = NULL;
	AlterOwnerStmt *alterOwner = NULL;
	AlterDatabaseSetStmt *alterDbSet = NULL;
	AlterOpFamilyStmt *alterOpFamily = NULL;
	RenameStmt *rename = NULL;
	AlterFunctionStmt *alterFunction = NULL;
	TruncateStmt *truncateStatement = NULL;
	AlterFdwStmt *alterFdw = NULL;
	CreateSchemaStmt *createSchema = NULL;
	DefineStmt *defineStmt = NULL;
	CreateOpFamilyStmt *createOpFamily = NULL;
	CreateOpClassStmt *createOpClass = NULL;
	CreateFunctionStmt *createFunction = NULL;
	CreateForeignTableStmt *createForeignTable = NULL;
	CreateForeignServerStmt *createForeignServer = NULL;
	CreateFdwStmt *createFdw = NULL;
	CreateDomainStmt *createDomain = NULL;
	IndexStmt *indexStmt = NULL;
	CreateTableAsStmt *createTableAs = NULL;
	RefreshMatViewStmt *refreshMatView = NULL;
	AlterEventTrigStmt *alterEventTrig = NULL;
	CreateEventTrigStmt *createEventTrig = NULL;

	switch (parsetree->type)
	{
	case T_CreateStmt:
		event->objectName = getFullObjectName(((CreateStmt *) parsetree)->relation);
		break;

	case T_CreatedbStmt:
		event->objectName = pstrdup(((CreatedbStmt *) parsetree)->dbname);
		event->objectType = "DATABASE";
		break;

	case T_CreateTableAsStmt:
		createTableAs = (CreateTableAsStmt *) parsetree;

		if (createTableAs->relkind == OBJECT_MATVIEW)
		{
			// we cannot pull out the accessed object here
			// but at least we can change the command
			event->command = "CREATE MATERIALIZED VIEW";	// not "CREATE TABLE AS"
		}
		else
		{
			event->objectName = getFullObjectName(createTableAs->into->rel);
			event->command = "CREATE TABLE";	// not "CREATE TABLE AS"
			event->objectType = "TABLE";
		}
		event->objectList = NULL;
		break;

	case T_CreateTableSpaceStmt:
		event->objectName = pstrdup(((CreateTableSpaceStmt *) parsetree)->tablespacename);
		event->objectType = "TABLESPACE";
		break;

	case T_CreateSeqStmt:
		event->objectName = getFullObjectName(((CreateSeqStmt *) parsetree)->sequence);
		event->objectType = "SEQUENCE";
		break;

	case T_CreateSchemaStmt:
		createSchema = (CreateSchemaStmt *) parsetree;
		// schema name is optional in some cases, see the grammar
		// only update if we can supply the name
		if (createSchema->schemaname != NULL)
		{
			event->objectList = NULL;
			event->objectType = "SCHEMA";
			event->objectName = pstrdup(createSchema->schemaname);
		}
		break;

	case T_DefineStmt:
		// create operator, create aggregate, create collation
		defineStmt = (DefineStmt *) parsetree;
		switch (defineStmt->kind)
		{
		case OBJECT_AGGREGATE:
		case OBJECT_OPERATOR:
		case OBJECT_COLLATION:
			event->objectName = NULL;
			event->objectList = defineStmt->defnames;
			event->objectType = objectTypeToString(defineStmt->kind);
			break;
		default:
			break;
		}
		break;

	case T_CreateOpFamilyStmt:
		createOpFamily = (CreateOpFamilyStmt *) parsetree;
		event->objectName = NULL;
		event->objectList = createOpFamily->opfamilyname;
		event->objectType = "OPERATOR FAMILY";
		break;

	case T_CreateOpClassStmt:
		createOpClass = (CreateOpClassStmt *) parsetree;
		event->objectName = NULL;
		event->objectList = createOpClass->opclassname;
		event->objectType = "OPERATOR CLASS";
		break;

	case T_CreateFunctionStmt:
		createFunction = (CreateFunctionStmt *) parsetree;
		event->objectName = NULL;
		event->objectList = createFunction->funcname;
		event->objectType = "FUNCTION";
		break;

	case T_CreateForeignTableStmt:
		createForeignTable = (CreateForeignTableStmt *) parsetree;
		event->objectName = getFullObjectName(createForeignTable->base.relation);
		event->objectList = NULL;
		event->objectType = "FOREIGN TABLE";
		break;

	case T_CreateForeignServerStmt:
		createForeignServer = (CreateForeignServerStmt *) parsetree;
		event->objectName = pstrdup(createForeignServer->servername);
		event->objectList = NULL;
		event->objectType = "SERVER";
		break;

	case T_CreateFdwStmt:
		createFdw = (CreateFdwStmt *) parsetree;
		event->objectName = pstrdup(createFdw->fdwname);
		event->objectList = NULL;
		event->objectType = "FOREIGN DATA WRAPPER";
		break;

	case T_CreateDomainStmt:
		createDomain = (CreateDomainStmt *) parsetree;
		event->objectName = NULL;
		event->objectList = createDomain->domainname;
		event->objectType = "DOMAIN";
		break;

	// create index
	case T_IndexStmt:
		indexStmt = (IndexStmt *) parsetree;
		event->objectName = getFullObjectName(indexStmt->relation);
		event->objectList = NULL;
		event->objectType = "TABLE";
		break;

#if PG_VERSION_NUM >= 90500
	case T_CreatePolicyStmt:
		event->objectName = getFullObjectName(((CreatePolicyStmt *) parsetree)->table);
		event->objectType = "TABLE";
		break;
#endif

	case T_CreateRoleStmt:
		event->objectName = pstrdup(((CreateRoleStmt *) parsetree)->role);
		event->objectType = "ROLE";
		break;

	case T_CreateTrigStmt:
		event->objectName = getFullObjectName(((CreateTrigStmt *) parsetree)->relation);
		event->objectType = "TABLE";
		break;

	case T_DropdbStmt:
		event->objectName = pstrdup(((DropdbStmt *) parsetree)->dbname);
		event->objectType = "DATABASE";
		break;

	case T_RuleStmt:
		event->objectName = getFullObjectName(((RuleStmt *) parsetree)->relation);
		event->objectType = "TABLE";
		break;

	case T_AlterDatabaseSetStmt:
		alterDbSet = (AlterDatabaseSetStmt *) parsetree;
		event->objectName = pstrdup(alterDbSet->dbname);
		event->objectType = "DATABASE";
		break;

	case T_AlterTableSpaceOptionsStmt:
		event->objectName = pstrdup(((AlterTableSpaceOptionsStmt *) parsetree)->tablespacename);
		event->objectType = "TABLESPACE";
		break;

	case T_DropTableSpaceStmt:
		event->objectName = pstrdup(((DropTableSpaceStmt *) parsetree)->tablespacename);
		event->objectType = "TABLESPACE";
		break;

	case T_InsertStmt:
		event->objectName = getFullObjectName(((InsertStmt *) parsetree)->relation);
		break;

	case T_DeleteStmt:
		event->objectName = getFullObjectName(((DeleteStmt *) parsetree)->relation);
		break;

	case T_AlterRoleStmt:
		alterRole = (AlterRoleStmt *) parsetree;
#if PG_VERSION_NUM >= 100001
		event->objectName = getRoleName((const Node*)alterRole->role);
#else
		event->objectName = getRoleName(alterRole->role);
#endif
		break;

	case T_AlterRoleSetStmt:
		alterRoleSet = (AlterRoleSetStmt *) parsetree;
		if (alterRoleSet->role != NULL)
		{
#if PG_VERSION_NUM >= 100001
			event->objectName = getRoleName((const Node*)alterRoleSet->role);
#else
			event->objectName = getRoleName(alterRoleSet->role);
#endif
		}
		else
		{
			event->objectName = pstrdup(alterRoleSet->database);
		}
		break;

	case T_AlterSeqStmt:
		event->objectName = getFullObjectName(((AlterSeqStmt *) parsetree)->sequence);
		event->objectType = "SEQUENCE";
		break;

	case T_AlterTableStmt:
		event->objectName = getFullObjectName(((AlterTableStmt *) parsetree)->relation);
		event->objectType = objectTypeToString(((AlterTableStmt *) parsetree)->relkind);
		break;

	// These statement use lists of objects, the names will be formatted when logged
	case T_AlterOpFamilyStmt:
		alterOpFamily = (AlterOpFamilyStmt *) parsetree;
		event->objectList = alterOpFamily->opfamilyname;
		event->objectName = NULL;
		event->objectType = "OPERATOR FAMILY";
		break;

	case T_AlterDomainStmt:
		alterDomain = (AlterDomainStmt *) parsetree;
		event->objectList = alterDomain->typeName;
		event->objectName = NULL;
		break;

	case T_AlterOwnerStmt:
		alterOwner = (AlterOwnerStmt *) parsetree;
		if (alterOwner->object->type == T_List)
		{
			event->objectList = (List*)alterOwner->object;
		}
#if PG_VERSION_NUM >= 100001
		// ALTER AGGREGATE OWNER handling
		else if (alterOwner->object->type == T_ObjectWithArgs)
		{
			event->objectList = ((ObjectWithArgs* )alterOwner->object)->objname;
		}
#endif
		else
		{
			AUDIT_WARNING_LOG("case T_AlterOwnerStmt, unsupported object type");
			event->objectList = NULL;
		}
		event->objectType = objectTypeToString(alterOwner->objectType);
		event->objectName = NULL;
		break;

	case T_AlterFdwStmt:
		alterFdw = (AlterFdwStmt *) parsetree;
		event->objectList = NULL;
		event->objectType = "FOREIGN DATA WRAPPER";
		event->objectName = pstrdup(alterFdw->fdwname);
		break;

	case T_AlterFunctionStmt:
		alterFunction = (AlterFunctionStmt *) parsetree;
#if PG_VERSION_NUM >= 100001
		event->objectList = alterFunction->func->objname;
#else
		event->objectList = alterFunction->func->funcname;
#endif
		event->objectType = "FUNCTION";
		event->objectName = NULL;
		break;


	case T_CreateEventTrigStmt:
		createEventTrig = (CreateEventTrigStmt *) parsetree;
		event->objectName = pstrdup(createEventTrig->trigname);
		event->objectList = NULL;
		event->objectType = "EVENT TRIGGER";
		break;

	case T_AlterEventTrigStmt:
		alterEventTrig = (AlterEventTrigStmt *) parsetree;
		event->objectList = NULL;
		event->objectType = "EVENT TRIGGER";
		event->objectName = pstrdup(alterEventTrig->trigname);
		break;

	case T_RefreshMatViewStmt:
		refreshMatView = (RefreshMatViewStmt *) parsetree;
		event->objectList = NULL;
		event->objectType = "MATERIALIZED VIEW";
		event->objectName = getFullObjectName(refreshMatView->relation);
		break;

	case T_TruncateStmt:
		truncateStatement = (TruncateStmt *) parsetree;
		event->objectName = NULL;
		event->objectType = "TABLE";
		event->objectList = truncateStatement->relations;
		break;

	case T_DropStmt:
		dropStatement = (DropStmt *) parsetree;
		event->objectType = objectTypeToString(dropStatement->removeType);
		event->objectList = dropStatement->objects;
		event->objectName = NULL;

		// See the grammar in the PostgresSQL source code.
		// For these statements, the item dropped is appended to the list
		// with the name of the accessed object.
		switch (dropStatement->removeType)
		{
		case OBJECT_RULE:
		case OBJECT_TRIGGER:
		case OBJECT_OPCLASS:
		case OBJECT_OPFAMILY:
#if PG_VERSION_NUM >= 90500
		case OBJECT_POLICY:
#endif
			event->useLastInList = true;
			break;
		case OBJECT_CAST:
			// DROP CAST:
			// can't get name, don't provide accessed object
			event->objectList = NULL;
			event->objectName = NULL;
			break;
		default:
			break;
		}
		break;

	case T_DropRoleStmt:
		dropRole = (DropRoleStmt *) parsetree;
		event->objectType = "ROLE";
		event->objectList = dropRole->roles;
		event->objectName = NULL;
		break;

	case T_RenameStmt:	// ALTER statement, many varieties; see grammar
		rename = (RenameStmt *) parsetree;
		event->objectType = objectTypeToString(rename->renameType);

		switch (rename->renameType)
		{
		case OBJECT_OPCLASS:
		case OBJECT_OPFAMILY:
			event->useLastInList = true;
			// fall through
		case OBJECT_AGGREGATE:
		case OBJECT_COLLATION:
		case OBJECT_CONVERSION:
		case OBJECT_DOMAIN:
		case OBJECT_FDW:
		case OBJECT_FOREIGN_SERVER:
		case OBJECT_FUNCTION:
		case OBJECT_LANGUAGE:
		case OBJECT_TSDICTIONARY:
		case OBJECT_TSTEMPLATE:
		case OBJECT_TSCONFIGURATION:
		case OBJECT_TSPARSER:
		case OBJECT_TYPE:
		case OBJECT_EVENT_TRIGGER:
#if PG_VERSION_NUM >= 90500
		case OBJECT_DOMCONSTRAINT:
#endif
			if (rename->object->type == T_List)
			{
				event->objectList = (List*)rename->object;
			}
#if PG_VERSION_NUM >= 100001
			// Special handling for: OBJECT_AGGREGATE
			else if (rename->object->type == T_ObjectWithArgs)
			{
				event->objectList = ((ObjectWithArgs*)rename->object)->objname;
			}
#endif /* PG_VERSION_NUM >= 100001 */
			else
			{
				AUDIT_WARNING_LOG("Unsupported rename object type [%d]", rename->object->type);
				event->objectList = NULL;
			}
			event->objectName = NULL;
			break;
		case OBJECT_ATTRIBUTE:
		case OBJECT_DATABASE:
		case OBJECT_ROLE:
		case OBJECT_TABLESPACE:
		case OBJECT_SCHEMA:
#if PG_VERSION_NUM >= 90500
		case OBJECT_POLICY:
#endif
			event->objectName = pstrdup(rename->subname);
			break;
		case OBJECT_COLUMN:
		case OBJECT_FOREIGN_TABLE:
		case OBJECT_INDEX:
		case OBJECT_TABLE:
		case OBJECT_TRIGGER:
		case OBJECT_SEQUENCE:
		case OBJECT_VIEW:
		case OBJECT_MATVIEW:
#if PG_VERSION_NUM >= 90500
		case OBJECT_TABCONSTRAINT:
#endif
			event->objectName = getFullObjectName(rename->relation);
			break;
		case OBJECT_RULE:
			event->objectList = NULL;
			event->objectName = pstrdup(rename->subname);
			break;
		default:
			break;
		}
	default:
		break;
	break;
	}
}

/*
 * Hook ProcessUtility to do session auditing for DDL and utility commands.
 */
static void
audit_ProcessUtility_hook(   
#if PG_VERSION_NUM >= 100001
                             PlannedStmt *pstmt,
#else
                             Node *parsetree,
#endif
                             const char *queryString,
                             ProcessUtilityContext context,
                             ParamListInfo params,
#if PG_VERSION_NUM >= 100001
							 QueryEnvironment *queryEnv,
#endif
                             DestReceiver *dest,
#if PG_VERSION_NUM >= 130000
                             QueryCompletion *queryCompletion)
#else
                             char *completionTag)
#endif
{
	AUDIT_DEBUG_LOG("audit_ProcessUtility_hook");

#if PG_VERSION_NUM >= 100001
	Node *parsetree = (Node*)pstmt;
#endif

	AuditEventStackItem *stackItem = NULL;
	int64 stackId = 0;

	/*
	 * Don't audit substatements.  All the substatements we care about should
	 * be covered by the event triggers.
	 */
	if (context <= PROCESS_UTILITY_QUERY && !IsAbortedTransactionBlockState())
	{
		/* Process top level utility statement */
		if (context == PROCESS_UTILITY_TOPLEVEL)
		{
			if (auditEventStack != NULL)
			{
				// elog(ERROR, "audit stack is not empty"); // Bug#1137978 log level ERROR cause to abort transaction, refer to elog.h
				// not using log level WARNING directly, so log message will not be presented to client but only to server log
				AUDIT_WARNING_LOG("audit stack is not empty");
			}

			stackItem = stack_push();
			stackItem->auditEvent.paramList = params;
			}
			else
			{
				stackItem = stack_push();
			}

		stackId = stackItem->stackId;
#ifndef EDB_ENTERPRISE
		stackItem->auditEvent.logStmtLevel = GetCommandLogLevel(parsetree);
#else // Build "EDB Postgres Enterprise" variant
		stackItem->auditEvent.logStmtLevel = LOGSTMT_NONE; // Prevent unnecessary logic activation in log_audit_event()
#endif
		stackItem->auditEvent.commandTag = nodeTag(parsetree);
		stackItem->auditEvent.command = commandTagToString(CreateCommandTag(parsetree));
		stackItem->auditEvent.commandText = queryString;

		/*
		 * If this is a DO block log it before calling the next ProcessUtility
		 * hook.
		 */
		if (stackItem->auditEvent.commandTag == T_DoStmt &&
				!IsAbortedTransactionBlockState())
		{
			log_audit_event(stackItem);
		}
	}

	/* Call the standard process utility chain. */
#if PG_VERSION_NUM >= 130000
	if (next_ProcessUtility_hook)
	{
		(*next_ProcessUtility_hook) (pstmt, queryString, context,
				params, queryEnv, dest, queryCompletion);
	}
	else
	{
		standard_ProcessUtility(pstmt, queryString, context,
				params, queryEnv, dest, queryCompletion);
	}
#elif PG_VERSION_NUM < 130000 && PG_VERSION_NUM >= 100001
	if (next_ProcessUtility_hook)
	{
		(*next_ProcessUtility_hook) (pstmt, queryString, context,
				params, queryEnv, dest, completionTag);
	}
	else
	{
		standard_ProcessUtility(pstmt, queryString, context,
				params, queryEnv, dest, completionTag);
	}
#else
	if (next_ProcessUtility_hook)
	{
		(*next_ProcessUtility_hook) (parsetree, queryString, context,
				params, dest, completionTag);
	}
	else
	{
		standard_ProcessUtility(parsetree, queryString, context,
				params, dest, completionTag);
	}
#endif

	/*
	 * Process the audit event if there is one.  Also check that this event
	 * was not popped off the stack by a memory context being free'd
	 * elsewhere.
	 */
	if (stackItem && !IsAbortedTransactionBlockState())
	{
		AUDIT_DEBUG_LOG("Processing the audit event");

		/*
		 * Make sure the item we want to log is still on the stack - if not
		 * then something has gone wrong and an error will be raised.
		 */
		stack_valid(stackId);

		stackItem->auditEvent.objectList = NULL;

		// Fill in accessed-object info
#if PG_VERSION_NUM >= 100001
		const Node  *parsetreetmp = ((PlannedStmt *)parsetree)->utilityStmt;
		updateAccessedObjectInfo(& stackItem->auditEvent, parsetreetmp);
#else
		updateAccessedObjectInfo(& stackItem->auditEvent, parsetree);
#endif

		/*
		 * Log the utility command if logging is on, the command has not
		 * already been logged by another hook, and the transaction is not
		 * aborted.
		 */
		if (/* auditLogBitmap != 0 && */ !stackItem->auditEvent.logged)
		{
			AUDIT_DEBUG_LOG("Logging the utility command");
			log_audit_event(stackItem);
		}
	}

	/* Pop audit event from the stack */
	if (stackItem)
	{
		stack_pop(stackItem->stackId);
#if PG_VERSION_NUM < 90500
		stack_free(stackItem);
#endif
	}
}

/*
 * Hook object_access_hook to provide fully-qualified object names for function
 * calls.
 */
static void
audit_object_access_hook(ObjectAccessType access,
                            Oid classId,
                            Oid objectId,
                            int subId,
                            void *arg)
{
	AUDIT_DEBUG_LOG("audit_object_access_hook");

	if (access == OAT_FUNCTION_EXECUTE &&
			auditEventStack && !IsAbortedTransactionBlockState())
	{
		log_function_execute(objectId);
	}

	if (next_object_access_hook)
	{
		(*next_object_access_hook)(access, classId, objectId, subId, arg);
	}
}

/*
 *  This hook is called at the end of execution of the query plan
 *
 *  used for correctly managing the stack in PostgreSQL version before 9.5.0
 *  thus register this hook only for required versions (refer to _PG_init)
 */
#if PG_VERSION_NUM < 90500
static void
audit_ExecutorEnd_hook(QueryDesc *queryDesc)
{
	AUDIT_DEBUG_LOG("audit_ExecutorEnd_hook");

	if (queryDesc == NULL)
	{
		AUDIT_DEBUG_LOG("WARNING: queryDesc is NULL");
		return;
	}

	// audit_ExecutorStart_hook did stack_push
	// so need to stack_free it (stack_pop only handles the MemoryContext, not the stack management)
	stack_free(auditEventStack);

	// trigger next hook, if any
	if (next_ExecutorEnd_hook)
	{
		(*next_ExecutorEnd_hook)(queryDesc);
	}
	else
	{
		standard_ExecutorEnd(queryDesc);
	}
}
#endif

/*
 * Originally this hook is for intercepting messages before they are sent to PostgreSQL log server.
 *
 * Here it is used to audit invalid statements (statements that contains syntax errors),
 * Or statements which cause an ERROR and abortion of current transaction.
 *
 * Implementing this hook is required since in these cases of invalid statements
 * none of the other hooks is triggered (for invalid syntax)
 * or execution is stopped in the middle
 * (for example, ProcessUtility_hook execution can be break if trying to DROP AGGREGATE which doesnt exist)
 *
 * Of course, you must NOT call elog() from this hook (otherwise will cause an infinite loop)
 *
 */

static void
audit_emit_log_hook(ErrorData *edata)
{
	if (edata == NULL || internalStatement || edata->elevel < WARNING)
	{
		if (next_emit_log_hook)
			(*next_emit_log_hook)(edata);
		return;
	}

	/*
	 * - auditEventStack exists
	 * - an error during execution of a valid query
	 */
	if (auditEventStack)
	{
		AuditError* error = (AuditError*)palloc(sizeof(*error));
		error->sqlerrcode = edata->sqlerrcode;
		error->message = edata->message;
		auditEventStack->auditEvent.errorList = lappend(auditEventStack->auditEvent.errorList, error);

		// logging an ERROR is throwig an exception
		// the query will not be processed futher and no further hooks will be called
		// the event needs to be generated here
		if (edata->elevel >= ERROR)
			log_audit_event(auditEventStack);
	}

	/*
	 * - auditEventStack does not exist
	 * - debug_query_string exists
	 * - there is a query, but there was an error already before the query started executing
	 */
	else if (debug_query_string)
	{
		AuditError* error = (AuditError*)palloc(sizeof(*error));
		error->sqlerrcode = edata->sqlerrcode;
		error->message = strdup(edata->message);

		AuditEventStackItem *stackItem = NULL;

		stackItem = stack_push();
		stackItem->auditEvent.errorList = lappend(stackItem->auditEvent.errorList, error);

		// Default values
		stackItem->auditEvent.logStmtLevel = LOGSTMT_ALL;
		stackItem->auditEvent.commandTag = T_Invalid;
#if PG_VERSION_NUM >= 130000
		stackItem->auditEvent.command = commandTagToString(CMDTAG_UNKNOWN);
#else
		stackItem->auditEvent.command = COMMAND_INVALID_SYNTAX;
#endif
		stackItem->auditEvent.commandText = debug_query_string;

		log_audit_event(stackItem);
	}

	/*
	 * - auditEventStack does not exist
	 * - debug_query_string does not exist
	 * - an error in the session itself
	 */
	else
	{
		const ProcError error = {
			edata->sqlerrcode
			,edata->message
		};
		g_proc.error_list.push_back(error);

		// ensure sensor event if auth hook got bypased
		const int cat = ERRCODE_TO_CATEGORY(edata->sqlerrcode);
		if (!g_proc.initialized && cat == ERRCODE_INVALID_AUTHORIZATION_SPECIFICATION) {
			initHandlers(MyProcPort, &g_proc);
			updateProc(&g_proc, MyProcPort);
			g_proc.initialized = true;
			json_file_handler.set_enable(json_file_handler_enable);
			json_unix_socket_handler.set_enable(json_unix_socket_handler_enable);
			// Done with configuration, the actual logging will be done by run_at_exit()
		}
	}

	// clean-up
	// should be OK, since for these log levels PG abort the transaction (at least)
	if (edata->elevel >= ERROR)
	{
		auditEventStack = NULL;
		internalStatement = false;
		substatementTotal = 0;
		statementLogged = false;
		stackTotal = 0;
	}

	// trigger next hook, if any
	if (next_emit_log_hook)
	{
		(*next_emit_log_hook)(edata);
	}

}


/*
 * Event trigger functions
 */

/*
 * Supply additional data for (non drop) statements that have event trigger
 * support and can be deparsed.
 *
 * Drop statements are handled below through the older sql_drop event trigger.
 */
Datum
pgaudit_ddl_command_end(PG_FUNCTION_ARGS)
{
	AUDIT_DEBUG_LOG("pgaudit_ddl_command_end");

	EventTriggerData *eventData;
	int result;
	unsigned int row;
	TupleDesc spiTupDesc;
	const char *query;
	MemoryContext contextQuery;
	MemoryContext contextOld;

	/* Be sure the module was loaded */
	if (auditEventStack == NULL)
	{
		// not using log level WARNING directly, so log message will not be presented to client but only to server log
		AUDIT_WARNING_LOG("audit not loaded before call to "
				"pgaudit_ddl_command_end()");
		PG_RETURN_NULL();
	}

	/* This is an internal statement - do not log it */
	internalStatement = true;

	/* Make sure the fuction was fired as a trigger */
	if (!CALLED_AS_EVENT_TRIGGER(fcinfo))
	{
		// not using log level WARNING directly, so log message will not be presented to client but only to server log
		AUDIT_WARNING_LOG("not fired by event trigger manager");
		PG_RETURN_NULL();
	}

	/* Switch memory context for query */
	contextQuery = AllocSetContextCreate(
			CurrentMemoryContext,
			"pgaudit_func_ddl_command_end temporary context",
#if PG_VERSION_NUM >= 110000
			ALLOCSET_DEFAULT_SIZES);
#else
			ALLOCSET_DEFAULT_MINSIZE,
			ALLOCSET_DEFAULT_INITSIZE,
			ALLOCSET_DEFAULT_MAXSIZE);
#endif
	contextOld = MemoryContextSwitchTo(contextQuery);

	/* Get information about triggered events */
	eventData = (EventTriggerData *) fcinfo->context;

	auditEventStack->auditEvent.logStmtLevel =
#ifndef EDB_ENTERPRISE
		GetCommandLogLevel(eventData->parsetree);
#else // Build "EDB Postgres Enterprise" variant
		LOGSTMT_NONE; // Prevent unnecessary logic activation in log_audit_event()
#endif
	auditEventStack->auditEvent.commandTag =
		nodeTag(eventData->parsetree);
	auditEventStack->auditEvent.command =
		commandTagToString(CreateCommandTag(eventData->parsetree));

	/* Return objects affected by the (non drop) DDL statement */
	query = "SELECT UPPER(object_type), object_identity, UPPER(command_tag)\n"
		"  FROM pg_catalog.pg_event_trigger_ddl_commands()";

	/* Attempt to connect */
	result = SPI_connect();
	if (result < 0)
	{
		elog(ERROR, "pgaudit_ddl_command_end: SPI_connect returned %d",
				result);
	}

	/* Execute the query */
	result = SPI_execute(query, true, 0);
	if (result != SPI_OK_SELECT)
	{
		elog(ERROR, "pgaudit_ddl_command_end: SPI_execute returned %d",
				result);
	}

	/* Iterate returned rows */
	spiTupDesc = SPI_tuptable->tupdesc;
	for (row = 0; row < SPI_processed; row++)
	{
		HeapTuple    spiTuple;

		spiTuple = SPI_tuptable->vals[row];

		/* Supply object name and type for audit event */
		auditEventStack->auditEvent.objectType =
			SPI_getvalue(spiTuple, spiTupDesc, 1);
		auditEventStack->auditEvent.objectName =
			SPI_getvalue(spiTuple, spiTupDesc, 2);
		auditEventStack->auditEvent.command =
			SPI_getvalue(spiTuple, spiTupDesc, 3);

		auditEventStack->auditEvent.logged = false;

		/*
		 * Identify grant/revoke commands - these are the only non-DDL class
		 * commands that should be coming through the event triggers.
		 */
		if (pg_strcasecmp(auditEventStack->auditEvent.command, COMMAND_GRANT) == 0 ||
				pg_strcasecmp(auditEventStack->auditEvent.command, COMMAND_REVOKE) == 0)
		{
			NodeTag currentCommandTag = auditEventStack->auditEvent.commandTag;

			auditEventStack->auditEvent.commandTag = T_GrantStmt;
			log_audit_event(auditEventStack);

			auditEventStack->auditEvent.commandTag = currentCommandTag;
		}
		else
		{
			log_audit_event(auditEventStack);
		}
	}

	/* Complete the query */
	SPI_finish();

	MemoryContextSwitchTo(contextOld);
	MemoryContextDelete(contextQuery);
#if PG_VERSION_NUM < 90500
	stack_free(auditEventStack);
#endif

	/* No longer in an internal statement */
	internalStatement = false;

	PG_RETURN_NULL();
}

/*
 * Supply additional data for drop statements that have event trigger support.
 */
Datum
pgaudit_sql_drop(PG_FUNCTION_ARGS)
{
	AUDIT_DEBUG_LOG("pgaudit_sql_drop");

	int result;
	unsigned int row;
	TupleDesc spiTupDesc;
	const char *query;
	MemoryContext contextQuery;
	MemoryContext contextOld;

	/* Be sure the module was loaded */
	if (auditEventStack == NULL)
	{
		// not using log level WARNING directly, so log message will not be presented to client but only to server log
		AUDIT_WARNING_LOG("audit not loaded before call to "
				"audit_sql_drop()");
		PG_RETURN_NULL();
	}

	/* This is an internal statement - do not log it */
	internalStatement = true;

	/* Make sure the fuction was fired as a trigger */
	if (!CALLED_AS_EVENT_TRIGGER(fcinfo))
	{
		// not using log level WARNING directly, so log message will not be presented to client but only to server log
		AUDIT_WARNING_LOG("not fired by event trigger manager");
		PG_RETURN_NULL();
	}

	/* Switch memory context for the query */
	contextQuery = AllocSetContextCreate(
			CurrentMemoryContext,
			"pgaudit_func_ddl_command_end temporary context",
#if PG_VERSION_NUM >= 110000
			ALLOCSET_DEFAULT_SIZES);
#else
			ALLOCSET_DEFAULT_MINSIZE,
			ALLOCSET_DEFAULT_INITSIZE,
			ALLOCSET_DEFAULT_MAXSIZE);
#endif
	contextOld = MemoryContextSwitchTo(contextQuery);

	/* Return objects affected by the drop statement */
	query = "SELECT UPPER(object_type),\n"
		"       object_identity\n"
		"  FROM pg_catalog.pg_event_trigger_dropped_objects()\n"
		" WHERE lower(object_type) <> 'type'\n"
		"   AND schema_name <> 'pg_toast'";

	/* Attempt to connect */
	result = SPI_connect();
	if (result < 0)
	{
		// not using log level WARNING directly, so log message will not be presented to client but only to server log
		AUDIT_WARNING_LOG("pgaudit_ddl_drop: SPI_connect returned %d",
				result);
		PG_RETURN_NULL();
	}

	/* Execute the query */
	result = SPI_execute(query, true, 0);
	if (result != SPI_OK_SELECT)
	{
		// not using log level WARNING directly, so log message will not be presented to client but only to server log
		AUDIT_WARNING_LOG("pgaudit_ddl_drop: SPI_execute returned %d",
				result);
		PG_RETURN_NULL();
	}

	/* Iterate returned rows */
	spiTupDesc = SPI_tuptable->tupdesc;
	for (row = 0; row < SPI_processed; row++)
	{
		HeapTuple    spiTuple;

		spiTuple = SPI_tuptable->vals[row];

		auditEventStack->auditEvent.objectType =
			SPI_getvalue(spiTuple, spiTupDesc, 1);
		auditEventStack->auditEvent.objectName =
			SPI_getvalue(spiTuple, spiTupDesc, 2);

		auditEventStack->auditEvent.logged = false;
		log_audit_event(auditEventStack);
	}

	/* Complete the query */
	SPI_finish();

	MemoryContextSwitchTo(contextOld);
	MemoryContextDelete(contextQuery);
#if PG_VERSION_NUM < 90500
	stack_free(auditEventStack);
#endif

	/* No longer in an internal statement */
	internalStatement = false;

	PG_RETURN_NULL();
}

////////////////////////// end of pgaudit code //////////////////////////////

// generate /var/tmp/audit/<portNumber>_<serverVersion>_<auditVersion>_<auditProtocolVersion> file
void generate_version_file()
{
	AUDIT_DEBUG_LOG("generate_version_file");

	memset(version_filename, 0, 256);

	const char* location = "/var/tmp/isecg_audit";

	// server version, get from configuration variable
	const char *server_version = GetConfigOption("server_version", false, false);

	sprintf(version_filename, "%s/%d_%s_%s_%s",
			location,
			PostPortNumber,
			server_version,
			audit_version,
			audit_protocol_version);

	AUDIT_DEBUG_LOG("plugin version_filename: [%s]", version_filename);

	if (mkdir(location, 0777) < 0 && errno != EEXIST)
	{
#if PG_VERSION_NUM >= 120000
		const char *error_string = strerror(errno);
		ereport(WARNING, (errcode(ERRCODE_IO_ERROR),
				errmsg(
				"%s Error mkdir: [%s]",
				AUDIT_ERROR_PREFIX, error_string)));
#else
		AUDIT_ERROR_LOG("Error mkdir: [%s]", strerror(errno));
#endif
	}
	(void) chmod(location, 0777);

	FILE *fp = fopen(version_filename, "w");
	if (NULL == fp)
	{
#if PG_VERSION_NUM >= 120000
		const char *error_string = strerror(errno);
		ereport(WARNING, (errcode(ERRCODE_IO_ERROR),
				errmsg(
				"%s Error creating file: [%s]",
				AUDIT_ERROR_PREFIX, error_string)));
#else
		AUDIT_ERROR_LOG("Error creating file: [%s]", strerror(errno));
#endif
	}
	else
	{
		fclose(fp);
	}
	(void) chmod(version_filename, 0777);
}


void remove_version_file()
{
	if (postmaster_pid == getpid())
	{
		AUDIT_DEBUG_LOG("deleting plugin version file..");
		remove(version_filename);
	}
}

static ProcError synthesize_failed_login(const Port *port)
{
	const char *errstr;
	int errcode_return = ERRCODE_INVALID_AUTHORIZATION_SPECIFICATION;

	switch (port->hba->auth_method) {
	case uaReject:
	case uaImplicitReject:
		errstr = gettext_noop("authentication failed for user \"%s\": host rejected");
		break;
	case uaTrust:
		errstr = gettext_noop("\"trust\" authentication failed for user \"%s\"");
		break;
	case uaIdent:
		errstr = gettext_noop("Ident authentication failed for user \"%s\"");
		break;
	case uaPeer:
		errstr = gettext_noop("Peer authentication failed for user \"%s\"");
		break;
	case uaPassword:
	case uaMD5:
#if PG_VERSION_NUM >= 100000
	case uaSCRAM:
#endif
		errstr = gettext_noop("password authentication failed for user \"%s\"");
		/* We use it to indicate if a .pgpass password failed. */
		errcode_return = ERRCODE_INVALID_PASSWORD;
		break;
	case uaGSS:
		errstr = gettext_noop("GSSAPI authentication failed for user \"%s\"");
		break;
	case uaSSPI:
		errstr = gettext_noop("SSPI authentication failed for user \"%s\"");
		break;
	case uaPAM:
		errstr = gettext_noop("PAM authentication failed for user \"%s\"");
		break;
#if PG_VERSION_NUM >= 90600
	case uaBSD:
		errstr = gettext_noop("BSD authentication failed for user \"%s\"");
		break;
#endif
	case uaLDAP:
		errstr = gettext_noop("LDAP authentication failed for user \"%s\"");
		break;
	case uaCert:
		errstr = gettext_noop("certificate authentication failed for user \"%s\"");
		break;
	case uaRADIUS:
		errstr = gettext_noop("RADIUS authentication failed for user \"%s\"");
		break;
	default:
		errstr = gettext_noop("authentication failed for user \"%s\": invalid authentication method");
		break;
	}

	char* error_message = NULL;
	const int res = asprintf(&error_message, errstr, port->user_name);
	if (res == -1)
		error_message = NULL;

	const ProcError error = {errcode_return, error_message ? error_message : "<not enough memory to generate error message>"};
	free(error_message);

	return error;
}


/* Module initialization */

/*
 * Define GUC variables and install hooks upon module load.
 */
extern "C" {

static void
run_at_exit(void)
{
	AUDIT_DEBUG_LOG("%d run_at_exit running", getpid());

	// libpq goes to stright exit on STATUS_EOF, without logging the error.
	// Regenerate the error code here.
	if (g_proc.auth_status == STATUS_EOF && !g_proc.connected && g_proc.user[0] && g_proc.error_list.empty())
		g_proc.error_list.push_back(synthesize_failed_login(MyProcPort));

	// log disconnect here
	g_proc.query_id++;
	Audit_handler::log_audit_disconnect();
	g_proc = PostgreSQL_proc();  // clear it out, AFTER any final logging

	// release allocated memory (allocated directly by malloc/strdup
	// and not part of PG MemoryContext)
	if (whitelist_cmds_array != NULL)
	{
		if (whitelist_cmds_array[0] != NULL)
		{
			free(whitelist_cmds_array[0]);
			whitelist_cmds_array[0] = NULL;
		}

		free(whitelist_cmds_array);
		whitelist_cmds_array = NULL;
	}

	// Shut everything down
	Audit_handler::stop_all();

	remove_version_file();
}

#ifndef GUC_DISALLOW_IN_AUTO_FILE
#define GUC_DISALLOW_IN_AUTO_FILE 0
#endif

void
_PG_init(void)
{
	if (log_min_messages > WARNING) {
		const char* old_min_name = "???";
		if (log_min_messages == FATAL) old_min_name = "FATAL";
		if (log_min_messages == PANIC) old_min_name = "PANIC";
		if (log_min_messages == ERROR) old_min_name = "ERROR";
		log_min_messages = WARNING;
		AUDIT_DEBUG_LOG("Lowering log_min_messages from [%s] to [WARNING] as required by error code collection.", old_min_name);
	}
	/* Must be loaded with shared_preload_libaries */
	if (IsUnderPostmaster)
	{
		ereport(ERROR, (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
					errmsg("audit must be loaded via shared_preload_libraries")));
	}

	postmaster_pid = getpid();
	elog(LOG, "%s _PG_init starting, pid = %d", AUDIT_LOG_PREFIX, postmaster_pid);

	// init the handlers
	json_formatter.m_perform_password_masking = check_do_password_masking;

	int res = json_file_handler.init(&json_formatter);
	if (res != 0)
	{
		// best guess at error code
		ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_RESOURCES),
				errmsg(
				"%s unable to init json file handler. res: %d. Aborting.",
				AUDIT_LOG_PREFIX, res)));
	}
	res = json_unix_socket_handler.init(&json_formatter);
	if (res != 0)
	{
		// best guess at error code
		ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_RESOURCES),
				errmsg(
				"%s unable to init json socket handler. res: %d. Aborting.",
				AUDIT_LOG_PREFIX, res)));
	}

	/* Define audit.json_file */
	DefineCustomBoolVariable(
			"audit.json_file",
			"Specifies that audit should log JSON messages to a file.",
			NULL,
			&json_file_handler_enable,
			false,
			PGC_SUSET,
			GUC_NOT_IN_SAMPLE,
			NULL, NULL, NULL);

	/* Define audit.json_file_flush */
	DefineCustomBoolVariable(
			"audit.json_file_flush",

			"Specifies that audit should flush the log file.",

			NULL,
			&json_file_handler_flush,
			true,
			PGC_SUSET,
			GUC_NOT_IN_SAMPLE,
			NULL,
			assign_json_file_flush,
			NULL);


	/* Define audit.json_file_name */
	DefineCustomStringVariable(
			"audit.json_file_name",
			"Specifies the name of the file to which audit should send JSON "
			"messages when audit_json_file is true",
			NULL,
			& json_file_handler.m_io_dest,
			DEFAULT_JSON_FILENAME,
			PGC_SUSET,
			GUC_NOT_IN_SAMPLE,
			check_json_file_name,
			NULL,
			NULL);

	/* Define audit_json_unix_socket */
	DefineCustomBoolVariable(
			"audit.json_unix_socket",
			"Specifies that audit should log JSON messages to a UNIX domain socket.",
			NULL,
			&json_unix_socket_handler_enable,
			false,
			PGC_SUSET,
			GUC_NOT_IN_SAMPLE,
			NULL, NULL, NULL);

	/* Define audit.json_unix_socket_name */
	DefineCustomStringVariable(
			"audit.json_unix_socket_name",
			"Specifies the pathname of the socket to which audit should send JSON "
			"messages when audit_json_unix_socket is true",
			NULL,
			& json_unix_socket_handler.m_io_dest,
			Audit_utils::plugin_socket_name(),	// default value
			PGC_SUSET,
			GUC_NOT_IN_SAMPLE,
			check_json_unix_socket_name,
			NULL,
			NULL);

	AUDIT_DEBUG_LOG("Set json_socket_name value: [%s]",
		json_unix_socket_handler.m_io_dest ?  json_unix_socket_handler.m_io_dest : "null");

	/* Define audit_header_msg */
	DefineCustomBoolVariable(
			"audit.header_msg",
			"Specifies that audit should write a header start message at start "
			"of logging or file flush. Default enabled.",
			NULL,
			&json_formatter.m_write_start_msg,
			true,
			PGC_SUSET,
			GUC_NOT_IN_SAMPLE,
			NULL, NULL, NULL);

	/* Define audit.password_masking_regex */
	DefineCustomStringVariable(
			"audit.password_masking_regex",
			"Specifies the PCRE compliant regex for password masking",
			NULL,
			&password_masking_regex,
			default_pw_masking_regex,
			PGC_SUSET,
			GUC_NOT_IN_SAMPLE,
			check_password_masking_regex,
			NULL,
			NULL);

	/* Define audit.audit_version */
	DefineCustomStringVariable(
			"audit.audit_version",
			"Indicates the version and revision of the  audit plugin",
			NULL,
			& audit_version_ptr,
			audit_version,
			PGC_SUSET,
			GUC_NOT_IN_SAMPLE |  GUC_DISALLOW_IN_FILE | GUC_DISALLOW_IN_AUTO_FILE,
			check_audit_version,
			NULL,
			NULL);

	/* Define audit.audit_version */
	DefineCustomStringVariable(
			"audit.audit_protocol_version",
			"Indicates the protocol version of the audit plugin",
			NULL,
			& audit_protocol_version_ptr,
			audit_protocol_version,
			PGC_SUSET,
			GUC_NOT_IN_SAMPLE |  GUC_DISALLOW_IN_FILE | GUC_DISALLOW_IN_AUTO_FILE,
			check_audit_protocol_version,
			NULL,
			NULL);

	/* Define audit.whitelist_cmds */
	DefineCustomStringVariable(
			"audit.whitelist_cmds",
			"Comma separated list of commands for which queries are not recorded",
			NULL,
			& whitelist_cmds_ptr,
			"BEGIN,END,COMMIT",
			PGC_SUSET,
			GUC_NOT_IN_SAMPLE | GUC_DISALLOW_IN_AUTO_FILE,
			check_whitelist_cmds,
			assign_whitelist_cmds,
			NULL);

	// Backwards compatibility with earlier plugin:
	/* Define isecgaudit.audit_version */
	DefineCustomStringVariable(
			"isecgaudit.audit_version",
			"Indicates the version and revision of the  audit plugin",
			NULL,
			& audit_version_ptr,
			audit_version,
			PGC_SUSET,
			GUC_NOT_IN_SAMPLE |  GUC_DISALLOW_IN_FILE | GUC_DISALLOW_IN_AUTO_FILE,
			check_audit_version,
			NULL,
			NULL);

	// Backwards compatibility with earlier plugin:
	/* Define isecgaudit.audit_version */
	DefineCustomStringVariable(
			"isecgaudit.audit_protocol_version",
			"Indicates the protocol version of the audit plugin",
			NULL,
			& audit_protocol_version_ptr,
			audit_protocol_version,
			PGC_SUSET,
			GUC_NOT_IN_SAMPLE |  GUC_DISALLOW_IN_FILE | GUC_DISALLOW_IN_AUTO_FILE,
			check_audit_protocol_version,
			NULL,
			NULL);

	// Backwards compatibility with earlier plugin:
	/* Define isecgaudit.json_unix_socket_name */
	DefineCustomStringVariable(
			"isecgaudit.json_unix_socket_name",
			"Specifies the pathname of the socket to which audit should send JSON "
			"messages when audit_json_unix_socket is true",
			NULL,
			& dummy_json_unix_socket_name,
			json_unix_socket_handler.m_io_dest,	// default value from real
			PGC_SUSET,
			GUC_NOT_IN_SAMPLE |  GUC_DISALLOW_IN_FILE | GUC_DISALLOW_IN_AUTO_FILE,
			NULL,
			NULL,
			NULL);

	/*
	 * enable/disable audit debug logging
	 *
	 * Note:
	 * plugin logs using PostgreSQL elog(),
	 * thus need to define also matching elog configuration (see PG documentation)
	 */
	DefineCustomBoolVariable(
			"audit.debug_logs",
			"Enable/disable audit plugin debug logging. Default: disabled",
			NULL,
			&audit_logging,
			false,
			PGC_SUSET,
			GUC_NOT_IN_SAMPLE,
			NULL,
			NULL,
			NULL);

	// Don't enable here, but rather in each server process forked from postmater
	Audit_handler::m_audit_handler_list[Audit_handler::JSON_FILE_HANDLER] = &json_file_handler;
	Audit_handler::m_audit_handler_list[Audit_handler::JSON_UNIX_SOCKET_HANDLER] = &json_unix_socket_handler;

	/*
	 * Install our hook functions after saving the existing pointers to
	 * preserve the chains.
	 */
	next_ExecutorStart_hook = ExecutorStart_hook;
	ExecutorStart_hook = audit_ExecutorStart_hook;

	next_ExecutorCheckPerms_hook = ExecutorCheckPerms_hook;
	ExecutorCheckPerms_hook = audit_ExecutorCheckPerms_hook;

	next_ProcessUtility_hook = ProcessUtility_hook;
	ProcessUtility_hook = audit_ProcessUtility_hook;

	next_object_access_hook = object_access_hook;
	object_access_hook = audit_object_access_hook;

	next_ClientAuthentication_hook = ClientAuthentication_hook;
	ClientAuthentication_hook = audit_ClientAuthentication_hook;

#if PG_VERSION_NUM < 90500
	next_ExecutorEnd_hook = ExecutorEnd_hook;
	ExecutorEnd_hook = audit_ExecutorEnd_hook;
#endif

	next_emit_log_hook = emit_log_hook;
	emit_log_hook = audit_emit_log_hook;

	generate_version_file();

	atexit(run_at_exit);

	/* Log that the extension has completed initialization */
	ereport(LOG, (errmsg("Intel Security postgresql-audit extension initialized")));
}

};
