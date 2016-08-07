extern "C" {
/*
 * An AuditEvent represents an operation that potentially affects a single
 * object.  If a statement affects multiple objects then multiple AuditEvents
 * are created to represent them.
 */

// Revised to use C++ conventions - struct xxx instead of typedef struct xxx{ ... } xxx;
struct AuditEvent
{
    int64 statementId;          /* Simple counter */
    int64 substatementId;       /* Simple counter */

    LogStmtLevel logStmtLevel;  /* From GetCommandLogLevel when possible,
                                   generated when not. */
    NodeTag commandTag;         /* same here */
    const char *command;        /* same here */
    const char *objectType;     /* From event trigger when possible,
                                   generated when not. */
    char *objectName;           /* Fully qualified object identification */
    const char *commandText;    /* sourceText / queryString */
    ParamListInfo paramList;    /* QueryDesc/ProcessUtility parameters */

    bool granted;               /* Audit role has object permissions? */
    bool logged;                /* Track if we have logged this event, used
                                   post-ProcessUtility to make sure we log */
    bool statementLogged;       /* Track if we have logged the statement */

    const char *className;      /* Class of item being logged */
    List *objectList;           /* List of objects, e.g. in a DROP statement */
    bool useLastInList;         /* True if last element in list is the object name */
};

/*
 * A simple FIFO queue to keep track of the current stack of audit events.
 */
struct AuditEventStackItem
{
    struct AuditEventStackItem *next;

    AuditEvent auditEvent;

    int64 stackId;

    MemoryContext contextAudit;
#if PG_VERSION_NUM >= 90500
    MemoryContextCallback contextCallback;
#endif
};
};
