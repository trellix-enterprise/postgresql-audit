# postgresql-audit
Audit plugin for PostgreSQL<sup>*</sup> database.

A PostgreSQL plugin from McAfee providing audit capabilities for the Open Source releases
of PostgreSQL, designed with an emphasis on security and audit requirements. The plugin may be used
as a standalone audit solution or configured to feed data to external monitoring tools.


Installation and Configuration
------------------------------

Official McAfee plugin binary releases can be downloaded from the Releases page on GitHub:
https://github.com/mcafee/postgresql-audit/releases

Please refer to the wiki on GitHub for detailed installation and configuration instructions:
https://github.com/mcafee/postgresql-audit/wiki

Issues
------------------------------

Found a bug? Got a feature request or question?

Please feel free to report to: https://github.com/mcafee/postgresql-audit/issues

If reporting a bug, please describe the problem verbosely. Try to see if it reproduces and
include a detailed description on how to reproduce.

Make sure to include your PostgreSQL Server version and Audit Plugin version.
To print PostgreSQL Server version: log into PostgreSQL and execute the command:

    select version();

Please include with the bug thePostgreSSQL error log.
Log file location is configured in the postgresql.conf configuration
file.  You can see the log destination (syslog, a file or something else)
using the command

     show log_destination;

Source Code
-------------------------------
Source code is available at: https://github.com/mcafee/postgresql-audit


License
-------------------------------
Copyright (C) 2016-2021 McAfee, LLC.

This program is free software; you can redistribute it and/or modify it under the terms of the GNU
General Public License as published by the Free Software Foundation; version 2 of the License.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See the GNU General Public License for more details.

See COPYING file for a copy of the GPL Version 2 license.

<sup>*</sup> Other trademarks and brands may be claimed as the property of others.
