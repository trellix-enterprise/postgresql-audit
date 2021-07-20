# Contributing to postresql-audit

Welcome, and thank you for your interest in contributing to postresql-audit!


## Asking Questions

Have a question? </br> 
We accept questions as issues on GitHub.</br>
https://github.com/mcafee/postgresql-audit/issues


## Providing Feedback

Have some feedback? We would love to hear it!</br>
Open an issue and let us know what you think.</br>
https://github.com/mcafee/postgresql-audit/issues


## Reporting Issues
Found a bug? Got a feature request or question?

Please feel free to report to: https://github.com/mcafee/postgresql-audit/issues

### Look For an Existing Issue

Before you create a new issue, please do a search in [open issues](https://github.com/mcafee/postgresql-audit/issues) to see if the issue or feature request has already been filed.

If you find your issue already exists, make relevant comments and add your [reaction](https://github.com/blog/2119-add-reactions-to-pull-requests-issues-and-comments). Use a reaction in place of a "+1" comment:

* 👍 - upvote
* 👎 - downvote

If you cannot find an existing issue that describes your bug or feature, create a new issue using the guidelines below.

### Writing Good Bug Reports and Feature Requests

Be sure to include a **title and clear description** with as much information as possible.

If reporting a bug, please describe the problem verbosely. Try to see if it reproduces and
include a detailed description on how to reproduce.

Make sure to include your PostgreSQL Server version and Audit Plugin version.
To print PostgreSQL Server version: log into PostgreSQL and execute the command:

    select version();

Please include with the bug the PostgreSQL error log.
Log file location is configured in the postgresql.conf configuration
file.  You can see the log destination (syslog, a file or something else)
using the command

     show log_destination;

## Contributing 

* Open a new GitHub pull request with a patch - name the patch something along the lines of `{contributor-name}-short-description`
* Ensure the pull request description clearly describes the problem/fix and solution.  Include the relevant issue number if applicable.
* Follow the coding and documentation conventions in the existing project.  Pull requests that simply reformat or restructure the content will not be accepted.


# Thank You!

Your contributions to open source, large or small, make great projects like this possible. Thank you for taking the time to contribute.

