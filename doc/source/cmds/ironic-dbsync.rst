=============
ironic-dbsync
=============

The :command:`ironic-dbsync` utility is used to create the database schema
tables that the ironic services will use for storage. It can also be used to
upgrade (or downgrade) existing database tables when migrating between
different versions of ironic.

The `Alembic library <http://alembic.readthedocs.org>`_ is used to perform
the database migrations.

Options
=======

This is a partial list of the most useful options. To see the full list,
run the following::

  ironic-dbsync --help

.. program:: ironic-dbsync

.. option:: -h, --help

  Show help message and exit.

.. option:: --config-dir <DIR>

  Path to a config directory with configuration files.

.. option:: --config-file <PATH>

  Path to a configuration file to use.

.. option:: -d, --debug

  Print debugging output.

.. option:: -v, --verbose

  Print more verbose output.

.. option:: --version

  Show the program's version number and exit.

.. option:: upgrade, downgrade, stamp, revision, version, create_schema

  The :ref:`command <dbsync_cmds>` to run.

Usage
=====

Options for the various :ref:`commands <dbsync_cmds>` for
:command:`ironic-dbsync` are listed when the :option:`-h` or :option:`--help`
option is used after the command.

For example::

  ironic-dbsync create_schema --help

Information about the database is read from the ironic configuration file
used by the API server and conductor services. This file must be specified
with the :option:`--config-file` option::

  ironic-dbsync --config-file /path/to/ironic.conf create_schema

The configuration file defines the database backend to use with the
*connection* database option::

  [database]
  connection=mysql://root@localhost/ironic

If no configuration file is specified with the :option:`--config-file` option,
:command:`ironic-dbsync` assumes an SQLite database.

.. _dbsync_cmds:

Command Options
===============

:command:`ironic-dbsync` is given a command that tells the utility what actions
to perform. These commands can take arguments. Several commands are available:

.. _create_schema:

create_schema
-------------

.. program:: create_schema

.. option:: -h, --help

  Show help for create_schema and exit.

This command will create database tables based on the most current version.
It assumes that there are no existing tables.

An example of creating database tables with the most recent version::

  ironic-dbsync --config-file=/etc/ironic/ironic.conf create_schema

downgrade
---------

.. program:: downgrade

.. option:: -h, --help

  Show help for downgrade and exit.

.. option:: --revision <REVISION>

  The revision number you want to downgrade to.

This command will revert existing database tables to a previous version.
The version can be specified with the :option:`--revision` option.

An example of downgrading to table versions at revision 2581ebaf0cb2::

  ironic-dbsync --config-file=/etc/ironic/ironic.conf downgrade --revision 2581ebaf0cb2

revision
--------

.. program:: revision

.. option:: -h, --help

  Show help for revision and exit.

.. option:: -m <MESSAGE>, --message <MESSAGE>

  The message to use with the revision file.

.. option:: --autogenerate

  Compares table metadata in the application with the status of the database
  and generates migrations based on this comparison.

This command will create a new revision file. You can use the
:option:`--message` option to comment the revision.

This is really only useful for ironic developers making changes that require
database changes. This revision file is used during database migration and
will specify the changes that need to be made to the database tables. Further
discussion is beyond the scope of this document.

stamp
-----

.. program:: stamp

.. option:: -h, --help

  Show help for stamp and exit.

.. option:: --revision <REVISION>

  The revision number.

This command will 'stamp' the revision table with the version specified with
the :option:`--revision` option. It will not run any migrations.

upgrade
-------

.. program:: upgrade

.. option:: -h, --help

  Show help for upgrade and exit.

.. option:: --revision <REVISION>

  The revision number to upgrade to.

This command will upgrade existing database tables to the most recent version,
or to the version specified with the :option:`--revision` option.

If there are no existing tables, then new tables are created, beginning
with the oldest known version, and successively upgraded using all of the
database migration files, until they are at the specified version. Note
that this behavior is different from the :ref:`create_schema` command
that creates the tables based on the most recent version.

An example of upgrading to the most recent table versions::

  ironic-dbsync --config-file=/etc/ironic/ironic.conf upgrade

.. note::

  This command is the default if no command is given to
  :command:`ironic-dbsync`.

.. warning::

  The upgrade command is not compatible with SQLite databases since it uses
  ALTER TABLE commands to upgrade the database tables. SQLite supports only
  a limited subset of ALTER TABLE.

version
-------

.. program:: version

.. option:: -h, --help

  Show help for version and exit.

This command will output the current database version.
