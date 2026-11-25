Combination preflight
=====================

The offline combination preflight resolves the transitive dependency closure
of a candidate set of already verified targets and checks the caller interface
and configuration declarations. It performs no network or filesystem I/O.

Use :func:`tuf.ngclient.combination.preflight_combination`, the
:class:`tuf.ngclient.combination.CombinationPreflight` class, or
:meth:`tuf.ngclient.Updater.preflight_combination`.

Module declarations are read from the target ``custom`` field. See the module
documentation for the accepted schema and for the structured conflict result.

.. automodule:: tuf.ngclient.combination
   :members:
