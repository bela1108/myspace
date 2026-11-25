def test_reconcile_module_imports():
    from pip_audit._reconcile import LockReconciler

    assert LockReconciler is not None
