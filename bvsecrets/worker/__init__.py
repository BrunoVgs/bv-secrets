"""Spool worker — privileged execution of jobs dropped by the web UI.

Nothing is imported here: the service runs `-m bvsecrets.worker.loop`, and eagerly
importing `.loop` would load the module twice (once as a package submodule, once as
__main__).
"""
