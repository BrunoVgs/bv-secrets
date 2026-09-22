"""Le dashboard depose ses jobs par la primitive du coeur.

Garde le module pour ne pas changer les appelants, mais la logique vit dans
`bvsecrets.spool` : l'ecouteur HTTP du worker depose exactement de la meme facon,
et deux copies auraient diverge.
"""
from bvsecrets.spool import job_result, queue as _queue, requests_dir, results_dir

REQ = requests_dir()
RES = results_dir()


def queue(**fields):
    return _queue(src="web", **fields)


__all__ = ["queue", "job_result", "REQ", "RES"]
