"""Worker du spool — exécution privilégiée des jobs déposés par l'UI web.

Rien n'est importé ici : le service lance `-m bvsecrets.worker.loop`, et un import
anticipé de `.loop` ferait charger le module deux fois (une comme sous-module du
paquet, une comme __main__).
"""
