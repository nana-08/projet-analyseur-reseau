Loona Macabre 28609645\
Carla Giuliani 28605022
************************************************************

Structure du code de l’analyseur


Notre analyseur est codé en python et composé de 4 fichiers sources :

* Errors.py 
- notre gestionnaire d’erreurs : il permet de lever des exceptions pour les erreurs qui requièrent un traitement particulier comme les offsets invalides (mal écrits ou de taille inférieure à 3 octets) ou les lignes incomplètes. Lorsqu’une exception est levée, le programme s’interrompt avec un message d’erreur décrivant la cause et la position du problème.
Remarque : il peut y avoir plusieurs erreurs dans le les trames entrées par l’utilisateur. L'exception levée sera uniquement la première sur laquelle tombe le programme. 
 
* Trame.py 
- importe Errors.py et décrit deux fonctions de lecture et écriture dans un fichier. C’est dans ce fichier que toutes les possibles erreurs seront détectées, au niveau de la fonction de lecture de trames. Cette fonction permet de nettoyer les trames en entrée avant de les analyser, voire d’interrompre le programme dans le cas d’erreurs plus graves.

* Analyse.py 
- fichier où sont décrites toutes les fonctions d’analyse de chacune des couches. Chaque fonction écrit son analyse dans le fichier résultats, de façon formatée.

* Analyseur.py 
- fichier exécutable : c’est lui qui lance le programme et qui interagit avec l’utilisateur. Il commence par demander à l’utilisateur le nom du fichier contenant la (les) trame(s) à analyser puis, s' il existe, procède à la lecture de la trame et si aucune erreur n’est détectée alors il lance une à une les analyses de chaque protocole. Si le protocole n’est pas traité par notre analyseur, alors le programme arrêtera son analyse à la couche précédente.


A l’issue de l’analyse, le fichier texte Resultats_analyse.txt est créé : il s’agit du fichier où sont enregistrées les analyses formatées des différents protocoles, précédées de la trame affichée avec un offset de 16 octets pour chaque ligne, à la manière de Wireshark.