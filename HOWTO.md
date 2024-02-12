Loona Macabre 28609645\
Carla Giuliani 28605022
************************************************************

Guide d’installation/exécution du programme


* Installation : 

L’analyseur ne possède pas d’interface graphique, il faudra l’exécuter depuis le terminal. Il suffit donc de télécharger et décompresser le dossier contenant le code source.


* Exécution :

Avant de suivre les instructions suivantes, il faut veiller à ce que les trames à analyser soient écrites dans un fichier, et que celui-ci soit présent dans le dossier où l’analyseur a été enregistré.

1. Dans un terminal, se placer dans le répertoire où a été enregistré le programme;

2. Exécuter la commande suivante :
        python Analyseur.py

3. Le programme est lancé : il vous demande alors de rentrer le nom du fichier dans lequel sont écrites la ou les trame(s) à analyser. Si le fichier n’existe pas, le programme vous demandera de saisir le nom du fichier à nouveau, jusqu’à ce qu’il le trouve;

4. Suite à l’exécution de la commande ci-dessus, un fichier texte nommé Resultats_analyse.txt a été créé et enregistré dans le répertoire courant. Il s’agit des résultats de l’analyse de la ou des trames entrées.
/!\ Si une exception a été levée, le programme n’a pas pu aboutir auquel cas le fichier Resultats_analyse.txt sera vide.