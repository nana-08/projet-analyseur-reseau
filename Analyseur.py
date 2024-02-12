# PROJET ANALYSEUR RESEAU OFFLINE
# 2021-2022
# LOONA MACABRE & CARLA GIULIANI 


from Analyse import *
from Trame import *

print("\n\n---------- ANALYSEUR DE PROTOCOLES RESEAU OFFLINE ----------\nLoona Macabre, Carla Giuliani -- 2021-2022 -- L3 Sorbonne Universite\n")
resultats = open("Resultats_analyse.txt", "w")
while True:
    try:
        nomF = input("---------- Entrez le nom de la trace a analyser : ")
        trace = open(nomF, "r")
        trames = lectureTrame(trace)
        if trames:
            print("\n-----> Vous trouverez les resultats de l'analyse dans le fichier nomme\n'Resultats_analyse.txt', figurant dans le repertoire ou vous avez\nenregistre notre programme.\n")
            i = 0
            while i<len(trames):
                #affichage de la trame courante
                resultats.write('---------- Trame '+str(i+1)+' ----------\n')
                ecrireTrame(trames[i], resultats)
                #analyse Ethernet
                suite, typ = analyseEthernet(trames[i], resultats)
                if typ == "0800 (IPv4)\n" :
                    suite, proto = analyseIP(suite, resultats)
                    if proto == "11 (UDP)":
                        suite, psrc, pdest = analyseUDP(suite, resultats)
                        if ((psrc == '0043')&(pdest == '0044'))|((psrc == '0044')&(pdest == '0043')):
                            analyseDHCP(suite, resultats)
                        elif (psrc == '0035')|(pdest == '0035'):
                            analyseDNS(suite, resultats)
                resultats.write('\n')
                i+=1
        else:
            print("L'analyse n'a pas pu aboutir. Veuillez entrer des trames valides.")

        trace.close()
    except FileNotFoundError as exc:
        print(FileNotFoundError.__doc__, " : ", exc,"\n\nERREUR : Veuillez saisir un nom de fichier valide.")
        continue
    break
print("\n------------------------------------------------------------\n")