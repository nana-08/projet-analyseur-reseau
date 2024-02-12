# PROJET ANALYSEUR RESEAU OFFLINE
# 2021-2022
# LOONA MACABRE & CARLA GIULIANI 


from io import TextIOWrapper
from Errors import *

def lectureTrame(f:TextIOWrapper):
    #etape 1 : on lit l'integralite du fichier et on stocke ligne par ligne
    lignes = []
    for line in f:
        line = line.upper()
        l = line.strip()
        l = l.split(maxsplit=1)
        if len(l) == 2:
            lignes.append(l)

    ## GESTION DES ERREURS
    # 1) ERREURS D'OFFSET + VALEURS TEXTUELLES ENTRE LES LIGNES/TRAMES
    # 2) SEPARATION DES TRAMES : ERREURS DE LIGNE INCOMPLETE + VALEURS TEXTUELLES EN FIN DE LIGNE

    tramesOffsetOK = []        
    i=1
    for ligneCour in lignes :
        try:
            offsetVerif(ligneCour[0], ligneCour[1])
            tramesOffsetOK.append(ligneCour)
            i+=1
        except OffsetInvalide as exc1:
            print(OffsetInvalide.__doc__, " : ", exc1,"\nPosition : ligne "+str(i)+".")
            return
        
    tramesLignesOK = tramesOffsetOK
    for ligne in tramesOffsetOK:
        #valeurs textuelles
        for c in ligne[0]:
            if (c not in "ABCDEF0123456789") & (c != ' '):
                tramesLignesOK.remove(ligne)
                break

    i=0
    for ligne in tramesLignesOK[1:]:
        lignePrec = tramesLignesOK[i][1]
        offsetP = int(tramesLignesOK[i][0], 16)
        offsetC = int(ligne[0], 16)
        try:
            ligneVerif(offsetC, offsetP, lignePrec)
            i+=1
        except LigneIncomplete as exc2:
            print(LigneIncomplete.__doc__, " : ", exc2,"\nPosition : ligne "+str(i)+".")
            return

    # -> determine le nombre de trames dans le fichier
    # + la taille de chacune et les stocke dans une liste
    nbT = 0
    taillesTrames = []
    lenT = 0
    for l in tramesLignesOK :
        if int(l[0], 16) == 0:
            nbT+=1
            taillesTrames.append(lenT)
            lenT=0
        lenT+=1
    taillesTrames.append(lenT)
    taillesTrames.remove(0)
    print ("Il y a "+str(nbT)+" trame(s) a analyser.")

    #but : concatener toutes les suites d'octets d'une trame dans une seule chaine de caracteres
    res = [] #res est une liste de listes de str (trames sans offset)
    tmpRes = ""
    i=1
    j=0
    k=1
    longueur=0
    for t in tramesLignesOK:
        if i<len(tramesLignesOK):
            offset = tramesLignesOK[i][0]
        new = t[1].split()
        longueur+=len(new)
        if (int(offset, 16) < longueur) & (k<taillesTrames[j]):
            longueur-=len(new)
            new = new[:int(offset,16)-int(t[0], 16)]
            longueur+=len(new)
        tmp = " ".join(new)
        tmpRes += ' '+tmp
        tmpRes = tmpRes.strip()
        if k==taillesTrames[j]:
            res.append(tmpRes)
            tmpRes = ""
            longueur=0
            k=0
            j+=1
        i+=1
        k+=1
    return res


def ecrireTrame(T:str, res:TextIOWrapper):
    i = 0
    offset = 0
    while i<len(T):
        res.write(hex(offset)+' ')
        if (i+47)<len(T):
            res.write(T[i:i+47])
        else:
            res.write(T[i:])
        i+=48
        offset+=16
        res.write('\n')
