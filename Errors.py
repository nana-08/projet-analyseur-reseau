# PROJET ANALYSEUR RESEAU OFFLINE
# 2021-2022
# LOONA MACABRE & CARLA GIULIANI 


class OffsetInvalide(Exception):
    """/!\ ERREUR - Offset invalide"""
    pass

class LigneIncomplete(Exception):
    """/!\ ERREUR - Ligne incomplete"""
    pass

def offsetVerif(offset:str, octets:str):
    """
    Verifie la validite de l'offset -> si invalide leve une exception 
    """
    test2 = False #ce n'est pas une erreur liee a l'ecriture de l'offset mais juste a sa taille
    for elem in offset:
        if (elem not in "0123456789ABCDEF"):
            test2 = True #l'erreur provient de l'ecriture de l'offset
            #on verifie que c'est un probleme d'offset et pas juste une ligne textuelle a ignorer
            # => suite d'octets valide
            sp = octets.split()
            test = True #oui, c'est une erreur d'offset
            for elem in sp:
                if (len(elem) != 2):
                    for elem2 in elem:
                        if elem2 not in "0123456789ABCDEF":
                            #la suite d'octet n'est pas valide non plus -> c'est juste une ligne textuelle
                            test = False #non, ce n'est en fait pas une erreur d'offset
                            break
                    if test == False:
                        break
            if test:
                raise OffsetInvalide(offset)
    if (len(offset) < 6) & (test2 == False): #bien ecrit mais taille inf a 3 o
        raise OffsetInvalide(offset)

def ligneVerif(offsetC:int, offsetP:int, lignePrec:str):
    """
    Verifie si la ligne est complete -> sinon, on leve une exception
    """
    if len(lignePrec.split()) < offsetC-offsetP:
        raise LigneIncomplete(lignePrec)
