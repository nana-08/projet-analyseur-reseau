# PROJET ANALYSEUR RESEAU OFFLINE
# 2021-2022
# LOONA MACABRE & CARLA GIULIANI 


from io import TextIOWrapper
from textwrap import wrap
from typing import Protocol
import codecs


def analyseEthernet (trame:str, res:TextIOWrapper):
    dest = trame[:18].replace(' ',':')
    src = trame[18:36].replace(' ',':')
    dest = dest[:len(dest)-1]
    src = src[:len(src)-1]
    ethertype = trame[36:41].replace(' ','')
    
    if  ethertype == "0800" :
        ethertype += " (IPv4)\n"
    if  ethertype == "86DD" :
        ethertype += " (IPv6)\n"
    if  ethertype == "0805" :
        ethertype += " (X.25 lvl 3)\n"
    if  ethertype == "0806" :
        ethertype += " (ARP)\n"
    if  ethertype == "8035" :
        ethertype += " (RARP)\n"
    if  ethertype == "8098" :
        ethertype += " (Appletalk)\n"
    if  ethertype == "88CD" :
        ethertype += " (SERCOS III)\n"
    if  ethertype == "0600" :
        ethertype += " (XNS)\n"
    if  ethertype == "8100" :
        ethertype += " (VLAN)\n"

    res.write("Ethernet Header:\n\tDestination MAC Address: "+dest+"\n\tSource MAC Address: "+src+"\n\tEtherType : 0x"+ethertype)
    return trame[42:], ethertype


def sur16bits(B:str):
    return '0b'+(18-len(B))*'0'+B[2:]


def analyseIP(trame:str, res:TextIOWrapper):
    version, ihl, tos = (trame[0], trame[1], int(trame[3]+trame[4], 16))
    totalLen = trame[6:11].replace(' ','')
    id =trame[12:17].replace(' ','')
    flagANDfragOff = bin(int(trame[18:23].replace(' ','')))
    if (len(flagANDfragOff) < 18):
        flagANDfragOff = sur16bits(flagANDfragOff)
    df, mf = (flagANDfragOff[2], flagANDfragOff[3])
    fragOffset=flagANDfragOff[4:]
    ttl=trame[24:26]
    protocol=trame[27:29]
    checksum=trame[30:35].replace(' ','')
    tmpSrc, tmpDest = trame[36:47].split(), trame[48:59].split()
    for i in range(0, 4):
        tmpSrc[i] = str(int(tmpSrc[i], 16))
        tmpDest[i] = str(int(tmpDest[i], 16))
    src, dest = '.'.join(tmpSrc), '.'.join(tmpDest)

    if protocol == "01":
        protocol += " (ICMP)"
    if protocol == "02":
        protocol += " (IGMP)"
    if protocol == "06":
        protocol += " (TCP)"
    if protocol == "08":
        protocol += " (EGP)"
    if protocol == "09":
        protocol += " (IGP)"
    if protocol == "11":
        protocol += " (UDP)"
    if protocol == "24":
        protocol += " (XTP)"
    if protocol == "2E" :
        protocol += ' (RSVP)'

    res.write("IP Header:\n\tVersion: "+version+"\n\tIHL: 0x"+ihl+" ("+str(int(ihl, 16)*4)+" o)\n\tTOS: "+\
        str(tos)+"\n\tTotal Length: 0x"+totalLen+" ("+str(int(totalLen, 16))+" o)\n\tIdentification: 0x"+\
        id+"\n\tFlags: 0 | DF = "+df+" | MF = "+mf+"\n\tFragment Offset: "+str(int(fragOffset, 2))+"\n\tTTL: "+\
        str(int(ttl, 16))+"\n\tProtocol: 0x"+protocol+"\n\tHeader Checksum: 0x"+checksum+"\n\tSource IP Address: "+\
        src+"\n\tDestination IP Address: "+dest)

    i=0
    j=60
    if int(ihl, 16) > 5:
        lenOptPad = int(ihl, 16)*4 - 20
        res.write("\n\tOptions:\n\tTotal option+padding length: "+str(lenOptPad)+" o")
        optTot = 0
        while i<lenOptPad:
            opt = trame[j]+trame[j+1]
            optLen = int(trame[j+3]+trame[j+4], 16)
            optTot += optLen
            if opt == "00":
                break
            if opt == "01":
                opt += ": No Operation (NOP)"
            if opt == "07":
                opt += ": Record Route (RR)"
            if opt == "44":
                opt += ": Time Stamp (TS)"
            if opt == "83":
                opt += ": Loose Source Route (LSR)"
            if opt == "89":
                opt += ": Strict Source Route (SSR)"

            opt += "\n\t\tOption Length: "+str(optLen)+" o"
            res.write("\n\t\t"+opt)
            j+=optLen*3
            i+=optLen
        pad = lenOptPad-optTot
        res.write("\n\t\tPadding: "+str(pad)+" o\n")
    
    return trame[int(ihl,16)*4*3:], protocol


def analyseUDP(trame:str, res:TextIOWrapper):
    psrc= trame[:5].replace(' ','')
    pdest= trame[6:11].replace(' ','')
    leng= trame[12:17].replace(' ','')
    checksum=trame[18:23].replace(' ','')

    res.write("\nUDP Header:\n\tSource Port: 0x"+psrc+ "\n\tDestination Port: 0x"+pdest+ "\n\tLength: "+leng+" ("+str(int(leng, 16))+" o)\n\tChecksum: "+checksum+"\n")
    
    return trame[24:], psrc, pdest
    

def Name(trame,position,res,chaine):
    pos=position
    x=trame[pos:pos+2]
    mot=''
    name=chaine
    y=0

    while (x!="00") & (x!='C0'):
        y=int(x,16)
        pos=pos+3
        tmp=trame[pos:pos+y*3-1].replace(' ','')
        pos=pos+y*3
        mot=codecs.decode(tmp,'hex')
        mot=str(mot,'utf-8')
        name+=mot+'.'
        x=trame[pos:pos+2]

    if x=='C0':
        x=trame[pos+3:pos+5]
        y=int(x,16)
        x=trame[y*3:y*3+2]
        pos=y*3
        Name(trame, pos, res, name)
        return position+3

    name = name[:len(name)-1] #on enleve le dernier point
    res.write(name+"\n")
    return pos


def whichType(typ:str):
    if typ == "0001":
        return "A"
    if typ == "0005":
        return "CNAME"
    if typ == "0002":
        return "NS"
    if typ == "000F":
        return "MX"
    if typ == "001C":
        return "AAAA"


def analyseDNS(trame:str, res:TextIOWrapper):
    #entête
    id="".join(trame[:5].split())
    control="".join(trame[6:11].split())
    Nbquestions=int(trame[12:17].replace(' ',''), 16)
    NbreponsesRRs=int(trame[18:23].replace(' ',''), 16)
    NbautoriteRRs=int(trame[24:29].replace(' ',''), 16)
    NbadditionalRRs=int(trame[30:35].replace(' ',''), 16)
    
    res.write("DNS Header:\n\tTransaction ID: 0x"+id+"\n\tControl: 0x"+control+"\n\tQuestions: "+str(Nbquestions)+"\n\tAnswers RRs: "+str(NbreponsesRRs)+"\n\tAuthority RRs: "+str(NbautoriteRRs)+"\n\tAdditional RRs: "+str(NbadditionalRRs)+"\n")

    #QUESTIONS
    position=36
    Typeq=""
    Classq=""
    res.write("\tQueries:\n")
    for i in range(0,Nbquestions):
        res.write("\t\t"+str(i+1)+") Name: ")
        position=Name(trame,position,res,"")
        Typeq=trame[position+3:position+8].replace(' ','')
        Classq=trame[position+9:position+14].replace(' ','')
        res.write("\t\t\tType: "+whichType(Typeq)+ "\n\t\t\tClass: "+str(int(Classq,16))+'\n')
        position=position+15
    
    #RESPONSES
    Typer=""
    Classr=""
    TTLr=""
    R_DATA_LENGHTr=""
    R_DATAr=""
    res.write("\tAnswers:")
    for i in range(0,NbreponsesRRs):
        res.write("\n\t\t"+str(i+1)+") Name: ")
        position=Name(trame,position,res,"")
        Typer=trame[position+3:position+8].replace(' ','')
        Classr=trame[position+9:position+14].replace(' ','')
        TTLr=trame[position+15:position+26].replace(' ','')
        R_DATA_LENGHTr=trame[position+27:position+32].replace(' ','')
        res.write("\t\t\tType: "+whichType(Typer)+ "\n\t\t\tClass: "+ str(int(Classr,16))+"\n\t\t\tTTL: " + str(int(TTLr,16)) + " s\n\t\t\tData Length: "+ str(int(R_DATA_LENGHTr,16)) + " o\n\t\t\tData: ")
        if Typer == "0001": #type A
            tmpR_DATAr=trame[position+33:position+33+int(R_DATA_LENGHTr,16)*3].split()
            for i in range(0, 4):
                tmpR_DATAr[i] = str(int(tmpR_DATAr[i], 16))
            R_DATAr = '.'.join(tmpR_DATAr)
            res.write(R_DATAr+"\n")
        elif Typer == "001C": #type AAAA
            tmpR_DATAr=trame[position+33:position+33+int(R_DATA_LENGHTr,16)*3].replace(' ','')
            R_DATAr = tmpR_DATAr[:4]+":"+tmpR_DATAr[5:9]+":"+tmpR_DATAr[10:14]+"::"+tmpR_DATAr[28:]
            res.write(R_DATAr+"\n")
        else:
            Name(trame,position+33,res,"")
        
        position=position+33+int(R_DATA_LENGHTr, 16)*3

    #AUTHORITÉ
    Typea=""
    Classa=""
    TTLa=""
    R_DATA_LENGHTa=""
    R_DATAa=""
    res.write("\tAuthoritative Nameservers:\n")
    for i in range(0,NbautoriteRRs):
        res.write("\t\t"+str(i+1)+") Name: ")
        position=Name(trame,position,res,"")
        Typea=trame[position+3:position+8].replace(' ','')
        Classa=trame[position+9:position+14].replace(' ','')
        TTLa=trame[position+15:position+26].replace(' ','')
        R_DATA_LENGHTa=trame[position+27:position+32].replace(' ','')
        res.write("\t\t\tType: "+whichType(Typea)+ "\n\t\t\tClass: "+ str(int(Classa,16))+"\n\t\t\tTTL: " + str(int(TTLa,16)) + " s\n\t\t\tData Length: "+ str(int(R_DATA_LENGHTa,16)) + " o\n\t\t\tData: ")
        if Typea == "0001": #type A
            tmpR_DATAa=trame[position+33:position+33+int(R_DATA_LENGHTa,16)*3].split()
            for i in range(0, 4):
                tmpR_DATAa[i] = str(int(tmpR_DATAa[i], 16))
            R_DATAa = '.'.join(tmpR_DATAa)
            res.write(R_DATAa+"\n")
        elif Typea == "001C": #type AAAA
            tmpR_DATAa=trame[position+33:position+33+int(R_DATA_LENGHTa,16)*3].replace(' ','')
            R_DATAa = tmpR_DATAa[:4]+":"+tmpR_DATAa[5:9]+":"+tmpR_DATAa[10:14]+"::"+tmpR_DATAa[28:]
            res.write(R_DATAa+"\n")
        else:
            Name(trame,position+33,res,"")
        position=position+33+int(R_DATA_LENGHTa, 16)*3

    #ADDITIONAL INFO
    Typeai=""
    Classai=""
    TTLai=""
    R_DATA_LENGHTai=""
    R_DATAai=""
    res.write("\tAdditional Records:\n")
    for i in range(0,NbadditionalRRs):
        res.write("\t\t"+str(i+1)+") Name: ")
        position=Name(trame,position,res,"")
        Typeai=trame[position+3:position+8].replace(' ','')
        Classai=trame[position+9:position+14].replace(' ','')
        TTLai=trame[position+15:position+26].replace(' ','')
        R_DATA_LENGHTai=trame[position+27:position+32].replace(' ','')
        res.write("\t\t\tType: "+ whichType(Typeai)+ "\n\t\t\tClass: "+str(int(Classai,16)) +"\n\t\t\tTTL: " +str(int(TTLai,16)) + " s\n\t\t\tData Length: "+ str(int(R_DATA_LENGHTai,16)) + " o\n\t\t\tData: ")
        if Typeai == "0001": #type A
            tmpR_DATAai=trame[position+33:position+33+int(R_DATA_LENGHTai,16)*3].split()
            for i in range(0, 4):
                tmpR_DATAai[i] = str(int(tmpR_DATAai[i], 16))
            R_DATAai = '.'.join(tmpR_DATAai)
            res.write(R_DATAai+"\n")
        elif Typeai == "001C": #type AAAA
            tmpR_DATAai=trame[position+33:position+33+int(R_DATA_LENGHTai,16)*3].replace(' ','')
            R_DATAai = tmpR_DATAai[:4]+":"+tmpR_DATAai[5:9]+":"+tmpR_DATAai[10:14]+"::"+tmpR_DATAai[28:]
            res.write(R_DATAai+"\n")
        else:
            Name(trame,position+33,res,"")
        position=position+33+int(R_DATA_LENGHTai,16)*3


def analyseDHCP(trame:str, res:TextIOWrapper):
    op = trame[:2] 
    hwType = trame[3:5]
    hwAddLen = trame[6:8]
    hops = trame[9:11]
    id = trame[12:23].replace(' ','')
    nbSec = trame[24:29].replace(' ','')
    flags = trame[30:35].replace(' ','')
    if flags == '8000':
        flags += " (Broadcast)"
    else:
        flags += " (Unicast)"

    tmpclIP, tmpurIP, tmpservIP, tmpgwIP = trame[36:47].split(), trame[48:59].split(), trame[60:71].split(), trame[72:83].split()
    for i in range(0, 4):
        tmpclIP[i] = str(int(tmpclIP[i], 16))
        tmpurIP[i] = str(int(tmpurIP[i], 16))
        tmpservIP[i] = str(int(tmpservIP[i], 16))
        tmpgwIP[i] = str(int(tmpgwIP[i], 16))
    clIP, urIP, servIP, gwIP = '.'.join(tmpclIP), '.'.join(tmpurIP), '.'.join(tmpservIP), '.'.join(tmpgwIP)
    
    clMAC = trame[84:101].replace(' ',':') 
    clHW = clMAC+" (Padding: "+trame[102:131].replace(' ','')+")" # 6 premiers octets = adresse mac client, 10 suivants = padding
    a = trame[132:323].replace(' ','')
    b = trame[324:707].replace(' ','')
    if a != len(a)*'0':
        tmpServHN = bytes.fromhex(a)
        servHostName = tmpServHN.decode("ASCII")
    else:
        servHostName = "not given"

    if b != len(b)*'0':
        tmpBootFN = bytes.fromhex(b)
        bootFName = tmpBootFN.decode("ASCII")
    else:
        bootFName = "not given"

    res.write("DHCP Header:\n\tOpcode: 0x"+op+"\n\tHardware Type: "+str(int(hwType,16))+"\n\tHardware Address Length: "+\
        str(int(hwAddLen,16))+"\n\tHops: "+str(int(hops,16))+"\n\tTransaction ID: 0x"+id+"\n\tSeconds elapsed: "+str(int(nbSec, 16))\
        +"\n\tFlags: 0x"+flags+"\n\tClient IP Address: "+clIP+"\n\tYour IP Address: "+urIP+"\n\tServer IP Address: "+\
        servIP+"\n\tGateway IP Address: "+gwIP+"\n\tClient Hardware Address: "+clHW+"\n\tServer Host Name: "+servHostName+\
        "\n\tBoot File Name: "+bootFName+"\n")

    # options DHCP commence a 720. on prend la suite de la trame sous forme de liste
    trameListe = trame[720:].split()
    i = 0
    while trameListe[i] != 'FF':
        opt = "Option: ("+str(int(trameListe[i],16))+")"
        optLen = int(trameListe[i+1], 16)
        if trameListe[i] == '35': # Option: (53) Message Type
            opt += " DHCP Message Type"
            messType = trameListe[i+2]
            if messType == '01':
                opt += " (DISCOVER)"
                messType += " DISCOVER"
            if messType == '02':
                opt += " (OFFER)"
                messType += " OFFER"
            if messType == '03':
                opt += " (REQUEST)"
                messType += " REQUEST"
            if messType == '04':
                opt += " (DECLINE)"
                messType += " DECLINE"
            if messType == '05':
                opt += " (ACK)"
                messType += " ACK"
            if messType == '06':
                opt += " (NAK)"
                messType += " NAK"
            if messType == '07':
                opt += " (RELEASE)"
                messType += " RELEASE"
            if messType == '08':
                opt += " (INFORM)"
                messType += " INFORM"
            res.write("\t"+opt+"\n\t\tLength: "+str(optLen)+"\n")
            res.write("\t\tDHCP: "+messType+"\n")
        elif trameListe[i] == '3D': #client identifier
            opt += " Client Identifier ("+clMAC+")"
            res.write("\t"+opt+"\n\t\tLength: "+str(optLen)+"\n\t\tHardware Type: "+trameListe[i+2]+"\n\t\tClient MAC Address: "+clMAC+"\n")
        elif trameListe[i] == "36": #server identifier
            tmpID = trameListe[i+2:i+6]
            for j in range(0, 4):
                tmpID[j] = str(int(tmpID[j], 16))
            servID = '.'.join(tmpID)
            opt += " DHCP Server Identifier ("+servID+")"
            res.write("\t"+opt+"\n\t\tLength: "+str(optLen)+"\n\t\tDHCP Server Identifier: "+servID+"\n")
        elif trameListe[i] == "01": #subnet mask
            tmpMask = trameListe[i+2:i+6]
            for j in range(0, 4):
                tmpMask[j] = str(int(tmpMask[j], 16))
            mask = '.'.join(tmpMask)
            opt += " Subnet Mask ("+mask+")"
            res.write("\t"+opt+"\n\t\tLength: "+str(optLen)+"\n\t\tSubnet Mask: "+mask+"\n")
        elif trameListe[i] == "03": #router
            tmpRout = trameListe[i+2:i+6]
            for j in range(0, 4):
                tmpRout[j] = str(int(tmpRout[j], 16))
            rout = '.'.join(tmpRout)
            opt += " Router"
            res.write("\t"+opt+"\n\t\tLength: "+str(optLen)+"\n\t\tRouter: "+rout+"\n")
        elif trameListe[i] == "06": #dns
            tmpDNS = trameListe[i+2:i+6]
            for j in range(0, 4):
                tmpDNS[j] = str(int(tmpDNS[j], 16))
            dns = '.'.join(tmpDNS)
            opt += " Domain Name Server"
            res.write("\t"+opt+"\n\t\tLength: "+str(optLen)+"\n\t\tDomain Name Server: "+dns+"\n")
        elif trameListe[i] == "0C":
            HNtmp = bytes.fromhex("".join(trameListe[i+2:i+optLen+2]))
            hostname = HNtmp.decode("ASCII")
            opt += " Host Name"
            res.write("\t"+opt+"\n\t\tLength: "+str(optLen)+"\n\t\tHost Name: "+hostname+"\n")
        else:
            res.write("\t"+opt+"\n\t\tLength: "+str(optLen)+"\n")
            optContenu = ""
            j = i+2
            while j<i+2+optLen:
                optContenu += trameListe[j]
                j+=1
            res.write("\t\t0x"+optContenu+"\n")
        i+=optLen+2
    res.write("\tOption: (255) End\n\t\tOption End: 255\n")