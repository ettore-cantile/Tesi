import json
import numpy as np  #utilizzato per gestire gli array e effettuare operazioni in modo più efficiente
import time  # Importa il modulo time

def intermedio(byte_pt, byte_chiave_ipotetica, sbox):
    # Restituisce il valore dell'S-box per il byte del plaintext e l'ipotesi di chiave
    return sbox[byte_pt ^ byte_chiave_ipotetica] #si ottiene tramite operazione XOR

def modello_potenza(valore_intermedio):
    # Calcola il peso di Hamming del valore intermedio
    return np.sum(np.unpackbits(np.array([valore_intermedio], dtype=np.uint8)))

def calcola_correlazione_ipotetica(byte_chiave_ipotetica, indice_byte, tracce, plaintexts, sbox):
    # Precalcolo del modello di utilizzo della potenza per ogni plaintext
    modello_utilizzato = np.array([
        modello_potenza(intermedio(plaintext[indice_byte], byte_chiave_ipotetica, sbox))
        for plaintext in plaintexts
    ])

    # Conversione delle tracce in un array numpy
    tracce = np.array(tracce)

    # Calcolo delle correlazioni per ogni punto di misura nelle tracce
    correlazioni = []
    for indice_punto in range(tracce.shape[1]):   #si sceglie il punto di misura della traccia
        misurazioni = tracce[:, indice_punto]   #si estrae il punto di misura corrente da tutte le tracce, si genera un array di misurazioni
        if np.std(misurazioni) != 0:  # si verifica che la deviazione standard sia diversa da 0.
            correlazioni.append(
                np.abs(np.corrcoef(modello_utilizzato, misurazioni)[0, 1]) #permette il calcolo di media e deviazione standard in un'unica operazione
            )           #si considera il valore assoluto tramite .abs
        else:
            correlazioni.append(0)

    # Restituisce la correlazione massima trovata
    return np.max(correlazioni)

def trova_byte_chiave_corretto(indice_byte, tracce, plaintexts, sbox):
    # Inizializza la correlazione massima e la chiave corrispondente al valore massimo
    coefficiente_massimo, miglior_chiave_ipotetica = 0, 0

    # Prova ogni possibile valore del byte della chiave (0-255)
    for byte_chiave_ipotetica in range(256):
        coefficiente_ipotetico = calcola_correlazione_ipotetica(byte_chiave_ipotetica, indice_byte, tracce, plaintexts, sbox)
        if coefficiente_ipotetico > coefficiente_massimo:
            coefficiente_massimo, miglior_chiave_ipotetica = coefficiente_ipotetico, byte_chiave_ipotetica

    # Restituisce il miglior ipotesi di chiave e la correlazione associata
    return miglior_chiave_ipotetica, coefficiente_massimo

def trova_chiave(tracce, plaintexts, sbox):
    chiave = []

    # Analizza ogni byte della chiave (16 byte in totale)
    for indice in range(16):
        chiave_ipotetica, coefficiente = trova_byte_chiave_corretto(indice, tracce, plaintexts, sbox)
        chiave.append((chiave_ipotetica, coefficiente))
        #vengono create due liste per le stampe
        print(f"Coefficienti: {[f'{x[1]:.2f}' for x in chiave]}") # con x[i] ci riferiamo all'i-esimo elemento della lista
        print(f"Chiave ipotetica: {[f'0x{x[0]:02x}' for x in chiave]}") #formattazione che stampa le chiavi ipotetiche in formato esadecimale

    # al termine del for si restituisce la chiave completa
    return [x[0] for x in chiave]

def main():
    #si fa partire il tempo
    start_time = time.time()
    # Carica i plaintext e le tracce dal file JSON
    with open('traces.json') as f:
        dati = json.load(f)

    plaintexts = dati["plaintexts"]
    tracce = dati["traces"]

    # Definizione della S-box, tabella di 256 valori che può essere utile per la sostituzione dei byte nelle operazioni di cifratura e decifratura
    sbox = (
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    )

    # Chiave effettiva utilizzata dall'algoritmo, la quale viene stampata sempre in formato esadecimale con il prefisso 0x
    chiave_effettiva = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c]
    print(f"Chiave effettiva: {[f'0x{x:02x}' for x in chiave_effettiva]}")

    # Recupero della chiave
    chiave_recuperata = trova_chiave(tracce, plaintexts, sbox)
    print(f"Chiave recuperata: {[f'0x{x:02x}' for x in chiave_recuperata]}")   
    
    end_time = time.time()

    # Calcola e stampa il tempo di esecuzione
    execution_time = end_time - start_time
    print(f"Tempo di esecuzione: {execution_time:.2f} secondi") #formattazione a due decimali
    
 #si impiegano circa 23 minuti per eseguire il codice e recuperare la chiave, la quale differisce per 3 byte, ma si può sfruttare un attacco brute force per ottenerli.
if __name__ == "__main__":
    main()
    
   