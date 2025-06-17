# makefile per compilare oneTimeXOR.c in modo statico

# compilatore e flag
CC = gcc

# flag di compilazione
CFLAGS = -Wall -Wextra -std=c99 -O2

# flag di link: l'ordine è importante:
# iniziamo con -Wl,-Bstatic per dire al linker di preferire le librerie statiche;
# poi elenchiamo le librerie di OpenSSL (-lssl -lcrypto);
# concludiamo con -Wl,-Bdynamic per tornare al linking dinamico per le librerie di sistema;
# aggiungiamo -ldl -lpthread che sono dipendenze di OpenSSL;
LDFLAGS = -Wl,-Bstatic -lssl -lcrypto -Wl,-Bdynamic -ldl -lpthread

# nome dell'eseguibile finale
TARGET = onetimexor

# file sorgente
SRCS = oneTimeXOR.c

# regola predefinita: compila il programma
all: $(TARGET)

# regola per creare l'eseguibile
$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRCS) $(LDFLAGS)
	@echo "Compilazione statica completata. Eseguibile: $(TARGET)"

# regola per pulire i file generati
clean:
	rm -f $(TARGET)
	@echo "File generati eliminati."

# target fittizi
.PHONY: all clean
