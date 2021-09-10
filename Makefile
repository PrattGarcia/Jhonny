BIN = bins/
SRC = sources/
INCL = headers/
LIBS= library/
EXEC = encrypter

all: $(BIN) $(EXEC)

$(BIN):
	mkdir -p $(BIN)

$(EXEC): $(BIN)bm.o $(BIN)sha256.o $(BIN)aes.o $(BIN)blowfish.o $(BIN)$(EXEC).o
	gcc $(DFLAGS) -Wall -o $@ $(BIN)bm.o $(BIN)sha256.o $(BIN)aes.o $(BIN)blowfish.o $(BIN)$(EXEC).o 

$(BIN)%.o: $(SRC)%.c $(INCL)bm.h $(INCL)sha256.h $(INCL)aes.h $(INCL)blowfish.h
	gcc $(DFLAGS) -Wall -c -o $@ $< -iquote $(INCL)

$(BIN)%.o: $(LIBS)%.c $(INCL)%.h
	gcc $(DFLAGS) -Wall -c -o $@ $< -iquote $(INCL)

.PHONY: all clean sanitize debug 

debug: DFLAGS = -g
debug: clean $(BIN) $(EXEC)

# Compila habilitando la herramienta AddressSanitizer para
# facilitar la depuración en tiempo de ejecución.
sanitize: DFLAGS = -fsanitize=address,undefined
sanitize: clean $(BIN) $(EXEC)

clean:
	rm -f $(BIN)* $(EXEC)

