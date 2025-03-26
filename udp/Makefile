# Define the compiler
CC = gcc

# Define the source files and output names
COMMON_SRC = crypt.c udp.c
ALICE_SRC = alice.c $(COMMON_SRC)
ALICE_OUT = alice
BOB_SRC = bob.c $(COMMON_SRC)
BOB_OUT = bob

# Target to build alice
$(ALICE_OUT): $(ALICE_SRC)
	$(CC) -o $(ALICE_OUT) $(ALICE_SRC)

# Target to build bob
$(BOB_OUT): $(BOB_SRC)
	$(CC) -o $(BOB_OUT) $(BOB_SRC)

# Clean up generated files
clean:
	rm -f $(ALICE_OUT) $(BOB_OUT)
