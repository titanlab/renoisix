CC = gcc
CFLAGS = -I. -O0
LDFLAGS = -L. -lX11 -lXi
OBJ = main.o map.o

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

renoisix: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)
