CLANG = clang

TARGET = hello

BPFPRO = bpf_hello



LIBRARY_PATH = -L/usr/src/5.19.0-35-generic/tools/lib/bpf/
LDFLAGS = -lbpf


all: $(TARGET)

build: ${BPFCODE.c} 
	$(CLANG) -O2 -target bpf -c $(BPFPRO:=.c) $(CCINCLUDE) -o ${BPFPRO:=.o}

$(TARGET): build
	clang $(CFLAGS) -Wall -O2  hello.c -static    $(LIBRARY_PATH)   $(LDFLAGS) -lelf -lz -o $(TARGET) 

clean:
	rm -f *.o  $(TARGET)
