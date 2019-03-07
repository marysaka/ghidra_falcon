NAME := faucon

all: $(NAME)_fw.h

$(NAME)_fw.bin: $(NAME).asm
	envyas -m falcon -V fuc5 -F crypt $? -i -o $@

$(NAME)_fw.h: $(NAME)_fw.bin
	bin2c -o $@ $?

print_dis: $(NAME)_fw.bin
	envydis -i $? -m falcon -V fuc5 -F crypt -n

clean:
	rm -f $(NAME)_fw.h $(NAME)_fw.bin