CC = gcc
DBUG = -g
CCFLAGS = -O2 -Wall -pedantic
OBJFILES = main.o rsa.o utils.o

TARGET = assign_4


all: $(TARGET)

$(TARGET): $(OBJFILES)
	$(CC) $(CFLAGS) $(DBG) -o $(TARGET) $(OBJFILES) -lm

clean:
	rm -f $(TARGET) *.o
	rm -f $(OBJFILES)

run:
	# mkdir ../outputFiles
	./assign_4 -i ../files/hpy414_encryptme_pub.txt -o ../outputFiles/TUC2017030142_encrypted_pub.txt -k ../files/hpy414_public.key -e
	./assign_4 -i ../files/hpy414_decryptme_pub.txt -o ../outputFiles/TUC2017030142_decrypted_pub.txt -k ../files/hpy414_public.key -d
	./assign_4 -i ../files/hpy414_encryptme_priv.txt -o ../outputFiles/TUC2017030142_encrypted_priv.txt -k ../files/hpy414_private.key -e
	./assign_4 -i ../files/hpy414_decryptme_priv.txt -o ../outputFiles/TUC2017030142_decrypted_priv.txt -k ../files/hpy414_private.key -d

	# ./assign_4 -i ../outputFiles/TUC2017030142_encrypted_pub.txt -o TUC2017030142_decrypted_pub.txt -k ../files/hpy414_private.key -d
	