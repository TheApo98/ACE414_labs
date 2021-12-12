#!/bin/bash

# Password for the encryption
password=1234

uusage="\n
        Usage:\n
        $0 -d DIRECTORY -f NUM_OF_FILES -m [0|1|2]\n
        $0 -h\n
        \n
        Options:\n
            \t-d    path    Path to the directory with files\n
            \t-f    <ΙΝΤ>   The number of files to be encrypted\n
            \t-h            This help message\n
            \t-m    [0|1|2] 0=create, 1=encrypt-delete, 2=decrypt-delete\n"


if [ $# -eq 0 ] 
then
    echo -e $uusage
    exit
fi  

while getopts d:f:h:m: flag
do  
    # echo ${OPTIND}
    case "${flag}" in
        d) 
            directory=${OPTARG};;
        f) 
            no_of_files=${OPTARG};;
        m)
            mode=${OPTARG};;
        *) 
            echo -e $uusage
            exit ;;
    esac
done

# echo $directory
# echo $no_of_files

# Navigate in the given directory
cd $directory

case "${mode}" in 
    0)
        # Create a number of files
        for ((i = 0; i < $no_of_files; i++)); do
            touch file_$i.txt
            echo "file_$i" > file_$i.txt
        done
        ;;
    1)
        for ((i = 0; i < $no_of_files; i++)); do
            # Encrypt the files
            openssl enc -aes-256-ecb -in file_$i.txt -out file_$i.txt.encrypt -k $password &> /dev/null
            # Delete the original files
            rm file_$i.txt
        done
        ;;
    2)
        for ((i = 0; i < $no_of_files; i++)); do
            # Decrypt the files
            openssl aes-256-ecb -in file_$i.txt.encrypt -out file_$i.txt -d -k $password &> /dev/null
            # Delete the encypted files
            rm file_$i.txt.encrypt
        done        
        ;;
    *)
        echo -e uusage
        exit;;

esac






