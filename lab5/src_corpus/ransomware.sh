#!/bin/bash

# Password for the encryption
password=1234
fname_format="file_"

uusage="\n
        Usage:\n
        $0 -d DIRECTORY -f NUM_OF_FILES -m [0|1|2]\n
        $0 -h\n
        \n
        Options:\n
            \t-d    path   , Path to the directory with files\n
            \t-f    <ΙΝΤ>  , The number of files to be encrypted\n
            \t-h           , This help message\n
            \t-m    [0|1|2], 0=create, 1=encrypt-delete, 2=decrypt-delete\n"


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

# Check if directory path is valid
if [ ! -d $directory ] 
then
    echo "No such file or directory"
    exit -1
fi

# Navigate in the given directory
# cd $directory

case "${mode}" in 
    0)
        # Create a number of files
        # for ((i = 0; i < $no_of_files; i++)); do
        #     cur_file="file_$i.txt"
        #     touch $directory/$cur_file
        #     echo "file_$i" > $directory/$cur_file
        # done

        # Create a number of files using test_aclog
        if [ -x "test_aclog" ] 
        then
            export LD_PRELOAD=./logger.so
            ./test_aclog $no_of_files $directory $fname_format
        else
            echo "File 'test_aclog' doesn't exist or is not executable"
        fi
        ;;
    1)
        for ((i = 0; i < $no_of_files; i++)); do
            cur_file="$fname_format$i.txt"
            if [ ! -w $directory/$cur_file ] 
            then
                echo "File '$directory/$cur_file' doesn't exist or is read-only"
            else
                # Encrypt the files
                export LD_PRELOAD=./logger.so
                openssl enc -aes-256-ecb -pbkdf2 -in $directory/$cur_file -out $directory/$cur_file.encrypt -k $password #&> /dev/null
                # Delete the original files
                rm -rf $directory/$cur_file
            fi
        done
        ;;
    2)
        for ((i = 0; i < $no_of_files; i++)); do
            cur_file="$fname_format$i.txt"
            if [ ! -w $directory/$cur_file.encrypt ] 
            then
                echo "File '$directory/$cur_file.encrypt' doesn't exist or is read-only"
            else
                # Decrypt the files
                export LD_PRELOAD=./logger.so
                openssl aes-256-ecb -pbkdf2 -in $directory/$cur_file.encrypt -out $directory/$cur_file -d -k $password #&> /dev/null
                # Delete the encypted files
                rm -rf $directory/$cur_file.encrypt
            fi
        done        
        ;;
    *)
        echo -e $uusage
        exit;;

esac

echo
# ls $directory





