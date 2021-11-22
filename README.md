# Payment with Dispute Resolution: A Protocol For Reimbursing Frauds’ Victims


# Dependencies

* GMP: https://gmplib.org/
* Cryptopp: https://www.cryptopp.com
* Bloom filter: http://www.partow.net/programming/bloomfilter/index.html


# Runnig a Test

1. clone the above libraries, and the PwDR file.
2. install the libraries and unzip "PwDR-main" file.
3. run the following command lines in order:

        cd Directory/PwDR-main
        
        g++ -c Rand.cpp
        
        g++ -I /Directory/cryptopp -I/Directory/bloom_filter/bloom_filter.hpp  Rand.o  X /Directory/cryptopp/libcryptopp.a  -o main -lgmpxx -lgmp
        
        ./main
        
        
    

