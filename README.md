# ssha-attack

<a href="https://scan.coverity.com/projects/ssha-attack">
  <img alt="Coverity Scan Build Status"
       src="https://img.shields.io/coverity/scan/21325.svg"/>
</a>

SSHA Attack

This simple prog is the first release of a tool to attack, or try to crack,
salted SHA hashes (SSHA) as they are used in some of today's modern day apps,
especially LDAP. RFC-3112 provides more details on this technology.  

This is not a silver bullet prog and simply works against a very specific type of data.
It DOES NOT crack every type of salted hash in existence.
Read the usage statement for more details, ./ssha_attack -h.

The prog currently supports dictionary style attacks as well as some brute-force models.

The OpenSSL lib's are required.

If you are on Ubuntu also add the following:

sudo apt install libbsd-dev

To compile untar and:

    make clean
    make

The prog should compile cleanly on any recent version of x-86 based Linux.
It was created on Fedora Core 5.

Before using the prog decide what attack model you want to follow.  
Your current choices are:

    Dictionary based attack (-d)
    Brute force incremental attack with a predefined alphabet (that you choose) (-a [1 - 11] and -n)
    Brute force attack with a custom alphabet you provide (-a 20 and -c)
    Brute force incremental attack with a custom alphabet you provide (-a 20 and -c and -n)


Usage:

    ./ssha_attack -m mode [-d attack_dictionary_file | [-l min] -u max -a alphabet | -a 20 -c custom_alphabet] -s SSHA_hash_string

      -m  This is the mode for the prog to operate under.  The currently supported modes
          are "dictionary" and "brute-force".  This switch is required.

      -d  This option is to be used to engage "dictionary" mode.
          The dictionary is a regular text file containing one entry per line.
          The data from this file is what will be used as the clear text data
          to which the discovered salt will get applied.

      -l  The minimum amount of attack characters to begin with.

      -u  The maximum amount of attack characters to use. If -l is not used processing
          will start with size 1

      -a  The numerical index of the attack alphabet to use:
          	1. Numbers only
          	2. lowercase hex
          	3. UPPERCASE HEX
          	4. lowercase alpha characters
          	5. UPPERCASE ALPHA characters
          	6. lowercase alphanumeric characters
          	7. UPPERCASE ALPHANUMERIC characters
          	8. lowercase & UPPERCASE ALPHA characters
          	9. lowercase & UPPERCASE ALPHAnumeric characters
          	10. All printable ASCII characters
          	11. lowercase & UPPERCASE ALPHAnumeric characters, as well as:
          	    !"£$%^&*()_+-=[]{}'#@~,.<>?/|
          	20. Custom alphabet - must be used with -c switch

      -c  The custom attack alphabet to use, for example abcABC123!
          Take note that this forces a permutation based process so the larger the alphabet
          the longer the process will take. Also, when used with the -a 20 switch, but
          not the -u switch, the permutations are all based on the size of the alphabet
          you submit.
          Using the example from above all permutations would be 10 characters in length.
          This can also force an incremental attack when coupled with the -n switch

      -s  The SSHA hash string that will be attacked.  This must be a Base64 encoded string.
          This switch is required.


To run:

############### Dictionary attack ######################################
Dictionary based attack

    ./ssha_attack -m dictionary -d dictionary.txt -s {SSHA}1sx3RjtI6KLpqb3hHPDTKqIVBd9UukC3

############### Dictionary attack ######################################

############### Brute-Force incremental ################################
Brute force attack with a predefined alphabet (that you choose)

    ./ssha_attack -m brute-force -a 4 -l 3 -u 10 -s {SSHA}Ig272xI9C9H4kvL8vHA6UcK57Y4ad97O

Here are some examples from when I was unit testing:


    ./ssha_attack -m brute-force -l 3 -u 9 -a 9 -s {SSHA}EEiUTlF29/g8H6GlqVJT8JtGhmMkeU4S

    Hash Algorithm Detected: SHA1


    Trying Word Length: 3

    There is a match on value "3ee"

    Elapsed time: Day(s): 0, Hour(s): 0, Minutes: 0, Seconds: 0



    ./ssha_attack -m brute-force -a 9 -l 3 -u 10 -s Tt8H7clbL9y8ryN4/RLYrCEsKqbjJsWcPmKb4wOdZDJzYWx0

    Hash Algorithm Detected: SHA256


    Trying Word Length: 3
    No hits for Word Length: 3

    Trying Word Length: 4

    There is a match on value "test"

    Elapsed time: Day(s): 0, Hour(s): 0, Minutes: 0, Seconds: 23



    ./ssha_attack -m brute-force -l 3 -u 15 -a 9 -s {SSHA}PT8wnRusJxl3E7JnW6ufaFNiO6RWy6qH

    Hash Algorithm Detected: SHA1


    Trying Word Length: 3
    No hits for Word Length: 3

    Trying Word Length: 4
    No hits for Word Length: 4

    Trying Word Length: 5

    There is a match on value "Yt35T"

    Elapsed time: Day(s): 0, Hour(s): 0, Minutes: 39, Seconds: 42


############### Brute-Force incremental ################################

############### Custom Alphabet ########################################
Brute force attack with a custom alphabet you provide

    ./ssha_attack -m brute-force -a 20 -c custom -s {SSHA}iLWyP3dJamxdFc6sHLSJErt69+mb6en+

Here are some examples from when I was unit testing:

    ./ssha_attack -m brute-force -a 20 -c "#h5sa3l" -s {SSHA384}hZJ29z/c3f1Lms5Xid2L+wuXbNWcg87SM5I5/BCcYBRwDlYUxgxvCqMvAdQPnDgiOTBhYjE4OWY= -l 3 -u 12

    Hash Algorithm Detected: SHA384


    Trying Word Length: 3
    No hits for Word Length: 3

    Trying Word Length: 4
    No hits for Word Length: 4

    Trying Word Length: 5
    No hits for Word Length: 5

    Trying Word Length: 6
    No hits for Word Length: 6

    Trying Word Length: 7
    No hits for Word Length: 7

    Trying Word Length: 8

    There is a match on value "l3a#5h3l"

    Elapsed time: Day(s): 0, Hour(s): 0, Minutes: 0, Seconds: 49

############### Custom Alphabet ########################################

############### Brute Force incremental with Custom Alphabet ###########
Brute force incremental attack with a custom alphabet you provide

    ./ssha_attack -m brute-force -a 20 -c custom -n 2 -s {SSHA}owN4fkZDoCeXo4iw1fzqWe9u4/79vrfQ

Here is an example from when I was unit testing:

    ./ssha_attack -m brute-force -a 20 -c tse -l 2 -u 10 -s {SSHA256}H0fvfbrcXAzg3uAYesE5babwQGbTsFdhphdJ1jaUEUxzYWx0

    Hash Algorithm Detected: SHA256


    Trying Word Length: 2
    No hits for Word Length: 2

    Trying Word Length: 3
    No hits for Word Length: 3

    Trying Word Length: 4
    No hits for Word Length: 4

    Trying Word Length: 5
    No hits for Word Length: 5

    Trying Word Length: 6
    No hits for Word Length: 6

    Trying Word Length: 7

    There is a match on value "testees"

    Elapsed time: Day(s): 0, Hour(s): 0, Minutes: 0, Seconds: 0


############### Brute Force incremental with Custom Alphabet ###########

Some things to keep in mind when using this prog....

If you know the length of the clear text string you are attacking you may be best
suited using the "-a 20 -c your_dict" options. Just pass in a -c value of that size and
the brute force process will work away at the target string. It would obviously help if
you know the characters for a given clear text string, if you do then you should also
use this same option. If your custom alphabet contains non alpha numeric characters
then enclose them in double quotes.

If you arent sure of the number of characters in the target clear text string then
use the "-a 20 -c your_dict -n x" option where x is the minimum size of the attack string.
This will force an incremental brute force using the alphabet passed in via the -c
switch.
