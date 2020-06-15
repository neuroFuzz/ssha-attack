/* ------------------------------------------------------------------------------------
Author:   Andres Andreu <andres [at] neurofuzzsecurity dot com>

Date:     Jan 2008

Version:  0.5

Desc:     This is simply a file of mixed functions for the SSHA attack tool.

License:  The MIT License

Copyright (c) 2007 - 2020 Andres Andreu

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
------------------------------------------------------------------------------------ */

#include "includes.h"

/* ------------------------------------------------------------------------------------
Function: stripnl
Params:   char* --> the char array to be processed
Desc:     Strips CR & LF from the param data
Return:   Nothing
------------------------------------------------------------------------------------ */
void stripnl(char *str) {

    while(strlen(str) && ((str[strlen(str) - 1] == 13) ||
    (str[strlen(str) - 1] == 10))) {
        str[strlen(str) - 1] = 0;
    }
}

/* ------------------------------------------------------------------------------------
Function: substring_r
Params:   char* --> the char array to hold resulting data
char* --> the char array to be processed
int --> starting index
int --> ending index
Desc:     Chops up a string based on the indexes passed in.
Return:   Nothing
------------------------------------------------------------------------------------ */
void *substring_r(char *buffer, char *str, int start, int end) {

    int i, x = 0;

    for (i = start; i <= end; i++)
    buffer[x++] = str[i];

    buffer[x] = '\0';

}

/* ------------------------------------------------------------------------------------
Function: WithinBounds
Params:   const char* --> the char array to be checked
Desc:     Performs boundary check on the param data
Return:   1 if the data is within bounds
0 if the data is outside of the established boundaries
------------------------------------------------------------------------------------ */
int WithinBounds (const char *source) {

    if ((strlen(source) > MIN_BUF_SIZE) && (strlen(source) < MAX_BUF_SIZE)) {
        return 1;
    }

    return FALSE;
}

/* ------------------------------------------------------------------------------------
Function: WithinGivenBounds
Params:   const char* --> the char array to be checked
int --> the boundary not to be surpassed
Desc:     Performs boundary check on the param data
Return:   1 if the data is within bounds
0 if the data is outside of the established boundaries
------------------------------------------------------------------------------------ */
int WithinGivenBounds (const char *source, int bound) {

    if ((strlen(source) > MIN_BUF_SIZE) && (strlen(source) < bound)) {
        return 1;
    }

    return FALSE;
}

/* ------------------------------------------------------------------------------------
Function: WithinSSHABounds
Params:   const char* --> the char array to be checked
Desc:     Performs boundary check on the param data
Return:   1 if the data is within bounds
0 if the data is outside of the established boundaries
------------------------------------------------------------------------------------ */
int WithinSSHABounds (const char *source) {

    if ((strlen(source) > MIN_BUF_SIZE) && (strlen(source) <= MAX_SSHA_SIZE)) {
        return 1;
    }

    return FALSE;
}

/* ------------------------------------------------------------------------------------
Function: WithinGivenIntBounds
Params:   int --> the lower bound
int --> the upper bound
int --> the num to check
Desc:     Performs boundary check on the param data
Return:   1 if the data is within bounds
0 if the data is outside of the established boundaries
------------------------------------------------------------------------------------ */
int WithinGivenIntBounds (int begin, int bound, int target) {

    if ((target >= begin) && (target <= bound)) {
        return 1;
    }

    return FALSE;
}

/* ------------------------------------------------------------------------------------
Function: DecodeBase64
Params:   char*        --> the place to put the decoded string
const char*  --> the base64 encoded object
Desc:     Decodes a base-64 encoded string into raw binary.  This is a self
contained function, there are no external dependencies.
Return:   length of the string
------------------------------------------------------------------------------------ */
int DecodeBase64(char *out, const char *in) {

    #define BAD     -1
    static const char base64val[] = {
        BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD,
        BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD,
        BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD, BAD,BAD,BAD, 62, BAD,BAD,BAD, 63,
        52, 53, 54, 55,  56, 57, 58, 59,  60, 61,BAD,BAD, BAD,BAD,BAD,BAD,
        BAD,  0,  1,  2,   3,  4,  5,  6,   7,  8,  9, 10,  11, 12, 13, 14,
        15, 16, 17, 18,  19, 20, 21, 22,  23, 24, 25,BAD, BAD,BAD,BAD,BAD,
        BAD, 26, 27, 28,  29, 30, 31, 32,  33, 34, 35, 36,  37, 38, 39, 40,
        41, 42, 43, 44,  45, 46, 47, 48,  49, 50, 51,BAD, BAD,BAD,BAD,BAD
    };
    #define DECODE64(c)  (isascii(c) ? base64val[c] : BAD)

    int len = 0;
    register unsigned char digit1, digit2, digit3, digit4;

    if (in[0] == '+' && in[1] == ' ')
    in += 2;
    if (*in == '\r')
    return(0);

    do {
        digit1 = in[0];
        if (DECODE64(digit1) == BAD)
        return(-1);
        digit2 = in[1];
        if (DECODE64(digit2) == BAD)
        return(-1);
        digit3 = in[2];
        if (digit3 != '=' && DECODE64(digit3) == BAD)
        return(-1);
        digit4 = in[3];
        if (digit4 != '=' && DECODE64(digit4) == BAD)
        return(-1);
        in += 4;
        *out++ = (DECODE64(digit1) << 2) | (DECODE64(digit2) >> 4);
        ++len;

        if (digit3 != '=') {
            *out++ = ((DECODE64(digit2) << 4) & 0xf0) | (DECODE64(digit3) >> 2);
            ++len;

            if (digit4 != '=') {
                *out++ = ((DECODE64(digit3) << 6) & 0xc0) | DECODE64(digit4);
                ++len;
            }
        }
    } while (*in && *in != '\r' && digit4 != '=');

    return (len);

}

/* ------------------------------------------------------------------------------------
Function: ToHex
Params:   const unsigned char*  --> the place to put the decoded string
char*  --> the base64 encoded object
int  --> size boundary
Desc:     Encodes raw binary data into a hex encoded string
Return:   void
------------------------------------------------------------------------------------ */
void ToHex(const unsigned char* temp, char* target, int n) {

    int i = 0;

    for(i=0; i < n; i++) {
        sprintf(&target[i*2], "%02x", temp[i]); // write out the hex values into the buffer
    }
}

/* ------------------------------------------------------------------------------------
Function: GenerateHash
Params:   const char* --> the digest you are using (i.e. md5, sha1, sha, etc.)
const char* --> the value of the object you are hashing
const char* --> the salt value (MUST BE NULL IF NO SALT REQUIRED)
char*           --> the result of the hash is stored here
Desc:     Generates the hash value for the string passed in (including salt if it
is not set to NULL).  The digest string determines which SLL hash to
use.
Return:   Length of the hash
------------------------------------------------------------------------------------ */
int GenerateHash(const char* digest, const char* value, const char* salt, char* buffer) {

    EVP_MD_CTX *mdctx;                      // OpenSSL variables
    const EVP_MD *md;
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len, i;

    OpenSSL_add_all_digests();              // Load up all the possible digests

    if(!(digest || value || buffer)) {      // make sure we have valid data
        return -1;
    }

    md = EVP_get_digestbyname(digest);      // Load up the digest needed

    if(!md) {                               // If the digest is not valid get out
        return -1;
    }

    //  EVP_MD_CTX_init(mdctx);
    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, md, NULL);     // Initialize the digest
    EVP_DigestUpdate(mdctx,                 // Add the clear text password to the digest
        value,
        (unsigned int) strlen(value));

    if(salt) {
        EVP_DigestUpdate(mdctx,             // If we have a salt, add that to the digest as well
            salt,
            (unsigned int) strlen(value));
    }

    EVP_DigestFinal_ex(mdctx,               // Create the hash
        md_value,
        &md_len);

    EVP_MD_CTX_free(mdctx);                 // Do some cleanup

    for(i = 0; i < md_len; i++) {
        sprintf(&buffer[i*2], "%02x", md_value[i]); // copy the hex values into the buffer
    }

    return md_len;                          // All is good so return the hash length

}

/* ------------------------------------------------------------------------------------
Function: ValidatePassword
Params:   const char* --> the clear text attack string
const char* --> the SSHA hash from the LDAP server
const char* --> type of hash
Desc:     Checks the clear text string for matches after applying
the salt extracted from the known salted SHA hash.
Return:   Success: 1 (the passwords match)
Failure: 0
Notes:    The data from LDAP (SSHA hash) has to be a base-64 encoded string.
This needs to be decoded back to binary and then encoded as hex
for comparison purposes.
------------------------------------------------------------------------------------ */
int ValidatePassword(const char *requestPW, const char *storedPW, const char *hashtype) {
    // while 1024 is way too big, its safe and irrelevent
    char buffer[MAX_BUF_SIZE], binaryPW[MAX_BUF_SIZE];
    char formattedPW[MAX_BUF_SIZE], salt[MAX_BUF_SIZE];
    unsigned char temp[MAX_BUF_SIZE], tempSalt[MAX_BUF_SIZE];
    char finalRequestPW[MAX_BUF_SIZE], tempArr[MAX_BUF_SIZE];
    int start = 0;

    // Make sure there is good data to play with
    if (storedPW && requestPW &&
        (WithinBounds(storedPW) != 0) &&
        (WithinBounds(requestPW) != 0)) {

        // initilize all buffer's to empty chars of 0
        memset(buffer, 0, MAX_BUF_SIZE);
        memset(formattedPW, 0, MAX_BUF_SIZE);
        memset(salt, 0, MAX_BUF_SIZE);
        memset(temp, 0, MAX_BUF_SIZE);
        memset(tempSalt, 0, MAX_BUF_SIZE);
        memset(finalRequestPW, 0, MAX_BUF_SIZE);
        memset(tempArr, 0, MAX_BUF_SIZE);

        if(strstr(storedPW, "{SSHA")) {
            if (strcmp(hashtype, "SHA1") == 0) {
                start = strlen("{SSHA}");
            } else {
                start = 9;
            }
            strcpy(binaryPW, storedPW);                        // copy storedPW into binaryPW
            int n = DecodeBase64(temp, binaryPW + start);      // base-64 decode into temp

            if (strcmp(hashtype, "SHA1") == 0) {
                strcpy(tempSalt, temp + 20);                     // grab salt from temp & cpy to tempSalt
            } else if (strcmp(hashtype, "SHA224") == 0) {
                strcpy(tempSalt, temp + 28);
            } else if (strcmp(hashtype, "SHA256") == 0) {
                strcpy(tempSalt, temp + 32);
            } else if (strcmp(hashtype, "SHA384") == 0) {
                strcpy(tempSalt, temp + 48);
            } else if (strcmp(hashtype, "SHA512") == 0) {
                strcpy(tempSalt, temp + 64);
            }
            ToHex(temp, tempArr, n);                           // conv to hex in tempArr

            if (strcmp(hashtype, "SHA1") == 0) {
                strncpy(formattedPW, tempArr, 40);               // chop this down to char's as hex in formattedPW
            } else if (strcmp(hashtype, "SHA224") == 0) {
                strncpy(formattedPW, tempArr, 56);
            } else if (strcmp(hashtype, "SHA256") == 0) {
                strncpy(formattedPW, tempArr, 64);
            } else if (strcmp(hashtype, "SHA384") == 0) {
                strncpy(formattedPW, tempArr, 96);
            } else if (strcmp(hashtype, "SHA512") == 0) {
                strncpy(formattedPW, tempArr, 128);
            }

            strcpy(finalRequestPW, requestPW);                 // copy requestPW to an unsigned array
            strcat(finalRequestPW, tempSalt);                  // cat the binary salt to binary array
            GenerateHash(hashtype, finalRequestPW, NULL, buffer);// generate a salted sha hash
        }

        // perform the actual comparison of formattedPW and buffer
        if(strcmp(formattedPW, buffer) == 0) {
            return 1;                                          // passwords matched
        }

        return FALSE;                                          // nothing going on
    }

    return FALSE;

}

/* ------------------------------------------------------------------------------------
Function: PrintTimeDiff
Params:   time_t --> timestamp of prog run
time_t --> timestamp of prog inititation
Desc:     Calculates the diff between 2 time_t values and displays it.
Return:   Nothing
------------------------------------------------------------------------------------ */
void PrintTimeDiff(time_t t1, time_t t0) {

    //printf ("Elapsed time in seconds for successful attack: %ld\n", (long) (t1 - t0));
    OutputSecondsToDay((int)(t1 - t0));

}

/* ------------------------------------------------------------------------------------
Function: doDictAttack
Params:   char* --> the SSHA hash from the LDAP server
char* --> the name of the dictionary file to use
time_t --> start time for porg execution
const char* --> type of hash
Desc:     Reads the data in from the dictionary file.
Then it iterates over the data from the dictionary and
calls ValidatePassword with each clear text attack vector
and the SSHA hash submitted via command line.
Return:   Nothing
------------------------------------------------------------------------------------ */
void doDictAttack(char *inhash, char *dictfile, time_t t0, const char *hashtype) {

    FILE *infile;
    char line[100];
    int lcount;
    int hit = 0;
    time_t t1;

    stripnl(dictfile);

    if ((infile = fopen(dictfile, "r")) == NULL) {
        printf("\nError opening file, exiting prog now\n\n");
        exit(0);
    }

    while (fgets(line, sizeof(line), infile) != NULL) {
        lcount++;
        stripnl(line);
        //printf("Hash: %s, Line %d: %s\n", inhash, lcount, line);
        if (ValidatePassword(line, inhash, hashtype) == 1) {
            printf("\nThere is a match on value \"%s\"\n\n", line);
            hit = 1;
            t1 = time(NULL);
        }
        if (hit == 1) {
            fclose(infile);
            PrintTimeDiff(t1, t0);
            exit(0);
        }
    }

    fclose(infile);

    if (hit == 0)
    printf("\nNo hits \n\n");

}

/* ------------------------------------------------------------------------------------
Function: doBruteForceAttack
Params:   char* --> the traget SSHA hash string
char* --> the data to be used for brute forcing
time_t --> start time for porg execution
const char* --> type of hash
Desc:     Simple wrapper function that calls necessary functions to effect the
brute force attack.
Return:   Nothing
------------------------------------------------------------------------------------ */
void doBruteForceAttack(char *inhash, char *alphabet, time_t t0, const char *hashtype) {

    genident(alphabet, inhash, strlen(alphabet), t0, hashtype);

    if (Permutate(alphabet, inhash, 0, strlen(alphabet), t0, hashtype) == 0) {
        printf("\nNo hits from the permutation process\n\n");
    }

}

/* ------------------------------------------------------------------------------------
Function: swap
Params:   char* --> the data source
char* --> the data destination
Desc:     Performs an in line swap of data from one pointer to another.
Return:   Nothing
------------------------------------------------------------------------------------ */
void swap(char* src, char* dst) {
    char ch = *dst;
    *dst = *src;
    *src = ch;
}

/* ------------------------------------------------------------------------------------
Function: genident
Params:   char* --> the char array to be processed
char* --> the SSHA hash string
int --> size boundary
time_t --> start time for porg execution
const char* --> type of hash
Desc:     Generates attack vectors of each unique character from set .
For each generated word (attack vector) a call to the ValidatePassword
function is made, upon a match processing will cease.
Return:   0 if there is no match of data
------------------------------------------------------------------------------------ */
int genident(char *set, char *inhash, int end, time_t t0, const char *hashtype) {

    int i;
    int j;
    char tmp[1024];
    int hit = 0;
    time_t t1;

    for (i = 0; i < end; i++) {
        for (j = 0; j < end; j++)
        tmp[j] = set[i];

        tmp[j++] = '\0';
        if (ValidatePassword(tmp, inhash, hashtype) == 1) {
            printf("\nThere is a match on value \"%s\"\n\n", tmp);
            t1 = time(NULL);
            hit = 1;
        }
        if (hit == 1) {
            PrintTimeDiff(t1, t0);
            exit(0);
        }

    }
    if (hit == 0)
        printf("\nNo hits with identical values for the alphabet ...\n\n");

    return 0;

}

/* ------------------------------------------------------------------------------------
Function: Permutate
Params:   char* --> the char array to be processed
char* --> the SSHA hash string
int --> low size boundary
int --> upper size boundary
time_t --> starting time for prog execution
const char* --> type of hash
Desc:     Generates permutations of the data in set. For each generated word (attack vector)
a call to the ValidatePassword function is made, upon a match processing
will cease.
Return:   0 if there is no match of data
------------------------------------------------------------------------------------ */
int Permutate(char* set, char *inhash, int begin, int end, time_t t0, const char *hashtype) {
    int i;
    int range = end - begin;
    char *p;
    int hit = 0;
    time_t t1;

    if (range == 1) {
        if (ValidatePassword(set, inhash, hashtype) == 1) {
            printf("\nThere is a match on value \"%s\"\n\n", set);
            t1 = time(NULL);
            hit = 1;
        }
        if (hit == 1) {
            PrintTimeDiff(t1, t0);
            exit(0);
        }

    } else {
        for(i=0; i<range; i++) {
            swap(&set[begin], &set[begin+i]);
            Permutate(set, inhash, begin+1, end, t0, hashtype);
            swap(&set[begin], &set[begin+i]);       /* set back */
        }
    }
    return 0;

}

/* ------------------------------------------------------------------------------------
Function: get_index
Params:   char* --> the char array to be searched
char --> the character to search for
Desc:     Returns the index position of ch in the alphabet string
Return:   int
------------------------------------------------------------------------------------ */
int get_index(char *string, char ch) {
    int i = 0;
    while(string[i]) {
        if(ch == string[i]) {
            return(i);
        }
        i++;
    }
    return i;
}

/* ------------------------------------------------------------------------------------
Function: CPABrute
Params:   char* --> the SSHA hash string
char* --> alphabet to be used
time_t --> start time for prog run
const char* --> the type of SHA hash at hand
int --> the attack string minimum
int --> the attack string maximum
Desc:     Generates combinations of the data in alphabet based on the size that is
established in the params. For each generated word (attack vector)
a call to the ValidatePassword function is made, upon a match processing
will cease.
Return:   Nothing
------------------------------------------------------------------------------------ */
void CPABrute(char *inhash, char Alphabet[], time_t t0, const char *hashtype, int min, int max) {
    int a,b,c;
    char Password[128];
    int hit = 0;
    time_t t1;

    for (a = min-1; a < max; a++) {
        printf ("\nTrying Word Length: %d\n", a+1);
        for(b=0; b <= a; b++) {
            Password[b]=Alphabet[0];
        }
        Password[b]='\0';

        b=0;        /* Start at position zero */
        while(b <= a) {
            if(!b) {
                //printf("[%s]\n", Password); /* Print out the password */
                if (ValidatePassword(Password, inhash, hashtype) == 1) {
                    printf("\nThere is a match on value \"%s\"\n\n", Password);
                    t1 = time(NULL);
                    hit = 1;
                }
                if (hit == 1) {
                    PrintTimeDiff(t1, t0);
                    exit(0);
                }
            }

            c = get_index(Alphabet, Password[b]);
            c++;

            if(c >= strlen(Alphabet)) {
                Password[b] = Alphabet[0];      /* Reset this to first char */
                b++;                            /* increment POSITION */
                continue;                       /* and keep going with loop */
            }
            Password[b] = Alphabet[c];                /* Set new alpha */
            b = 0;                                    /* Back to zero position */
        }
        if (hit == 0)
        printf("No hits for Word Length: %d\n", a+1);

    }

}

/* ------------------------------------------------------------------------------------
Function: OutputSecondsToDay
Params:   int --> timestamp
Desc:     Calculates and outputs day,hour,minutes,seconds
Return:   Nothing
------------------------------------------------------------------------------------ */
void OutputSecondsToDay(int n) {

    int day = n / (24 * 3600);

    n = n % (24 * 3600);
    int hour = n / 3600;

    n %= 3600;
    int minutes = n / 60;

    n %= 60;
    int seconds = n;

    printf("Elapsed time: Day(s): %d, Hour(s): %d, Minutes: %d, Seconds: %d\n\n", day, hour, minutes, seconds);

}
