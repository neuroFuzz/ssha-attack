#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <getopt.h>
#include <time.h>
#include <sys/types.h>

#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/ssl.h> 

/* ------------------------------------------------------------------------------------
        DEFINITIONS
------------------------------------------------------------------------------------ */
#define FALSE 0                        // Make sure FALSE is 0 not something other than 1
#define SHA_SIZE 20                    // Size for SHA
#define MIN_BUF_SIZE 0                 // min size for buffers
#define MAX_BUF_SIZE 1024              // max size for buffers
#define MAX_SSHA_SIZE 105              // max size for buffers

/* ------------------------------------------------------------------------------------
        FORWARD DECLARATIONS
------------------------------------------------------------------------------------ */
int ValidatePassword(const char* requestPW, const char* storedPW, const char *hashtype);
int GenerateHash(const char* digest, const char* value, const char* salt, char* buffer);
int DecodeBase64(char *out, const char *in);
int WithinBounds (const char *source);
int WithinSSHABounds (const char *source);
int WithinGivenBounds (const char *source, int bound);
int WithinGivenIntBounds (int begin, int bound, int target);
int Permutate(char* set, char *inhash, int begin, int end, time_t t0, const char *hashtype);
void SetHashType(char *buffer, char *hash);
void ToHex(const unsigned char* temp, char* target, int n);
void PrintTimeDiff(time_t t1, time_t t0);
void stripnl(char *str);

static const char *pUsage = 
  "\n  Usage: ./ssha_attack -m mode [-d attack_dictionary_file | [-n min] -u max -a alphabet | -a 20 -c custom_alphabet] -s SSHA_hash_string\n\n"
  "  -m  This is the mode for the prog to operate under.  The currently supported modes\n"
  "      are \"dictionary\" and \"brute-force\".  This switch is required.\n\n"
  "  -d  This option is to be used to engage \"dictionary\" mode.\n"
  "      The dictionary is a regular text file containing one entry per line.\n"  
  "      The data from this file is what will be used as the clear text data\n"
  "      to which the discovered salt will get applied.\n\n"
  "  -l  The minimum amount of attack characters to begin with.\n\n"
  "  -u  The maximum amount of attack characters to use. If -l is not used processing\n"
  "      will start with size 1\n\n"
  "  -a  The numerical index of the attack alphabet to use:\n"
  "      \t1. Numbers only\n"
  "      \t2. lowercase hex\n"
  "      \t3. UPPERCASE HEX\n"
  "      \t4. lowercase alpha characters\n"
  "      \t5. UPPERCASE ALPHA characters\n"
  "      \t6. lowercase alphanumeric characters\n"
  "      \t7. UPPERCASE ALPHANUMERIC characters\n"
  "      \t8. lowercase & UPPERCASE ALPHA characters\n"
  "      \t9. lowercase & UPPERCASE ALPHAnumeric characters\n"
  "      \t10. All printable ASCII characters\n"
  "      \t11. lowercase & UPPERCASE ALPHAnumeric characters, as well as: \n"
  "      \t    !\"£$%^&*()_+-=[]{}'#@~,.<>?/|\n"
  "      \t20. Custom alphabet - must be used with -c switch\n\n"
  "  -c  The custom attack alphabet to use, for example abcABC123!\n"
  "      Take note that this forces a permutation based process so the larger the alphabet\n"
  "      the longer the process will take. Also, when used with the -a 20 switch, but\n"
  "      not the -u switch, the permutations are all based on the size of the alphabet\n"
  "      you submit.\n"
  "      Using the example from above all permutations would be 10 characters in length.\n"
  "      This can also force an incremental attack when coupled with the -n switch\n\n"
  "  -s  The SSHA hash string that will be attacked.  This must be a Base64 encoded string. \n"
  "      This switch is required.\n\n";

