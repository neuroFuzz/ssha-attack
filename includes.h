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

#include <bsd/string.h>

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
int ValidatePassword(const char *, const char *, const char *);
int GenerateHash(const char *, const char *, const char *, char *);
int DecodeBase64(char *, const char *);
int WithinBounds (const char *);
int WithinSSHABounds (const char *);
int WithinGivenBounds (const char *, int);
int WithinGivenIntBounds (int, int, int);
int Permutate(char *, char *, int, int, time_t, const char *);
int genident(char *, char *, int, time_t, const char *);
void SetHashType(char *, char *);
void ToHex(const unsigned char *, char *, int);
void PrintTimeDiff(time_t, time_t);
void stripnl(char *);
void doDictAttack(char *, char *, time_t, const char *);
void OutputSecondsToDay(int);
void doBruteForceAttack(char *, char *, time_t, const char *);
void CPABrute(char *, char [], time_t, const char *, int, int);

static const char *pUsage =
  "\n  Usage: ./ssha_attack -m mode [-d attack_dictionary_file | [-l min] -u max -a alphabet | -a 20 -c custom_alphabet] -s SSHA_hash_string\n\n"
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
