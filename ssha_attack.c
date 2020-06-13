/* ------------------------------------------------------------------------------------
Author:   Andres Andreu <http://xri.net/=andres.andreu> 

Date:     Jan 2008

Version:  0.4

Desc:     This simple prog is the first release of a tool to attack,
          or try to crack, salted SHA hashes (SSHA) as they are used in some of
          today's modern day apps, especially LDAP. RFC-3112 provides more details 
          on this technology.  This is not a silver bullet prog and simply works
          against a very specific type of data.  Read the usage statement for more
          details.
          The prog currently supports dictionary style attacks as well as some
          brute-force models.    

Notes:    Use this prog at your own risk, it comes with no guarantees.
          
          How you obtain a hash to crack with this prog is your problem, not mine.

          How you generate or obtain the attack dictionary files is also your 
          problem. Just remember that dictionary attacks are only as good
          as the dictionary files used for the process.
          
          The code was compiled on a Linux (x-86) based OS using OpenSSL 0.9.8, since
          the OpenSSL API's changed from 0.9.7 on it probably wont compile cleanly
          on a system using 0.9.6 or less. 


License:  The MIT License

          Copyright (c) 2007 Andres Andreu

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
#include "alphabet.h"


int main(int argc, char *argv[]) {
    
  char modeval[12];
  char *sshahash = NULL; 
  char *dictfile = NULL; 
  char *custom = NULL;
  char *hashtype = NULL;
  int c, set, min = 0, max = 0;
  time_t t0, t1;
  char buffer[1024];

  while ((c = getopt(argc, argv, "m:l:u:a:s:d:c:h")) != -1)
  
  switch(c) {
    case 'm':
      if (WithinGivenBounds(optarg, 12) == 1)
        sprintf(modeval, "%s", optarg);
      else {
        printf("\nMode entry beyond bounds, exiting ...\n\n");
        exit(0);
      }
      break;
    case 's':
      if (WithinSSHABounds(optarg) == 1) {
        sshahash = optarg;
        switch (strlen(sshahash)) {
          case 32:
          case 40:
            strcpy(buffer, "{SSHA}");
            strcat(buffer, sshahash);
            strcpy(sshahash, buffer);
          case 38:
          case 46:
            hashtype = "SHA1";
            break;
          case 44:
            strcpy(buffer, "{SSHA224}");
            strcat(buffer, sshahash);
            strcpy(sshahash, buffer);
          case 53:
            hashtype = "SHA224";
            break;
          case 48:
          case 56:
            strcpy(buffer, "{SSHA256}");
            strcat(buffer, sshahash);
            strcpy(sshahash, buffer);
          case 57:
          case 65:
            hashtype = "SHA256";
            break;
          case 72:
          case 76:
            strcpy(buffer, "{SSHA384}");
            strcat(buffer, sshahash);
            strcpy(sshahash, buffer);
          case 81:
          case 85:
            hashtype = "SHA384";
            break;
          case 92:
          case 96:
            strcpy(buffer, "{SSHA512}");
            strcat(buffer, sshahash);
            strcpy(sshahash, buffer);
          case 101:
          case 105:
            hashtype = "SHA512";
            break;
          default:
            printf("Hash size is invalid\n\n");
            exit(0);
        }
        printf("\nHash Algorithm Detected: %s\n\n", hashtype);
      } else {
        printf("\nHash entry beyond bounds, exiting ...\n\n");
        exit(0);
      }
      break;
    case 'd':
      if (WithinBounds(optarg) == 1)
        dictfile = optarg;
      else {
        printf("\nDictionary value entry beyond bounds, exiting ...\n\n");
        exit(0);
      }
      break;
    case 'l':
      sscanf(optarg, "%i", &min);
      break;
    case 'u':
      sscanf(optarg, "%i", &max);
      break;
    case 'a':
      if ((WithinGivenIntBounds(1, 11, atoi(optarg)) == 1) ||
          (atoi(optarg) == 20))
        sscanf(optarg, "%i", &set);
      else {
        printf("\nSet number entry beyond bounds - see Usage, exiting ...\n\n");
        exit(0);
      }
      break;
    case 'c':
      if (WithinGivenBounds(optarg, 12) == 1)
        custom = optarg;
      else {
        printf("\nCustom alphabet entry beyond bounds - this is limited to 12 char's, exiting ...\n\n");
        exit(0);
      }
      break;
    case 'h':
      printf(pUsage);
      exit(0);
  default:
    printf("Out\n");
  }
  
  // No SSHA hash is provided 
  if (sshahash == NULL) {
    printf("\nThe prog can\'t run with no SSHA hash to attack, use the -s switch\n\n");
    exit(0);
  }

  // No upper boundary established 
  if ((max == 0) &&
      (custom == NULL)) {
    printf("\nThe prog can\'t run with no upper boundary of attack size\n\n");
    exit(0);
  }
  
  // No upper boundary established 
  if ((max == 0) &&
      (custom != NULL)) {
    printf("\nThe prog can\'t run with no upper boundary of attack size\n\n");
    exit(0);
  }

  if ((max != 0) && (min != 0) &&
      (min > max)) {
    printf("\nThe lower bound cannot be greater than the upper boundary of the attack size\n\n");
    exit(0);
  }

  // Dictionary file name is provided but mode dictionary
  // has not been established
  if ((dictfile == NULL) &&
      (strncmp(modeval, "dictionary", 10) != 0) &&
      (strncmp(modeval, "brute-force", 11) != 0)) {
    printf("\nThe prog needs to know what to do.  Please establish a mode and ");
    printf("provide further data based on the mode chosen.\n\n");
    exit(0);
  }

  // Dictionary mode is chosen with no dictionary file
  // name provided
  if ((strncmp(modeval, "dictionary", 10) == 0) &&
      (dictfile == NULL)) {
    printf("\nThe prog can\'t be in dictionary mode with no dictionary value,");
    printf(" please establish a value with the -d switch\n\n");
    exit(0);
  }

  // A dictionary file name is provided with no mode established
  if ((dictfile != NULL) &&
      (strncmp(modeval, "dictionary", 10) != 0)) {
    printf("\nThe prog can\'t have a dictionary value established without ");
    printf("being in dictionary mode, please establish the dictionary mode with the -m switch\n\n");
    exit(0);
  }

  if (strncmp(modeval, "brute-force", 11) == 0) {
    // -a 20 without a custom alphabet
    if ((set == 20) && (custom == NULL)) {
      printf("\nThe -a 20 option requires a custom alphabet to be provided by you.\n");
      printf("Please use the -c switch and provide that.\n\n");
      exit(0);
    }

    // custom alphabet provided but missing -a 20
    if ((custom != NULL) && (set != 20)) {
      printf("\nA custom alphabet has been provided but -a 20 is missing.\n");
      printf("Please use the -a 20 switch with the -c option.\n\n");
      exit(0);
    } 
  
    // alphabet chosen with no maximum and no custom alphabet  
    if (((WithinGivenIntBounds(1, 20, set)) == 1) &&
        (max == 0) &&
        (custom == NULL)) {
      printf("\nAn alphabet has been chosen but a maximum\n");
      printf("number of characters has not been chosen, please use the -u switch.\n\n");
      exit(0);
    }

    // maximum provided with no alphabet
    if (((WithinGivenIntBounds(1, 20, set)) != 1) &&
        (max != 0) &&
        (custom == NULL)) {
      printf("\nA maximum has been provided but no alphabet has been\n");
      printf("chosen, please use the -a switch.\n\n");
      exit(0);
    }

  }

  t0 = time(NULL);
  // Now we attack the hash
  // dictionary attack
  if ((WithinSSHABounds(sshahash) == 1) &&
      (strncmp(modeval, "dictionary", 10) == 0)) {
      doDictAttack(sshahash, dictfile, t0, hashtype);
  }
  // brtute force attack
  if ((WithinSSHABounds(sshahash) == 1) &&
      (strncmp(modeval, "brute-force", 11) == 0)) {
      uint16_t x, i = 0;
      memset (alphabet, '\0', sizeof (alphabet) );
      //printf("\nM: %d, S: %d\n\n", min, set);

      switch (set) {
        case 1:         strncpy (alphabet, set1, strlen (set1) );     break;
        case 2:         strncpy (alphabet, set2, strlen (set2) );     break;
        case 3:         strncpy (alphabet, set3, strlen (set3) );     break;
        case 4:         strncpy (alphabet, set4, strlen (set4) );     break;
        case 5:         strncpy (alphabet, set5, strlen (set5) );     break;
        case 6:         strncpy (alphabet, set6, strlen (set6) );     break;
        case 7:         strncpy (alphabet, set7, strlen (set7) );     break;
        case 8:         strncpy (alphabet, set8, strlen (set8) );     break;
        case 9:         strncpy (alphabet, set9, strlen (set9) );     break;
        case 10:
                        for (x = 33; x < 127; x++)
                          set10[i++] = x;
                        set10[i] = '\0';
                        strncpy (alphabet, set10, strlen (set10) );
                        break;
        case 11:        strncpy (alphabet, set11, strlen (set11) );   break;
        case 20:	strncpy (alphabet, custom, strlen (custom) ); break;
        default:        fprintf (stderr, "Unknown alphabet set");
                        exit(1);
      }

      if ((custom != NULL) && (max == 0))
        doBruteForceAttack(sshahash, alphabet, t0, hashtype);
      if (min == 0)
        CPABrute(sshahash, alphabet, t0, hashtype, 1, max);  
      else {
        CPABrute(sshahash, alphabet, t0, hashtype, min, max);  
      }
  }
  t1 = time(NULL);
  printf ("\nElapsed run time in seconds: %ld\n\n", (long) (t1 - t0));
  return 0;
}


