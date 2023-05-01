#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MIN_PASSWORD_LENGTH 1
#define MAX_PASSWORD_LENGTH 24
#define MAX_CHAR_REPETITION 24

static const char* charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789#!-$@%&*_^~=?+:;.<>|";

static int min_password_len = MIN_PASSWORD_LENGTH;
static int max_password_len = MAX_PASSWORD_LENGTH;
static int max_char_repetition = MAX_CHAR_REPETITION;
static int only_decorators = 0;
static int leet_letters = 0;
static int leet_numbers = 0;
static int leet_symbols = 0;

int isSymbol(const char c)
{
   static const char* symbols = "#!-$@%&*_^~=?+:;.<>|0123456789";
   
   for(int i = 0; symbols[i] != 0; i++)
   {
       if(c == symbols[i])
           return 1;
   }
   return 0;
}

int checkCmpSubstring(const char* passwdBuf, const char* substring, const int nLen)
{
    int result = 0;
    for(int i = 0; i < nLen && passwdBuf[i] != 0 && substring[i] != 0 && !result; i++)
    {
       const char c1 = toupper(passwdBuf[i]);
       const char c2 = toupper(substring[i]);
       
       if (c1 == c2)
         continue;
         
       if (c2 == ' ' && ( !only_decorators || isSymbol(c1) ) )
         continue;
       
       result = -1;
       if (leet_letters && c2 >= 'A' && c2 <= 'Z' )
       {
           switch(c2)
           {
               /* Let's try some common Leet character substitutions */
               case 'A': result = c1 == '4' || c1 == '@' || c1 == '^' || c1 == '\\' ? 0 : -1; break;
               case 'B': result = c1 == '8' ? 0 : -1; break;
               case 'C': result = c1 == '[' || c1 == '<' || c1 == '(' ? 0 : -1; break;
               case 'E': result = c1 == '3' || c1 == '&' ? 0 : -1; break;
               case 'F': result = c1 == 'V' ? 0 : -1; break;
               case 'G': result = c1 == '6' || c1 == '&' || c1 == '9' ? 0 : -1; break;
               case 'H': result = c1 == '#' ? 0 : -1; break;
               case 'I': result = c1 == '1' || c1 == '!' || c1 == 'L' ? 0 : -1; break;
               case 'J': result = c1 == ']' ? 0 : -1; break;
               case 'K': result = c1 == '|' ? 0 : -1; break;
               case 'L': result = c1 == '1' || c1 == '!' || c1 == 'I' || c1 == '7' || c1 == '|' ? 0 : -1; break;
               case 'N': result = c1 == '^' ? 0 : -1; break;
               case 'O': result = c1 == '0' || c1 == '*' ? 0 : -1; break;
               case 'P': result = c1 == '9' || c1 == '?' ? 0 : -1; break;
               case 'Q': result = c1 == '2' || c1 == '&' || c1 == '9' ? 0 : -1; break;
               case 'R': result = c1 == '4' ? 0 : -1; break;
               case 'S': result = c1 == '5' || c1 == '$' || c1 == 'Z' || c1 == '2' ? 0 : -1; break;
               case 'T': result = c1 == '7' || c1 == '+' ? 0 : -1; break;
               case 'U': result = c1 == 'V' ? 0 : -1; break;
               case 'V': result = c1 == 'U' || c1 == 'F' ? 0 : -1; break;
               case 'W': result = c1 == 'M' ? 0 : -1; break;
               case 'X': result = c1 == '*' ? 0 : -1; break;
               case 'Y': result = c1 == '&' || c1 == 'J' ? 0 : -1; break;
               case 'Z': result = c1 == '2' || c1 == '7' || c1 == '%' || c1 == 'S' ? 0 : -1; break;
               default: result = -1;
           }
           
           if (!result) continue;
       }

       if (leet_numbers && c2 >= '0' && c2 <= '9' )
       {
           switch(c2)
           {
               /* Let's try some common Leet character substitutions */
               case '1': result = c1 == 'I' || c1 == '!' || c1 == 'L' ? 0 : -1; break;
               case '2': result = c1 == 'Z' ? 0 : -1; break;
               case '3': result = c1 == 'E' ? 0 : -1; break;
               case '4': result = c1 == 'A' ? 0 : -1; break;
               case '5': result = c1 == 'S' ? 0 : -1; break;
               case '6': result = c1 == 'G' || c1 == '&' || c1 == '9' ? 0 : -1; break;
               case '7': result = c1 == 'T' || c1 == 'L' ? 0 : -1; break;
               case '8': result = c1 == 'B' ? 0 : -1; break;
               case '9': result = c1 == 'P' || c1 == 'G' || c1 == '6' ? 0 : -1; break;
               case '0': result = c1 == 'O' ? 0 : -1; break;
               default: result = -1;
           }
           
           if (!result) continue;
       }

       if (leet_symbols)
       {
           switch(c2)
           {
               /* Let's try some common Leet character substitutions */
               case '&': result = c1 == 'Y' || c1 == 'G' || c1 == '6' ? 0 : -1; break;
               default: result = -1;
           }
           
           if (!result) continue;
       }
       
    }
    
    return result;
}

int checkAvoidManyRepetitions(const char* buff, const int charRepetitions)
{
   for(int i = 0; buff[i] != 0; i++)
   {
      int counter = 1;
      for(int j = i + 1; buff[j] != 0; j++) {
          if (buff[i] == buff[j])
              counter++;
      }
      
      if (counter > charRepetitions)
          return 0;
   }
   
   return 1;
}

int checkAvoidTripleChars(const char* buff)
{
   const char b0 = toupper(buff[0]);
   const char b1 = toupper(buff[1]);
   const char b2 = toupper(buff[2]);
   return !( b0 == b1 && b0 == b2 );
}


int checkAllowedDoubleChars(const char* buff)
{
   static const char* allowedDoubleChars = "ABCDEILMNOPRST1234567890#!-$@%&*_^~=?+:;.<>|";
   const char b0 = toupper(buff[0]);
   const char b1 = toupper(buff[1]);
   if (b0 != b1)
       return 1;

   for(int i = 0; allowedDoubleChars[i] != 0; i++)
   {
      if (b0 == allowedDoubleChars[i])
        return 1;
   }

   return 0;
}

void generate_passwords_helper(char* password, int index, char* passwordSubstring, int substringPosition, int charRepetitions, int num_characters)
{
    password[index] = 0;
    password[index + 1] = 0;

    if (index == max_password_len) {
        printf("%s\n", password);
        password[index] = 0;
        return;    
    }
    
    if (index + 1 > min_password_len + substringPosition) { 	
        printf("%s\n", password);
    }
    
    int substringLen = strlen(passwordSubstring);
    if (substringLen > 0) 
    {
	if (index >= substringPosition)
            substringLen = (index - substringPosition + 1) < substringLen ? (index - substringPosition + 1) : substringLen;
        else
            substringLen = 0;
    }
    
    for (int i = 0; i < num_characters; i++) {
        password[index] = charset[i];

        if (only_decorators && !isSymbol(password[index]))
        {
           if ( index < substringPosition )
           	continue;
           	
           if ( index >= substringPosition + substringLen)
               continue;
        }
                
        if ( substringLen > 0 && checkCmpSubstring(password + substringPosition, passwordSubstring, substringLen) != 0 )
        {
           continue;
        }     
     
        if (index > 1)
        {
          if ( !(checkAllowedDoubleChars(&password[index - 1]) && checkAvoidTripleChars(&password[index - 2])) ) {
            continue;
          }
        }
        else if (index > 0)
        {
          if ( !checkAllowedDoubleChars(&password[index - 1]) ) {
            continue;
          }
        }

        if (index >= charRepetitions && !checkAvoidManyRepetitions(password, charRepetitions) )
            continue;
        
        generate_passwords_helper(password, index + 1, passwordSubstring, substringPosition, charRepetitions, num_characters);
    }
    
    password[index] = 0;
}


void parseOptions(const int argc, char** argv, char* passwordSubstring)
{
   min_password_len = MIN_PASSWORD_LENGTH;
   max_password_len = MAX_PASSWORD_LENGTH;
   max_char_repetition = MAX_CHAR_REPETITION;
   
   char opt;
   while ((opt = getopt(argc, argv, "LANSdl:m:r:p:")) != -1)
   {
       switch (opt)
       {
           case 'L': leet_letters = leet_numbers = leet_symbols = 1; break;
           case 'A': leet_letters = 1; break;
           case 'N': leet_numbers = 1; break;
           case 'S': leet_symbols = 1; break;
           case 'd': only_decorators = 1; break;
           case 'l': min_password_len = atoi(optarg); break;
           case 'm': max_password_len = atoi(optarg); break;
           case 'r': max_char_repetition = atoi(optarg); break;
           case 'p': strncpy(passwordSubstring, optarg, MAX_PASSWORD_LENGTH); break;
           default:
               fprintf(stderr, "Usage: %s [-LANSd] [-l min_password_length] [-m max_password_length] [-r max_char_repetition] [-p password_prefix] \n", argv[0]);
               exit(EXIT_FAILURE);
       }
   }

   int substringLen = strlen(passwordSubstring);
   min_password_len = min_password_len < substringLen ? substringLen : min_password_len;
   min_password_len = min_password_len > MIN_PASSWORD_LENGTH ? min_password_len : MIN_PASSWORD_LENGTH;
   max_password_len = max_password_len > MIN_PASSWORD_LENGTH ? max_password_len : MIN_PASSWORD_LENGTH;
   max_password_len = max_password_len < MAX_PASSWORD_LENGTH ? max_password_len : MAX_PASSWORD_LENGTH;
   min_password_len = min_password_len > max_password_len ? max_password_len : min_password_len;
   
   max_char_repetition = max_char_repetition < 1 ? 1 : max_char_repetition;
   max_char_repetition = max_char_repetition > max_password_len ? max_password_len : max_char_repetition;
   
}

int main(const int argc, char** argv)
{
    const int num_characters = strlen(charset);
    char password[MAX_PASSWORD_LENGTH + 1];
    memset(password, 0, sizeof(password));
    
    char passwordSubstring[MAX_PASSWORD_LENGTH + 1];
    memset(passwordSubstring, 0, sizeof(password));
        
    parseOptions(argc, argv, passwordSubstring);
    int substringLen = strlen(passwordSubstring);

    if (substringLen > 0)
    {
        for (int substringPosition = 0; substringPosition <= (max_password_len - substringLen); substringPosition++)
   	    generate_passwords_helper(password, 0, passwordSubstring, substringPosition, max_char_repetition, num_characters); 
    }
    else
    {
        generate_passwords_helper(password, 0, passwordSubstring, 0, max_char_repetition, num_characters);
    }
    return 0;
}

