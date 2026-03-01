#include <stdio.h>
#include <ctype.h>

long Hash( char* String )
{
  unsigned long Hash = 236;
	int c;

	while (c = *String++)
		Hash = c + (Hash << 4) + c +  (Hash << 13) - Hash;

	return Hash;
}

long HashStringA( char*  String )
{
    unsigned long Hash = 236;
    int c;

    while (c = *String++)
        Hash = c + (Hash << 4) + c +  (Hash << 13) - Hash;

    return Hash;
}

void ToUpperString(char * temp) {
  // Convert to upper case
  char *s = temp;
  while (*s) {
    *s = toupper((unsigned char) *s);
    s++;
  }
}

int main(int argc, char** argv) 
{
  if (argc < 2)
    return 0;



  printf("\n[+] CoffAPI Hashed %s ==> 0x%x\n\n", argv[1], HashStringA( argv[1] )); 
  ToUpperString(argv[1]);
  printf("\n[+] Hashed %s ==> 0x%x\n\n", argv[1], Hash( argv[1] )); 
  return 0;
}
