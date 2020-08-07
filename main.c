#include <assert.h>
#include <stdio.h>
#include "cssobf.h"

int
main(int argc, char *argv[])
{
	if (argc != 3)
		return -1;

	css_obfuscate(argv[1], argv[2]);

	return 0;
fail:
	fprintf(stderr, "Error\n");
	return -1;
}
